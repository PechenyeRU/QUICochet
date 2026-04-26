package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestDeriveTLSCertificateDeterministic verifies the core invariant
// the whole Q-02/Q-03 fix depends on: two calls with the same shared
// secret produce a byte-identical certificate.
func TestDeriveTLSCertificateDeterministic(t *testing.T) {
	var secret [KeySize]byte
	for i := range secret {
		secret[i] = byte(i)
	}

	cert1, err := DeriveTLSCertificate(secret)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	cert2, err := DeriveTLSCertificate(secret)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}

	if len(cert1.Certificate) != 1 || len(cert2.Certificate) != 1 {
		t.Fatalf("expected exactly one cert in chain, got %d / %d", len(cert1.Certificate), len(cert2.Certificate))
	}
	if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatalf("two derivations of the same secret produced different DER")
	}

	// Sanity: the cert really is a valid x509 leaf with the expected
	// fixed Subject and validity window.
	parsed, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("parse derived cert: %v", err)
	}
	if parsed.Subject.CommonName != "quiccochet" {
		t.Errorf("Subject.CommonName = %q, want %q", parsed.Subject.CommonName, "quiccochet")
	}
	if parsed.NotAfter.Year() < 2099 {
		t.Errorf("NotAfter year = %d, want >= 2099", parsed.NotAfter.Year())
	}
}

// TestDeriveTLSCertificateDifferentSecrets verifies that different
// shared secrets produce different certificates (otherwise pinning
// would be a no-op).
func TestDeriveTLSCertificateDifferentSecrets(t *testing.T) {
	var s1, s2 [KeySize]byte
	for i := range s1 {
		s1[i] = byte(i)
	}
	for i := range s2 {
		s2[i] = byte(i + 1)
	}

	c1, err := DeriveTLSCertificate(s1)
	if err != nil {
		t.Fatalf("derive s1: %v", err)
	}
	c2, err := DeriveTLSCertificate(s2)
	if err != nil {
		t.Fatalf("derive s2: %v", err)
	}
	if bytes.Equal(c1.Certificate[0], c2.Certificate[0]) {
		t.Fatalf("different secrets produced identical DER — derivation is broken")
	}
}

// TestDeriveTLSCertHashMatchesSha256OfDER verifies the hash helper is
// consistent with what VerifyPeerCertificate will compute on the
// remote DER cert.
func TestDeriveTLSCertHashMatchesSha256OfDER(t *testing.T) {
	var secret [KeySize]byte
	for i := range secret {
		secret[i] = byte(i + 5)
	}
	cert, err := DeriveTLSCertificate(secret)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	want := sha256.Sum256(cert.Certificate[0])

	got, err := DeriveTLSCertHash(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("DeriveTLSCertHash mismatch — got %x, want %x", got, want[:])
	}
}

// TestMakeVerifyPeerCertificate exercises the VerifyPeerCertificate
// callback in isolation: the matching hash passes, a wrong hash fails,
// and an empty cert chain fails closed.
func TestMakeVerifyPeerCertificate(t *testing.T) {
	var secret [KeySize]byte
	for i := range secret {
		secret[i] = byte(0xa0 + i)
	}
	cert, _ := DeriveTLSCertificate(secret)
	hash, _ := DeriveTLSCertHash(secret)

	verify := MakeVerifyPeerCertificate(hash)

	if err := verify([][]byte{cert.Certificate[0]}, nil); err != nil {
		t.Fatalf("matching cert rejected: %v", err)
	}

	tampered := append([]byte(nil), cert.Certificate[0]...)
	tampered[0] ^= 0xFF
	if err := verify([][]byte{tampered}, nil); err == nil {
		t.Fatal("tampered cert accepted")
	}

	if err := verify(nil, nil); err == nil {
		t.Fatal("empty cert chain accepted")
	}
}

// TestDerivedCertHandshakeRoundTrip is the integration test: spin up a
// real TLS server and client over a net.Pipe, both using the
// derived cert + pinned VerifyPeerCertificate, and confirm:
//
//   - matching shared secrets handshake successfully;
//   - mismatched shared secrets fail the handshake on both sides.
//
// This validates the wire-level glue (mutual auth, ClientAuth=
// RequireAnyClientCert, InsecureSkipVerify+VerifyPeerCertificate
// interaction) end-to-end without involving quic-go.
func TestDerivedCertHandshakeRoundTrip(t *testing.T) {
	var secret [KeySize]byte
	for i := range secret {
		secret[i] = byte(0x55 + i)
	}

	t.Run("MatchingSecretsHandshakeSucceeds", func(t *testing.T) {
		if err := tlsHandshakePair(t, secret, secret); err != nil {
			t.Fatalf("matching-secret handshake failed: %v", err)
		}
	})

	t.Run("MismatchedSecretsHandshakeFails", func(t *testing.T) {
		var other [KeySize]byte
		for i := range other {
			other[i] = byte(0xAA - i)
		}
		err := tlsHandshakePair(t, secret, other)
		if err == nil {
			t.Fatal("mismatched-secret handshake unexpectedly succeeded")
		}
	})
}

// tlsHandshakePair runs a single TLS handshake over net.Pipe, with the
// server using serverSecret and the client using clientSecret. Returns
// the first error seen on either side, or nil if both succeed.
func tlsHandshakePair(t *testing.T, serverSecret, clientSecret [KeySize]byte) error {
	t.Helper()

	serverCert, err := DeriveTLSCertificate(serverSecret)
	if err != nil {
		return err
	}
	clientCert, err := DeriveTLSCertificate(clientSecret)
	if err != nil {
		return err
	}
	// Each side pins the hash of its OWN derived cert: the contract is
	// "I expect my peer to share my secret, therefore to derive the
	// same cert as me". With matching secrets both hashes coincide and
	// the handshake succeeds; with different secrets the peer presents
	// a cert derived from a different secret, the local hash does not
	// match, and the handshake fails.
	serverExpected, _ := DeriveTLSCertHash(serverSecret)
	clientExpected, _ := DeriveTLSCertHash(clientSecret)

	serverConf := &tls.Config{
		Certificates:          []tls.Certificate{*serverCert},
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: MakeVerifyPeerCertificate(serverExpected),
	}
	clientConf := &tls.Config{
		Certificates:          []tls.Certificate{*clientCert},
		InsecureSkipVerify:    true, //nolint:gosec  // VerifyPeerCertificate replaces chain validation.
		MinVersion:            tls.VersionTLS13,
		ServerName:            "quiccochet.local",
		VerifyPeerCertificate: MakeVerifyPeerCertificate(clientExpected),
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		s := tls.Server(serverConn, serverConf)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srvErrCh <- s.HandshakeContext(ctx)
	}()

	c := tls.Client(clientConn, clientConf)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cErr := c.HandshakeContext(ctx)
	sErr := <-srvErrCh

	switch {
	case cErr != nil && sErr != nil:
		// Both sides reported an error — return whichever is more
		// specific (server tends to report the cert mismatch first
		// because client cert verification runs server-side).
		return errors.Join(sErr, cErr)
	case cErr != nil:
		return cErr
	case sErr != nil:
		return sErr
	default:
		return nil
	}
}

// Compile-time check: deterministicReader satisfies io.Reader.
var _ io.Reader = (*deterministicReader)(nil)
