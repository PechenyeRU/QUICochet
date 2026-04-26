package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/hkdf"
)

// DeriveTLSCertificate produces a deterministic ed25519 TLS certificate
// from the X25519 shared secret. Both peers run this on the same secret
// and obtain a byte-identical cert; each peer presents that cert at the
// QUIC TLS handshake and pins the remote cert with sha256-equality
// (DeriveTLSCertHash). This binds the QUIC handshake itself to the
// shared secret, instead of the previous unauth ephemeral self-signed
// cert + InsecureSkipVerify pair (Q-02 / Q-03).
//
// Determinism rationale:
//   - the ed25519 keypair seed is HKDF(sharedSecret, "tls-cert-seed");
//   - all template fields (SerialNumber, NotBefore, NotAfter, Subject,
//     SAN) are fixed constants;
//   - ed25519 signatures are deterministic by RFC 8032, and the
//     deterministic rand reader passed to x509.CreateCertificate covers
//     any other randomness the encoder might pull;
//
// so two calls with the same secret return the same DER cert.
func DeriveTLSCertificate(sharedSecret [KeySize]byte) (*tls.Certificate, error) {
	cert, _, err := deriveTLSCertInternal(sharedSecret)
	return cert, err
}

// DeriveTLSCertHash returns sha256 of the deterministic cert leaf,
// intended for VerifyPeerCertificate fast-path comparison.
func DeriveTLSCertHash(sharedSecret [KeySize]byte) ([]byte, error) {
	_, der, err := deriveTLSCertInternal(sharedSecret)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(der)
	return h[:], nil
}

func deriveTLSCertInternal(sharedSecret [KeySize]byte) (*tls.Certificate, []byte, error) {
	// HKDF a 32-byte seed for the ed25519 keypair.
	seedReader := hkdf.New(sha256.New, sharedSecret[:],
		[]byte("quiccochet-v2-tls-cert"), []byte("ed25519-seed"))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(seedReader, seed); err != nil {
		return nil, nil, fmt.Errorf("derive ed25519 seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "quiccochet"},
		Issuer:                pkix.Name{CommonName: "quiccochet"},
		NotBefore:             time.Unix(0, 0).UTC(),
		NotAfter:              time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"quiccochet.local"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Use a deterministic reader so any randomness the encoder might
	// pull (none for ed25519 today, but defensive) does not perturb
	// the output across runs.
	detRand := newDeterministicReader(sharedSecret)
	certDER, err := x509.CreateCertificate(detRand, template, template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        nil, // computed lazily by tls.Config if needed
	}
	return tlsCert, certDER, nil
}

// MakeVerifyPeerCertificate returns a callback for tls.Config that
// fails the handshake unless the peer's leaf certificate matches the
// expected sha256 hash. Used by both client and server so the QUIC
// handshake is mutually authenticated against the shared secret.
//
// Comparison is constant-time. The expected hash is itself derived
// from the shared secret, so a non-constant-time compare would in
// principle leak hash bits via handshake timing — pratically a
// non-issue (each leak attempt is a visible failed handshake) but
// trivial to close at this layer.
func MakeVerifyPeerCertificate(expectedHash []byte) func([][]byte, [][]*x509.Certificate) error {
	expected := append([]byte(nil), expectedHash...)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		got := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(got[:], expected) != 1 {
			return errors.New("peer certificate does not match shared-secret-derived expected cert")
		}
		return nil
	}
}

// deterministicReader is an infinite stream of bytes derived from the
// shared secret via HKDF. Used as the rand argument to
// x509.CreateCertificate to keep the output reproducible even if a
// future encoder pulls bytes for ASN.1 padding or extensions.
type deterministicReader struct {
	r io.Reader
}

func newDeterministicReader(secret [KeySize]byte) *deterministicReader {
	return &deterministicReader{
		r: hkdf.New(sha256.New, secret[:],
			[]byte("quiccochet-v2-tls-cert"), []byte("x509-rand")),
	}
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	return io.ReadFull(d.r, p)
}
