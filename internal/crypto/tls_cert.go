package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
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

// GenerateEphemeralTLSCertificate produces a fresh, NON-deterministic
// ed25519 self-signed certificate. Used for the server's GetCertificate
// fallback path: when an incoming QUIC ClientHello arrives from a wire
// source IP that does NOT map to any peer, we still need to present a
// valid TLS certificate (the handshake then fails at peer-cert-pinning
// on the client side, but quic-go requires GetCertificate to return a
// non-nil cert to start the handshake). Returning one of the real
// peers' certs would leak peer identity to any internet scanner that
// completes a ClientHello — see Sec-H3 in the v2.0.0 audit. This
// function returns a cert with a random key and random serial that
// reveals nothing about any peer's shared secret.
func GenerateEphemeralTLSCertificate() (*tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral cert: gen ed25519 key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ephemeral cert: random serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("ephemeral cert: create cert: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

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

// MakeVerifyPeerCertificateMulti returns a callback for tls.Config that
// accepts the handshake when the peer's leaf certificate sha256 is found
// in the provided set. Used by the server to gate on "is this a known
// peer at all" — the set is built from all peers[].peer_public_key →
// derived cert hashes at server startup.
//
// SECURITY NOTE: this is the "do we know this client?" gate. The actual
// per-peer cipher selection is handled in ObfuscatedConn by wire source
// IP dispatch (see tunnel/obfuscator.go). Both guards must pass for
// any packet to be decrypted: TLS handshake authenticates the
// session-level identity, AEAD with the peer-specific key authenticates
// each packet.
//
// Comparison iterates the FULL snapshot (no early-return) and
// OR-accumulates each constant-time compare so the call's runtime
// reveals neither which hash matched nor whether any matched at all
// until the final branch. Without this, the time-to-return depends on
// the iteration position of the matching hash in the snapshot — which
// for a `map[[32]byte]struct{}` source is randomised once per process,
// so the leak is fixed-per-process rather than per-handshake, but the
// textbook constant-time pattern costs nothing extra and closes the
// observation cleanly.
func MakeVerifyPeerCertificateMulti(hashes map[[32]byte]struct{}) func([][]byte, [][]*x509.Certificate) error {
	// Snapshot the map into a fixed slice so the callback is
	// independent of any future modification to the caller's map.
	known := make([][32]byte, 0, len(hashes))
	for h := range hashes {
		known = append(known, h)
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		got := sha256.Sum256(rawCerts[0])
		var match int
		for _, expected := range known {
			match |= subtle.ConstantTimeCompare(got[:], expected[:])
		}
		if match == 1 {
			return nil
		}
		return errors.New("peer certificate does not match any known peer's shared-secret-derived cert")
	}
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
//
// SECURITY NOTE: do NOT call this with a tls.Config that has chain
// validation enabled. The cert returned by DeriveTLSCertificate has
// NotBefore=Unix(0,0) and NotAfter=2099-12-31 so its determinism
// holds across runs — a CA-style chain validator would reject it
// (or accept absurd validity windows), defeating the pinning.
// VerifyPeerCertificate is the ONLY auth mechanism here; the cert
// itself is just a deterministic carrier of the shared-secret hash.
func MakeVerifyPeerCertificate(expectedHash []byte) func([][]byte, [][]*x509.Certificate) error {
	// Defensive: the only legitimate caller passes DeriveTLSCertHash output
	// which is exactly sha256.Size (32) bytes. Anything shorter or longer
	// is a misconfiguration; refuse to accept any handshake rather than
	// silently rely on subtle.ConstantTimeCompare's length-mismatch
	// behaviour (which today returns 0 — correct — but ties this verifier
	// to that detail of the stdlib API).
	if len(expectedHash) != sha256.Size {
		return func(_ [][]byte, _ [][]*x509.Certificate) error {
			return fmt.Errorf("peer cert verifier misconfigured: expected hash is %d bytes, want %d", len(expectedHash), sha256.Size)
		}
	}
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
