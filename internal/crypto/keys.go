package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the size of X25519 keys in bytes
	KeySize = 32
)

// KeyPair holds a private and public key pair
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	// Generate random private key
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	// Clamp private key (X25519 requirement)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// PrivateKeyBase64 returns the private key as base64
func (kp *KeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey[:])
}

// PublicKeyBase64 returns the public key as base64
func (kp *KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey[:])
}

// ParsePrivateKey parses a base64 encoded private key and derives the public key
func ParsePrivateKey(b64 string) (*KeyPair, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	if len(data) != KeySize {
		return nil, fmt.Errorf("invalid private key length: %d (expected %d)", len(data), KeySize)
	}

	var privateKey [KeySize]byte
	var publicKey [KeySize]byte
	copy(privateKey[:], data)

	// Derive public key from private key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ParsePublicKey parses a base64 encoded public key
func ParsePublicKey(b64 string) ([KeySize]byte, error) {
	var publicKey [KeySize]byte

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return publicKey, fmt.Errorf("decode public key: %w", err)
	}

	if len(data) != KeySize {
		return publicKey, fmt.Errorf("invalid public key length: %d (expected %d)", len(data), KeySize)
	}

	copy(publicKey[:], data)
	return publicKey, nil
}

// ComputeSharedSecret computes the shared secret using X25519 ECDH
func ComputeSharedSecret(privateKey [KeySize]byte, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var sharedSecret [KeySize]byte

	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return sharedSecret, fmt.Errorf("compute shared secret: %w", err)
	}

	copy(sharedSecret[:], result)
	return sharedSecret, nil
}

// DeriveSessionKeys derives encryption keys from the shared secret using HKDF (RFC 5869).
// Returns: (sendKey, receiveKey, error)
// The salt is fixed (no per-session randomness needed since X25519 shared secrets
// are already unique per key pair). Info strings differentiate send/receive keys.
func DeriveSessionKeys(sharedSecret [KeySize]byte, isInitiator bool) ([KeySize]byte, [KeySize]byte, error) {
	var sendKey, recvKey [KeySize]byte

	salt := []byte("quiccochet-v2-session-keys")

	// Derive initiator→responder key
	irReader := hkdf.New(sha256.New, sharedSecret[:], salt, []byte("initiator-to-responder"))
	if _, err := io.ReadFull(irReader, sendKey[:]); err != nil {
		return sendKey, recvKey, fmt.Errorf("derive send key: %w", err)
	}

	// Derive responder→initiator key
	riReader := hkdf.New(sha256.New, sharedSecret[:], salt, []byte("responder-to-initiator"))
	if _, err := io.ReadFull(riReader, recvKey[:]); err != nil {
		return sendKey, recvKey, fmt.Errorf("derive recv key: %w", err)
	}

	// Swap keys based on role (initiator sends, responder receives with same key)
	if !isInitiator {
		sendKey, recvKey = recvKey, sendKey
	}

	return sendKey, recvKey, nil
}
