package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestKeyPairGeneration(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Keys should be different
	if bytes.Equal(kp1.PrivateKey[:], kp2.PrivateKey[:]) {
		t.Error("Generated keys should be unique")
	}
}

func TestKeyPairParsing(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Parse the base64 private key
	kp2, err := ParsePrivateKey(kp1.PrivateKeyBase64())
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(kp1.PublicKey[:], kp2.PublicKey[:]) {
		t.Error("Public key mismatch after parsing")
	}
}

func TestSharedSecret(t *testing.T) {
	// Generate two key pairs
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Compute shared secrets
	aliceSecret, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (alice): %v", err)
	}

	bobSecret, err := ComputeSharedSecret(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (bob): %v", err)
	}

	// Shared secrets should be identical
	if !bytes.Equal(aliceSecret[:], bobSecret[:]) {
		t.Error("Shared secrets should be equal")
	}
}

func TestCipherEncryptDecrypt(t *testing.T) {
	// Generate keys
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Compute shared secret
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)

	// Derive session keys
	aliceSend, aliceRecv, _ := DeriveSessionKeys(sharedSecret, true)
	bobSend, bobRecv, _ := DeriveSessionKeys(sharedSecret, false)

	// Create ciphers
	aliceCipher, err := NewCipher(aliceSend, aliceRecv)
	if err != nil {
		t.Fatalf("NewCipher (alice): %v", err)
	}

	bobCipher, err := NewCipher(bobSend, bobRecv)
	if err != nil {
		t.Fatalf("NewCipher (bob): %v", err)
	}

	// Test encryption/decryption
	plaintext := []byte("Hello, this is a secret message!")

	// Alice encrypts, Bob decrypts
	ciphertext, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := bobCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Bob encrypts, Alice decrypts
	ciphertext2, _ := bobCipher.Encrypt(plaintext)
	decrypted2, err := aliceCipher.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt (bob->alice): %v", err)
	}

	if !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("Decrypted text mismatch (bob->alice)")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	sendKey, recvKey, _ := DeriveSessionKeys(sharedSecret, true)
	cipher, _ := NewCipher(sendKey, recvKey)

	data := make([]byte, 1400) // MTU size
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = cipher.Encrypt(data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	aliceSend, aliceRecv, _ := DeriveSessionKeys(sharedSecret, true)
	bobSend, bobRecv, _ := DeriveSessionKeys(sharedSecret, false)

	aliceCipher, _ := NewCipher(aliceSend, aliceRecv)
	bobCipher, _ := NewCipher(bobSend, bobRecv)

	data := make([]byte, 1400)
	ciphertext, _ := aliceCipher.Encrypt(data)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = bobCipher.Decrypt(ciphertext)
	}
}

func TestReplayCheckRejectsForeignPrefix(t *testing.T) {
	c, _ := NewCipher([32]byte{1}, [32]byte{2})

	// First packet establishes the peer prefix
	nonce1 := make([]byte, NonceSize)
	copy(nonce1[:4], []byte{0xAA, 0xAA, 0xAA, 0xAA})
	binary.BigEndian.PutUint64(nonce1[4:], 100)
	if !c.replayCheck(nonce1) {
		t.Fatal("first packet should be accepted")
	}

	// Packet with a foreign prefix must be rejected, not reset the window
	nonce2 := make([]byte, NonceSize)
	copy(nonce2[:4], []byte{0xBB, 0xBB, 0xBB, 0xBB})
	binary.BigEndian.PutUint64(nonce2[4:], 200)
	if c.replayCheck(nonce2) {
		t.Fatal("foreign prefix must be rejected")
	}

	// Original prefix with already-seen counter must still be rejected
	if c.replayCheck(nonce1) {
		t.Fatal("replay must be rejected after foreign-prefix attempt")
	}
}

func TestReplayCheckSlidingWindow(t *testing.T) {
	c, _ := NewCipher([32]byte{1}, [32]byte{2})

	prefix := []byte{0xCC, 0xCC, 0xCC, 0xCC}
	makeNonce := func(counter uint64) []byte {
		n := make([]byte, NonceSize)
		copy(n[:4], prefix)
		binary.BigEndian.PutUint64(n[4:], counter)
		return n
	}

	// First packet
	if !c.replayCheck(makeNonce(1)) {
		t.Fatal("counter 1 should be accepted")
	}

	// Same counter = replay
	if c.replayCheck(makeNonce(1)) {
		t.Fatal("counter 1 replay should be rejected")
	}

	// Higher counter
	if !c.replayCheck(makeNonce(5)) {
		t.Fatal("counter 5 should be accepted")
	}

	// Out of order within window
	if !c.replayCheck(makeNonce(3)) {
		t.Fatal("counter 3 within window should be accepted")
	}

	// Counter 3 again = replay
	if c.replayCheck(makeNonce(3)) {
		t.Fatal("counter 3 replay should be rejected")
	}
}
