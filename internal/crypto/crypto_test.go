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

func TestReplayCheckPrefixTransitions(t *testing.T) {
	c, _ := NewCipher([32]byte{1}, [32]byte{2})

	makeNonceP := func(prefix byte, counter uint64) []byte {
		n := make([]byte, NonceSize)
		n[0], n[1], n[2], n[3] = prefix, prefix, prefix, prefix
		binary.BigEndian.PutUint64(n[4:], counter)
		return n
	}

	// First packet establishes prefix A
	if !c.replayCheck(makeNonceP(0xAA, 100)) {
		t.Fatal("first packet should be accepted")
	}

	// New prefix B (peer restart) should be accepted
	if !c.replayCheck(makeNonceP(0xBB, 1)) {
		t.Fatal("new prefix (peer restart) should be accepted")
	}

	// Old prefix A is now dead — reject (toggle replay attack prevention)
	if c.replayCheck(makeNonceP(0xAA, 50)) {
		t.Fatal("dead prefix must be rejected")
	}

	// Third prefix C (another restart) should be accepted
	if !c.replayCheck(makeNonceP(0xCC, 1)) {
		t.Fatal("another new prefix should be accepted")
	}

	// Both A and B are now dead
	if c.replayCheck(makeNonceP(0xAA, 999)) {
		t.Fatal("prefix A still dead")
	}
	if c.replayCheck(makeNonceP(0xBB, 999)) {
		t.Fatal("prefix B still dead")
	}
}

func TestReplayCheckTogglePrefixAttack(t *testing.T) {
	c, _ := NewCipher([32]byte{1}, [32]byte{2})

	makeNonceP := func(prefix byte, counter uint64) []byte {
		n := make([]byte, NonceSize)
		n[0], n[1], n[2], n[3] = prefix, prefix, prefix, prefix
		binary.BigEndian.PutUint64(n[4:], counter)
		return n
	}

	// Establish session with prefix B, counter 200
	if !c.replayCheck(makeNonceP(0xBB, 200)) {
		t.Fatal("first packet should be accepted")
	}

	// Attacker sends old session prefix A to trigger reset
	c.replayCheck(makeNonceP(0xAA, 10))

	// Attacker tries to replay the SAME counter 200 from prefix B.
	// With naive auto-reset this would succeed because the bitmap was flushed.
	// With dead prefix tracking, prefix B is dead → reject.
	if c.replayCheck(makeNonceP(0xBB, 200)) {
		t.Fatal("replay of already-seen counter must be rejected even after prefix toggle")
	}
}

func TestReplayCheckDeadPrefixCap(t *testing.T) {
	c, _ := NewCipher([32]byte{1}, [32]byte{2})

	makeNonce := func(p1, p2 byte, counter uint64) []byte {
		n := make([]byte, NonceSize)
		n[0], n[1] = p1, p2
		binary.BigEndian.PutUint64(n[4:], counter)
		return n
	}

	// Establish prefix 0,0
	if !c.replayCheck(makeNonce(0, 0, 1)) {
		t.Fatal("first packet")
	}

	// Cycle through 257 different prefixes
	for i := 1; i <= 257; i++ {
		if !c.replayCheck(makeNonce(byte(i>>8), byte(i&0xff), 1)) {
			t.Fatalf("prefix %d should be accepted", i)
		}
	}

	// After cap reset, the very first prefix should be accepted again
	if !c.replayCheck(makeNonce(0, 0, 1)) {
		t.Fatal("after dead set cap, recycled prefix should be accepted")
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

	// Way below window = stale, rejected
	if !c.replayCheck(makeNonce(10000)) {
		t.Fatal("counter 10000 should advance window")
	}
	if c.replayCheck(makeNonce(100)) {
		t.Fatal("counter 100 below window should be rejected")
	}

	// Huge jump clears the entire window without panicking
	if !c.replayCheck(makeNonce(100000)) {
		t.Fatal("huge counter should be accepted")
	}
	if !c.replayCheck(makeNonce(99000)) {
		t.Fatal("counter within new window should be accepted")
	}
}

func FuzzCipherDecrypt(f *testing.F) {
	c, _ := NewCipher([32]byte{1}, [32]byte{2})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = c.Decrypt(data)
	})
}
