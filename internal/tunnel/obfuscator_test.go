package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

func TestObfuscationLogic(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)

	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	// Manual test of WriteTo logic (without network)
	msg := []byte("test message")
	// [Type:1][Len:2][Payload:variable]
	plaintext := make([]byte, 3+len(msg))
	plaintext[0] = pktTypeData
	plaintext[1] = byte(len(msg) >> 8)
	plaintext[2] = byte(len(msg) & 0xFF)
	copy(plaintext[3:], msg)

	buf1 := make([]byte, 2048)
	encLen, err := cipher1.EncryptTo(buf1, plaintext)
	if err != nil {
		t.Fatalf("EncryptTo failed: %v", err)
	}

	// Decrypt back
	buf2 := make([]byte, 2048)
	decLen, err := cipher2.DecryptTo(buf2, buf1[:encLen])
	if err != nil {
		t.Fatalf("DecryptTo failed: %v", err)
	}

	if !bytes.Equal(plaintext, buf2[:decLen]) {
		t.Errorf("Mismatch! Expected %x, got %x", plaintext, buf2[:decLen])
	}
}

func TestObfuscatedConn(t *testing.T) {
	// Setup real keys
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)

	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	// Local UDP pair
	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc1.Close()

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc2.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 100, // Force heavy padding for the test
		},
	}

	oc1 := NewObfuscatedConn(pc1, cipher1, cfg)
	oc2 := NewObfuscatedConn(pc2, cipher2, cfg)

	addr1 := oc1.LocalAddr()
	addr2 := oc2.LocalAddr()

	t.Run("DataPacket", func(t *testing.T) {
		msg := []byte("hello obfuscation")
		_, err := oc1.WriteTo(msg, addr2)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 2048)
		oc2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := oc2.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(msg, buf[:n]) {
			t.Errorf("expected %s, got %s", msg, buf[:n])
		}
		if addr.String() != addr1.String() {
			t.Errorf("expected addr %s, got %s", addr1, addr)
		}
	})

	// Regression for Q-10: verify that the on-wire packet size only ever
	// takes one of the two fixed bucket values, and that anything beyond
	// the second bucket is dropped (CBR invariant).
	t.Run("BucketSizing", func(t *testing.T) {
		// With MTU=100 the AEAD overhead (12+16) gives:
		//   targetPtSize  = 72   → wire size 100
		//   bucket2PtSize = 144  → wire size 172
		// Listener for direct (un-obfuscated) reads so we can measure
		// the raw on-wire size.
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()

		send := func(payloadLen int) int {
			payload := bytes.Repeat([]byte("x"), payloadLen)
			before := oc1.OversizeDrops()
			_, werr := oc1.WriteTo(payload, raw.LocalAddr())
			if werr != nil {
				t.Fatalf("WriteTo(%d): %v", payloadLen, werr)
			}
			if oc1.OversizeDrops() > before {
				return -1 // dropped
			}
			buf := make([]byte, 4096)
			_ = raw.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, rerr := raw.ReadFrom(buf)
			if rerr != nil {
				t.Fatalf("ReadFrom(%d): %v", payloadLen, rerr)
			}
			return n
		}

		// Tier-1 bucket: small payload should produce a 100-byte wire packet.
		if got := send(10); got != 100 {
			t.Errorf("small payload wire size = %d, want 100", got)
		}
		// Tier-1 boundary: payload that just fits in tier 1 (72-3 = 69).
		if got := send(69); got != 100 {
			t.Errorf("tier-1 boundary wire size = %d, want 100", got)
		}
		// Tier-2 bucket: payload that overflows tier 1 should land in tier 2.
		if got := send(70); got != 172 {
			t.Errorf("tier-2 lower wire size = %d, want 172", got)
		}
		if got := send(141); got != 172 {
			t.Errorf("tier-2 upper wire size = %d, want 172", got)
		}
		// Oversize: must be dropped; counter must increment; nothing on wire.
		dropsBefore := oc1.OversizeDrops()
		_, werr := oc1.WriteTo(bytes.Repeat([]byte("x"), 200), raw.LocalAddr())
		if werr != nil {
			t.Fatalf("WriteTo oversize unexpectedly errored: %v", werr)
		}
		if oc1.OversizeDrops() != dropsBefore+1 {
			t.Errorf("OversizeDrops = %d, want %d", oc1.OversizeDrops(), dropsBefore+1)
		}
		_ = raw.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := make([]byte, 4096)
		if _, _, err := raw.ReadFrom(buf); err == nil {
			t.Error("expected timeout on oversize drop, got a packet")
		}
	})

	t.Run("DummyPacket", func(t *testing.T) {
		// Send a dummy from 1 to 2
		err := oc1.SendChaff(addr2)
		if err != nil {
			t.Fatal(err)
		}

		// Send a real packet from 1 to 2
		msg := []byte("after dummy")
		go func() {
			time.Sleep(100 * time.Millisecond)
			oc1.WriteTo(msg, addr2)
		}()

		// oc2.ReadFrom should skip the dummy and return "after dummy"
		buf := make([]byte, 2048)
		oc2.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := oc2.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(msg, buf[:n]) {
			t.Errorf("expected %s, got %s", msg, buf[:n])
		}
	})
}

func BenchmarkObfuscatorWrite(b *testing.B) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	cipher, _ := crypto.NewCipher(sk1, rk1)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 1400,
		},
	}

	oc := NewObfuscatedConn(pc, cipher, cfg)
	addr := oc.LocalAddr()

	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oc.WriteTo(data, addr)
	}
}

func BenchmarkObfuscatorRead(b *testing.B) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc1.Close()

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc2.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 1400,
		},
	}

	oc1 := NewObfuscatedConn(pc1, cipher1, cfg)
	oc2 := NewObfuscatedConn(pc2, cipher2, cfg)

	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}

	// Pre-send packets
	addr2 := oc2.LocalAddr()
	go func() {
		for {
			oc1.WriteTo(data, addr2)
		}
	}()

	buf := make([]byte, 2048)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		oc2.ReadFrom(buf)
	}
}
