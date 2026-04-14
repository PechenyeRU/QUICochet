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
