package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// benchTunnel sets up a loopback QUIC tunnel for benchmarking.
func benchTunnel(b *testing.B) (*quic.Conn, *quic.Conn, func()) {
	b.Helper()

	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)
	clientCipher, _ := crypto.NewCipher(sk1, rk1)
	serverCipher, _ := crypto.NewCipher(sk2, rk2)

	serverPC, _ := net.ListenPacket("udp", "127.0.0.1:0")
	clientPC, _ := net.ListenPacket("udp", "127.0.0.1:0")

	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
	}

	serverObf := NewObfuscatedConn(serverPC, serverCipher, cfg)
	clientObf := NewObfuscatedConn(clientPC, clientCipher, cfg)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quiccochet-bench"},
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:             10 * time.Second,
		MaxStreamReceiveWindow:     5 * 1024 * 1024,
		MaxConnectionReceiveWindow: 15 * 1024 * 1024,
		EnableDatagrams:            true,
	}

	ln, _ := quic.Listen(serverObf, tlsConf, quicConf)

	type ar struct {
		s *quic.Conn
		e error
	}
	ch := make(chan ar, 1)
	go func() {
		s, e := ln.Accept(context.Background())
		ch <- ar{s, e}
	}()

	clientTr := &quic.Transport{Conn: clientObf}
	clientConn, err := clientTr.Dial(
		context.Background(),
		serverObf.LocalAddr(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"quiccochet-bench"}},
		quicConf,
	)
	if err != nil {
		b.Fatal(err)
	}

	result := <-ch
	if result.e != nil {
		b.Fatal(result.e)
	}

	cleanup := func() {
		clientConn.CloseWithError(0, "done")
		result.s.CloseWithError(0, "done")
		ln.Close()
		clientTr.Close()
		serverPC.Close()
		clientPC.Close()
	}

	return clientConn, result.s, cleanup
}

func BenchmarkFullStack(b *testing.B) {
	clientConn, serverSess, cleanup := benchTunnel(b)
	defer cleanup()

	data := make([]byte, 32*1024) // 32KB chunks
	rand.Read(data)

	// Server: accept streams and drain data
	go func() {
		for {
			stream, err := serverSess.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func(s *quic.Stream) {
				io.Copy(io.Discard, s)
				s.Close()
			}(stream)
		}
	}()

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream, err := clientConn.OpenStreamSync(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		stream.Write(data)
		stream.Close()
	}
}

func BenchmarkPacketAllocation(b *testing.B) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)
	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	pc1, _ := net.ListenPacket("udp", "127.0.0.1:0")
	pc2, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc1.Close()
	defer pc2.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
	}

	oc1 := NewObfuscatedConn(pc1, cipher1, cfg)
	oc2 := NewObfuscatedConn(pc2, cipher2, cfg)

	addr2 := oc2.LocalAddr()
	data := make([]byte, 1200)

	// Pre-fill the receive side
	go func() {
		for {
			oc1.WriteTo(data, addr2)
		}
	}()

	buf := make([]byte, 2048)
	// Warm up
	oc2.ReadFrom(buf)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		oc2.ReadFrom(buf)
	}
}

func BenchmarkStreamOpen(b *testing.B) {
	clientConn, serverSess, cleanup := benchTunnel(b)
	defer cleanup()

	// Server: accept and close streams immediately
	go func() {
		for {
			stream, err := serverSess.AcceptStream(context.Background())
			if err != nil {
				return
			}
			stream.Close()
		}
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream, err := clientConn.OpenStreamSync(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		stream.Close()
	}
}
