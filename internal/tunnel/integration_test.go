package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// testTunnel holds a loopback QUIC tunnel for integration testing.
type testTunnel struct {
	serverConn *ObfuscatedConn
	clientConn *ObfuscatedConn
	listener   *quic.Listener
	serverSess *quic.Conn
	clientQUIC *quic.Conn
	clientTr   *quic.Transport
	cleanup    func()
}

func setupTestTunnel(t *testing.T) *testTunnel {
	t.Helper()

	kp1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ss, err := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sk1, rk1, err := crypto.DeriveSessionKeys(ss, true)
	if err != nil {
		t.Fatal(err)
	}
	sk2, rk2, err := crypto.DeriveSessionKeys(ss, false)
	if err != nil {
		t.Fatal(err)
	}

	clientCipher, err := crypto.NewCipher(sk1, rk1)
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := crypto.NewCipher(sk2, rk2)
	if err != nil {
		t.Fatal(err)
	}

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		serverPC.Close()
		t.Fatal(err)
	}

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 1400,
		},
	}

	serverObf := NewObfuscatedConn(serverPC, serverCipher, cfg)
	clientObf := NewObfuscatedConn(clientPC, clientCipher, cfg)

	tlsConf := generateTestTLSConfig(t)

	quicConf := &quic.Config{
		MaxIdleTimeout:             10 * time.Second,
		MaxStreamReceiveWindow:     5 * 1024 * 1024,
		MaxConnectionReceiveWindow: 15 * 1024 * 1024,
		EnableDatagrams:            true,
	}

	ln, err := quic.Listen(serverObf, tlsConf, quicConf)
	if err != nil {
		serverPC.Close()
		clientPC.Close()
		t.Fatal(err)
	}

	type acceptResult struct {
		sess *quic.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		sess, err := ln.Accept(context.Background())
		acceptCh <- acceptResult{sess, err}
	}()

	serverAddr := serverObf.LocalAddr()
	clientTr := &quic.Transport{Conn: clientObf}

	clientConn, err := clientTr.Dial(
		context.Background(),
		serverAddr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"quiccochet-test"},
		},
		quicConf,
	)
	if err != nil {
		ln.Close()
		clientTr.Close()
		serverPC.Close()
		clientPC.Close()
		t.Fatal(err)
	}

	ar := <-acceptCh
	if ar.err != nil {
		clientConn.CloseWithError(0, "setup failed")
		ln.Close()
		clientTr.Close()
		serverPC.Close()
		clientPC.Close()
		t.Fatal(ar.err)
	}

	return &testTunnel{
		serverConn: serverObf,
		clientConn: clientObf,
		listener:   ln,
		serverSess: ar.sess,
		clientQUIC: clientConn,
		clientTr:   clientTr,
		cleanup: func() {
			clientConn.CloseWithError(0, "test done")
			ar.sess.CloseWithError(0, "test done")
			ln.Close()
			clientTr.Close()
			serverPC.Close()
			clientPC.Close()
		},
	}
}

func generateTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quiccochet-test"},
	}
}

func TestQUICHandshake(t *testing.T) {
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	// Server: accept stream, read data, reply on a new server-initiated stream
	serverDone := make(chan error, 1)
	go func() {
		stream, err := tt.serverSess.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		data, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			serverDone <- err
			return
		}

		reply, err := tt.serverSess.OpenStreamSync(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		_, err = reply.Write(data)
		reply.Close()
		serverDone <- err
	}()

	// Client: send "ping", close, read reply from server-initiated stream
	stream, err := tt.clientQUIC.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	stream.Close()

	reply, err := tt.clientQUIC.AcceptStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	buf, err := io.ReadAll(reply)
	reply.Close()
	if err != nil {
		t.Fatal(err)
	}

	if string(buf) != "ping" {
		t.Errorf("expected 'ping', got '%s'", buf)
	}

	if err := <-serverDone; err != nil {
		t.Errorf("server: %v", err)
	}
}

func TestStreamMultiplexing(t *testing.T) {
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	const numStreams = 10

	// Server: accept streams, read data, echo with prefix on server-initiated streams
	go func() {
		for i := 0; i < numStreams; i++ {
			stream, err := tt.serverSess.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func(s *quic.Stream) {
				data, err := io.ReadAll(s)
				s.Close()
				if err != nil {
					return
				}
				reply, err := tt.serverSess.OpenStreamSync(context.Background())
				if err != nil {
					return
				}
				replyData := append([]byte("echo:"), data...)
				reply.Write(replyData)
				reply.Close()
			}(stream)
		}
	}()

	// Client: open streams and send data
	var wg sync.WaitGroup
	errs := make(chan error, numStreams)
	sent := make(map[string]bool)
	var sentMu sync.Mutex

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stream, err := tt.clientQUIC.OpenStreamSync(context.Background())
			if err != nil {
				errs <- fmt.Errorf("stream %d open: %w", idx, err)
				return
			}
			msg := fmt.Sprintf("msg-%d", idx)
			if _, err := stream.Write([]byte(msg)); err != nil {
				errs <- fmt.Errorf("stream %d write: %w", idx, err)
				return
			}
			stream.Close()
			sentMu.Lock()
			sent[msg] = true
			sentMu.Unlock()
		}(i)
	}
	wg.Wait()

	// Collect all replies from server-initiated streams
	received := make(map[string]bool)
	for i := 0; i < numStreams; i++ {
		reply, err := tt.clientQUIC.AcceptStream(context.Background())
		if err != nil {
			errs <- fmt.Errorf("accept reply %d: %w", i, err)
			continue
		}
		data, err := io.ReadAll(reply)
		reply.Close()
		if err != nil {
			errs <- fmt.Errorf("read reply %d: %w", i, err)
			continue
		}
		received[string(data)] = true
	}

	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Verify all messages were echoed
	for msg := range sent {
		expected := "echo:" + msg
		if !received[expected] {
			t.Errorf("missing echo for %s", msg)
		}
	}
}

func TestDataIntegrity(t *testing.T) {
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	const dataSize = 256 * 1024
	data := make([]byte, dataSize)
	rand.Read(data)
	expectedHash := sha256.Sum256(data)

	serverDone := make(chan error, 1)
	go func() {
		stream, err := tt.serverSess.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}

		received, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			serverDone <- err
			return
		}

		hash := sha256.Sum256(received)

		reply, err := tt.serverSess.OpenStreamSync(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		_, err = reply.Write(hash[:])
		reply.Close()
		serverDone <- err
	}()

	stream, err := tt.clientQUIC.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := stream.Write(data); err != nil {
		t.Fatal(err)
	}
	stream.Close()

	reply, err := tt.clientQUIC.AcceptStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hashBuf := make([]byte, 32)
	if _, err := io.ReadFull(reply, hashBuf); err != nil {
		t.Fatal(err)
	}
	reply.Close()

	var got [32]byte
	copy(got[:], hashBuf)
	if got != expectedHash {
		t.Error("data integrity check failed: SHA256 mismatch after 256KB transfer")
	}

	if err := <-serverDone; err != nil {
		t.Errorf("server: %v", err)
	}
}

func TestChaffFiltering(t *testing.T) {
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	serverDone := make(chan error, 1)
	go func() {
		stream, err := tt.serverSess.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		data, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			serverDone <- err
			return
		}
		reply, err := tt.serverSess.OpenStreamSync(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		_, err = reply.Write(data)
		reply.Close()
		serverDone <- err
	}()

	// Inject chaff from both sides
	serverAddr := tt.serverConn.LocalAddr()
	clientAddr := tt.clientConn.LocalAddr()
	for i := 0; i < 50; i++ {
		tt.clientConn.SendChaff(serverAddr)
		tt.serverConn.SendChaff(clientAddr)
	}

	// Real stream should work despite chaff
	stream, err := tt.clientQUIC.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("through-chaff")); err != nil {
		t.Fatal(err)
	}
	stream.Close()

	reply, err := tt.clientQUIC.AcceptStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	buf, err := io.ReadAll(reply)
	reply.Close()
	if err != nil {
		t.Fatal(err)
	}

	if string(buf) != "through-chaff" {
		t.Errorf("expected 'through-chaff', got '%s'", buf)
	}

	if err := <-serverDone; err != nil {
		t.Errorf("server: %v", err)
	}
}
