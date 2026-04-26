package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// TestQUICHandshakePinnedToSharedSecret is the critical regression for
// Q-02 / Q-03: prove that the QUIC TLS handshake itself authenticates
// the peer against the shared secret. Two scenarios:
//
//   - matching secrets → handshake succeeds;
//   - mismatched secrets → handshake fails, period.
//
// We run this with the obfuscator OFF (raw UDP under quic-go) so the
// only authentication in play is the new pinned-cert mechanism. Before
// this fix the same setup would have completed the handshake and
// exposed the server as an open relay.
func TestQUICHandshakePinnedToSharedSecret(t *testing.T) {
	var secretA, secretB [crypto.KeySize]byte
	for i := range secretA {
		secretA[i] = byte(i + 1)
	}
	for i := range secretB {
		secretB[i] = byte(0xFF - i)
	}

	t.Run("MatchingSecretsHandshakeSucceeds", func(t *testing.T) {
		err := runPinnedQUICHandshake(t, secretA, secretA)
		if err != nil {
			t.Fatalf("matching-secret handshake failed: %v", err)
		}
	})

	t.Run("MismatchedSecretsHandshakeFails", func(t *testing.T) {
		err := runPinnedQUICHandshake(t, secretA, secretB)
		if err == nil {
			t.Fatal("mismatched-secret handshake unexpectedly succeeded — Q-02/Q-03 fix is not in effect")
		}
	})
}

// runPinnedQUICHandshake stands up a real QUIC listener + dialer over
// loopback UDP, both using the deterministic shared-secret-derived TLS
// cert + pinned VerifyPeerCertificate. Returns nil if the dial
// completes, the first error otherwise.
func runPinnedQUICHandshake(t *testing.T, serverSecret, clientSecret [crypto.KeySize]byte) error {
	t.Helper()

	serverCert, err := crypto.DeriveTLSCertificate(serverSecret)
	if err != nil {
		return err
	}
	clientCert, err := crypto.DeriveTLSCertificate(clientSecret)
	if err != nil {
		return err
	}
	serverExpected, _ := crypto.DeriveTLSCertHash(serverSecret)
	clientExpected, _ := crypto.DeriveTLSCertHash(clientSecret)

	serverTLS := &tls.Config{
		Certificates:          []tls.Certificate{*serverCert},
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"quiccochet-v2"},
		VerifyPeerCertificate: crypto.MakeVerifyPeerCertificate(serverExpected),
	}
	clientTLS := &tls.Config{
		Certificates:          []tls.Certificate{*clientCert},
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"quiccochet-v2"},
		ServerName:            "quiccochet.local",
		VerifyPeerCertificate: crypto.MakeVerifyPeerCertificate(clientExpected),
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:    2 * time.Second,
		HandshakeIdleTimeout: 2 * time.Second,
	}

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer serverPC.Close()

	ln, err := quic.Listen(serverPC, serverTLS, quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()

	type acceptResult struct {
		sess *quic.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sess, aerr := ln.Accept(ctx)
		acceptCh <- acceptResult{sess, aerr}
	}()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer clientPC.Close()
	tr := &quic.Transport{Conn: clientPC}
	defer tr.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, dErr := tr.Dial(dialCtx, serverPC.LocalAddr(), clientTLS, quicConf)

	// Wait for the accept side too so we observe the server's view.
	ar := <-acceptCh

	if dErr != nil {
		return dErr
	}
	if ar.err != nil {
		clientConn.CloseWithError(0, "test done")
		return ar.err
	}
	clientConn.CloseWithError(0, "test done")
	ar.sess.CloseWithError(0, "test done")
	return nil
}
