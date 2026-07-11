package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// reverseRig drives the reverse port-forward (ssh -R) path end to end on top
// of the loopback QUIC tunnel from setupTestTunnel. The server side opens the
// bidi stream toward the client and splices it into a plain TCP listener; the
// client side accepts the stream, enforces the allow list and dials the
// client-local target. Nothing here reimplements the tunnel logic — it wires
// the real Server.handleReverseConn and Client.acceptReverseStreams against an
// established *quic.Conn pair.
type reverseRig struct {
	tt        *testTunnel
	revListen string // server-side reverse listen addr for a plain net.Dial
	stop      func()
}

// setupReverseRig builds a reverse-forward rig: a client-side reverse acceptor
// bound to accept, and a server-side reverse TCP listener that tunnels every
// accepted connection to peer and asks the client to dial target. The reverse
// listen address is chosen with the ":0 then read Addr" trick so the port is
// free and known.
func setupReverseRig(t *testing.T, accept config.ReverseAcceptConfig, target, peer string) *reverseRig {
	t.Helper()
	tt := setupTestTunnel(t)

	// StreamCloseTimeoutSec must be > 0 so the graceful-close timer in
	// spliceStream does not fire immediately.
	serverCfg := &config.Config{QUIC: config.QUICConfig{StreamCloseTimeoutSec: 5}}
	clientCfg := &config.Config{
		QUIC:          config.QUICConfig{StreamCloseTimeoutSec: 5},
		ReverseAccept: accept,
	}

	// Client: accept server-opened reverse streams on the dialed conn.
	cli := &Client{config: clientCfg}
	cli.running.Store(true)
	go cli.acceptReverseStreams(tt.clientQUIC)

	// Server: register the live session for peer and drive a reverse listener
	// through the real handleReverseConn (open stream, write header, splice).
	srv := &Server{config: serverCfg}
	srv.running.Store(true)
	srv.registerReverseSession(peer, tt.serverSess)

	revLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tt.cleanup()
		t.Fatalf("reverse listen: %v", err)
	}
	go func() {
		for {
			conn, err := revLn.Accept()
			if err != nil {
				return
			}
			go srv.handleReverseConn(conn, target, peer)
		}
	}()

	stop := func() {
		cli.running.Store(false)
		srv.running.Store(false)
		revLn.Close()
		tt.cleanup()
	}
	return &reverseRig{tt: tt, revListen: revLn.Addr().String(), stop: stop}
}

// startEchoTarget starts a client-local TCP echo listener that stands in for
// the reverse-forward target. Its address is used both as the dial target and
// (in the positive test) as the allow-list entry. accepted receives one value
// per accepted connection so a test can assert whether the client actually
// dialed the target.
func startEchoTarget(t *testing.T) (addr string, accepted chan net.Conn, closer func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo target listen: %v", err)
	}
	accepted = make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
			go io.Copy(conn, conn) // echo back everything received
		}
	}()
	return ln.Addr().String(), accepted, func() { ln.Close() }
}

// TestReverseForwardRoundTrip is the positive path: the target is on the
// allow list, so a plain TCP client that connects to the server-side reverse
// port has its bytes tunnelled to the client-local echo target and back
// unchanged (256 KB SHA-256 integrity check, mirroring TestDataIntegrity).
func TestReverseForwardRoundTrip(t *testing.T) {
	const peer = "peer-a"

	targetAddr, accepted, closeTarget := startEchoTarget(t)
	defer closeTarget()

	rig := setupReverseRig(t,
		config.ReverseAcceptConfig{Enabled: true, Allow: []string{targetAddr}},
		targetAddr, peer)
	defer rig.stop()

	conn, err := net.DialTimeout("tcp", rig.revListen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial reverse listener: %v", err)
	}
	defer conn.Close()

	const dataSize = 256 * 1024
	data := make([]byte, dataSize)
	rand.Read(data)
	expected := sha256.Sum256(data)

	// Write in a goroutine so the concurrent echo return path can drain while
	// we read it back; writing then reading serially would deadlock.
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(data)
		writeErr <- err
	}()

	got := make([]byte, dataSize)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echoed data: %v", err)
	}
	if sha256.Sum256(got) != expected {
		t.Error("reverse round-trip integrity check failed: SHA256 mismatch after 256KB")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write payload: %v", err)
	}

	// The client should have dialed the target exactly once.
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("client never dialed the reverse target")
	}
}

// TestReverseForwardDenied is the negative path: the target is NOT on the
// allow list, so the client must refuse the reverse stream without dialing.
// The client-local target must see no connection and the external TCP peer
// must observe the stream refused (EOF / short read), never an echo.
func TestReverseForwardDenied(t *testing.T) {
	const peer = "peer-a"

	targetAddr, accepted, closeTarget := startEchoTarget(t)
	defer closeTarget()

	// Enabled, but the allow list matches a different address, so dialing
	// targetAddr is default-denied. This exercises isReverseTargetAllowed
	// rather than the plain Enabled=false short-circuit.
	rig := setupReverseRig(t,
		config.ReverseAcceptConfig{Enabled: true, Allow: []string{"127.0.0.1:1"}},
		targetAddr, peer)
	defer rig.stop()

	conn, err := net.DialTimeout("tcp", rig.revListen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial reverse listener: %v", err)
	}
	defer conn.Close()

	// Push data the client must never forward.
	_, _ = conn.Write([]byte("should-not-arrive"))

	// 1) The client-local target must never be connected to.
	select {
	case <-accepted:
		t.Fatal("client dialed a target that is not on the allow list")
	case <-time.After(1500 * time.Millisecond):
		// good: no connection reached the target
	}

	// 2) The external peer sees the refused stream: EOF or short read, no echo.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("expected refused reverse stream, got %d bytes of echo back", n)
	}
}
