package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// TestQUICHandshakeOverIPv6Loopback is the outer-v6 smoke test: the
// QUIC tunnel must complete a full pinned-cert handshake and a
// short data exchange when the underlay is IPv6 loopback. Mirrors
// runPinnedQUICHandshake (tls_pinning_test.go) but binds on [::1]:0
// instead of 127.0.0.1:0 — exercises the same code path with the v6
// address family so any v4-only assumption (sockaddr layout, addr
// formatting, family-aware logic) trips here.
func TestQUICHandshakeOverIPv6Loopback(t *testing.T) {
	if !ipv6LoopbackUsable(t) {
		t.Skip("IPv6 loopback unavailable on this host")
	}

	var secret [crypto.KeySize]byte
	for i := range secret {
		secret[i] = byte(i + 11)
	}

	cert, err := crypto.DeriveTLSCertificate(secret)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := crypto.DeriveTLSCertHash(secret)
	verify := crypto.MakeVerifyPeerCertificate(expected)

	srvTLS := &tls.Config{
		Certificates:          []tls.Certificate{*cert},
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"quiccochet-v6test"},
		VerifyPeerCertificate: verify,
	}
	cliTLS := &tls.Config{
		Certificates:          []tls.Certificate{*cert},
		InsecureSkipVerify:    true, //nolint:gosec — relying on VerifyPeerCertificate
		MinVersion:            tls.VersionTLS13,
		ServerName:            "quiccochet.local",
		NextProtos:            []string{"quiccochet-v6test"},
		VerifyPeerCertificate: verify,
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:       3 * time.Second,
		HandshakeIdleTimeout: 3 * time.Second,
	}

	srvPC, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen v6 server: %v", err)
	}
	defer srvPC.Close()

	ln, err := quic.Listen(srvPC, srvTLS, quicConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type ar struct {
		s *quic.Conn
		e error
	}
	acceptCh := make(chan ar, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s, e := ln.Accept(ctx)
		acceptCh <- ar{s, e}
	}()

	cliPC, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen v6 client: %v", err)
	}
	defer cliPC.Close()
	tr := &quic.Transport{Conn: cliPC}
	defer tr.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := tr.Dial(dialCtx, srvPC.LocalAddr(), cliTLS, quicConf)
	if err != nil {
		t.Fatalf("dial v6: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	a := <-acceptCh
	if a.e != nil {
		t.Fatalf("accept v6: %v", a.e)
	}
	defer a.s.CloseWithError(0, "test done")

	// One short stream exchange to prove the handshake actually
	// produced a usable session (handshake-only is not enough — a
	// silent v4-vs-v6 mismatch could complete the handshake and
	// then deadlock on the first stream send).
	srvCh := make(chan []byte, 1)
	go func() {
		s, _ := a.s.AcceptStream(context.Background())
		if s == nil {
			srvCh <- nil
			return
		}
		buf, _ := io.ReadAll(s)
		srvCh <- buf
	}()

	cs, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("OpenStreamSync v6: %v", err)
	}
	want := []byte("hello over v6 loopback")
	if _, err := cs.Write(want); err != nil {
		t.Fatalf("write v6: %v", err)
	}
	cs.Close()

	select {
	case got := <-srvCh:
		if string(got) != string(want) {
			t.Fatalf("payload mismatch: got %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server-side stream read timeout")
	}
}

// TestServerDialerReachesIPv6Literal validates the inner-v6 path: the
// payload tunnelled through QUIC carries a v6 IP-literal target, and
// the server dials it successfully via the standard net.Dialer used
// by handleStream. Bypasses the QUIC layer and exercises only the
// dial portion (targetBlocked + DialContext) since that is the new
// surface area where v6 literal handling could regress.
//
// Uses block_private_targets=false because the test target is on
// IPv6 loopback (::1) which the production guard correctly rejects;
// the test asserts the dial succeeds when policy allows.
func TestServerDialerReachesIPv6Literal(t *testing.T) {
	if !ipv6LoopbackUsable(t) {
		t.Skip("IPv6 loopback unavailable on this host")
	}

	// Stand up a tiny TCP echo server on [::1]:0.
	echoLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen v6 echo: %v", err)
	}
	defer echoLn.Close()

	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	echoAddr := echoLn.Addr().(*net.TCPAddr)
	target := net.JoinHostPort(echoAddr.IP.String(), fmt.Sprintf("%d", echoAddr.Port))
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort returned error on v6 literal %q: %v", target, err)
	}
	if host == "" {
		t.Fatalf("SplitHostPort lost the host part of %q", target)
	}

	// Build a Server with block_private_targets=false so ::1 passes
	// targetBlocked (production policy correctly blocks loopback —
	// we are only verifying the dial path works for legit v6).
	allow := false
	s := &Server{
		config: &config.Config{
			Security: config.SecurityConfig{
				BlockPrivateTargets: &allow,
			},
		},
		dialer: &net.Dialer{Timeout: 2 * time.Second},
	}

	// targetBlocked must let it through (loopback would normally
	// block, but block_private_targets=false disables the guard).
	if blocked, reason := s.targetBlocked(host, host); blocked {
		t.Fatalf("v6 loopback target blocked despite block_private_targets=false: %s", reason)
	}

	// Dial via the same dialer the production handleStream uses.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := s.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext v6: %v", err)
	}
	defer conn.Close()

	// Echo a payload to prove end-to-end v6 reachability.
	want := []byte("inner v6 echo")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write v6: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read v6: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q, want %q", got, want)
	}

	// Drain echo goroutine.
	conn.Close()
	select {
	case <-echoDone:
	case <-time.After(time.Second):
		t.Log("echo goroutine did not exit (best-effort, not a failure)")
	}
}

// TestRealPeerDualStackRouting pins the per-family WriteTo routing on
// transportPacketConn that landed in the realPeer split (Phase 1b):
// outbound packets must hit the v4 realPeer when the destination is
// v4-or-v4-mapped, and the v6 realPeer when the destination is
// native v6. Without the per-family slot a dual-stack server would
// either lose v6 traffic or rewrite it to a v4 destination.
func TestRealPeerDualStackRouting(t *testing.T) {
	cap := &capturingTransport{}
	c := &transportPacketConn{trans: cap}

	// Seed both families. storeRealPeer normalises v4 to its
	// canonical 4-byte form, so the assertions below compare
	// against that.
	c.storeRealPeer(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111})
	c.storeRealPeer(&net.UDPAddr{IP: net.ParseIP("2001:db80::1"), Port: 2222})

	// v4 destination quic-go would hand to WriteTo: gets rewritten
	// to the v4 realPeer.
	if _, err := c.WriteTo([]byte("v4-payload"), &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9999}); err != nil {
		t.Fatalf("WriteTo v4: %v", err)
	}
	got := cap.lastIP()
	if !got.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("v4 dst rewrite: got %v, want 10.0.0.1", got)
	}
	if cap.lastPort() != 1111 {
		t.Fatalf("v4 port override: got %d, want 1111", cap.lastPort())
	}

	// v4-mapped v6 destination must follow the same v4 route — the
	// production WriteTo path on dual-stack receives v4 traffic in
	// this form via ReadFromUDP on AF_INET6.
	if _, err := c.WriteTo([]byte("v4-mapped"), &net.UDPAddr{IP: net.ParseIP("::ffff:198.51.100.7"), Port: 9999}); err != nil {
		t.Fatalf("WriteTo v4-mapped: %v", err)
	}
	got = cap.lastIP()
	if !got.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("v4-mapped dst rewrite: got %v, want 10.0.0.1", got)
	}

	// Native v6 destination → v6 realPeer.
	if _, err := c.WriteTo([]byte("v6-payload"), &net.UDPAddr{IP: net.ParseIP("2001:db80::ffff"), Port: 9999}); err != nil {
		t.Fatalf("WriteTo v6: %v", err)
	}
	got = cap.lastIP()
	if !got.Equal(net.ParseIP("2001:db80::1")) {
		t.Fatalf("v6 dst rewrite: got %v, want 2001:db80::1", got)
	}
	if cap.lastPort() != 2222 {
		t.Fatalf("v6 port override: got %d, want 2222", cap.lastPort())
	}
}

// TestMaybeUpdatePeerPerFamily checks that learned-port updates are
// scoped to the family of the authenticated source: a v4 packet
// updates only realPeer4.Port and never touches the v6 slot, and
// vice versa.
func TestMaybeUpdatePeerPerFamily(t *testing.T) {
	c := &transportPacketConn{trans: &capturingTransport{}}
	c.storeRealPeer(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 0})
	c.storeRealPeer(&net.UDPAddr{IP: net.ParseIP("2001:db80::1"), Port: 0})

	c.MaybeUpdatePeer(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5555})
	if got := c.realPeer4.Load().Port; got != 5555 {
		t.Fatalf("v4 port not learned: got %d, want 5555", got)
	}
	if got := c.realPeer6.Load().Port; got != 0 {
		t.Fatalf("v6 port leaked from v4 update: got %d, want 0", got)
	}

	c.MaybeUpdatePeer(&net.UDPAddr{IP: net.ParseIP("2001:db80::dead"), Port: 6666})
	if got := c.realPeer6.Load().Port; got != 6666 {
		t.Fatalf("v6 port not learned: got %d, want 6666", got)
	}
	if got := c.realPeer4.Load().Port; got != 5555 {
		t.Fatalf("v4 port clobbered by v6 update: got %d, want 5555", got)
	}
}

// capturingTransport is a tiny in-memory transport.Transport stub
// that records the destination of the last Send call. Avoids needing
// raw sockets / CAP_NET_RAW for routing-only assertions.
type capturingTransport struct {
	mu       sync.Mutex
	lastIPv  net.IP
	lastPrt  uint16
}

func (c *capturingTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make(net.IP, len(dstIP))
	copy(cp, dstIP)
	c.lastIPv = cp
	c.lastPrt = dstPort
	return nil
}
func (c *capturingTransport) Receive(buf []byte) (int, net.IP, uint16, error) {
	// Block forever — the routing tests never read.
	select {}
}
func (c *capturingTransport) Close() error      { return nil }
func (c *capturingTransport) LocalPort() uint16 { return 0 }
func (c *capturingTransport) SetReadBuffer(int) error  { return nil }
func (c *capturingTransport) SetWriteBuffer(int) error { return nil }

func (c *capturingTransport) lastIP() net.IP {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastIPv
}
func (c *capturingTransport) lastPort() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPrt
}

// ipv6LoopbackUsable reports whether ::1 can be bound on this host.
// Some CI environments and minimal containers ship without IPv6
// loopback configured; skipping is preferable to false-failing.
func ipv6LoopbackUsable(t *testing.T) bool {
	t.Helper()
	pc, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		return false
	}
	pc.Close()
	return true
}

// TestInnerIPv6OverIPv4Tunnel proves the cross-family scenario the user
// flagged: the QUIC outer transport runs over IPv4 (loopback 127.0.0.1)
// but the tunnelled CONNECT target is an IPv6 literal. The expectation
// is that the outer family is irrelevant to the inner dial — the
// server's net.Dialer dials TCP6 from its own stack regardless of what
// family is carrying the QUIC packets.
//
// Failure mode caught: any code path that conflates outer and inner
// families would either drop the v6 target string, format it
// incorrectly, or refuse the dial — none should happen.
func TestInnerIPv6OverIPv4Tunnel(t *testing.T) {
	if !ipv6LoopbackUsable(t) {
		t.Skip("IPv6 loopback unavailable on this host")
	}

	// v6 echo server — the inner target.
	echoLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen v6 echo: %v", err)
	}
	defer echoLn.Close()

	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)
	target := net.JoinHostPort(echoAddr.IP.String(), fmt.Sprintf("%d", echoAddr.Port))

	// v4 outer tunnel via the existing helper (binds 127.0.0.1).
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	// Server-side handler that mimics Server.handleStream's wire
	// protocol: a 2-byte length followed by the target string,
	// then bidirectional byte copy with a real net.Dialer. Kept
	// inline so the test does not depend on instantiating a full
	// Server with all of its production dependencies.
	allow := false
	srv := &Server{
		config: &config.Config{
			Security: config.SecurityConfig{
				BlockPrivateTargets: &allow,
			},
		},
		dialer: &net.Dialer{Timeout: 2 * time.Second},
	}

	srvDone := make(chan error, 1)
	go func() {
		stream, err := tt.serverSess.AcceptStream(context.Background())
		if err != nil {
			srvDone <- fmt.Errorf("AcceptStream: %w", err)
			return
		}
		defer stream.Close()

		var hdr [2]byte
		if _, err := io.ReadFull(stream, hdr[:]); err != nil {
			srvDone <- fmt.Errorf("read target len: %w", err)
			return
		}
		tlen := int(hdr[0])<<8 | int(hdr[1])
		buf := make([]byte, tlen)
		if _, err := io.ReadFull(stream, buf); err != nil {
			srvDone <- fmt.Errorf("read target: %w", err)
			return
		}
		gotTarget := string(buf)

		host, _, err := net.SplitHostPort(gotTarget)
		if err != nil {
			srvDone <- fmt.Errorf("server SplitHostPort %q: %w", gotTarget, err)
			return
		}
		if blocked, reason := srv.targetBlocked(host, host); blocked {
			srvDone <- fmt.Errorf("targetBlocked rejected legitimate v6 target: %s", reason)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		dst, err := srv.dialer.DialContext(ctx, "tcp", gotTarget)
		if err != nil {
			srvDone <- fmt.Errorf("server dial %q: %w", gotTarget, err)
			return
		}
		defer dst.Close()

		// Bidirectional copy. The client closes its write side
		// after sending the payload, so the upload goroutine
		// returns when it sees EOF; we then close dst's write so
		// the echo flushes back, then read from dst → stream.
		copyDone := make(chan struct{}, 2)
		go func() {
			io.Copy(dst, stream)
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
			copyDone <- struct{}{}
		}()
		go func() {
			io.Copy(stream, dst)
			copyDone <- struct{}{}
		}()
		<-copyDone
		<-copyDone
		srvDone <- nil
	}()

	// Client side: open stream, write target len + target, write
	// payload, half-close to flush, read back.
	cs, err := tt.clientQUIC.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}

	tlen := uint16(len(target))
	hdr := [2]byte{byte(tlen >> 8), byte(tlen)}
	if _, err := cs.Write(hdr[:]); err != nil {
		t.Fatalf("write target len: %v", err)
	}
	if _, err := cs.Write([]byte(target)); err != nil {
		t.Fatalf("write target: %v", err)
	}

	want := []byte("inner v6 over v4 tunnel hello world")
	if _, err := cs.Write(want); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	cs.Close() // half-close write so the server-side upload copy returns

	got, err := io.ReadAll(cs)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q, want %q", got, want)
	}

	if err := <-srvDone; err != nil {
		t.Fatalf("server-side handler: %v", err)
	}

	// Drain the echo accept goroutine so the test does not race.
	select {
	case <-echoDone:
	case <-time.After(2 * time.Second):
		t.Log("echo accept goroutine did not exit (best-effort)")
	}
}
