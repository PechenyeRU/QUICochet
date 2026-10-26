package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

const peerIdentityTestTimeout = 5 * time.Second

type peerIdentitySessionCache struct {
	tls.ClientSessionCache
	puts chan struct{}
}

func newPeerIdentitySessionCache() *peerIdentitySessionCache {
	return &peerIdentitySessionCache{
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		puts:               make(chan struct{}, 8),
	}
}

func (c *peerIdentitySessionCache) Put(key string, session *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, session)
	if session != nil {
		select {
		case c.puts <- struct{}{}:
		default:
		}
	}
}

func (c *peerIdentitySessionCache) waitForTicket(t *testing.T) {
	t.Helper()
	timer := time.NewTimer(peerIdentityTestTimeout)
	defer timer.Stop()
	select {
	case <-c.puts:
	case <-timer.C:
		t.Fatal("timed out waiting for a TLS session ticket")
	}
}

type peerIdentityDialer struct {
	calls atomic.Int32
}

func (d *peerIdentityDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("unexpected target dial")
}

type peerIdentityRig struct {
	server     *Server
	certA      *tls.Certificate
	dialer     *peerIdentityDialer
	listener   *quic.Listener
	serverPC   net.PacketConn
	quicConfig *quic.Config
}

type peerIdentitySession struct {
	rig        *peerIdentityRig
	clientConn *quic.Conn
	serverConn *quic.Conn
	transport  *quic.Transport
	packetConn net.PacketConn
	done       chan struct{}
	closeOnce  sync.Once
}

func newPeerIdentityRig(t *testing.T) *peerIdentityRig {
	t.Helper()

	ipA := netip.MustParseAddr("127.0.0.1")
	ipB := netip.MustParseAddr("127.0.0.2")
	certA, _ := derivePeerIdentityCertificate(t, 1)
	certB, _ := derivePeerIdentityCertificate(t, 101)
	knownHashes := map[[32]byte]struct{}{
		sha256.Sum256(certA.Certificate[0]): {},
		sha256.Sum256(certB.Certificate[0]): {},
	}
	dialer := &peerIdentityDialer{}
	server := &Server{
		config: &config.Config{
			Obfuscation:     config.ObfuscationConfig{Mode: string(config.ObfuscationNone)},
			ReverseForwards: []config.ReverseForwardConfig{{Peer: "peer-a"}},
		},
		dialer:         dialer,
		peerCerts:      map[netip.Addr]*tls.Certificate{ipA: certA, ipB: certB},
		verifyPeerCert: crypto.MakeVerifyPeerCertificateMulti(knownHashes),
		peerByAddr:     map[netip.Addr]string{ipA: "peer-a", ipB: "peer-b"},
		peerCounters: map[string]*peerCounters{
			"peer-a": {},
			"peer-b": {},
		},
	}
	server.running.Store(true)

	tlsConfig, err := server.generateTLSConfig()
	if err != nil {
		t.Fatalf("generate server TLS config: %v", err)
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: peerIdentityTestTimeout,
		MaxIdleTimeout:       peerIdentityTestTimeout,
		EnableDatagrams:      true,
		Allow0RTT:            false,
	}
	serverPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for server UDP: %v", err)
	}
	listener, err := quic.Listen(serverPC, tlsConfig, quicConfig)
	if err != nil {
		_ = serverPC.Close()
		t.Fatalf("listen for QUIC: %v", err)
	}

	rig := &peerIdentityRig{
		server:     server,
		certA:      certA,
		dialer:     dialer,
		listener:   listener,
		serverPC:   serverPC,
		quicConfig: quicConfig,
	}
	t.Cleanup(func() {
		server.running.Store(false)
		_ = listener.Close()
		_ = serverPC.Close()
	})
	return rig
}

func (r *peerIdentityRig) dial(t *testing.T, clientIP string, cache tls.ClientSessionCache) *peerIdentitySession {
	t.Helper()

	packetConn, err := net.ListenPacket("udp4", net.JoinHostPort(clientIP, "0"))
	if err != nil {
		t.Fatalf("listen for client UDP on %s: %v", clientIP, err)
	}
	transport := &quic.Transport{Conn: packetConn}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*r.certA},
		ClientSessionCache: cache,
		InsecureSkipVerify: true, //nolint:gosec // Reach the post-handshake IP-to-certificate check.
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"quiccochet-v2"},
		ServerName:         "quiccochet.local",
	}

	dialCtx, cancelDial := context.WithTimeout(context.Background(), peerIdentityTestTimeout)
	clientConn, err := transport.Dial(dialCtx, r.serverPC.LocalAddr(), tlsConfig, r.quicConfig)
	cancelDial()
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		t.Fatalf("dial QUIC from %s: %v", clientIP, err)
	}

	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), peerIdentityTestTimeout)
	serverConn, err := r.listener.Accept(acceptCtx)
	cancelAccept()
	if err != nil {
		_ = clientConn.CloseWithError(0, "accept failed")
		_ = transport.Close()
		_ = packetConn.Close()
		t.Fatalf("accept QUIC from %s: %v", clientIP, err)
	}

	session := &peerIdentitySession{
		rig:        r,
		clientConn: clientConn,
		serverConn: serverConn,
		transport:  transport,
		packetConn: packetConn,
	}
	t.Cleanup(func() { session.close(t) })
	return session
}

func (s *peerIdentitySession) startHandler() {
	s.rig.server.activeSessions.Add(1)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		s.rig.server.handleSession(s.serverConn)
	}()
}

func (s *peerIdentitySession) close(t *testing.T) {
	t.Helper()
	s.closeOnce.Do(func() {
		_ = s.clientConn.CloseWithError(0, "test done")
		_ = s.serverConn.CloseWithError(0, "test done")
		if s.done != nil {
			timer := time.NewTimer(peerIdentityTestTimeout)
			defer timer.Stop()
			select {
			case <-s.done:
			case <-timer.C:
				t.Error("timed out waiting for handleSession to exit")
			}
		}
		_ = s.transport.Close()
		_ = s.packetConn.Close()
	})
}

func (s *peerIdentitySession) assertState(t *testing.T, wantIP string, wantResumed bool) {
	t.Helper()

	remote, ok := s.serverConn.RemoteAddr().(*net.UDPAddr)
	if !ok || remote == nil {
		t.Fatalf("server remote address is %T, not UDP", s.serverConn.RemoteAddr())
	}
	gotIP, ok := netip.AddrFromSlice(remote.IP)
	if !ok || gotIP.Unmap().String() != wantIP {
		t.Fatalf("server remote IP = %v, want %s", remote.IP, wantIP)
	}
	if got := s.clientConn.ConnectionState().TLS.DidResume; got != wantResumed {
		t.Fatalf("client DidResume = %t, want %t", got, wantResumed)
	}
	state := s.serverConn.ConnectionState()
	if got := state.TLS.DidResume; got != wantResumed {
		t.Fatalf("server DidResume = %t, want %t", got, wantResumed)
	}
	if len(state.TLS.PeerCertificates) == 0 {
		t.Fatal("server has no peer certificate after the QUIC handshake")
	}
	if !bytes.Equal(state.TLS.PeerCertificates[0].Raw, s.rig.certA.Certificate[0]) {
		t.Fatal("server peer certificate is not certificate A")
	}
}

func (s *peerIdentitySession) queueTunnelTraffic(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), peerIdentityTestTimeout)
	defer cancel()
	stream, err := s.clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream before session validation: %v", err)
	}
	target := "192.0.2.1:9"
	request := append([]byte{byte(len(target))}, target...)
	if _, err := stream.Write(request); err != nil {
		t.Fatalf("write stream before session validation: %v", err)
	}
	_ = stream.Close()

	datagram := []byte{0, 0, 0, 1, 1, 192, 0, 2, 1, 0, 53, 0}
	if err := s.clientConn.SendDatagram(datagram); err != nil {
		t.Fatalf("send datagram before session validation: %v", err)
	}
}

func (r *peerIdentityRig) waitForReverseSession(t *testing.T, peer string, conn *quic.Conn) {
	t.Helper()

	timer := time.NewTimer(peerIdentityTestTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		r.server.revMu.Lock()
		_, registered := r.server.revSessions[peer][conn]
		r.server.revMu.Unlock()
		if registered {
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("timed out waiting for reverse session registration")
		}
	}
}

func (r *peerIdentityRig) reverseSessionCount() int {
	r.server.revMu.Lock()
	defer r.server.revMu.Unlock()
	count := 0
	for _, sessions := range r.server.revSessions {
		count += len(sessions)
	}
	return count
}

func (s *peerIdentitySession) assertRejected(t *testing.T) {
	t.Helper()

	timer := time.NewTimer(peerIdentityTestTimeout)
	defer timer.Stop()
	select {
	case <-s.done:
	case <-timer.C:
		t.Fatal("handleSession did not reject the mismatched peer")
	}

	select {
	case <-s.clientConn.Context().Done():
	case <-timer.C:
		t.Fatal("client did not observe the rejected session closing")
	}
	var appErr *quic.ApplicationError
	if cause := context.Cause(s.clientConn.Context()); !errors.As(cause, &appErr) || !appErr.Remote || appErr.ErrorCode != 0x3 {
		t.Fatalf("client close cause = %v, want remote application error 0x3", cause)
	}

	if got := s.rig.reverseSessionCount(); got != 0 {
		t.Fatalf("reverse sessions registered for rejected peer: %d", got)
	}
	if got := s.rig.server.peerCounters["peer-b"].streamsOpened.Load(); got != 0 {
		t.Fatalf("streams accepted for rejected peer: %d", got)
	}
	if got := s.rig.dialer.calls.Load(); got != 0 {
		t.Fatalf("target dials for rejected peer: %d", got)
	}
	if got := s.rig.server.udpRoutes.Load(); got != 0 {
		t.Fatalf("datagram routes created for rejected peer: %d", got)
	}
	if got := s.rig.server.activeSessions.Load(); got != 0 {
		t.Fatalf("active sessions after rejection: %d", got)
	}
}

func TestValidatePeerConnectionEndToEnd(t *testing.T) {
	rig := newPeerIdentityRig(t)
	resumptionCache := newPeerIdentitySessionCache()

	if !t.Run("certificate A from IP A accepted", func(t *testing.T) {
		session := rig.dial(t, "127.0.0.1", resumptionCache)
		session.assertState(t, "127.0.0.1", false)
		session.startHandler()
		rig.waitForReverseSession(t, "peer-a", session.serverConn)
		if err := session.serverConn.Context().Err(); err != nil {
			t.Fatalf("matching session closed: %v", err)
		}
		resumptionCache.waitForTicket(t)
		session.close(t)
		if got := rig.reverseSessionCount(); got != 0 {
			t.Fatalf("reverse sessions after matching session closed: %d", got)
		}
	}) {
		return
	}

	t.Run("certificate A from IP B rejected after full handshake", func(t *testing.T) {
		session := rig.dial(t, "127.0.0.2", newPeerIdentitySessionCache())
		session.assertState(t, "127.0.0.2", false)
		session.queueTunnelTraffic(t)
		session.startHandler()
		session.assertRejected(t)
	})

	t.Run("certificate A from IP B rejected after resumed handshake", func(t *testing.T) {
		session := rig.dial(t, "127.0.0.2", resumptionCache)
		session.assertState(t, "127.0.0.2", true)
		session.queueTunnelTraffic(t)
		session.startHandler()
		session.assertRejected(t)
	})
}
