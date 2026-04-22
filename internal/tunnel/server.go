package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"

	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
	"github.com/pechenyeru/quiccochet/internal/socks"
	"github.com/pechenyeru/quiccochet/internal/transport"
	"golang.org/x/net/proxy"
)

// Server is the tunnel server
type Server struct {
	config *config.Config
	cipher *crypto.Cipher
	trans  transport.Transport

	listener *quic.Listener
	rawConn  *transportPacketConn
	obfConn  *ObfuscatedConn // nil when obfuscation.mode="none" (fast path)

	clientRealIP net.IP

	dialer proxy.ContextDialer

	running atomic.Bool
	stopCh  chan struct{}

	bytesSent      atomic.Uint64
	bytesReceived  atomic.Uint64
	activeSessions atomic.Int32

	// UDP relay telemetry — aggregated across all sessions for server stats.
	udpRoutes      atomic.Int64  // current live UDP relay routes
	udpEvictions   atomic.Uint64 // total LRU evictions (cap hit)
	udpIdleClosed  atomic.Uint64 // total closed due to idle timeout

	startedAt time.Time

	pprof *admin.PprofServer
}

// NewServer creates a new tunnel server
func NewServer(cfg *config.Config, cipher *crypto.Cipher) (*Server, error) {
	transportCfg := &transport.Config{
		SourceIP:       net.ParseIP(cfg.Spoof.SourceIP),
		SourceIPv6:     net.ParseIP(cfg.Spoof.SourceIPv6),
		SourceIPs:      config.ParseIPs(cfg.Spoof.SourceIPs),
		SourceIPv6s:    config.ParseIPs(cfg.Spoof.SourceIPv6s),
		ListenPort:     uint16(cfg.ListenPort),
		PeerSpoofIP:    net.ParseIP(cfg.Spoof.PeerSpoofIP),
		PeerSpoofIPv6:  net.ParseIP(cfg.Spoof.PeerSpoofIPv6),
		PeerSpoofIPs:   config.ParseIPs(cfg.Spoof.PeerSpoofIPs),
		PeerSpoofIPv6s: config.ParseIPs(cfg.Spoof.PeerSpoofIPv6s),
		BufferSize:     cfg.Performance.BufferSize,
		ReadBuffer:     cfg.Performance.ReadBuffer,
		WriteBuffer:    cfg.Performance.WriteBuffer,
		MTU:            cfg.Performance.MTU,
		ProtocolNumber: cfg.Transport.ProtocolNumber,
		ICMPEchoID:     cfg.Transport.ICMPEchoID,
		PacingRateMbps: cfg.Performance.PacingRateMbps,
	}

	var trans transport.Transport
	var err error

	switch cfg.Transport.Type {
	case config.TransportICMP:
		mode := transport.ICMPModeReply
		if cfg.Transport.ICMPMode == config.ICMPModeEcho {
			mode = transport.ICMPModeEcho
		}
		trans, err = transport.NewICMPTransport(transportCfg, mode)
	case config.TransportRAW:
		trans, err = transport.NewRawTransport(transportCfg)
	case config.TransportSynUDP:
		trans, err = transport.NewSynUDPTransport(transportCfg)
	default:
		trans, err = transport.NewUDPTransport(transportCfg)
	}

	if err != nil {
		return nil, fmt.Errorf("create transport: %w", err)
	}

	s := &Server{
		config:          cfg,
		cipher:          cipher,
		trans:           trans,
		clientRealIP:    net.ParseIP(cfg.Spoof.ClientRealIP),
		stopCh:          make(chan struct{}),
		startedAt:       time.Now(),
		pprof:           admin.NewPprofServer(),
	}

	if cfg.OutboundProxy.Enabled {
		var auth *proxy.Auth
		if cfg.OutboundProxy.Username != "" {
			auth = &proxy.Auth{User: cfg.OutboundProxy.Username, Password: cfg.OutboundProxy.Password}
		}
		proxyDialer, err := proxy.SOCKS5("tcp", cfg.OutboundProxy.Address, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("create outbound proxy dialer: %w", err)
		}
		ctxDialer, ok := proxyDialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("outbound proxy dialer does not support ContextDialer")
		}
		s.dialer = ctxDialer
	} else {
		s.dialer = &net.Dialer{}
	}

	return s, nil
}

// Start starts the server
func (s *Server) Start() error {
	s.running.Store(true)

	slog.Info("server listening", "port", s.config.ListenPort)

	rawConn := &transportPacketConn{
		trans: s.trans,
	}
	if s.clientRealIP != nil {
		rawConn.realPeer.Store(&net.UDPAddr{IP: s.clientRealIP})
	}
	s.rawConn = rawConn

	// Optional receive-side jitter-smoothing shim; zero-overhead when
	// performance.jitter_buffer_ms == 0 (returns the input verbatim).
	netConn := maybeWrapJitterBuffer(rawConn, s.config.Performance.JitterBufferMs, "server")

	// Obfuscator fast-path: see client.go for rationale. In mode="none" we
	// hand the bare (optionally jitter-wrapped) rawConn straight to quic-go
	// and skip the per-packet encrypt+framing+pool dance entirely.
	var quicConn net.PacketConn = netConn
	if s.config.Obfuscation.Mode != string(config.ObfuscationNone) {
		obfConn := NewObfuscatedConn(netConn, s.cipher, s.config)
		s.obfConn = obfConn
		quicConn = obfConn
	} else {
		slog.Info("obfuscator bypassed — fast path", "component", "quic", "reason", "obfuscation.mode=none")
	}

	tlsConf, err := s.generateTLSConfig()
	if err != nil {
		return err
	}

	// QUIC performance tuning (server side):
	quicConf := &quic.Config{
		KeepAlivePeriod:                time.Duration(s.config.QUIC.KeepAlivePeriodSec) * time.Second,
		MaxIdleTimeout:                 time.Duration(s.config.QUIC.MaxIdleTimeoutSec) * time.Second,
		InitialStreamReceiveWindow:     initialStreamReceiveWindow,
		MaxStreamReceiveWindow:         uint64(s.config.QUIC.MaxStreamReceiveWindow),
		InitialConnectionReceiveWindow: initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     uint64(s.config.QUIC.MaxConnectionReceiveWindow),
		MaxIncomingStreams:             int64(s.config.QUIC.MaxIncomingStreams),
		MaxIncomingUniStreams:          int64(s.config.QUIC.MaxIncomingUniStreams),
		EnableDatagrams:                true,
		DisablePathMTUDiscovery:        !s.config.QUIC.EnablePathMTUDiscovery,
		InitialPacketSize:              initialPacketSize(s.config.Performance.MTU),
		// 0-RTT would let a replayed first stream open a duplicate SOCKS5
		// CONNECT (non-idempotent). Tickets-for-1-RTT-resume stay on — we
		// only want to forbid early-data replay, not resumption itself.
		Allow0RTT: false,
		// qlog tracer — see client.go for details.
		Tracer: qlog.DefaultConnectionTracer,
	}
	applyCongestionControl(quicConf, s.config.QUIC.CongestionControl, "server")
	quic.SetPacketThreshold(int64(s.config.QUIC.PacketThreshold))
	logQUICConfig(quicConf, "server", s.config.QUIC.PacketThreshold)

	ln, err := quic.Listen(quicConn, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}
	s.listener = ln

	go s.acceptLoop()

	// Start the active defense chaff ticker (paranoid mode only).
	// When obfuscation.mode="none" we bypass the obfuscator entirely so
	// obfConn is nil; chaffTicker is paranoid-only anyway, so skip.
	if s.obfConn != nil {
		go s.chaffTicker(s.obfConn, rawConn)
	}

	// Periodic stats for diagnostics
	go s.statsTicker()

	<-s.stopCh
	return nil
}

func (s *Server) acceptLoop() {
	for s.running.Load() {
		sess, err := s.listener.Accept(context.Background())
		if err != nil {
			if s.running.Load() {
				slog.Error("accept error", "component", "quic", "error", err)
			}
			return
		}
		go s.handleSession(sess)
	}
}

func (s *Server) handleSession(sess *quic.Conn) {
	s.activeSessions.Add(1)
	defer s.activeSessions.Add(-1)

	start := time.Now()
	remote := sess.RemoteAddr()
	slog.Info("new session",
		"component", "quic",
		"remote", remote,
		"active", s.activeSessions.Load(),
		"tls_resumed", sess.ConnectionState().TLS.DidResume)
	var streamCount atomic.Uint64
	defer func() {
		sess.CloseWithError(0, "session closed")
		slog.Debug("session ended", "component", "quic", "remote", remote, "duration", time.Since(start).Round(time.Millisecond), "streams", streamCount.Load(), "exit_reason", context.Cause(sess.Context()))
	}()

	go s.handleDatagrams(sess)

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			slog.Debug("accept stream exit", "component", "quic", "remote", remote, "error", err)
			return
		}
		streamCount.Add(1)
		go s.handleStream(stream)
	}
}

// datagramRoute represents an active UDP relay to a target.
//
// lastActivity is touched on every datagram flowing in either direction
// (client→target send in handleDatagrams, target→client recv in the
// receive loop). The receive-loop wakes on a short tick deadline and
// uses lastActivity to decide whether the route is truly idle — this
// replaces the old "fixed 5-minute read deadline" pattern which closed
// routes based on absolute time since deadline-set rather than real
// idleness and produced both fd leaks and periodic cleanup waves.
//
// closed is a one-shot CAS guard so that a race between the receive
// loop and the background janitor (both of which can close the route)
// only results in a single conn.Close() and a single totalRoutes
// decrement.
type datagramRoute struct {
	directConn   *net.UDPConn          // used when no outbound proxy
	proxyConn    *socks.UDPProxyClient // used when outbound proxy enabled
	lastActivity atomic.Int64          // unix nanos; monotonic-ish, only compared with itself
	closed       atomic.Bool
}

func (r *datagramRoute) touch() {
	r.lastActivity.Store(time.Now().UnixNano())
}

// shutdown closes the underlying connection(s) exactly once. Returns
// true if this call performed the close, false if another goroutine
// already closed it. Callers decrement the server's route counter only
// on a true return to avoid double-counting.
func (r *datagramRoute) shutdown() bool {
	if !r.closed.CompareAndSwap(false, true) {
		return false
	}
	if r.directConn != nil {
		_ = r.directConn.Close()
	}
	if r.proxyConn != nil {
		_ = r.proxyConn.Close()
	}
	return true
}

// handleDatagrams relays UDP traffic between client and targets via QUIC datagrams.
// Format: [AssocID:4][ATYP+ADDR+PORT][PAYLOAD]
func (s *Server) handleDatagrams(sess *quic.Conn) {
	routes := make(map[string]*datagramRoute)
	var mu sync.Mutex
	remote := sess.RemoteAddr()
	slog.Debug("datagrams: enter", "component", "udp", "remote", remote)

	// Janitor: sweeps idle routes every 30s as a safety net. The receive
	// loop already handles idle eviction on its own wakeup, but the
	// janitor catches edge cases where Read is blocked in the kernel
	// (e.g. a route that is sending out but never receiving anything).
	janitorCtx, janitorCancel := context.WithCancel(context.Background())
	defer janitorCancel()
	go s.routeJanitor(janitorCtx, routes, &mu, remote)

	defer func() {
		mu.Lock()
		closed := 0
		for _, r := range routes {
			if r.shutdown() {
				closed++
				s.udpRoutes.Add(-1)
			}
		}
		mu.Unlock()
		slog.Debug("datagrams: exit", "component", "udp", "remote", remote, "routes_closed", closed)
	}()

	for s.running.Load() {
		msg, err := sess.ReceiveDatagram(context.Background())
		if err != nil {
			slog.Debug("datagrams: receive error", "component", "udp", "remote", remote, "error", err)
			return
		}
		if len(msg) < 7 {
			continue
		}

		assocID := msg[0:4]
		host, port, addrLen, err := socks.ParseAddress(msg[4:])
		if err != nil {
			continue
		}

		portStr := strconv.Itoa(int(port))
		targetAddr := net.JoinHostPort(host, portStr)

		// Resolve domain once to prevent TOCTOU DNS rebinding.
		// For outbound proxy mode, skip resolve — the proxy handles DNS.
		resolvedHost := host
		if !s.config.OutboundProxy.Enabled && net.ParseIP(host) == nil {
			lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 3*time.Second)
			ips, lookupErr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
			lookupCancel()
			if lookupErr != nil || len(ips) == 0 {
				slog.Warn("dns lookup failed", "component", "udp", "target", targetAddr, "error", lookupErr)
				continue
			}
			resolvedHost = ips[0].IP.String()
		}

		if s.config.Security.BlocksPrivateTargets() {
			if blocked, reason := isPrivateTarget(resolvedHost); blocked {
				slog.Warn("blocked private udp target", "component", "udp", "target", targetAddr, "reason", reason)
				continue
			}
		}

		resolvedTargetAddr := net.JoinHostPort(resolvedHost, portStr)
		routeKey := fmt.Sprintf("%d_%s", binary.BigEndian.Uint32(assocID), resolvedTargetAddr)
		payload := msg[4+addrLen:]

		mu.Lock()
		route, exists := routes[routeKey]
		if !exists {
			// Enforce hard cap: if at capacity, evict the route with the
			// oldest lastActivity (LRU). Linear scan is O(n) but route
			// creation is the slow path (~hundreds/sec at most under
			// real traffic) and n is bounded by UDPRouteMax.
			if cap := s.config.QUIC.UDPRouteMax; cap > 0 && len(routes) >= cap {
				s.evictOldestRouteLocked(routes)
			}

			route = &datagramRoute{}
			route.touch()
			if s.config.OutboundProxy.Enabled {
				var auth *socks.ProxyAuth
				if s.config.OutboundProxy.Username != "" {
					auth = &socks.ProxyAuth{
						Username: s.config.OutboundProxy.Username,
						Password: s.config.OutboundProxy.Password,
					}
				}
				proxyClient, err := socks.NewUDPProxyClient(s.config.OutboundProxy.Address, auth)
				if err != nil {
					slog.Error("proxy associate failed", "component", "udp", "target", targetAddr, "error", err)
					mu.Unlock()
					continue
				}
				route.proxyConn = proxyClient
				routes[routeKey] = route
				s.udpRoutes.Add(1)
				slog.Debug("route created (proxy)", "component", "udp", "remote", remote, "target", targetAddr, "routes", len(routes))

				go s.receiveProxyDatagrams(sess, route, proxyClient, assocID, host, port, routeKey, routes, &mu)
			} else {
				// Use resolved IP directly — no second lookup
				udpAddr := &net.UDPAddr{IP: net.ParseIP(resolvedHost), Port: int(port)}
				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				route.directConn = conn
				routes[routeKey] = route
				s.udpRoutes.Add(1)
				slog.Debug("route created (direct)", "component", "udp", "remote", remote, "target", targetAddr, "routes", len(routes))

				go s.receiveDirectDatagrams(sess, route, conn, assocID, resolvedHost, port, routeKey, routes, &mu)
			}
		}
		mu.Unlock()

		// Touch on the send path too: a route that only ever sends
		// (e.g. a one-way fire-and-forget flow) must not be closed by
		// the idle janitor while actively in use.
		route.touch()
		if route.proxyConn != nil {
			_ = route.proxyConn.SendTo(payload, host, port)
		} else if route.directConn != nil {
			_, _ = route.directConn.Write(payload)
		}
		s.bytesReceived.Add(uint64(len(payload)))
	}
}

// evictOldestRouteLocked removes the route with the oldest lastActivity
// from the map, closes it, and bumps the eviction counter. Caller must
// hold mu.
func (s *Server) evictOldestRouteLocked(routes map[string]*datagramRoute) {
	var oldestKey string
	var oldestNanos int64 = math.MaxInt64
	for k, r := range routes {
		la := r.lastActivity.Load()
		if la < oldestNanos {
			oldestNanos = la
			oldestKey = k
		}
	}
	if oldestKey == "" {
		return
	}
	victim := routes[oldestKey]
	delete(routes, oldestKey)
	if victim.shutdown() {
		s.udpRoutes.Add(-1)
		s.udpEvictions.Add(1)
	}
}

// routeJanitor periodically sweeps the route map for routes that have
// been idle longer than UDPRouteIdleSec and evicts them. This is a
// safety net: the per-route receive loops already self-close on idle,
// but if a route's Read is stuck in the kernel (e.g. a target that
// never sends back while the client is actively pushing) the receive
// loop never wakes — the janitor catches those cases.
func (s *Server) routeJanitor(ctx context.Context, routes map[string]*datagramRoute, mu *sync.Mutex, remote net.Addr) {
	tick := 30 * time.Second
	idle := time.Duration(s.config.QUIC.UDPRouteIdleSec) * time.Second
	if idle <= 0 {
		return
	}
	if tick > idle/2 {
		tick = idle / 2
		if tick < 5*time.Second {
			tick = 5 * time.Second
		}
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-idle).UnixNano()
			var victims []*datagramRoute
			mu.Lock()
			for k, r := range routes {
				if r.lastActivity.Load() < cutoff {
					victims = append(victims, r)
					delete(routes, k)
				}
			}
			mu.Unlock()
			if len(victims) > 0 {
				for _, r := range victims {
					if r.shutdown() {
						s.udpRoutes.Add(-1)
						s.udpIdleClosed.Add(1)
					}
				}
				slog.Debug("route janitor swept", "component", "udp", "remote", remote, "evicted", len(victims))
			}
		}
	}
}

func (s *Server) receiveDirectDatagrams(sess *quic.Conn, route *datagramRoute, conn *net.UDPConn, assocID []byte, host string, port uint16, routeKey string, routes map[string]*datagramRoute, mu *sync.Mutex) {
	buf := make([]byte, 65535)
	addrBytes := socks.BuildAddress(host, port)
	replyPrefix := make([]byte, 4+len(addrBytes))
	copy(replyPrefix[0:4], assocID)
	copy(replyPrefix[4:], addrBytes)

	idle := time.Duration(s.config.QUIC.UDPRouteIdleSec) * time.Second
	tick := idle / 3
	if tick < 5*time.Second {
		tick = 5 * time.Second
	}

	for {
		conn.SetReadDeadline(time.Now().Add(tick))
		n, err := conn.Read(buf)
		if err != nil {
			// A timeout just means nothing arrived in the tick window.
			// Use lastActivity (which is touched by both the send path
			// and this read path) to decide whether the route is truly
			// idle across BOTH directions. Only a real idle or a real
			// network error closes the route.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(time.Unix(0, route.lastActivity.Load())) < idle {
					continue
				}
				// Truly idle — fall through to close.
			}
			mu.Lock()
			delete(routes, routeKey)
			mu.Unlock()
			if route.shutdown() {
				s.udpRoutes.Add(-1)
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					s.udpIdleClosed.Add(1)
				}
			}
			slog.Debug("direct route closed", "component", "udp", "route", routeKey, "error", err)
			return
		}
		route.touch()

		reply, putReply := getDatagramBuf(len(replyPrefix) + n)
		copy(reply, replyPrefix)
		copy(reply[len(replyPrefix):], buf[:n])

		_ = sess.SendDatagram(reply)
		s.bytesSent.Add(uint64(n))
		putReply()
	}
}

func (s *Server) receiveProxyDatagrams(sess *quic.Conn, route *datagramRoute, proxy *socks.UDPProxyClient, assocID []byte, host string, port uint16, routeKey string, routes map[string]*datagramRoute, mu *sync.Mutex) {
	_ = host
	_ = port
	buf := make([]byte, 65535)

	idle := time.Duration(s.config.QUIC.UDPRouteIdleSec) * time.Second
	tick := idle / 3
	if tick < 5*time.Second {
		tick = 5 * time.Second
	}

	for {
		proxy.SetReadDeadline(time.Now().Add(tick))
		n, srcHost, srcPort, err := proxy.ReceiveFrom(buf)
		if err != nil {
			// Same bidirectional idle check as the direct path — only
			// close on true idle across both directions, not on an
			// empty tick window.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(time.Unix(0, route.lastActivity.Load())) < idle {
					continue
				}
			}
			mu.Lock()
			delete(routes, routeKey)
			mu.Unlock()
			if route.shutdown() {
				s.udpRoutes.Add(-1)
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					s.udpIdleClosed.Add(1)
				}
			}
			slog.Debug("proxy route closed", "component", "udp", "route", routeKey, "error", err)
			return
		}
		route.touch()

		addrBytes := socks.BuildAddress(srcHost, srcPort)
		reply, putReply := getDatagramBuf(4 + len(addrBytes) + n)
		copy(reply[0:4], assocID)
		copy(reply[4:], addrBytes)
		copy(reply[4+len(addrBytes):], buf[:n])

		_ = sess.SendDatagram(reply)
		s.bytesSent.Add(uint64(n))
		putReply()
	}
}

func (s *Server) handleStream(stream *quic.Stream) {
	defer stream.Close()

	header := make([]byte, 1)
	_, err := stream.Read(header)
	if err != nil {
		return
	}
	// A leading zero byte identifies a bench session (target length 0
	// is never valid for real traffic); dispatch and return so the
	// normal SOCKS-like path doesn't try to parse a target address.
	if header[0] == benchMarker {
		handleBenchStream(stream)
		return
	}
	targetLen := int(header[0])
	targetBuf := make([]byte, targetLen)
	_, err = io.ReadFull(stream, targetBuf)
	if err != nil {
		return
	}
	target := string(targetBuf)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		slog.Warn("invalid target", "component", "quic", "target", target, "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When using outbound proxy, pass the hostname directly — the proxy handles
	// DNS resolution (important for IPv4/IPv6 selection and anonymity).
	// When dialing directly, resolve once and validate to prevent DNS rebinding.
	dialTarget := target
	if !s.config.OutboundProxy.Enabled && net.ParseIP(host) == nil {
		lookupCtx, lookupCancel := context.WithTimeout(ctx, 3*time.Second)
		ips, lookupErr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
		lookupCancel()
		if lookupErr != nil || len(ips) == 0 {
			slog.Warn("dns lookup failed", "component", "quic", "target", target, "error", lookupErr)
			return
		}
		dialTarget = net.JoinHostPort(ips[0].IP.String(), port)
		host = ips[0].IP.String()
	}

	if s.config.Security.BlocksPrivateTargets() {
		if blocked, reason := isPrivateTarget(host); blocked {
			slog.Warn("blocked private target", "component", "quic", "target", target, "reason", reason)
			return
		}
	}

	targetConn, err := s.dialer.DialContext(ctx, "tcp", dialTarget)
	if err != nil {
		slog.Warn("dial target failed", "component", "quic", "target", target, "error", err)
		return
	}
	defer targetConn.Close()

	errCh := make(chan error, 2)

	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(targetConn, stream, *bufPtr)
		s.bytesReceived.Add(uint64(n))
		slog.Debug("upload finished", "component", "quic", "target", target, "bytes", n, "error", err)
		errCh <- err
	}()

	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(stream, targetConn, *bufPtr)
		s.bytesSent.Add(uint64(n))
		slog.Debug("download finished", "component", "quic", "target", target, "bytes", n, "error", err)
		errCh <- err
	}()

	firstErr := <-errCh
	slog.Debug("first copy done, closing", "component", "quic", "target", target, "err", firstErr)
	stream.Close()
	targetConn.Close()

	// If the first copy ended with an error (not clean EOF), the transfer
	// is already broken — no point waiting for the other half to drain.
	// Cancel the stream now so the second goroutine unblocks immediately.
	if firstErr != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}

	done := make(chan struct{})
	go func() { <-errCh; close(done) }()

	timer := time.NewTimer(time.Duration(s.config.QUIC.StreamCloseTimeoutSec) * time.Second)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
		slog.Debug("stream close timeout, aborting", "component", "quic", "target", target)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		<-done
	}
	slog.Debug("stream fully closed", "component", "quic", "target", target)
}

// statsTicker logs active session and byte counters every 30s for diagnostics.
func (s *Server) statsTicker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			fds := countFDs()
			slog.Log(context.Background(), s.config.StatsLogLevel(),
				"server stats",
				"component", "stats",
				"active_sessions", s.activeSessions.Load(),
				"bytes_sent", s.bytesSent.Load(),
				"bytes_received", s.bytesReceived.Load(),
				"open_fds", fds,
				"udp_routes", s.udpRoutes.Load(),
				"udp_evictions", s.udpEvictions.Load(),
				"udp_idle_closed", s.udpIdleClosed.Load(),
			)
		}
	}
}

func countFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// chaffTicker sends dummy packets at regular intervals in paranoid mode
// to maintain a constant bit rate and defeat traffic analysis.
// On the server side, chaff is only sent once a client has connected
// (realPeer has a port set).
func (s *Server) chaffTicker(obfConn *ObfuscatedConn, rawConn *transportPacketConn) {
	if s.config.Obfuscation.Mode != string(config.ObfuscationParanoid) {
		return
	}

	base := time.Duration(s.config.Obfuscation.ChaffingIntervalMs) * time.Millisecond
	if base <= 0 {
		base = 50 * time.Millisecond
	}

	for {
		jitter := time.Duration(mrand.Int64N(int64(base/2))) - base/4 // ±25%
		select {
		case <-s.stopCh:
			return
		case <-time.After(base + jitter):
			peer := rawConn.realPeer.Load()
			if peer == nil || peer.Port == 0 {
				continue // No client connected yet
			}
			lastSend := time.Unix(0, obfConn.lastSendTime.Load())
			if time.Since(lastSend) >= base {
				obfConn.SendChaff(peer)
			}
		}
	}
}

func (s *Server) Stop() error {
	if !s.running.Swap(false) {
		return nil
	}
	close(s.stopCh)

	// Mark rawConn closed so ReadFrom propagates the pending read error
	// to quic-go for a clean shutdown (instead of absorbing it).
	if s.rawConn != nil {
		s.rawConn.closed.Store(true)
	}

	// Set immediate read deadline to unblock any pending transport reads
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := s.trans.(deadliner); ok {
		d.SetReadDeadline(time.Now())
	}

	if s.listener != nil {
		s.listener.Close()
	}
	return s.trans.Close()
}

func (s *Server) generateTLSConfig() (*tls.Config, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Explicit SessionTicketKey rotated at every boot. Session tickets
	// are on by default in crypto/tls, but the derived default key is
	// shared across tls.Config copies in weird ways; an explicit 32-byte
	// random key is cleaner and boot-fresh (tickets issued by a prior
	// run are unusable, which is what we want given the shared-secret
	// auth already tied to this server instance).
	var sessionKey [32]byte
	if _, err := rand.Read(sessionKey[:]); err != nil {
		return nil, fmt.Errorf("session ticket key: %w", err)
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{tlsCert},
		NextProtos:       []string{"quiccochet-v1"},
		SessionTicketKey: sessionKey,
	}, nil
}

// isPrivateTarget checks if a host (must be an IP literal, not a domain)
// is a private/internal address. Returns (blocked, reason).
func isPrivateTarget(host string) (bool, string) {
	ip := net.ParseIP(host)
	if ip == nil {
		return false, ""
	}
	return checkIP(ip)
}

// cgnatNet is RFC 6598 Carrier-Grade NAT range, used by Tailscale et al.
var cgnatNet = &net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

// thisNetwork is RFC 1122 "this network" 0.0.0.0/8. ip.IsUnspecified()
// only matches the exact 0.0.0.0; the rest of the /8 must be blocked
// explicitly to prevent crafted source-address abuse.
var thisNetwork = &net.IPNet{
	IP:   net.IPv4(0, 0, 0, 0),
	Mask: net.CIDRMask(8, 32),
}

func checkIP(ip net.IP) (bool, string) {
	switch {
	case ip.IsLoopback():
		return true, "loopback"
	case ip.IsPrivate():
		return true, "private (RFC 1918 / ULA)"
	case ip.IsLinkLocalUnicast():
		return true, "link-local"
	case ip.IsMulticast():
		return true, "multicast"
	case ip.IsUnspecified():
		return true, "unspecified"
	case ip.Equal(net.IPv4bcast):
		return true, "broadcast"
	case ip.To4() != nil && cgnatNet.Contains(ip):
		return true, "CGNAT (RFC 6598)"
	case ip.To4() != nil && thisNetwork.Contains(ip):
		return true, "this network (RFC 1122 0.0.0.0/8)"
	}
	return false, ""
}

func (s *Server) Stats() (sent, received uint64, sessions int) {
	return s.bytesSent.Load(), s.bytesReceived.Load(), int(s.activeSessions.Load())
}

// StartPprof/StopPprof/PprofStatus delegate to the embedded
// admin.PprofServer so the Server satisfies admin.PprofBackend.
func (s *Server) StartPprof(addr string) (admin.PprofStatus, error) {
	return s.pprof.Start(addr)
}
func (s *Server) StopPprof() error       { return s.pprof.Stop() }
func (s *Server) PprofStatus() admin.PprofStatus { return s.pprof.Status() }

// Snapshot returns a point-in-time view of server state for the
// admin `stats` command. Counters are loaded atomically so the
// view is lock-free.
func (s *Server) Snapshot() admin.Snapshot {
	return admin.Snapshot{
		Role:           "server",
		ActiveSessions: s.activeSessions.Load(),
		UDPRoutes:      s.udpRoutes.Load(),
		UDPEvictions:   s.udpEvictions.Load(),
		UDPIdleClosed:  s.udpIdleClosed.Load(),
		BytesSent:      s.bytesSent.Load(),
		BytesReceived:  s.bytesReceived.Load(),
		OpenFDs:        countFDs(),
		StartedAt:      s.startedAt,
		UptimeSec:      time.Since(s.startedAt).Seconds(),
	}
}
