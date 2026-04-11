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
	"math/big"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

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

	expectedSpoofIP net.IP
	clientRealIP    net.IP

	dialer proxy.ContextDialer

	running atomic.Bool
	stopCh  chan struct{}

	bytesSent      atomic.Uint64
	bytesReceived  atomic.Uint64
	activeSessions atomic.Int32
}

// NewServer creates a new tunnel server
func NewServer(cfg *config.Config, cipher *crypto.Cipher) (*Server, error) {
	transportCfg := &transport.Config{
		SourceIP:       net.ParseIP(cfg.Spoof.SourceIP),
		SourceIPv6:     net.ParseIP(cfg.Spoof.SourceIPv6),
		ListenPort:     uint16(cfg.ListenPort),
		PeerSpoofIP:    net.ParseIP(cfg.Spoof.PeerSpoofIP),
		PeerSpoofIPv6:  net.ParseIP(cfg.Spoof.PeerSpoofIPv6),
		BufferSize:     cfg.Performance.BufferSize,
		MTU:            cfg.Performance.MTU,
		ProtocolNumber: cfg.Transport.ProtocolNumber,
		ICMPEchoID:     cfg.Transport.ICMPEchoID,
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
		expectedSpoofIP: net.ParseIP(cfg.Spoof.PeerSpoofIP),
		clientRealIP:    net.ParseIP(cfg.Spoof.ClientRealIP),
		stopCh:          make(chan struct{}),
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
		port:  0,
	}
	if s.clientRealIP != nil {
		rawConn.realPeer.Store(&net.UDPAddr{IP: s.clientRealIP})
	}

	obfConn := NewObfuscatedConn(rawConn, s.cipher, s.config)

	tlsConf, err := s.generateTLSConfig()
	if err != nil {
		return err
	}

	// QUIC performance tuning (server side):
	quicConf := &quic.Config{
		KeepAlivePeriod:            time.Duration(s.config.QUIC.KeepAlivePeriodSec) * time.Second,
		MaxIdleTimeout:             time.Duration(s.config.QUIC.MaxIdleTimeoutSec) * time.Second,
		MaxStreamReceiveWindow:     uint64(s.config.QUIC.MaxStreamReceiveWindow),
		MaxConnectionReceiveWindow: uint64(s.config.QUIC.MaxConnectionReceiveWindow),
		EnableDatagrams:            true,
		DisablePathMTUDiscovery: true,
	}

	ln, err := quic.Listen(obfConn, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}
	s.listener = ln

	go s.acceptLoop()

	// Start the active defense chaff ticker (paranoid mode only)
	go s.chaffTicker(obfConn, rawConn)

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

	slog.Info("new session", "component", "quic", "remote", sess.RemoteAddr())
	defer sess.CloseWithError(0, "session closed")

	go s.handleDatagrams(sess)

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
}

// datagramRoute represents an active UDP relay to a target.
type datagramRoute struct {
	directConn *net.UDPConn          // used when no outbound proxy
	proxyConn  *socks.UDPProxyClient // used when outbound proxy enabled
}

// handleDatagrams relays UDP traffic between client and targets via QUIC datagrams.
// Format: [AssocID:2][ATYP+ADDR+PORT][PAYLOAD]
func (s *Server) handleDatagrams(sess *quic.Conn) {
	routes := make(map[string]*datagramRoute)
	var mu sync.Mutex

	defer func() {
		mu.Lock()
		for _, r := range routes {
			if r.directConn != nil {
				r.directConn.Close()
			}
			if r.proxyConn != nil {
				r.proxyConn.Close()
			}
		}
		mu.Unlock()
	}()

	for s.running.Load() {
		msg, err := sess.ReceiveDatagram(context.Background())
		if err != nil {
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

		portStr := fmt.Sprintf("%d", port)
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
			route = &datagramRoute{}
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

				go s.receiveProxyDatagrams(sess, proxyClient, assocID, host, port, routeKey, routes, &mu)
			} else {
				// Use resolved IP directly — no second lookup
				udpAddr := &net.UDPAddr{IP: net.ParseIP(resolvedHost), Port: int(port)}
				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				route.directConn = conn

				go s.receiveDirectDatagrams(sess, conn, assocID, resolvedHost, port, routeKey, routes, &mu)
			}
			routes[routeKey] = route
		}
		mu.Unlock()

		if route.proxyConn != nil {
			_ = route.proxyConn.SendTo(payload, host, port)
		} else if route.directConn != nil {
			_, _ = route.directConn.Write(payload)
		}
		s.bytesReceived.Add(uint64(len(payload)))
	}
}

func (s *Server) receiveDirectDatagrams(sess *quic.Conn, conn *net.UDPConn, assocID []byte, host string, port uint16, routeKey string, routes map[string]*datagramRoute, mu *sync.Mutex) {
	buf := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			mu.Lock()
			delete(routes, routeKey)
			mu.Unlock()
			conn.Close()
			return
		}

		addrBytes := socks.BuildAddress(host, port)
		reply := make([]byte, 4+len(addrBytes)+n)
		copy(reply[0:4], assocID)
		copy(reply[4:], addrBytes)
		copy(reply[4+len(addrBytes):], buf[:n])

		_ = sess.SendDatagram(reply)
		s.bytesSent.Add(uint64(n))
	}
}

func (s *Server) receiveProxyDatagrams(sess *quic.Conn, proxy *socks.UDPProxyClient, assocID []byte, host string, port uint16, routeKey string, routes map[string]*datagramRoute, mu *sync.Mutex) {
	buf := make([]byte, 65535)
	for {
		n, srcHost, srcPort, err := proxy.ReceiveFrom(buf)
		if err != nil {
			mu.Lock()
			delete(routes, routeKey)
			mu.Unlock()
			proxy.Close()
			return
		}

		addrBytes := socks.BuildAddress(srcHost, srcPort)
		reply := make([]byte, 4+len(addrBytes)+n)
		copy(reply[0:4], assocID)
		copy(reply[4:], addrBytes)
		copy(reply[4+len(addrBytes):], buf[:n])

		_ = sess.SendDatagram(reply)
		s.bytesSent.Add(uint64(n))
	}
}

func (s *Server) handleStream(stream *quic.Stream) {
	defer stream.Close()

	header := make([]byte, 1)
	_, err := stream.Read(header)
	if err != nil {
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
		errCh <- err
	}()

	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(stream, targetConn, *bufPtr)
		s.bytesSent.Add(uint64(n))
		errCh <- err
	}()

	<-errCh
	stream.Close()
	targetConn.Close()
	<-errCh
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
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quiccochet-v1"},
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
	}
	return false, ""
}

func (s *Server) Stats() (sent, received uint64, sessions int) {
	return s.bytesSent.Load(), s.bytesReceived.Load(), int(s.activeSessions.Load())
}
