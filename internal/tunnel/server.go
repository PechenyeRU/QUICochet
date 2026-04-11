package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
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

	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

// NewServer creates a new tunnel server
func NewServer(cfg *config.Config, cipher *crypto.Cipher) (*Server, error) {
	transportCfg := &transport.Config{
		SourceIP:       net.ParseIP(cfg.Spoof.SourceIP),
		SourceIPv6:     net.ParseIP(cfg.Spoof.SourceIPv6),
		ListenPort:     uint16(cfg.Listen.Port),
		PeerSpoofIP:    net.ParseIP(cfg.Spoof.PeerSpoofIP),
		PeerSpoofIPv6:  net.ParseIP(cfg.Spoof.PeerSpoofIPv6),
		BufferSize:     cfg.Performance.BufferSize,
		MTU:            cfg.Performance.MTU,
		ProtocolNumber: cfg.Transport.ProtocolNumber,
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

	log.Printf("Server listening on port %d (QUIC + Obfuscation)", s.config.Listen.Port)

	rawConn := &transportPacketConn{
		trans:          s.trans,
		realClientIP:   s.clientRealIP,
		realClientPort: 0,
		port:           0,
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
				log.Printf("[QUIC] accept error: %v", err)
			}
			return
		}
		go s.handleSession(sess)
	}
}

func (s *Server) handleSession(sess *quic.Conn) {
	log.Printf("[QUIC] new session from %v", sess.RemoteAddr())
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

		targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		routeKey := fmt.Sprintf("%d_%s", binary.BigEndian.Uint32(assocID), targetAddr)
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
					log.Printf("[UDP] proxy associate failed for %s: %v", targetAddr, err)
					mu.Unlock()
					continue
				}
				route.proxyConn = proxyClient

				go s.receiveProxyDatagrams(sess, proxyClient, assocID, host, port, routeKey, routes, &mu)
			} else {
				addr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				conn, err := net.DialUDP("udp", nil, addr)
				if err != nil {
					mu.Unlock()
					continue
				}
				route.directConn = conn

				go s.receiveDirectDatagrams(sess, conn, assocID, host, port, routeKey, routes, &mu)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	targetConn, err := s.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("[QUIC] dial %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()

	errCh := make(chan error, 2)

	// High-performance proxying with server-side buffer pool
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
}

// chaffTicker sends dummy packets at regular intervals in paranoid mode
// to maintain a constant bit rate and defeat traffic analysis.
// On the server side, chaff is only sent once a client has connected
// (rawConn.realClientPort > 0).
func (s *Server) chaffTicker(obfConn *ObfuscatedConn, rawConn *transportPacketConn) {
	if s.config.Obfuscation.Mode != string(config.ObfuscationParanoid) {
		return
	}

	interval := time.Duration(s.config.Obfuscation.ChaffingIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			port := rawConn.realClientPort
			if port == 0 {
				continue // No client connected yet
			}
			lastSend := time.Unix(0, obfConn.lastSendTime.Load())
			if time.Since(lastSend) >= interval {
				addr := &net.UDPAddr{IP: s.clientRealIP, Port: int(port)}
				obfConn.SendChaff(addr)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
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

func (s *Server) Stats() (sent, received uint64, sessions int) {
	return s.bytesSent.Load(), s.bytesReceived.Load(), 0
}
