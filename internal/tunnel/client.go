package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
	"github.com/pechenyeru/quiccochet/internal/socks"
	"github.com/pechenyeru/quiccochet/internal/transport"
)

// proxyCopyPool is a global pool for copy buffers to avoid heavy allocations during proxying.
var proxyCopyPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024) // 32KB buffer for high-performance copying
		return &buf
	},
}

// Client is the tunnel client
type Client struct {
	config *config.Config
	cipher *crypto.Cipher
	trans  transport.Transport

	// --- CONNECTION POOLING ---
	// Instead of a single QUIC connection, we use a pool to maximize throughput
	// and bypass single-stream/single-connection congestion limits.
	tr       *quic.Transport
	conns    []*quic.Conn
	nextConn atomic.Uint32

	// RWMutex to protect the connection pool against concurrent read/reconnects
	mu sync.RWMutex

	serverIP   net.IP
	serverPort uint16

	expectedSpoofIP net.IP

	socksServer *socks.Server

	running atomic.Bool
	stopCh  chan struct{}

	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

// NewClient creates a new tunnel client
func NewClient(cfg *config.Config, cipher *crypto.Cipher) (*Client, error) {
	serverIP := net.ParseIP(cfg.Server.Address)
	if serverIP == nil {
		ips, err := net.LookupIP(cfg.Server.Address)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve server address: %w", err)
		}
		serverIP = ips[0]
	}

	transportCfg := &transport.Config{
		SourceIP:       net.ParseIP(cfg.Spoof.SourceIP),
		SourceIPv6:     net.ParseIP(cfg.Spoof.SourceIPv6),
		ListenPort:     0, // Dynamic
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
		mode := transport.ICMPModeEcho
		if cfg.Transport.ICMPMode == config.ICMPModeReply {
			mode = transport.ICMPModeReply
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

	return &Client{
		config:          cfg,
		cipher:          cipher,
		trans:           trans,
		serverIP:        serverIP,
		serverPort:      uint16(cfg.Server.Port),
		expectedSpoofIP: net.ParseIP(cfg.Spoof.PeerSpoofIP),
		stopCh:          make(chan struct{}),
	}, nil
}

// Start starts the client
func (c *Client) Start() error {
	c.running.Store(true)

	log.Printf("Starting client → %s:%d (QUIC + Obfuscation + Pooling)", c.serverIP, c.serverPort)

	rawConn := &transportPacketConn{
		trans: c.trans,
		port:  c.serverPort,
	}
	if c.serverIP != nil {
		rawConn.realClientIP = c.serverIP
	}
	obfConn := NewObfuscatedConn(rawConn, c.cipher, c.config)

	// quic.Transport allows us to multiplex MULTIPLE QUIC connections over a SINGLE net.PacketConn
	c.tr = &quic.Transport{
		Conn: obfConn,
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quiccochet-v1"},
	}

	// QUIC performance tuning
	quicConf := &quic.Config{
		KeepAlivePeriod:            time.Duration(c.config.QUIC.KeepAlivePeriodSec) * time.Second,
		MaxIdleTimeout:             time.Duration(c.config.QUIC.MaxIdleTimeoutSec) * time.Second,
		MaxStreamReceiveWindow:     5 * 1024 * 1024,
		MaxConnectionReceiveWindow: 15 * 1024 * 1024,
		EnableDatagrams:            true,
	}

	addr := &net.UDPAddr{IP: c.serverIP, Port: int(c.serverPort)}

	// --- INITIALIZE THE CONNECTION POOL ---
	// Read pool size from config, fallback to 4 if not set
	poolSize := c.config.QUIC.PoolSize
	if poolSize <= 0 {
		poolSize = 4 // Default sweet spot
	}
	c.conns = make([]*quic.Conn, poolSize)

	for i := 0; i < poolSize; i++ {
		conn, err := c.tr.Dial(context.Background(), addr, tlsConf, quicConf)
		if err != nil {
			return fmt.Errorf("quic pool dial (conn %d): %w", i, err)
		}
		c.conns[i] = conn
	}

	log.Printf("[QUIC] Master session pool established with %d connections", poolSize)

	// Start the pool health-checker in background
	go c.maintainPool(addr, tlsConf, quicConf)

	// Start the active defense chaff ticker (paranoid mode only)
	go c.chaffTicker(obfConn, addr)

	errCh := make(chan error, len(c.config.Inbounds))
	for _, inb := range c.config.Inbounds {
		switch inb.Type {
		case config.InboundSocks:
			go func(listen string) {
				log.Printf("[Inbound] SOCKS5 proxy on %s", listen)
				socksServer, err := socks.NewStreamServer(listen, c.handleStream)
				if err != nil {
					errCh <- err
					return
				}
				c.socksServer = socksServer
				errCh <- socksServer.Serve()
			}(inb.Listen)
		case config.InboundForward:
			go func(listen, target string) {
				log.Printf("[Inbound] TCP forward on %s → %s", listen, target)
				errCh <- c.startForwardInbound(listen, target)
			}(inb.Listen, inb.Target)
		}
	}

	select {
	case err := <-errCh:
		return err
	case <-c.stopCh:
		return nil
	}
}

// maintainPool runs in background and revives dead QUIC connections (Health Check)
func (c *Client) maintainPool(addr net.Addr, tlsConf *tls.Config, quicConf *quic.Config) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for c.running.Load() {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			for i, conn := range c.conns {
				// If connection is nil or its context is cancelled (connection closed/timed out)
				if conn == nil || conn.Context().Err() != nil {
					newConn, err := c.tr.Dial(context.Background(), addr, tlsConf, quicConf)
					if err != nil {
						log.Printf("[QUIC] Pool auto-heal failed for conn %d: %v", i, err)
					} else {
						c.conns[i] = newConn
						log.Printf("[QUIC] Pool auto-heal restored conn %d", i)
					}
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *Client) handleStream(target string, tcpConn net.Conn) error {
	defer tcpConn.Close()

	// --- ROUND-ROBIN LOAD BALANCING (WITH SAFETY READ LOCK) ---
	c.mu.RLock()
	poolLen := uint32(len(c.conns))
	if poolLen == 0 {
		c.mu.RUnlock()
		return fmt.Errorf("quic pool is empty")
	}

	idx := c.nextConn.Add(1) % poolLen
	session := c.conns[idx]
	c.mu.RUnlock()

	// Double check if the selected session is alive
	if session == nil || session.Context().Err() != nil {
		return fmt.Errorf("selected quic connection is temporarily dead")
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("open quic stream: %w", err)
	}
	defer stream.Close()

	targetData := []byte(target)
	if len(targetData) > 255 {
		return fmt.Errorf("target address too long")
	}

	header := []byte{byte(len(targetData))}
	_, err = stream.Write(header)
	if err != nil {
		return err
	}
	_, err = stream.Write(targetData)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)

	// High-performance proxying using buffer pools
	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(stream, tcpConn, *bufPtr)
		c.bytesSent.Add(uint64(n))
		errCh <- err
	}()

	go func() {
		bufPtr := proxyCopyPool.Get().(*[]byte)
		defer proxyCopyPool.Put(bufPtr)

		n, err := io.CopyBuffer(tcpConn, stream, *bufPtr)
		c.bytesReceived.Add(uint64(n))
		errCh <- err
	}()

	<-errCh
	return nil
}

func (c *Client) startForwardInbound(listenAddr, target string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for c.running.Load() {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go c.handleStream(target, conn)
	}
	return nil
}

// chaffTicker sends dummy packets at regular intervals in paranoid mode
// to maintain a constant bit rate and defeat traffic analysis.
func (c *Client) chaffTicker(obfConn *ObfuscatedConn, addr net.Addr) {
	if c.config.Obfuscation.Mode != string(config.ObfuscationParanoid) {
		return
	}

	interval := time.Duration(c.config.Obfuscation.ChaffingIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			lastSend := time.Unix(0, obfConn.lastSendTime.Load())
			if time.Since(lastSend) >= interval {
				obfConn.SendChaff(addr)
			}
		}
	}
}

func (c *Client) Stop() error {
	if !c.running.Swap(false) {
		return nil
	}
	close(c.stopCh)

	// Close all connections in the pool gracefully
	c.mu.Lock()
	if c.tr != nil {
		for _, conn := range c.conns {
			if conn != nil {
				conn.CloseWithError(0, "client stopping")
			}
		}
		c.tr.Close()
	}
	c.mu.Unlock()

	if c.socksServer != nil {
		c.socksServer.Close()
	}
	return c.trans.Close()
}

func (c *Client) Stats() (sent, received uint64) {
	return c.bytesSent.Load(), c.bytesReceived.Load()
}
