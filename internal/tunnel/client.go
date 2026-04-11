package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
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

const (
	backoffMin    = 500 * time.Millisecond
	backoffMax    = 30 * time.Second
	backoffFactor = 2
	backoffJitter = 0.25 // ±25%
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

	// --- LAZY CONNECTION POOL ---
	// Connections are created on-demand and cached. If a cached connection
	// is dead when needed, a new one is dialed inline — no request ever
	// fails just because a connection died on the spoofed path.
	tr       *quic.Transport
	tlsConf  *tls.Config
	quicConf *quic.Config
	addr     net.Addr
	conns    []*quic.Conn
	nextConn atomic.Uint32

	mu sync.RWMutex

	serverIP   net.IP
	serverPort uint16

	expectedSpoofIP net.IP

	socksServer *socks.Server

	// UDP association tracking for SOCKS5 UDP ASSOCIATE relay
	nextAssocID     atomic.Uint32
	udpAssociations sync.Map // map[uint32]*udpAssoc

	running atomic.Bool
	stopCh  chan struct{}

	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

type udpAssoc struct {
	conn       *net.UDPConn
	clientAddr atomic.Pointer[net.UDPAddr]
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
		ListenPort:     uint16(cfg.ListenPort), // 0 = dynamic, >0 = fixed (needed behind NAT)
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

	slog.Info("starting client", "server", fmt.Sprintf("%s:%d", c.serverIP, c.serverPort))

	rawConn := &transportPacketConn{
		trans: c.trans,
		port:  c.serverPort,
	}
	if c.serverIP != nil {
		rawConn.realPeer.Store(&net.UDPAddr{IP: c.serverIP, Port: int(c.serverPort)})
	}
	obfConn := NewObfuscatedConn(rawConn, c.cipher, c.config)

	// quic.Transport allows us to multiplex MULTIPLE QUIC connections over a SINGLE net.PacketConn
	c.tr = &quic.Transport{
		Conn: obfConn,
	}

	c.tlsConf = &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quiccochet-v1"},
	}

	c.quicConf = &quic.Config{
		KeepAlivePeriod:            time.Duration(c.config.QUIC.KeepAlivePeriodSec) * time.Second,
		MaxIdleTimeout:             time.Duration(c.config.QUIC.MaxIdleTimeoutSec) * time.Second,
		MaxStreamReceiveWindow:     5 * 1024 * 1024,
		MaxConnectionReceiveWindow: 15 * 1024 * 1024,
		EnableDatagrams:            true,
		DisablePathMTUDiscovery: true,
	}

	c.addr = &net.UDPAddr{IP: c.serverIP, Port: int(c.serverPort)}

	// --- INITIALIZE THE CONNECTION POOL ---
	poolSize := c.config.QUIC.PoolSize
	if poolSize <= 0 {
		poolSize = 4
	}
	c.conns = make([]*quic.Conn, poolSize)

	// First connection with backoff — blocks until server is reachable
	slog.Info("connecting to server", "component", "quic", "pool_size", poolSize)
	first, err := c.dialWithBackoff()
	if err != nil {
		return err // stopCh was closed
	}
	c.conns[0] = first

	// Remaining connections in parallel
	if poolSize > 1 {
		var wg sync.WaitGroup
		for i := 1; i < poolSize; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				conn, dialErr := c.dialWithBackoff()
				if dialErr != nil {
					return // stopCh closed
				}
				c.mu.Lock()
				c.conns[idx] = conn
				c.mu.Unlock()
			}(i)
		}
		wg.Wait()
	}

	slog.Info("pool established", "component", "quic", "connections", poolSize)

	// Start datagram receivers for UDP relay
	for _, conn := range c.conns {
		if conn != nil {
			go c.receiveDatagrams(conn)
		}
	}

	// Start the pool health-checker in background
	go c.maintainPool()

	// Start the active defense chaff ticker (paranoid mode only)
	go c.chaffTicker(obfConn, c.addr)

	errCh := make(chan error, len(c.config.Inbounds))
	for _, inb := range c.config.Inbounds {
		switch inb.Type {
		case config.InboundSocks:
			go func(listen string) {
				slog.Info("inbound started", "component", "socks5", "listen", listen)
				socksServer, err := socks.NewStreamServer(listen, c.handleStream, c.handleUDP)
				if err != nil {
					errCh <- err
					return
				}
				c.socksServer = socksServer
				errCh <- socksServer.Serve()
			}(inb.Listen)
		case config.InboundForward:
			go func(listen, target string) {
				slog.Info("inbound started", "component", "forward", "listen", listen, "target", target)
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

// maintainPool runs in background and revives dead QUIC connections with exponential backoff.
func (c *Client) maintainPool() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	backoffs := make([]time.Duration, len(c.conns))
	lastFail := make([]time.Time, len(c.conns))

	for c.running.Load() {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			// Detect dead slots via QUIC connection context
			c.mu.RLock()
			var deadSlots []int
			for i, conn := range c.conns {
				if conn == nil || conn.Context().Err() != nil {
					if backoffs[i] == 0 || time.Since(lastFail[i]) >= backoffs[i] {
						deadSlots = append(deadSlots, i)
					}
				}
			}
			c.mu.RUnlock()

			if len(deadSlots) == 0 {
				continue
			}

			// Reconnect dead slots in parallel
			type reconnResult struct {
				idx  int
				conn *quic.Conn
				err  error
			}
			results := make(chan reconnResult, len(deadSlots))

			for _, idx := range deadSlots {
				go func(i int) {
					dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
					// Cancel dial immediately if client is stopping
					go func() {
						select {
						case <-c.stopCh:
							dialCancel()
						case <-dialCtx.Done():
						}
					}()
					conn, err := c.tr.Dial(dialCtx, c.addr, c.tlsConf, c.quicConf)
					dialCancel()
					results <- reconnResult{i, conn, err}
				}(idx)
			}

			// Collect results without holding the lock so handleStream/handleUDP
			// aren't blocked during the 3s dial timeout
			collected := make([]reconnResult, 0, len(deadSlots))
			for range deadSlots {
				collected = append(collected, <-results)
			}

			c.mu.Lock()
			for _, r := range collected {
				if r.err != nil {
					if backoffs[r.idx] == 0 {
						backoffs[r.idx] = backoffMin
					} else {
						backoffs[r.idx] = min(backoffs[r.idx]*backoffFactor, backoffMax)
					}
					backoffs[r.idx] = addJitter(backoffs[r.idx])
					lastFail[r.idx] = time.Now()
					slog.Warn("pool reconnect failed", "component", "quic", "conn", r.idx, "retry_in", backoffs[r.idx].Round(time.Millisecond), "error", r.err)
				} else {
					c.conns[r.idx] = r.conn
					backoffs[r.idx] = 0
					go c.receiveDatagrams(r.conn)
					slog.Info("pool restored", "component", "quic", "conn", r.idx)
				}
			}
			c.mu.Unlock()
		}
	}
}

// dialWithBackoff retries quic.Transport.Dial with exponential backoff until
// it succeeds or the client is stopped. Returns (nil, error) only on shutdown.
func (c *Client) dialWithBackoff() (*quic.Conn, error) {
	// Base context that cancels when stopCh closes
	baseCtx, baseCancel := context.WithCancelCause(context.Background())
	go func() {
		<-c.stopCh
		baseCancel(fmt.Errorf("client stopped"))
	}()

	delay := backoffMin
	for {
		ctx, cancel := context.WithTimeout(baseCtx, 3*time.Second)
		conn, err := c.tr.Dial(ctx, c.addr, c.tlsConf, c.quicConf)
		cancel()

		if err == nil {
			return conn, nil
		}

		// Check if we were stopped
		select {
		case <-c.stopCh:
			return nil, fmt.Errorf("client stopped during reconnect")
		default:
		}

		delay = min(delay, backoffMax)
		jittered := addJitter(delay)

		slog.Warn("dial failed", "component", "quic", "retry_in", jittered.Round(time.Millisecond), "error", err)

		select {
		case <-c.stopCh:
			return nil, fmt.Errorf("client stopped during reconnect")
		case <-time.After(jittered):
		}

		delay *= backoffFactor
	}
}

// getOrDialConn returns a live QUIC connection from the pool using round-robin.
// If the selected connection is dead, dials a new one inline and replaces it.
func (c *Client) getOrDialConn() (*quic.Conn, error) {
	c.mu.RLock()
	poolLen := uint32(len(c.conns))
	c.mu.RUnlock()

	if poolLen == 0 {
		return nil, fmt.Errorf("pool is empty")
	}

	base := c.nextConn.Add(1)

	for attempt := uint32(0); attempt < poolLen; attempt++ {
		idx := (base + attempt) % poolLen

		c.mu.RLock()
		session := c.conns[idx]
		c.mu.RUnlock()

		if session != nil && session.Context().Err() == nil {
			return session, nil
		}

		// Dead or nil — dial a fresh connection inline
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
		newConn, err := c.tr.Dial(dialCtx, c.addr, c.tlsConf, c.quicConf)
		dialCancel()
		if err != nil {
			slog.Warn("inline dial failed", "component", "quic", "conn", idx, "error", err)
			continue
		}

		// Double-check under write lock — another goroutine may have
		// already installed a connection while we were dialing
		c.mu.Lock()
		if existing := c.conns[idx]; existing != nil && existing.Context().Err() == nil {
			c.mu.Unlock()
			newConn.CloseWithError(0, "race lost")
			return existing, nil
		}
		c.conns[idx] = newConn
		c.mu.Unlock()

		go c.receiveDatagrams(newConn)
		slog.Info("connection replaced inline", "component", "quic", "conn", idx)
		return newConn, nil
	}

	return nil, fmt.Errorf("all dial attempts failed")
}

func addJitter(d time.Duration) time.Duration {
	jitter := float64(d) * backoffJitter * (2*rand.Float64() - 1) // ±25%
	return d + time.Duration(jitter)
}

func (c *Client) handleStream(target string, tcpConn net.Conn) error {
	defer tcpConn.Close()

	// --- LAZY POOL: get or create connection ---
	session, err := c.getOrDialConn()
	if err != nil {
		return fmt.Errorf("no quic connection available: %w", err)
	}

	openCtx, openCancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := session.OpenStreamSync(openCtx)
	openCancel()
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
	tcpConn.Close()
	stream.Close()

	done := make(chan struct{})
	go func() { <-errCh; close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		stream.CancelRead(0)
		stream.CancelWrite(0)
		<-done
	}
	return nil
}

// handleUDP relays UDP traffic from a SOCKS5 UDP ASSOCIATE client through QUIC datagrams.
func (c *Client) handleUDP(tcpConn net.Conn, udpConn *net.UDPConn) error {
	defer tcpConn.Close()
	defer udpConn.Close()

	assocID := c.nextAssocID.Add(1)
	assoc := &udpAssoc{conn: udpConn}
	c.udpAssociations.Store(assocID, assoc)
	defer c.udpAssociations.Delete(assocID)

	buf := make([]byte, 65535)

	// Monitor TCP control connection — close means end of association
	tcpDone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, tcpConn)
		close(tcpDone)
	}()

	for {
		select {
		case <-tcpDone:
			return nil
		case <-c.stopCh:
			return nil
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		assoc.clientAddr.Store(clientAddr)

		// SOCKS5 UDP: [RSV:2][FRAG:1][ATYP...][DATA]
		if n < 4 || buf[2] != 0x00 {
			continue // drop fragments and malformed packets
		}

		// Skip RSV(2) + FRAG(1), keep ATYP+ADDR+PORT+DATA
		addrAndData := buf[3:n]

		// Build QUIC datagram: [AssocID:4][ATYP+ADDR+PORT+DATA]
		pkt := make([]byte, 4+len(addrAndData))
		binary.BigEndian.PutUint32(pkt[0:4], assocID)
		copy(pkt[4:], addrAndData)

		c.mu.RLock()
		if len(c.conns) > 0 {
			idx := c.nextConn.Add(1) % uint32(len(c.conns))
			if sess := c.conns[idx]; sess != nil && sess.Context().Err() == nil {
				_ = sess.SendDatagram(pkt)
				c.bytesSent.Add(uint64(n))
			}
		}
		c.mu.RUnlock()
	}
}

// receiveDatagrams handles UDP replies from the server via QUIC datagrams.
func (c *Client) receiveDatagrams(sess *quic.Conn) {
	for c.running.Load() {
		msg, err := sess.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(msg) < 7 {
			continue
		}

		assocID := binary.BigEndian.Uint32(msg[0:4])
		val, ok := c.udpAssociations.Load(assocID)
		if !ok {
			continue
		}

		assoc := val.(*udpAssoc)
		clientAddr := assoc.clientAddr.Load()
		if clientAddr == nil {
			continue
		}

		// Rebuild SOCKS5 UDP response: [RSV:0,0][FRAG:0][ATYP+ADDR+PORT+DATA]
		addrAndData := msg[4:]
		reply := make([]byte, 3+len(addrAndData))
		// reply[0:3] = 0 (RSV + FRAG)
		copy(reply[3:], addrAndData)

		_, _ = assoc.conn.WriteToUDP(reply, clientAddr)
		c.bytesReceived.Add(uint64(len(addrAndData)))
	}
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

// chaffTicker sends dummy packets at jittered intervals in paranoid mode
// to fill idle gaps and defeat traffic analysis without creating a
// perfectly periodic fingerprint.
func (c *Client) chaffTicker(obfConn *ObfuscatedConn, addr net.Addr) {
	if c.config.Obfuscation.Mode != string(config.ObfuscationParanoid) {
		return
	}

	base := time.Duration(c.config.Obfuscation.ChaffingIntervalMs) * time.Millisecond
	if base <= 0 {
		base = 50 * time.Millisecond
	}

	for {
		jitter := time.Duration(rand.Int64N(int64(base/2))) - base/4 // ±25%
		select {
		case <-c.stopCh:
			return
		case <-time.After(base + jitter):
			lastSend := time.Unix(0, obfConn.lastSendTime.Load())
			if time.Since(lastSend) >= base {
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

	// Set immediate read deadline to unblock any pending transport reads.
	// This must happen before locking mu, since maintainPool may hold it
	// while blocked on dial results that depend on transport reads.
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := c.trans.(deadliner); ok {
		d.SetReadDeadline(time.Now())
	}

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
