package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ProxyAuth holds SOCKS5 proxy authentication credentials.
type ProxyAuth struct {
	Username string
	Password string
}

// UDPProxyClient implements a SOCKS5 UDP ASSOCIATE client (RFC 1928).
// It maintains a TCP control connection to the proxy and relays UDP
// datagrams through the proxy's UDP relay port.
type UDPProxyClient struct {
	tcpConn   net.Conn     // control connection (must stay open)
	udpConn   *net.UDPConn // local UDP socket for sending/receiving via relay
	relayAddr *net.UDPAddr // proxy's UDP relay address (BND.ADDR:BND.PORT)
	tcpDone   chan struct{} // closed when TCP control connection drops
	sendPool  sync.Pool    // reusable buffers for SendTo
	recvPool  sync.Pool    // reusable buffers for ReceiveFrom
}

// NewUDPProxyClient establishes a SOCKS5 UDP ASSOCIATE session with the proxy.
// The TCP control connection remains open for the lifetime of the association.
func NewUDPProxyClient(proxyAddr string, auth *ProxyAuth) (*UDPProxyClient, error) {
	tcpConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	c := &UDPProxyClient{
		tcpConn: tcpConn,
		sendPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 65535+22)
				return &buf
			},
		},
		recvPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 65535+22)
				return &buf
			},
		},
	}

	if err := c.authenticate(auth); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth: %w", err)
	}

	if err := c.associate(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate: %w", err)
	}

	// Open local UDP socket matching the relay's address family
	network := "udp4"
	listenIP := net.IPv4zero
	if c.relayAddr.IP.To4() == nil {
		network = "udp6"
		listenIP = net.IPv6zero
	}
	c.udpConn, err = net.ListenUDP(network, &net.UDPAddr{IP: listenIP, Port: 0})
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	// Monitor TCP control connection — server closing it terminates the association
	c.tcpDone = make(chan struct{})
	go func() {
		io.Copy(io.Discard, tcpConn)
		close(c.tcpDone)
		c.udpConn.Close() // unblock any pending reads
	}()

	return c, nil
}

// SendTo sends a UDP datagram to the target through the SOCKS5 proxy.
func (c *UDPProxyClient) SendTo(data []byte, destHost string, destPort uint16) error {
	addr := BuildAddress(destHost, destPort)

	// SOCKS5 UDP header: [RSV:2][FRAG:1] + [ATYP+ADDR+PORT] + [DATA]
	pktLen := 3 + len(addr) + len(data)
	bufPtr := c.sendPool.Get().(*[]byte)
	pkt := (*bufPtr)[:pktLen]

	// RSV = 0x0000, FRAG = 0x00 (first 3 bytes are zero)
	pkt[0], pkt[1], pkt[2] = 0, 0, 0
	copy(pkt[3:], addr)
	copy(pkt[3+len(addr):], data)

	_, err := c.udpConn.WriteToUDP(pkt, c.relayAddr)
	c.sendPool.Put(bufPtr)
	return err
}

// ReceiveFrom receives a UDP datagram from the proxy and returns the payload
// along with the original source address.
func (c *UDPProxyClient) ReceiveFrom(buf []byte) (n int, srcHost string, srcPort uint16, err error) {
	tmpBufPtr := c.recvPool.Get().(*[]byte)
	tmpBuf := *tmpBufPtr
	defer c.recvPool.Put(tmpBufPtr)

	rn, _, err := c.udpConn.ReadFromUDP(tmpBuf)
	if err != nil {
		return 0, "", 0, err
	}

	if rn < 3 {
		return 0, "", 0, errors.New("udp relay packet too short")
	}

	// Drop fragmented packets (FRAG must be 0x00)
	if tmpBuf[2] != 0x00 {
		return 0, "", 0, errors.New("fragmented socks5 udp packet")
	}

	// Parse address after RSV(2) + FRAG(1)
	srcHost, srcPort, addrLen, err := ParseAddress(tmpBuf[3:rn])
	if err != nil {
		return 0, "", 0, err
	}

	payloadStart := 3 + addrLen
	if payloadStart > rn {
		return 0, "", 0, errors.New("malformed udp relay packet")
	}

	n = copy(buf, tmpBuf[payloadStart:rn])
	return n, srcHost, srcPort, nil
}

// Done returns a channel that is closed when the TCP control connection drops,
// signaling the end of the UDP association.
func (c *UDPProxyClient) Done() <-chan struct{} {
	return c.tcpDone
}

// SetReadDeadline sets the deadline for the next ReceiveFrom call.
// Required to enforce idle timeouts on UDP ASSOCIATE routes so they don't
// accumulate unbounded when the proxy stops sending on a given flow.
func (c *UDPProxyClient) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

// Close terminates the UDP association by closing both connections.
func (c *UDPProxyClient) Close() error {
	var firstErr error
	if c.udpConn != nil {
		if err := c.udpConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.tcpConn != nil {
		if err := c.tcpConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// authenticate performs SOCKS5 version/method negotiation and optional auth.
func (c *UDPProxyClient) authenticate(auth *ProxyAuth) error {
	if auth != nil && auth.Username != "" {
		// Offer both no-auth and username/password
		_, err := c.tcpConn.Write([]byte{Version5, 2, AuthNone, AuthPassword})
		if err != nil {
			return err
		}
	} else {
		_, err := c.tcpConn.Write([]byte{Version5, 1, AuthNone})
		if err != nil {
			return err
		}
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, resp); err != nil {
		return err
	}
	if resp[0] != Version5 {
		return ErrUnsupportedVersion
	}

	switch resp[1] {
	case AuthNone:
		return nil
	case AuthPassword:
		if auth == nil || auth.Username == "" {
			return errors.New("proxy requires auth but no credentials provided")
		}
		return c.authenticatePassword(auth)
	case AuthNoAccept:
		return ErrNoAcceptableAuth
	default:
		return fmt.Errorf("unsupported auth method: %d", resp[1])
	}
}

// authenticatePassword performs RFC 1929 username/password authentication.
func (c *UDPProxyClient) authenticatePassword(auth *ProxyAuth) error {
	// Version 1 of username/password auth (RFC 1929)
	msg := make([]byte, 0, 3+len(auth.Username)+len(auth.Password))
	msg = append(msg, 0x01) // auth version
	msg = append(msg, byte(len(auth.Username)))
	msg = append(msg, []byte(auth.Username)...)
	msg = append(msg, byte(len(auth.Password)))
	msg = append(msg, []byte(auth.Password)...)

	if _, err := c.tcpConn.Write(msg); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("proxy auth failed")
	}
	return nil
}

// associate sends the UDP ASSOCIATE request and parses the relay address.
func (c *UDPProxyClient) associate() error {
	// CMD=0x03 (UDP ASSOCIATE), DST.ADDR=0.0.0.0, DST.PORT=0
	req := []byte{
		Version5, CmdUDP, 0x00, // VER, CMD, RSV
		AddrIPv4, 0, 0, 0, 0, // ATYP + 0.0.0.0
		0, 0, // PORT = 0
	}
	if _, err := c.tcpConn.Write(req); err != nil {
		return err
	}

	// Parse reply: [VER][REP][RSV][ATYP][BND.ADDR][BND.PORT]
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.tcpConn, header); err != nil {
		return err
	}
	if header[0] != Version5 {
		return ErrUnsupportedVersion
	}
	if header[1] != ReplySuccess {
		return fmt.Errorf("udp associate rejected: reply code %d", header[1])
	}

	// Parse BND.ADDR based on ATYP
	var bindIP net.IP
	switch header[3] {
	case AddrIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c.tcpConn, buf); err != nil {
			return err
		}
		bindIP = net.IP(buf)
	case AddrIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c.tcpConn, buf); err != nil {
			return err
		}
		bindIP = net.IP(buf)
	case AddrDomain:
		// Reject domain in BND.ADDR — resolving it via system DNS would
		// leak the proxy's hostname in cleartext, breaking anonymity.
		// Compliant proxies return IP literals or 0.0.0.0 (handled below).
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c.tcpConn, lenBuf); err != nil {
			return err
		}
		if lenBuf[0] == 0 {
			return errors.New("empty domain in BND.ADDR")
		}
		// Drain the domain bytes + port so the TCP stream stays in sync
		discard := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(c.tcpConn, discard); err != nil {
			return err
		}
		return errors.New("proxy returned domain in BND.ADDR, not supported (DNS leak risk)")
	default:
		return fmt.Errorf("unsupported address type in reply: %d", header[3])
	}

	// Parse BND.PORT
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, portBuf); err != nil {
		return err
	}
	bindPort := int(binary.BigEndian.Uint16(portBuf))

	// If BND.ADDR is 0.0.0.0, use the proxy's TCP address
	if bindIP.Equal(net.IPv4zero) || bindIP.Equal(net.IPv6zero) {
		tcpAddr := c.tcpConn.RemoteAddr().(*net.TCPAddr)
		bindIP = tcpAddr.IP
	}

	c.relayAddr = &net.UDPAddr{IP: bindIP, Port: bindPort}
	return nil
}
