package tunnel

import (
	"log"
	"net"
	"time"

	"github.com/pechenyeru/quiccochet/internal/transport"
)

// transportPacketConn adapts transport.Transport to net.PacketConn interface.
// This is needed to wrap the transport with ObfuscatedConn and then pass it to QUIC.
type transportPacketConn struct {
	trans          transport.Transport
	realClientIP   net.IP // Real client IP (server mode) or real server IP (client mode)
	realClientPort uint16 // Real client port (server mode)
	port           uint16
}

func (c *transportPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	data, srcIP, srcPort, err := c.trans.Receive()
	if err != nil {
		return 0, nil, err
	}
	// Update port from the spoofed source
	c.port = srcPort
	// Always update real client port — the client may have restarted
	// on a new ephemeral port and we must track the change
	c.realClientPort = srcPort
	n = copy(p, data)
	// Return the spoofed address to QUIC (it needs to see consistent addresses)
	return n, &net.UDPAddr{IP: srcIP, Port: int(srcPort)}, nil
}

func (c *transportPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// In server mode: send to real client IP with spoofed source
	// In client mode: addr will be the server's spoofed IP, and we send there
	targetIP := addr.(*net.UDPAddr).IP
	targetPort := uint16(addr.(*net.UDPAddr).Port)

	// If we have a real client IP configured (server mode), use it instead of spoofed address
	if c.realClientIP != nil {
		targetIP = c.realClientIP
	}
	if c.realClientPort != 0 {
		targetPort = c.realClientPort
	}

	err = c.trans.Send(p, targetIP, targetPort)
	if err != nil {
		log.Printf("[CONN] Write error: %v", err)
	}
	return len(p), err
}

func (c *transportPacketConn) Close() error    { return c.trans.Close() }
func (c *transportPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// Deadline passthrough: if the transport supports deadlines (e.g. ICMP), use them.
// This is needed for QUIC timeout handling and clean shutdown.
func (c *transportPacketConn) SetDeadline(t time.Time) error {
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := c.trans.(deadliner); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *transportPacketConn) SetReadDeadline(t time.Time) error {
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := c.trans.(deadliner); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *transportPacketConn) SetWriteDeadline(t time.Time) error { return nil }
