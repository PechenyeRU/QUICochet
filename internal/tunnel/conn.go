package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pechenyeru/quiccochet/internal/transport"
)

// transportPacketConn adapts transport.Transport to net.PacketConn interface.
// This is needed to wrap the transport with ObfuscatedConn and then pass it to QUIC.
type transportPacketConn struct {
	trans transport.Transport

	// realPeer stores the real peer address atomically.
	// In server mode: the client's real IP + learned ephemeral port.
	// In client mode: the server's real IP (set once at init).
	realPeer atomic.Pointer[net.UDPAddr]

	port uint16

	// closed is set by Close() to signal that Receive errors should be
	// propagated to quic-go (for clean shutdown) rather than absorbed.
	closed atomic.Bool
}

// ReadFrom absorbs transient transport errors and retries, because quic-go
// treats any ReadFrom error as fatal and tears down the entire quic.Transport.
// Raw/spoofed sockets can produce sporadic errors (EINTR, stray packets, etc.)
// that must NOT kill the tunnel. Errors are only propagated after Close().
func (c *transportPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		var srcIP net.IP
		var srcPort uint16
		n, srcIP, srcPort, err = c.trans.Receive(p)
		if err != nil {
			if c.closed.Load() {
				return 0, nil, err
			}
			slog.Debug("transport receive error, retrying", "component", "conn", "error", err)
			time.Sleep(time.Millisecond)
			continue
		}
		c.port = srcPort

		// Atomically update the real peer address (port may change on client restart)
		if peer := c.realPeer.Load(); peer != nil {
			c.realPeer.Store(&net.UDPAddr{IP: peer.IP, Port: int(srcPort)})
		}

		return n, &net.UDPAddr{IP: srcIP, Port: int(srcPort)}, nil
	}
}

func (c *transportPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	targetIP := addr.(*net.UDPAddr).IP
	targetPort := uint16(addr.(*net.UDPAddr).Port)

	// If we have a real peer configured, use it instead of the spoofed address
	if peer := c.realPeer.Load(); peer != nil {
		targetIP = peer.IP
		if peer.Port != 0 {
			targetPort = uint16(peer.Port)
		}
	}

	err = c.trans.Send(p, targetIP, targetPort)
	if err != nil {
		slog.Error("write error", "component", "conn", "error", err)
	}
	return len(p), err
}

func (c *transportPacketConn) Close() error {
	c.closed.Store(true)
	return c.trans.Close()
}
func (c *transportPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

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

// SyscallConn delegates to the underlying transport so quic-go can tune
// socket buffer sizes on the real UDP/raw socket.
func (c *transportPacketConn) SyscallConn() (syscall.RawConn, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if sc, ok := c.trans.(syscallConner); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("transport does not support SyscallConn")
}
