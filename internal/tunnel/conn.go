package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pechenyeru/quiccochet/internal/crypto"
	"github.com/pechenyeru/quiccochet/internal/transport"
)

// datagramPool holds 2 KB buffers for building QUIC DATAGRAM payloads on the
// UDP relay hot path (SOCKS5 UDP ASSOCIATE). Sized to cover the QUIC datagram
// ceiling (~1340 bytes with MTU 1400) plus SOCKS5 framing headroom. Callers
// that need more should allocate and skip the pool.
var datagramPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 2048)
		return &buf
	},
}

// getDatagramBuf returns a buffer of at least n bytes. Tries the pool first,
// falls back to a fresh allocation for oversized packets.
func getDatagramBuf(n int) ([]byte, func()) {
	if n <= 2048 {
		bufPtr := datagramPool.Get().(*[]byte)
		return (*bufPtr)[:n], func() { datagramPool.Put(bufPtr) }
	}
	return make([]byte, n), func() {}
}

// obfuscatorOverheadBytes is the number of bytes the obfuscator adds on top
// of the quic-go plaintext before writing to the underlying transport:
//
//	3  bytes framing   (1 type + 2 length)
//	12 bytes nonce     (crypto.NonceSize, ChaCha20-Poly1305)
//	16 bytes auth tag  (crypto.TagSize,   Poly1305)
//
// When we set quic.Config.InitialPacketSize we must leave this many bytes
// of headroom so the obfuscator output still fits in cfg.Performance.MTU.
const obfuscatorOverheadBytes = 3 + crypto.NonceSize + crypto.TagSize

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

	// Absorb transient send errors. quic-go treats any WriteTo error as fatal
	// and tears down the entire quic.Transport — same class of bug that was
	// fixed for ReadFrom in v1.5.2. A spurious EAGAIN/EINTR/ENOBUFS from a
	// raw sendto under pressure would otherwise collapse the whole pool.
	err = c.trans.Send(p, targetIP, targetPort)
	if err != nil {
		if c.closed.Load() {
			return 0, err
		}
		if isTransientSendErr(err) {
			slog.Debug("transport send error, absorbing", "component", "conn", "error", err)
			return len(p), nil
		}
		slog.Error("write error", "component", "conn", "error", err)
	}
	return len(p), err
}

// isTransientSendErr classifies send errors that should not tear down the
// quic.Transport. EAGAIN/EWOULDBLOCK mean the kernel send buffer is full,
// EINTR means a signal interrupted us, ENOBUFS means socket send queue is
// momentarily full. None of these are a fatal path condition — quic-go will
// retransmit the packet anyway on its own timer.
func isTransientSendErr(err error) bool {
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	return false
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

// initialPacketSize computes quic.Config.InitialPacketSize from the
// configured transport MTU, accounting for the obfuscator's per-packet
// overhead so that the obfuscator output never exceeds cfg.MTU.
//
// Raising InitialPacketSize above the quic-go default (1252) reduces
// "DATAGRAM frame too large" drops on the SOCKS5 UDP ASSOCIATE relay.
// With the default MTU of 1400, this yields 1369, which accommodates
// DATAGRAM payloads up to ~1340 bytes (quic-go adds ~29 bytes of its
// own header+tag+frame overhead on top of InitialPacketSize).
//
// Payloads larger than ~1450 bytes (typical full-size UDP) are
// fundamentally unshippable over QUIC datagrams on a 1500-byte eth MTU.
func initialPacketSize(mtu int) uint16 {
	const floor = 1200 // quic-go minimum
	size := mtu - obfuscatorOverheadBytes
	if size < floor {
		return floor
	}
	return uint16(size)
}

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
