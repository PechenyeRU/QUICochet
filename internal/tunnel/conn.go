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

	"github.com/quic-go/quic-go"

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

		// Atomically update the real peer address (port may change on client restart)
		if peer := c.realPeer.Load(); peer != nil && peer.Port != int(srcPort) {
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

// Initial receive windows applied to every QUIC connection on both
// client and server. Setting these well above quic-go's defaults
// (512 KB stream / 512 KB conn) lets new streams skip 3-5 RTTs of
// slow-ramp on high-BDP links — the single biggest user-visible win
// for short-lived flows (HTTP, TLS handshakes) on WAN paths.
// Hardcoded (no config field) because these are safe on any modern
// host and a knob here would just invite misconfiguration. quic-go
// then auto-tunes up to Max*ReceiveWindow on demand.
const (
	initialStreamReceiveWindow     = 2 * 1024 * 1024 // 2 MB
	initialConnectionReceiveWindow = 4 * 1024 * 1024 // 4 MB
)

// logQUICConfig emits a one-shot INFO describing the effective QUIC
// flow-control + congestion settings at boot. Prints the raw numbers so
// diagnosing "is my config actually applied?" is a grep, not a guess.
func logQUICConfig(cfg *quic.Config, component string, packetThreshold int) {
	slog.Info("quic effective config",
		"component", component,
		"initial_stream_window_mb", cfg.InitialStreamReceiveWindow/(1024*1024),
		"max_stream_window_mb", cfg.MaxStreamReceiveWindow/(1024*1024),
		"initial_conn_window_mb", cfg.InitialConnectionReceiveWindow/(1024*1024),
		"max_conn_window_mb", cfg.MaxConnectionReceiveWindow/(1024*1024),
		"initial_packet_size", cfg.InitialPacketSize,
		"pmtud_enabled", !cfg.DisablePathMTUDiscovery,
		"datagrams", cfg.EnableDatagrams,
		"allow_0rtt", cfg.Allow0RTT,
		"packet_threshold", packetThreshold,
	)
}

// applyCongestionControl attaches a congestion-control factory to cfg
// based on the configured mode, and logs the outcome.
//
//   - "cubic" or "" (legacy default) → leave cfg.Congestion nil; quic-go
//     uses its built-in NewReno/CUBIC.
//   - "bbrv1" → opt-in to BBRv1 from the qiulaidongfeng/quic-go fork. If
//     the factory panics or returns nil (fork changes, integration bug),
//     we propagate the failure because the operator asked for BBRv1
//     explicitly.
//   - "auto" → try BBRv1 with a recover() and nil-check, silently fall
//     back to CUBIC if anything goes wrong. This is the failsafe mode
//     we expose as a default candidate after e2e validation.
//
// cfg must already have InitialPacketSize set (NewBBRv1 reads it on
// every connection open).
func applyCongestionControl(cfg *quic.Config, mode string, component string) {
	switch mode {
	case "bbrv1":
		cfg.Congestion = func() quic.SendAlgorithmWithDebugInfos {
			return quic.NewBBRv1(cfg)
		}
		slog.Info("quic congestion control", "component", component, "algo", "bbrv1")
	case "auto":
		cfg.Congestion = func() (algo quic.SendAlgorithmWithDebugInfos) {
			defer func() {
				if r := recover(); r != nil {
					slog.Warn("BBRv1 factory panicked; falling back to CUBIC",
						"component", component, "panic", r)
					algo = nil // quic-go falls back to its default (CUBIC)
				}
			}()
			bbr := quic.NewBBRv1(cfg)
			if bbr == nil {
				slog.Warn("BBRv1 factory returned nil; falling back to CUBIC",
					"component", component)
				return nil
			}
			return bbr
		}
		slog.Info("quic congestion control", "component", component, "algo", "auto (bbrv1 with cubic fallback)")
	default:
		// "cubic" or "" — let quic-go use its built-in default.
		slog.Info("quic congestion control", "component", component, "algo", "cubic")
	}
}

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

// SetReadBuffer / SetWriteBuffer are duck-typed by quic-go: if the
// conn passed to quic.Listen / quic.Transport exposes these methods,
// quic-go calls them to set SO_RCVBUF / SO_SNDBUF. Without them,
// quic-go logs "Not a *net.UDPConn … see UDP-Buffer-Sizes wiki" and
// falls back to the kernel default (~208 KB on Linux), which becomes
// a throughput ceiling above ~500 Mbps.
func (c *transportPacketConn) SetReadBuffer(size int) error {
	return c.trans.SetReadBuffer(size)
}

func (c *transportPacketConn) SetWriteBuffer(size int) error {
	return c.trans.SetWriteBuffer(size)
}
