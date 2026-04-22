package transport

import (
	"log/slog"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Verify rawFdConn satisfies syscall.RawConn at compile time.
var _ syscall.RawConn = (*rawFdConn)(nil)

// Transport is the interface for sending and receiving spoofed packets
type Transport interface {
	// Send sends a packet with spoofed source IP
	Send(payload []byte, dstIP net.IP, dstPort uint16) error

	// Receive receives a packet into buf, returns bytes written, source IP and port
	Receive(buf []byte) (n int, srcIP net.IP, srcPort uint16, err error)

	// Close closes the transport
	Close() error

	// LocalPort returns the local port being used
	LocalPort() uint16

	// SetReadBuffer sets the read buffer size
	SetReadBuffer(size int) error

	// SetWriteBuffer sets the write buffer size
	SetWriteBuffer(size int) error
}

// Config holds transport configuration
type Config struct {
	// SourceIP is the first entry from SourceIPs (backward compat).
	SourceIP net.IP
	// SourceIPv6 is the first entry from SourceIPv6s (backward compat).
	SourceIPv6 net.IP

	// SourceIPs is the full list of IPv4 source IPs for multi-spoof.
	// Each Send() picks one randomly.
	SourceIPs []net.IP
	// SourceIPv6s is the full list of IPv6 source IPs.
	SourceIPv6s []net.IP

	// ListenPort is the port to listen on for incoming packets
	ListenPort uint16

	// PeerSpoofIP is the first entry from PeerSpoofIPs (backward compat).
	PeerSpoofIP net.IP
	// PeerSpoofIPv6 is the first entry from PeerSpoofIPv6s (backward compat).
	PeerSpoofIPv6 net.IP
	// PeerSpoofIPs is the full list of expected peer IPv4 source IPs.
	PeerSpoofIPs []net.IP
	// PeerSpoofIPv6s is the full list of expected peer IPv6 source IPs.
	PeerSpoofIPv6s []net.IP

	// BufferSize is the size of pool buffers
	BufferSize int

	// ReadBuffer is the SO_RCVBUF size for the receive socket
	ReadBuffer int

	// WriteBuffer is the SO_SNDBUF size for the send socket
	WriteBuffer int

	// MTU is the maximum transmission unit
	MTU int

	// ProtocolNumber is the custom IP protocol number (1-255)
	// Used for raw transport type
	ProtocolNumber int

	// ICMPEchoID overrides the default ICMP echo ID.
	// Derived from shared secret so both peers use the same value.
	// 0 = use default.
	ICMPEchoID uint16

	// PacingRateMbps, when > 0, requests kernel-side packet pacing via
	// SO_MAX_PACING_RATE at this rate (Mbps). Requires `tc qdisc fq` on
	// the output interface to take effect; no-op otherwise.
	PacingRateMbps int
}

// rawFdConn implements syscall.RawConn for raw socket file descriptors.
//
// quic-go calls Control() to tune SO_RCVBUF / SO_SNDBUF on the underlying
// receive fd. Read/Write are intentional no-ops because:
//
//   - on a SOCK_RAW socket the kernel returns raw IP packets (with the IP
//     header prepended) rather than pure UDP payloads. quic-go's internal
//     batch read path (recvmmsg) assumes UDP semantics and cannot strip the
//     IP header, so forwarding Read() would corrupt the QUIC framing;
//   - SOCK_RAW also does not support CMSG/OOB data for ECN, UDP_GRO, or
//     IP_PKTINFO, so quic-go's OOB-based optimizations are a dead end.
//
// This means the raw / icmp / syn_udp transports fall back to quic-go's
// slow path: one ReadFrom() per packet instead of batched recvmmsg. In
// benchmarks this caps multi-stream throughput at ~1.2 Gbps vs ~2.2 Gbps
// on the UDP transport (which exposes a real *net.UDPConn via SyscallConn
// and gets the full batch/GRO path). Fixing this would require either
// reimplementing quic-go's batch reader on top of raw sockets with
// IP-header stripping, or restructuring these transports to use a
// SOCK_DGRAM receive socket alongside the SOCK_RAW send socket.
type rawFdConn struct{ fd int }

func (c *rawFdConn) Control(f func(uintptr)) error { f(uintptr(c.fd)); return nil }
func (c *rawFdConn) Read(func(uintptr) bool) error { return nil }
func (c *rawFdConn) Write(func(uintptr) bool) error { return nil }

// Validate validates the transport config
func (c *Config) Validate() error {
	if len(c.SourceIPs) == 0 && len(c.SourceIPv6s) == 0 && c.SourceIP == nil && c.SourceIPv6 == nil {
		return ErrNoSourceIP
	}
	if c.BufferSize == 0 {
		c.BufferSize = 65535
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	return nil
}

func (c *Config) icmpEchoID() uint16 {
	if c.ICMPEchoID == 0 {
		panic("ICMPEchoID must be set before creating ICMP transport")
	}
	return c.ICMPEchoID
}

// IsIPv6 returns true if using IPv6
func (c *Config) IsIPv6() bool {
	return c.SourceIP == nil || c.SourceIP.To4() == nil
}

// BufferDirRecv / BufferDirSend distinguish SO_RCVBUF from SO_SNDBUF in
// SetSocketBufferSmart. We don't use raw ints because a typo at a call
// site would silently pick the wrong socket option.
type BufferDirection int

const (
	BufferDirRecv BufferDirection = iota
	BufferDirSend
)

// bufferFallbackMin is the smallest value we'll ever ask the kernel for
// during the progressive halve-and-retry. Below this the kernel's own
// default (~208 KB) is a better fallback than a tiny explicit request.
// This is NOT a floor on the caller's request — explicit config values
// below this are honored verbatim to preserve backwards-compatibility
// with existing deployments that intentionally cap buffer memory.
const bufferFallbackMin = 256 * 1024

// SetSocketBufferSmart attempts to set the requested SO_RCVBUF / SO_SNDBUF
// size on fd with automatic privilege escalation and graceful fallback.
//
// Linux kernel caps the portable SO_RCVBUF/SO_SNDBUF at net.core.rmem_max /
// wmem_max (typically 208 KB on stock distros — brutally undersized for
// anything above a LAN). The FORCE variants bypass this cap for processes
// with CAP_NET_ADMIN, which quiccochet already has because raw sockets
// require root / CAP_NET_RAW. This means the common case (root-run tunnel)
// gets the full requested buffer with no sysctl tuning required.
//
// Algorithm: try FORCE → try portable → halve and retry → return whatever
// the kernel actually applied (reported via getsockopt; Linux doubles the
// stored value for bookkeeping so we halve it back for honest reporting).
// Never returns an error: the caller has no meaningful recovery and a
// smaller buffer is still better than none. The caller's requested size
// is honored verbatim — no floor is applied on entry, because explicit
// values from user config (including legacy defaults like 1 MB) must
// round-trip without silent mutation.
func SetSocketBufferSmart(fd int, want int, dir BufferDirection) int {
	if want <= 0 {
		return readSockBufSize(fd, dir.getOpt())
	}

	forceOpt := unix.SO_RCVBUFFORCE
	portableOpt := unix.SO_RCVBUF
	getOpt := unix.SO_RCVBUF
	dirName := "recv"
	if dir == BufferDirSend {
		forceOpt = unix.SO_SNDBUFFORCE
		portableOpt = unix.SO_SNDBUF
		getOpt = unix.SO_SNDBUF
		dirName = "send"
	}

	// Halve-and-retry from the caller's requested size down to
	// bufferFallbackMin. If the caller asked for less than that floor
	// to begin with, we'll still try once at their explicit size.
	for size := want; size >= bufferFallbackMin || size == want; {
		// Force path first: bypasses rmem_max/wmem_max when we have
		// CAP_NET_ADMIN.
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, forceOpt, size); err == nil {
			if got := readSockBufSize(fd, getOpt); got >= size {
				slog.Info("socket buffer applied",
					"component", "transport",
					"direction", dirName,
					"requested", size,
					"got", got,
					"path", "force")
				return got
			}
		}
		// Portable path: subject to rmem_max/wmem_max cap. Kernel will
		// silently clamp rather than error if the request exceeds the
		// cap, so we verify with getsockopt and halve on mismatch.
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, portableOpt, size); err == nil {
			if got := readSockBufSize(fd, getOpt); got >= size {
				slog.Info("socket buffer applied",
					"component", "transport",
					"direction", dirName,
					"requested", size,
					"got", got,
					"path", "portable")
				return got
			}
		}
		// First pass honored user's explicit request even if below
		// fallback min; subsequent halving stops at fallback min.
		if size < bufferFallbackMin {
			break
		}
		size /= 2
	}
	// Last-ditch: whatever the kernel currently has wins. This only
	// happens in extremely scapped containers; log so the operator
	// knows to raise net.core.{r,w}mem_max.
	got := readSockBufSize(fd, getOpt)
	slog.Warn("socket buffer request could not be honored; consider raising net.core.rmem_max/wmem_max",
		"component", "transport",
		"direction", dirName,
		"requested", want,
		"got", got)
	return got
}

// getOpt maps a BufferDirection to the corresponding SO_* option used
// for getsockopt.
func (d BufferDirection) getOpt() int {
	if d == BufferDirSend {
		return unix.SO_SNDBUF
	}
	return unix.SO_RCVBUF
}

// SetMaxPacingRate sets SO_MAX_PACING_RATE on fd at the given rate
// (bytes per second). The kernel will pace outgoing packets on this
// socket so their transmission rate does not exceed `bps`, spreading
// bursts evenly across time — the same behaviour TCP gets natively via
// GSO/TSO + TCP pacing. This is the single most effective thing we can
// do against the common real-world failure: user-space QUIC bursting
// at Go-scheduler speed, overflowing ISP router queues (1k-10k pkt),
// inducing drops that collapse quic-go's cwnd to near zero.
//
// **Requires `tc qdisc fq` on the output interface** (EDT — earliest
// departure time — scheduling). On fq_codel, pfifo, or bare netem the
// kernel accepts the sockopt but doesn't pace, so nothing happens but
// nothing breaks either. Check with `tc qdisc show dev <iface>` and
// install with `tc qdisc replace dev <iface> root fq`.
//
// rate <= 0 disables pacing (kernel sends as fast as it can). Never
// returns an error: a failed sockopt (unsupported kernel, insufficient
// privileges) is logged but not fatal.
func SetMaxPacingRate(fd int, bytesPerSec uint64) {
	if bytesPerSec == 0 {
		return
	}
	if err := unix.SetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_MAX_PACING_RATE, bytesPerSec); err != nil {
		slog.Warn("SO_MAX_PACING_RATE failed",
			"component", "transport",
			"bytes_per_sec", bytesPerSec,
			"error", err)
		return
	}
	slog.Info("pacing rate applied",
		"component", "transport",
		"bytes_per_sec", bytesPerSec,
		"mbps", bytesPerSec*8/1_000_000,
		"note", "requires fq qdisc on egress iface to take effect")
}

// readSockBufSize returns the effective buffer size as reported by the
// kernel. Linux stores SO_RCVBUF/SO_SNDBUF doubled (to reserve room for
// bookkeeping overhead), so we halve for the caller's perspective.
func readSockBufSize(fd int, opt int) int {
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, opt)
	if err != nil {
		return 0
	}
	return v / 2
}
