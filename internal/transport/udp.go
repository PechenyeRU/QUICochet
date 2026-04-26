package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendBufPool eliminates the per-transport mutex on send: each goroutine gets
// its own buffer from the pool, so multiple QUIC connections send concurrently.
var sendBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 20+8+65535) // IP header + UDP/ICMP header + max payload
		return &buf
	},
}

// oobPool4 holds pre-sized cmsg buffers for IPv4 IP_PKTINFO sendmsg.
var oobPool4 = sync.Pool{
	New: func() any {
		b := make([]byte, unix.CmsgSpace(pktinfo4Size))
		return &b
	},
}

// oobPool6 holds pre-sized cmsg buffers for IPv6 IPV6_PKTINFO sendmsg.
// Used both for native v6 destinations and (in dual-stack mode) for
// v4 destinations carried over an AF_INET6 socket via the v4-mapped
// form.
var oobPool6 = sync.Pool{
	New: func() any {
		b := make([]byte, unix.CmsgSpace(pktinfo6Size))
		return &b
	},
}

const (
	pktinfo4Size = 12 // sizeof(struct in_pktinfo)
	pktinfo6Size = 20 // sizeof(struct in6_pktinfo): 16 ipi6_addr + 4 ipi6_ifindex
)

// UDPTransport implements Transport using raw UDP sockets with IP spoofing
type UDPTransport struct {
	cfg *Config

	// Raw socket for sending spoofed packets (requires root/CAP_NET_RAW).
	// Only used when sendmsg mode is unavailable (fallback path).
	rawFd  int
	rawFd6 int

	// dualStack means the transport accepts and sends both v4 and v6
	// on the same recv socket (bound on [::]:port with IPV6_V6ONLY=0).
	dualStack bool

	// sendmsg mode: use the recvConn's underlying fd with the
	// transparent / freebind sockopts and sendmsg(2) +
	// IP_PKTINFO / IPV6_PKTINFO cmsgs for per-packet source IP
	// selection. Eliminates manual IP/UDP header construction and
	// checksum computation; the kernel handles everything + TX
	// checksum offload to NIC.
	//
	// sendIs6 picks the cmsg layout based on the recv socket family:
	//   - false → AF_INET socket, IP_PKTINFO + sockaddr_in4 (legacy
	//     single-stack v4 path).
	//   - true  → AF_INET6 socket, IPV6_PKTINFO + sockaddr_in6
	//     (single-stack v6 OR dual-stack with IPV6_V6ONLY=0; v4
	//     destinations are carried via the ::ffff: mapped form).
	useSendmsg bool
	sendIs6    bool
	sendFd     int // fd from recvConn, used for sendmsg (NOT owned — recvConn closes it)

	// Cached values to avoid per-packet conversions
	srcIPv4s  [][4]byte  // all IPv4 source IPs for multi-spoof
	srcIPv6s  [][16]byte // all IPv6 source IPs for multi-spoof
	localPort uint16     // cached local port (set after listen)

	// peerSpoofSet4 / peerSpoofSet6 are the receive-side IP filters built
	// from cfg.PeerSpoofIPs / cfg.PeerSpoofIPv6s. When non-empty Receive
	// drops packets whose source IP is not in the set — defense against
	// arbitrary off-path UDP injections that would otherwise reach the
	// AEAD layer (waste CPU on decrypt) or bypass it entirely in
	// obfuscation=none mode. Empty set = filter disabled (legacy
	// behaviour, accept any source).
	peerSpoofSet4 map[[4]byte]struct{}
	peerSpoofSet6 map[[16]byte]struct{}

	// Regular UDP socket for receiving (and for sendmsg-mode sending)
	recvConn *net.UDPConn

	// State
	closed atomic.Bool
}

// NewUDPTransport creates a new UDP transport with IP spoofing capability
func NewUDPTransport(cfg *Config) (*UDPTransport, error) {
	t := &UDPTransport{
		cfg:    cfg,
		rawFd:  -1,
		rawFd6: -1,
	}

	// Build plural IPv4 source IP list from cfg.SourceIPs, falling back to singular cfg.SourceIP
	if len(cfg.SourceIPs) > 0 {
		t.srcIPv4s = make([][4]byte, 0, len(cfg.SourceIPs))
		for _, ip := range cfg.SourceIPs {
			if v4 := ip.To4(); v4 != nil {
				var a [4]byte
				copy(a[:], v4)
				t.srcIPv4s = append(t.srcIPv4s, a)
			}
		}
	} else if cfg.SourceIP != nil {
		if v4 := cfg.SourceIP.To4(); v4 != nil {
			var a [4]byte
			copy(a[:], v4)
			t.srcIPv4s = [][4]byte{a}
		}
	}

	// Build plural IPv6 source IP list from cfg.SourceIPv6s, falling back to singular cfg.SourceIPv6
	if len(cfg.SourceIPv6s) > 0 {
		t.srcIPv6s = make([][16]byte, 0, len(cfg.SourceIPv6s))
		for _, ip := range cfg.SourceIPv6s {
			if v6 := ip.To16(); v6 != nil {
				var a [16]byte
				copy(a[:], v6)
				t.srcIPv6s = append(t.srcIPv6s, a)
			}
		}
	} else if cfg.SourceIPv6 != nil {
		if v6 := cfg.SourceIPv6.To16(); v6 != nil {
			var a [16]byte
			copy(a[:], v6)
			t.srcIPv6s = [][16]byte{a}
		}
	}

	// Build peer spoof IP sets for receive-side filtering
	if len(cfg.PeerSpoofIPs) > 0 {
		t.peerSpoofSet4 = make(map[[4]byte]struct{}, len(cfg.PeerSpoofIPs))
		for _, ip := range cfg.PeerSpoofIPs {
			if v4 := ip.To4(); v4 != nil {
				var key [4]byte
				copy(key[:], v4)
				t.peerSpoofSet4[key] = struct{}{}
			}
		}
	} else if cfg.PeerSpoofIP != nil {
		if v4 := cfg.PeerSpoofIP.To4(); v4 != nil {
			var key [4]byte
			copy(key[:], v4)
			t.peerSpoofSet4 = map[[4]byte]struct{}{key: {}}
		}
	}
	if len(cfg.PeerSpoofIPv6s) > 0 {
		t.peerSpoofSet6 = make(map[[16]byte]struct{}, len(cfg.PeerSpoofIPv6s))
		for _, ip := range cfg.PeerSpoofIPv6s {
			if v6 := ip.To16(); v6 != nil {
				var key [16]byte
				copy(key[:], v6)
				t.peerSpoofSet6[key] = struct{}{}
			}
		}
	} else if cfg.PeerSpoofIPv6 != nil {
		if v6 := cfg.PeerSpoofIPv6.To16(); v6 != nil {
			var key [16]byte
			copy(key[:], v6)
			t.peerSpoofSet6 = map[[16]byte]struct{}{key: {}}
		}
	}

	// Determine bind mode:
	//   - dualStack when both families have configured sources;
	//   - v6-only when only v6 sources are configured;
	//   - v4-only otherwise (matches legacy single-stack behaviour).
	hasV4 := len(t.srcIPv4s) > 0
	hasV6 := len(t.srcIPv6s) > 0
	t.dualStack = hasV4 && hasV6
	v6Only := !hasV4 && hasV6

	// Reject the asymmetric peer-spoof setup in dual-stack mode: if the
	// operator filtered v4 sources but left v6 wide open (or vice versa)
	// they unintentionally exposed an open relay on the unfiltered
	// family. Refuse to start with a clear message instead of silently
	// honouring the half-baked filter.
	if t.dualStack {
		v4Filtered := len(t.peerSpoofSet4) > 0
		v6Filtered := len(t.peerSpoofSet6) > 0
		if v4Filtered != v6Filtered {
			return nil, fmt.Errorf(
				"dual-stack mode requires symmetric peer-spoof config: " +
					"either configure peer_spoof_ip(s) AND peer_spoof_ipv6(s), or neither, " +
					"otherwise one family is left unfiltered",
			)
		}
	}

	// Create raw socket for IPv4 with IP_HDRINCL
	if len(t.srcIPv4s) > 0 {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("create raw socket: %w (need root or CAP_NET_RAW)", err)
		}

		// Enable IP_HDRINCL to include our own IP header
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
		}

		t.rawFd = fd
	}

	// Create raw socket for IPv6
	if len(t.srcIPv6s) > 0 {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			// IPv6 raw might not be available, that's ok
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}
	}

	// Create UDP listener for receiving.
	//   - dualStack / v6-only → bind on [::]:port (AF_INET6).
	//   - v4-only            → bind on 0.0.0.0:port (AF_INET, legacy).
	// For dual-stack we explicitly clear IPV6_V6ONLY so the same
	// socket accepts both v4 (via the ::ffff: mapped form) and native
	// v6 traffic. v6-only forces IPV6_V6ONLY=1 (defence in depth so
	// a misconfigured firewall cannot leak v4 onto a v6-only listen).
	// Both knobs must be set BEFORE bind on Linux — done via
	// ListenConfig.Control rather than after-the-fact setsockopt.
	var listenAddr string
	if t.dualStack || v6Only {
		listenAddr = fmt.Sprintf("[::]:%d", cfg.ListenPort)
	} else {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", cfg.ListenPort)
	}

	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if !(t.dualStack || v6Only) {
				return nil
			}
			v6OnlyVal := 1
			if t.dualStack {
				v6OnlyVal = 0
			}
			var ctlErr error
			if cErr := c.Control(func(fd uintptr) {
				ctlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v6OnlyVal)
			}); cErr != nil {
				return cErr
			}
			if ctlErr != nil {
				// Kernels that hard-pin IPV6_V6ONLY (e.g. via
				// net.ipv6.bindv6only sysctl with cap_lock) will
				// fail this. Warn but let the bind proceed — the
				// kernel default is still usable in most cases.
				slog.Warn("udp transport: setsockopt IPV6_V6ONLY failed pre-bind",
					"component", "transport", "value", v6OnlyVal, "error", ctlErr)
			}
			return nil
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp", listenAddr)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	recvConn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		t.Close()
		return nil, fmt.Errorf("listen udp: unexpected conn type %T", pc)
	}
	t.recvConn = recvConn
	t.localPort = uint16(recvConn.LocalAddr().(*net.UDPAddr).Port)

	// Apply socket buffers via the smart helper (BUFFORCE + progressive
	// fallback) so we get the full requested size on root-run tunnels
	// without requiring a sysctl tune of net.core.{r,w}mem_max.
	// Also apply SO_MAX_PACING_RATE if configured — the kernel will
	// then spread bursts evenly if the output iface uses the fq qdisc.
	if rawConn, rawErr := recvConn.SyscallConn(); rawErr == nil {
		rawConn.Control(func(fd uintptr) {
			if cfg.ReadBuffer > 0 {
				SetSocketBufferSmart(int(fd), cfg.ReadBuffer, BufferDirRecv)
			}
			if cfg.WriteBuffer > 0 {
				SetSocketBufferSmart(int(fd), cfg.WriteBuffer, BufferDirSend)
			}
			if cfg.PacingRateMbps > 0 {
				SetMaxPacingRate(int(fd), uint64(cfg.PacingRateMbps)*1_000_000/8)
			}
		})
	}

	// Probe sendmsg fast path. Eliminates manual IP/UDP header
	// construction + checksum computation + the separate raw socket;
	// the kernel handles everything and offloads TX checksum to the
	// NIC if supported. Requires CAP_NET_RAW or CAP_NET_ADMIN, both
	// already required for the raw-socket fallback.
	//
	// The probe enables the matching transparent / freebind sockopts
	// based on the recv socket family:
	//   - AF_INET   → IP_TRANSPARENT + IP_FREEBIND (single-stack v4).
	//   - AF_INET6  → IPV6_TRANSPARENT + IPV6_FREEBIND (single-stack
	//     v6 OR dual-stack); the v4-mapped form lets the same socket
	//     send v4 packets in dual-stack mode, so one sendmsg path
	//     handles both families.
	t.sendIs6 = t.dualStack || v6Only
	if rawConn, rawErr := recvConn.SyscallConn(); rawErr == nil {
		var sendFd int
		var probeErr error
		rawConn.Control(func(fd uintptr) {
			sendFd = int(fd)
			if t.sendIs6 {
				probeErr = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
				if probeErr == nil {
					_ = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
				}
			} else {
				probeErr = syscall.SetsockoptInt(sendFd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				if probeErr == nil {
					_ = syscall.SetsockoptInt(sendFd, syscall.SOL_IP, syscall.IP_FREEBIND, 1)
				}
			}
		})
		if probeErr == nil {
			t.useSendmsg = true
			t.sendFd = sendFd
			// Close the raw sockets — sendmsg covers both families
			// on the v6 socket and the v4 family on the v4 socket.
			if t.rawFd >= 0 {
				syscall.Close(t.rawFd)
				t.rawFd = -1
			}
			if t.rawFd6 >= 0 {
				syscall.Close(t.rawFd6)
				t.rawFd6 = -1
			}
			slog.Info("udp transport: sendmsg mode enabled",
				"component", "transport", "v6_socket", t.sendIs6, "dual_stack", t.dualStack)
		} else {
			slog.Debug("udp transport: sendmsg probe failed, using raw sockets",
				"component", "transport", "v6_socket", t.sendIs6, "error", probeErr)
		}
	}

	return t, nil
}

// Send sends a packet with spoofed source IP. Dispatches to the
// matching cmsg layout based on (a) whether sendmsg is available, and
// (b) whether the recv socket is AF_INET (legacy v4 single-stack) or
// AF_INET6 (single-stack v6 or dual-stack — both v4-via-mapped and
// native v6 are sent through one IPV6_PKTINFO path).
func (t *UDPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	isIPv6 := dstIP.To4() == nil

	if t.useSendmsg {
		if t.sendIs6 {
			// AF_INET6 socket: native v6 or v4-mapped, both via
			// IPV6_PKTINFO. The kernel routes v4-mapped via the
			// v4 stack and emits a v4 packet on the wire.
			return t.sendInet6Sendmsg(payload, dstIP, dstPort, isIPv6)
		}
		// Legacy AF_INET single-stack v4 path.
		if isIPv6 {
			return errors.New("v6 destination on a v4-only sendmsg socket")
		}
		return t.sendIPv4Sendmsg(payload, dstIP, dstPort)
	}

	if isIPv6 {
		return t.sendIPv6(payload, dstIP, dstPort)
	}
	return t.sendIPv4(payload, dstIP, dstPort)
}

// sendIPv4Sendmsg sends a UDP packet using sendmsg with IP_PKTINFO cmsg
// for source IP selection. The kernel builds the IP + UDP headers and
// computes all checksums (with TX offload to NIC if supported).
func (t *UDPTransport) sendIPv4Sendmsg(payload []byte, dstIP net.IP, dstPort uint16) error {
	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return errors.New("invalid IPv4 destination")
	}
	if len(t.srcIPv4s) == 0 {
		return errors.New("no IPv4 source IPs configured")
	}

	src := pickSourceIPv4(t.srcIPv4s, payload)

	dest := &unix.SockaddrInet4{Port: int(dstPort)}
	copy(dest.Addr[:], dstIP4)

	oobPtr := oobPool4.Get().(*[]byte)
	oob := *oobPtr
	buildPktinfo4(oob, src)

	err := unix.Sendmsg(t.sendFd, payload, oob, dest, 0)
	oobPool4.Put(oobPtr)

	if err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}
	return nil
}

// sendInet6Sendmsg sends a UDP packet on the AF_INET6 sendmsg socket
// using IPV6_PKTINFO for source-IP selection. Handles both native v6
// (isV6=true) and dual-stack v4 (isV6=false → v4-mapped src + dest).
//
// The kernel detects the v4-mapped form on a V6ONLY=0 socket and
// emits a real v4 packet on the wire, which is why this single path
// covers v4 destinations in dual-stack mode without going through the
// v4 raw socket.
func (t *UDPTransport) sendInet6Sendmsg(payload []byte, dstIP net.IP, dstPort uint16, isV6 bool) error {
	dest := &unix.SockaddrInet6{Port: int(dstPort)}
	var src *[16]byte

	if isV6 {
		dst16 := dstIP.To16()
		if dst16 == nil {
			return errors.New("invalid IPv6 destination")
		}
		copy(dest.Addr[:], dst16)
		if len(t.srcIPv6s) == 0 {
			return errors.New("no IPv6 source IPs configured")
		}
		src = pickSourceIPv6(t.srcIPv6s, payload)
	} else {
		dst4 := dstIP.To4()
		if dst4 == nil {
			return errors.New("invalid IPv4 destination")
		}
		// v4-mapped destination (::ffff:1.2.3.4) so the AF_INET6
		// socket emits a real v4 packet via the kernel's v4 stack.
		dest.Addr[10] = 0xff
		dest.Addr[11] = 0xff
		copy(dest.Addr[12:], dst4)
		if len(t.srcIPv4s) == 0 {
			return errors.New("no IPv4 source IPs configured")
		}
		v4src := pickSourceIPv4(t.srcIPv4s, payload)
		var mapped [16]byte
		mapped[10] = 0xff
		mapped[11] = 0xff
		copy(mapped[12:], v4src[:])
		src = &mapped
	}

	oobPtr := oobPool6.Get().(*[]byte)
	oob := *oobPtr
	buildPktinfo6(oob, src)

	err := unix.Sendmsg(t.sendFd, payload, oob, dest, 0)
	oobPool6.Put(oobPtr)

	if err != nil {
		return fmt.Errorf("sendmsg v6: %w", err)
	}
	return nil
}


// buildPktinfo4 writes an IP_PKTINFO cmsg into buf. buf must be at
// least unix.CmsgSpace(12) bytes. Sets ipi_spec_dst to src (the
// spoofed source IP), ipi_ifindex to 0 (kernel picks interface).
func buildPktinfo4(buf []byte, src *[4]byte) {
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = unix.SOL_IP
	h.Type = unix.IP_PKTINFO
	h.SetLen(unix.CmsgLen(pktinfo4Size))

	data := buf[cmsgAlignOf(unix.SizeofCmsghdr):]
	// struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; }
	_ = data[11] // bounds check hint
	data[0] = 0  // ipi_ifindex = 0 (4 bytes, all zero)
	data[1] = 0
	data[2] = 0
	data[3] = 0
	copy(data[4:8], src[:]) // ipi_spec_dst = spoofed source IP (network order)
	data[8] = 0             // ipi_addr = 0 (4 bytes, unused for send)
	data[9] = 0
	data[10] = 0
	data[11] = 0
}

// buildPktinfo6 writes an IPV6_PKTINFO cmsg into buf. buf must be at
// least unix.CmsgSpace(20) bytes. Sets ipi6_addr to src (the spoofed
// source IPv6, or v4-mapped form for dual-stack v4 sends), ipi6_ifindex
// to 0 (kernel picks the interface).
func buildPktinfo6(buf []byte, src *[16]byte) {
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = unix.IPPROTO_IPV6
	h.Type = unix.IPV6_PKTINFO
	h.SetLen(unix.CmsgLen(pktinfo6Size))

	data := buf[cmsgAlignOf(unix.SizeofCmsghdr):]
	// struct in6_pktinfo { struct in6_addr ipi6_addr; uint32_t ipi6_ifindex; }
	_ = data[19] // bounds check hint
	copy(data[:16], src[:])
	// ipi6_ifindex = 0 (4 bytes)
	data[16] = 0
	data[17] = 0
	data[18] = 0
	data[19] = 0
}

// cmsgAlignOf rounds n up to the cmsg alignment boundary (same as
// CMSG_ALIGN in the kernel). On 64-bit Linux this is 8 bytes.
func cmsgAlignOf(n int) int {
	const align = unix.SizeofPtr
	return (n + align - 1) &^ (align - 1)
}

// pickSourceIPv4 selects a spoof source IP for an outgoing QUIC packet.
//
// With a single configured IP the choice is trivial. With multi-spoof we hash
// the bytes after the QUIC header flags byte — for short-header packets these
// are the destination connection ID, so every packet belonging to the same
// QUIC connection maps to the same source IP. Spreading by connection instead
// of by packet keeps the kernel output path (conntrack, route cache, fq pacing)
// on a stable 5-tuple per flow, which is where the per-packet rotation burns
// throughput. Long-header (handshake) packets hash against version + part of
// the DCID, good enough given handshakes are short-lived and few.
func pickSourceIPv4(srcs [][4]byte, payload []byte) *[4]byte {
	if len(srcs) == 1 {
		return &srcs[0]
	}
	if len(payload) < 9 {
		return &srcs[mrand.IntN(len(srcs))]
	}
	return &srcs[fnv1aIndex(payload, uint64(len(srcs)))]
}

// pickSourceIPv6 mirrors pickSourceIPv4 for IPv6 sources. Same DCID-based
// hashing so a given QUIC connection sticks to a single spoofed source IP
// — without this, IPv6 multi-spoof reproduces the conntrack / route-cache
// / fq-pacing pathology that motivated the IPv4 fix.
func pickSourceIPv6(srcs [][16]byte, payload []byte) *[16]byte {
	if len(srcs) == 1 {
		return &srcs[0]
	}
	if len(payload) < 9 {
		return &srcs[mrand.IntN(len(srcs))]
	}
	return &srcs[fnv1aIndex(payload, uint64(len(srcs)))]
}

// fnv1aIndex is the shared FNV-1a-based per-flow hash used by both
// pickSourceIPv4 and pickSourceIPv6. Hashes payload[1..9] (the DCID
// region of a QUIC short-header packet) and reduces modulo n. 8 bytes
// is enough entropy to spread N <= 32 connections across 1..32 source
// IPs without collisions-by-design; worst case two conns share a src
// IP, which only returns them to the single-IP best case.
func fnv1aIndex(payload []byte, n uint64) uint64 {
	const (
		offset64 = 0xcbf29ce484222325
		prime64  = 0x100000001b3
	)
	h := uint64(offset64)
	for i := 1; i < 9; i++ {
		h ^= uint64(payload[i])
		h *= prime64
	}
	return h % n
}

func (t *UDPTransport) sendIPv4(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd < 0 {
		return errors.New("raw socket not available")
	}
	if len(t.srcIPv4s) == 0 {
		return errors.New("no IPv4 source IPs configured")
	}

	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return errors.New("invalid IPv4 destination")
	}

	// Select a source IP. With multi-spoof (len > 1), hash the QUIC destination
	// connection ID bytes in the payload so every packet of a given QUIC
	// connection goes out with the same spoofed source IP. See pickSourceIPv4.
	src := pickSourceIPv4(t.srcIPv4s, payload)

	const ipHL = 20
	const udpHL = 8
	totalLen := ipHL + udpHL + len(payload)

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	// ── IPv4 header (20 bytes) ──
	buf[0] = 0x45                                          // Version=4, IHL=5
	buf[1] = 0x00                                          // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen)) // Total length
	binary.BigEndian.PutUint16(buf[4:6], 0)                // Identification
	binary.BigEndian.PutUint16(buf[6:8], 0)                // Flags + Fragment offset
	buf[8] = 64                                            // TTL
	buf[9] = 17                                            // Protocol = UDP
	binary.BigEndian.PutUint16(buf[10:12], 0)              // Checksum (zero for calc)
	copy(buf[12:16], src[:])                               // Source IP (SPOOFED, randomly selected)
	copy(buf[16:20], dstIP4)                               // Dest IP

	// IP header checksum
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHL]))

	// ── UDP header (8 bytes) ──
	udp := buf[ipHL:]
	binary.BigEndian.PutUint16(udp[0:2], t.localPort)                // Source port
	binary.BigEndian.PutUint16(udp[2:4], dstPort)                    // Dest port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHL+len(payload))) // UDP length
	binary.BigEndian.PutUint16(udp[6:8], 0)                          // Checksum (zero for calc)

	// ── Payload ──
	copy(udp[udpHL:], payload)

	// UDP checksum (with pseudo-header)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src[:], dstIP4, udp[:udpHL+len(payload)]))

	// Build destination sockaddr
	var destAddr syscall.SockaddrInet4
	copy(destAddr.Addr[:], dstIP4)

	err := syscall.Sendto(t.rawFd, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

func (t *UDPTransport) sendIPv6(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd6 < 0 {
		return errors.New("IPv6 raw socket not available")
	}
	if len(t.srcIPv6s) == 0 {
		return errors.New("no IPv6 source IPs configured")
	}

	dstIP16 := dstIP.To16()
	if dstIP16 == nil {
		return errors.New("invalid IPv6 destination")
	}

	// Sticky-by-flow source IP selection (see pickSourceIPv6 godoc):
	// every packet of a given QUIC connection maps to the same
	// spoofed source so the kernel's conntrack/route-cache/fq-pacing
	// stays on a stable 5-tuple per flow.
	src := pickSourceIPv6(t.srcIPv6s, payload)

	// IPv6 with raw sockets: kernel builds the IPv6 header, we only send
	// UDP header + payload. The kernel uses the socket's bound source address.
	const udpHL = 8
	udpLen := udpHL + len(payload)

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:udpLen]

	// ── UDP header ──
	binary.BigEndian.PutUint16(buf[0:2], t.localPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(buf[6:8], 0) // checksum placeholder

	// ── Payload ──
	copy(buf[udpHL:], payload)

	// UDP checksum with IPv6 pseudo-header
	binary.BigEndian.PutUint16(buf[6:8], udp6Checksum(src[:], dstIP16, buf[:udpLen]))

	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], dstIP16)

	err := syscall.Sendto(t.rawFd6, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto ipv6: %w", err)
	}
	return nil
}

// Receive reads a packet directly into buf, avoiding intermediate allocations.
// Drops packets whose source IP is not in peerSpoofSet (when configured) so
// off-path injections never reach the AEAD layer.
func (t *UDPTransport) Receive(buf []byte) (int, net.IP, uint16, error) {
	for {
		if t.closed.Load() {
			return 0, nil, 0, ErrConnectionClosed
		}

		n, addr, err := t.recvConn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, 0, err
		}

		if t.acceptSrc(addr.IP) {
			return n, addr.IP, uint16(addr.Port), nil
		}
		// Source not in peerSpoofSet — silently drop and keep reading.
	}
}

// acceptSrc returns true when src matches the configured peerSpoofSet,
// or when no set is configured (filter disabled). Kept on the hot path,
// so it must not allocate.
func (t *UDPTransport) acceptSrc(src net.IP) bool {
	if v4 := src.To4(); v4 != nil {
		if len(t.peerSpoofSet4) == 0 {
			return true
		}
		var key [4]byte
		copy(key[:], v4)
		_, ok := t.peerSpoofSet4[key]
		return ok
	}
	if len(t.peerSpoofSet6) == 0 {
		return true
	}
	var key [16]byte
	copy(key[:], src.To16())
	_, ok := t.peerSpoofSet6[key]
	return ok
}

// Close closes the transport
func (t *UDPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	var errs []error

	if t.rawFd >= 0 {
		if err := syscall.Close(t.rawFd); err != nil {
			errs = append(errs, err)
		}
	}

	if t.rawFd6 >= 0 {
		if err := syscall.Close(t.rawFd6); err != nil {
			errs = append(errs, err)
		}
	}

	if t.recvConn != nil {
		if err := t.recvConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalPort returns the local port
func (t *UDPTransport) LocalPort() uint16 {
	if t.recvConn != nil {
		return uint16(t.recvConn.LocalAddr().(*net.UDPAddr).Port)
	}
	return t.cfg.ListenPort
}

// SetReadBuffer sets the read buffer size via SetSocketBufferSmart so
// quic-go's post-dial SO_RCVBUF tuning also benefits from BUFFORCE +
// fallback rather than being silently clamped by net.core.rmem_max.
func (t *UDPTransport) SetReadBuffer(size int) error {
	if t.recvConn == nil {
		return nil
	}
	rawConn, err := t.recvConn.SyscallConn()
	if err != nil {
		return t.recvConn.SetReadBuffer(size)
	}
	rawConn.Control(func(fd uintptr) {
		SetSocketBufferSmart(int(fd), size, BufferDirRecv)
	})
	return nil
}

// SetReadDeadline sets the read deadline on the receive socket.
// Used by QUIC for timeout handling and for unblocking Receive on shutdown.
func (t *UDPTransport) SetReadDeadline(deadline time.Time) error {
	if t.recvConn != nil {
		return t.recvConn.SetReadDeadline(deadline)
	}
	return nil
}

// SetWriteBuffer sets the write buffer size via SetSocketBufferSmart —
// see SetReadBuffer for the rationale.
func (t *UDPTransport) SetWriteBuffer(size int) error {
	if t.recvConn == nil {
		return nil
	}
	rawConn, err := t.recvConn.SyscallConn()
	if err != nil {
		return t.recvConn.SetWriteBuffer(size)
	}
	rawConn.Control(func(fd uintptr) {
		SetSocketBufferSmart(int(fd), size, BufferDirSend)
	})
	return nil
}

// SyscallConn exposes the underlying socket so quic-go can set buffer sizes.
func (t *UDPTransport) SyscallConn() (syscall.RawConn, error) {
	return t.recvConn.SyscallConn()
}

// Helper to calculate IP checksum (RFC 1071)
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum with an IPv4 pseudo-header.
func udpChecksum(srcIP, dstIP []byte, udpSegment []byte) uint16 {
	udpLen := len(udpSegment)

	// Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + udpLen(2) = 12 bytes
	var sum uint32
	sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	sum += 17 // protocol UDP
	sum += uint32(udpLen)

	// Sum UDP segment
	for i := 0; i+1 < udpLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpSegment[i:]))
	}
	if udpLen%2 == 1 {
		sum += uint32(udpSegment[udpLen-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udp6Checksum computes the UDP checksum with an IPv6 pseudo-header.
func udp6Checksum(srcIP, dstIP []byte, udpSegment []byte) uint16 {
	udpLen := len(udpSegment)

	// IPv6 pseudo-header: srcIP(16) + dstIP(16) + udpLen(4) + zero(3) + nextHdr(1) = 40 bytes
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	sum += uint32(udpLen)
	sum += 17 // next header = UDP

	// Sum UDP segment
	for i := 0; i+1 < udpLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpSegment[i:]))
	}
	if udpLen%2 == 1 {
		sum += uint32(udpSegment[udpLen-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
