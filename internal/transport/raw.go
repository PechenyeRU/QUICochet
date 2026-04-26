package transport

import (
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

	"golang.org/x/sys/unix"
)

// RawTransport implements Transport using raw IP sockets with custom protocol number
type RawTransport struct {
	cfg *Config

	// Raw socket for sending spoofed packets (requires root/CAP_NET_RAW).
	// Closed when the matching sendmsg fast path is enabled.
	rawFd  int
	rawFd6 int

	// dualStack means both v4 and v6 source lists are configured;
	// recv polls both family-specific sockets in parallel because the
	// custom IP protocol number is family-specific (one socket per
	// family).
	dualStack bool

	// sendmsg fast path per family. v4: IP_TRANSPARENT + IP_PKTINFO
	// on the recv socket. v6: IPV6_TRANSPARENT + IPV6_PKTINFO on the
	// recv socket. v6 sendmsg is critical for correctness — without
	// it the kernel picks its own src for outgoing packets and the
	// receiver would see a non-spoofed source.
	useSendmsg   bool
	useSendmsgV6 bool
	sendFd       int // recvFd alias when useSendmsg=true
	sendFd6      int // recvFd6 alias when useSendmsgV6=true

	// Cached source IPs (multi-spoof)
	srcIPv4s [][4]byte
	srcIPv6s [][16]byte

	// peerSpoofSet4 / peerSpoofSet6 are receive-side IP filters built
	// from cfg.PeerSpoof{IPs,IPv6s}. The custom IP protocol number is
	// not a security boundary on its own; without an IP filter any
	// host that can reach our recv socket can spray bytes through to
	// the AEAD layer (or, in obfuscation=none mode, to quic-go), and
	// burn server CPU on the failed-decrypt drop. Empty set = filter
	// disabled (legacy single-stack behaviour); dual-stack requires
	// both sets to be configured symmetrically (see NewRawTransport).
	peerSpoofSet4 map[[4]byte]struct{}
	peerSpoofSet6 map[[16]byte]struct{}

	// Raw socket for receiving packets with our protocol number
	recvFd  int
	recvFd6 int

	// State
	closed atomic.Bool

	// shutPipe: pipe used to unblock the receive Poll on shutdown.
	// pipeMu protects shutPipe[1] against the fd-reuse race between
	// concurrent Close() and SetReadDeadline() — once Close has
	// closed the write end, the same int could be reassigned by the
	// kernel to an unrelated fd, and writing to it would corrupt
	// that fd. shutPipe[1] is set to -1 under the mutex on Close.
	pipeMu   sync.Mutex
	shutPipe [2]int

	// Buffer pool for receive (need to strip IP/port headers before copying to caller)
	bufPool sync.Pool
}

// NewRawTransport creates a new raw transport with custom IP protocol number
func NewRawTransport(cfg *Config) (*RawTransport, error) {
	if cfg.ProtocolNumber < 1 || cfg.ProtocolNumber > 255 {
		return nil, fmt.Errorf("invalid protocol number: %d (must be 1-255)", cfg.ProtocolNumber)
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	t := &RawTransport{
		cfg:      cfg,
		rawFd:    -1,
		rawFd6:   -1,
		recvFd:   -1,
		recvFd6:  -1,
		shutPipe: [2]int{-1, -1},
		bufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Build plural IPv4 source list
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

	// Build plural IPv6 source list
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

	// Build peer-spoof filter sets (M-3 hardening).
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
			if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
				var key [16]byte
				copy(key[:], v6)
				t.peerSpoofSet6[key] = struct{}{}
			}
		}
	} else if cfg.PeerSpoofIPv6 != nil {
		if v6 := cfg.PeerSpoofIPv6.To16(); v6 != nil && cfg.PeerSpoofIPv6.To4() == nil {
			var key [16]byte
			copy(key[:], v6)
			t.peerSpoofSet6 = map[[16]byte]struct{}{key: {}}
		}
	}

	hasV4 := len(t.srcIPv4s) > 0
	hasV6 := len(t.srcIPv6s) > 0
	t.dualStack = hasV4 && hasV6

	// Symmetric peer-spoof guard for dual-stack: filtering one
	// family but not the other silently leaves an open recv path on
	// the unfiltered side. Mirrors the udp + icmp guard.
	if t.dualStack {
		v4Filtered := len(t.peerSpoofSet4) > 0
		v6Filtered := len(t.peerSpoofSet6) > 0
		if v4Filtered != v6Filtered {
			return nil, fmt.Errorf(
				"raw transport dual-stack requires symmetric peer-spoof config: " +
					"either configure peer_spoof_ip(s) AND peer_spoof_ipv6(s), or neither",
			)
		}
	}


	// Create raw socket for IPv4 sending with IP_HDRINCL
	if hasV4 {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("create raw send socket: %w (need root or CAP_NET_RAW)", err)
		}

		// Enable IP_HDRINCL to include our own IP header
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
		}

		t.rawFd = fd

		// Create raw socket for receiving with our protocol number
		recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, cfg.ProtocolNumber)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("create raw recv socket for protocol %d: %w", cfg.ProtocolNumber, err)
		}

		if cfg.ReadBuffer > 0 {
			syscall.SetsockoptInt(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.ReadBuffer)
		}

		t.recvFd = recvFd
	}

	// Create raw socket for IPv6.
	//
	// Send socket uses IPPROTO_RAW: kernel builds the v6 header with
	// next-header = ProtocolNumber based on the sockaddr_in6 we pass
	// to sendto. Used as the slow-path fallback if IPV6_TRANSPARENT
	// is unavailable; the sendmsg fast path below uses recvFd6 (an
	// IPPROTO_<custom> socket) and overrides the source via
	// IPV6_PKTINFO cmsg.
	if hasV6 {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}

		recvFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, cfg.ProtocolNumber)
		if err != nil {
			t.recvFd6 = -1
		} else {
			if cfg.ReadBuffer > 0 {
				syscall.SetsockoptInt(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.ReadBuffer)
			}
			t.recvFd6 = recvFd
		}
	}

	// Ensure we have at least one working socket pair
	if t.rawFd < 0 && t.rawFd6 < 0 {
		return nil, errors.New("no raw socket available (need root or CAP_NET_RAW)")
	}
	if t.recvFd < 0 && t.recvFd6 < 0 {
		t.Close()
		return nil, errors.New("no receive socket available")
	}

	// Probe sendmsg fast path per family. Both probes are independent
	// — single-stack and dual-stack get the same fast-path treatment.
	// Without IPV6_TRANSPARENT the v6 send falls back to the
	// IPPROTO_RAW socket, which silently drops at the receiver
	// because the kernel-chosen src does not match the configured
	// peer-spoof set on the other side.
	if t.recvFd >= 0 {
		if err := syscall.SetsockoptInt(t.recvFd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err == nil {
			_ = syscall.SetsockoptInt(t.recvFd, syscall.SOL_IP, syscall.IP_FREEBIND, 1)
			t.useSendmsg = true
			t.sendFd = t.recvFd
			if t.rawFd >= 0 {
				syscall.Close(t.rawFd)
				t.rawFd = -1
			}
		}
	}
	if t.recvFd6 >= 0 {
		if err := syscall.SetsockoptInt(t.recvFd6, syscall.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err == nil {
			_ = syscall.SetsockoptInt(t.recvFd6, syscall.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
			t.useSendmsgV6 = true
			t.sendFd6 = t.recvFd6
			if t.rawFd6 >= 0 {
				syscall.Close(t.rawFd6)
				t.rawFd6 = -1
			}
		}
	}
	if t.useSendmsg || t.useSendmsgV6 {
		slog.Info("raw transport: sendmsg mode enabled",
			"component", "transport",
			"v4_sendmsg", t.useSendmsg, "v6_sendmsg", t.useSendmsgV6,
			"dual_stack", t.dualStack)
	}

	// Shutdown pipe: writing to shutPipe[1] unblocks the poll in Receive.
	// Mark write end non-blocking so a future caller that hammers
	// SetReadDeadline can't block on a full pipe buffer (defensive — we
	// only ever write one byte today, but the invariant is cheaper to
	// uphold than to rediscover later).
	var pipeFds [2]int
	if err := syscall.Pipe(pipeFds[:]); err != nil {
		t.Close()
		return nil, fmt.Errorf("create shutdown pipe: %w", err)
	}
	if err := unix.SetNonblock(pipeFds[1], true); err != nil {
		syscall.Close(pipeFds[0])
		syscall.Close(pipeFds[1])
		t.Close()
		return nil, fmt.Errorf("set nonblock on shutdown pipe: %w", err)
	}
	t.shutPipe = pipeFds

	return t, nil
}

// Send sends a packet with spoofed source IP and custom protocol number
func (t *RawTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	isIPv6 := dstIP.To4() == nil

	if isIPv6 {
		if t.useSendmsgV6 {
			return t.sendIPv6Sendmsg(payload, dstIP, dstPort)
		}
		return t.sendIPv6(payload, dstIP, dstPort)
	}
	if t.useSendmsg {
		return t.sendIPv4Sendmsg(payload, dstIP, dstPort)
	}
	return t.sendIPv4(payload, dstIP, dstPort)
}

// sendIPv6Sendmsg sends a v6 raw packet via the recv socket with
// sendmsg + IPV6_PKTINFO so the kernel picks our spoofed src for the
// v6 header. Without this fast path the kernel chooses src by
// routing and the receiver's peer-spoof check (when enabled by the
// upper layer) drops the packet.
func (t *RawTransport) sendIPv6Sendmsg(payload []byte, dstIP net.IP, dstPort uint16) error {
	if len(t.srcIPv6s) == 0 {
		return errors.New("no IPv6 source addresses configured")
	}
	dstIP16 := dstIP.To16()
	if dstIP16 == nil {
		return errors.New("invalid IPv6 destination")
	}

	src := &t.srcIPv6s[mrand.IntN(len(t.srcIPv6s))]

	const portHL = 4
	totalLen := portHL + len(payload)
	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	binary.BigEndian.PutUint16(buf[0:2], t.cfg.ListenPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	copy(buf[portHL:], payload)

	dest := &unix.SockaddrInet6{}
	copy(dest.Addr[:], dstIP16)

	oobPtr := oobPool6.Get().(*[]byte)
	buildPktinfo6(*oobPtr, src)

	err := unix.Sendmsg(t.sendFd6, buf, *oobPtr, dest, 0)
	oobPool6.Put(oobPtr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendmsg v6: %w", err)
	}
	return nil
}

// sendIPv4Sendmsg sends via the recv socket with sendmsg + IP_PKTINFO.
// The kernel builds the IP header with our custom protocol number; we
// only build the 4-byte port header + payload. No checksums needed.
func (t *RawTransport) sendIPv4Sendmsg(payload []byte, dstIP net.IP, dstPort uint16) error {
	if len(t.srcIPv4s) == 0 {
		return errors.New("no IPv4 source addresses configured")
	}
	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return errors.New("invalid IPv4 destination")
	}

	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]

	const portHL = 4
	totalLen := portHL + len(payload)
	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	binary.BigEndian.PutUint16(buf[0:2], t.cfg.ListenPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	copy(buf[portHL:], payload)

	dest := &unix.SockaddrInet4{}
	copy(dest.Addr[:], dstIP4)

	oobPtr := oobPool4.Get().(*[]byte)
	buildPktinfo4(*oobPtr, src)

	err := unix.Sendmsg(t.sendFd, buf, *oobPtr, dest, 0)
	oobPool4.Put(oobPtr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}
	return nil
}

func (t *RawTransport) sendIPv4(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd < 0 {
		return errors.New("raw socket not available")
	}
	if len(t.srcIPv4s) == 0 {
		return errors.New("no IPv4 source addresses configured")
	}

	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return errors.New("invalid IPv4 destination")
	}

	const ipHL = 20
	const portHL = 4 // custom port header: src port(2) + dst port(2)
	totalLen := ipHL + portHL + len(payload)

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	// ── IPv4 header ──
	buf[0] = 0x45
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	buf[8] = 64
	buf[9] = byte(t.cfg.ProtocolNumber) // custom protocol
	binary.BigEndian.PutUint16(buf[10:12], 0)
	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]
	copy(buf[12:16], src[:])
	copy(buf[16:20], dstIP4)
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHL]))

	// ── Port header ──
	binary.BigEndian.PutUint16(buf[ipHL:ipHL+2], t.cfg.ListenPort)
	binary.BigEndian.PutUint16(buf[ipHL+2:ipHL+4], dstPort)

	// ── Payload ──
	copy(buf[ipHL+portHL:], payload)

	var destAddr syscall.SockaddrInet4
	copy(destAddr.Addr[:], dstIP4)

	err := syscall.Sendto(t.rawFd, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

func (t *RawTransport) sendIPv6(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd6 < 0 {
		return errors.New("IPv6 raw socket not available")
	}
	if len(t.srcIPv6s) == 0 {
		return errors.New("no IPv6 source addresses configured")
	}

	dstIP16 := dstIP.To16()
	if dstIP16 == nil {
		return errors.New("invalid IPv6 destination")
	}

	// IPv6 raw sockets: kernel builds IPv6 header, we send port header + payload
	const portHL = 4
	dataLen := portHL + len(payload)

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:dataLen]

	// ── Port header ──
	binary.BigEndian.PutUint16(buf[0:2], t.cfg.ListenPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)

	// ── Payload ──
	copy(buf[portHL:], payload)

	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], dstIP16)

	err := syscall.Sendto(t.rawFd6, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto ipv6: %w", err)
	}
	return nil
}

// Receive reads a packet into dst. In dual-stack mode poll() waits on
// both the v4 and v6 recv sockets; whichever family is ready feeds
// the read. Raw sockets require header stripping (v4 carries the IP
// header in the read, v6 strips it), so an internal pool buffer is
// used for the syscall read and only the payload is copied to dst.
func (t *RawTransport) Receive(dst []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	// Build a poll set that includes whichever recv fds are present
	// + the shutPipe wake-up. Indices are stable so the dispatch
	// below matches each ready fd to the right family without searching.
	var pollFds []unix.PollFd
	v4Idx, v6Idx := -1, -1
	if t.recvFd >= 0 {
		v4Idx = len(pollFds)
		pollFds = append(pollFds, unix.PollFd{Fd: int32(t.recvFd), Events: unix.POLLIN})
	}
	if t.recvFd6 >= 0 {
		v6Idx = len(pollFds)
		pollFds = append(pollFds, unix.PollFd{Fd: int32(t.recvFd6), Events: unix.POLLIN})
	}
	pipeIdx := len(pollFds)
	pollFds = append(pollFds, unix.PollFd{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN})
	if v4Idx == -1 && v6Idx == -1 {
		return 0, nil, 0, errors.New("no receive socket available")
	}

	for {
		_, perr := unix.Poll(pollFds, -1)
		if perr != nil {
			if perr == syscall.EINTR {
				continue
			}
			if errors.Is(perr, syscall.EBADF) {
				return 0, nil, 0, ErrConnectionClosed
			}
			return 0, nil, 0, fmt.Errorf("poll: %w", perr)
		}
		if pollFds[pipeIdx].Revents&unix.POLLIN != 0 {
			return 0, nil, 0, ErrConnectionClosed
		}

		if v4Idx >= 0 && pollFds[v4Idx].Revents&unix.POLLIN != 0 {
			n, ip, port, retry, rerr := t.tryRecvIPv4(dst, buf)
			if rerr != nil {
				return 0, nil, 0, rerr
			}
			if !retry {
				return n, ip, port, nil
			}
		}
		if v6Idx >= 0 && pollFds[v6Idx].Revents&unix.POLLIN != 0 {
			n, ip, port, retry, rerr := t.tryRecvIPv6(dst, buf)
			if rerr != nil {
				return 0, nil, 0, rerr
			}
			if !retry {
				return n, ip, port, nil
			}
		}
		// Spurious wake — re-poll.
	}
}

// tryRecvIPv4 does a single non-blocking read from recvFd. Returns
// the matching packet, retry=true when the read produced no usable
// packet (EAGAIN, malformed), or an error other than EAGAIN/EINTR.
func (t *RawTransport) tryRecvIPv4(dst, buf []byte) (n int, srcIP net.IP, srcPort uint16, retry bool, err error) {
	rn, from, rerr := syscall.Recvfrom(t.recvFd, buf, syscall.MSG_DONTWAIT)
	if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
		return 0, nil, 0, true, nil
	}
	if rerr != nil {
		return 0, nil, 0, false, fmt.Errorf("recvfrom: %w", rerr)
	}
	if rn < 20 {
		return 0, nil, 0, true, nil
	}
	ihl := int(buf[0]&0x0f) * 4
	if rn < ihl+4 {
		return 0, nil, 0, true, nil
	}
	sa, ok := from.(*syscall.SockaddrInet4)
	if !ok {
		return 0, nil, 0, true, nil
	}
	if len(t.peerSpoofSet4) > 0 {
		var key [4]byte = sa.Addr
		if _, ok := t.peerSpoofSet4[key]; !ok {
			return 0, nil, 0, true, nil
		}
	}
	srcIP = net.IP(make([]byte, 4))
	copy(srcIP, sa.Addr[:])
	srcPort = binary.BigEndian.Uint16(buf[ihl : ihl+2])
	payload := buf[ihl+4 : rn]
	if len(payload) == 0 {
		return 0, nil, 0, true, nil
	}
	copied := copy(dst, payload)
	return copied, srcIP, srcPort, false, nil
}

// tryRecvIPv6 mirrors tryRecvIPv4 for the v6 socket. v6 raw recv
// returns just the upper-layer payload (no IP header), so the parsing
// is shorter.
func (t *RawTransport) tryRecvIPv6(dst, buf []byte) (n int, srcIP net.IP, srcPort uint16, retry bool, err error) {
	rn, from, rerr := syscall.Recvfrom(t.recvFd6, buf, syscall.MSG_DONTWAIT)
	if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
		return 0, nil, 0, true, nil
	}
	if rerr != nil {
		return 0, nil, 0, false, fmt.Errorf("recvfrom ipv6: %w", rerr)
	}
	if rn < 4 {
		return 0, nil, 0, true, nil
	}
	sa, ok := from.(*syscall.SockaddrInet6)
	if !ok {
		return 0, nil, 0, true, nil
	}
	if len(t.peerSpoofSet6) > 0 {
		var key [16]byte = sa.Addr
		if _, ok := t.peerSpoofSet6[key]; !ok {
			return 0, nil, 0, true, nil
		}
	}
	srcIP = net.IP(make([]byte, 16))
	copy(srcIP, sa.Addr[:])
	srcPort = binary.BigEndian.Uint16(buf[0:2])
	payload := buf[4:rn]
	if len(payload) == 0 {
		return 0, nil, 0, true, nil
	}
	copied := copy(dst, payload)
	return copied, srcIP, srcPort, false, nil
}

// Close closes the transport
// SetReadDeadline unblocks a pending Receive by signaling the shutdown pipe
// when the deadline is immediate or in the past. Holds pipeMu so the write
// can't race with Close and accidentally hit a recycled fd.
func (t *RawTransport) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() || deadline.After(time.Now()) {
		return nil
	}
	t.pipeMu.Lock()
	defer t.pipeMu.Unlock()
	if t.shutPipe[1] >= 0 {
		syscall.Write(t.shutPipe[1], []byte{0})
	}
	return nil
}

func (t *RawTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	// Signal + close shutdown pipe under pipeMu so any concurrent
	// SetReadDeadline can't race on the write fd.
	t.pipeMu.Lock()
	if t.shutPipe[1] >= 0 {
		syscall.Write(t.shutPipe[1], []byte{0})
		syscall.Close(t.shutPipe[1])
		t.shutPipe[1] = -1
	}
	t.pipeMu.Unlock()
	if t.shutPipe[0] >= 0 {
		syscall.Close(t.shutPipe[0])
		t.shutPipe[0] = -1
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

	if t.recvFd >= 0 {
		if err := syscall.Close(t.recvFd); err != nil {
			errs = append(errs, err)
		}
	}

	if t.recvFd6 >= 0 {
		if err := syscall.Close(t.recvFd6); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalPort returns the local port (from config)
func (t *RawTransport) LocalPort() uint16 {
	return t.cfg.ListenPort
}

// SetReadBuffer sets the read buffer size on every receive socket.
// Joins errors so a v4 failure isn't silently shadowed by a v6 success.
func (t *RawTransport) SetReadBuffer(size int) error {
	var errs []error
	if t.recvFd >= 0 {
		if err := syscall.SetsockoptInt(t.recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size); err != nil {
			errs = append(errs, err)
		}
	}
	if t.recvFd6 >= 0 {
		if err := syscall.SetsockoptInt(t.recvFd6, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SetWriteBuffer sets the write buffer size on every send socket.
func (t *RawTransport) SetWriteBuffer(size int) error {
	var errs []error
	if t.rawFd >= 0 {
		if err := syscall.SetsockoptInt(t.rawFd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size); err != nil {
			errs = append(errs, err)
		}
	}
	if t.rawFd6 >= 0 {
		if err := syscall.SetsockoptInt(t.rawFd6, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SyscallConn exposes the receive fd so quic-go can set socket options.
func (t *RawTransport) SyscallConn() (syscall.RawConn, error) {
	if t.recvFd >= 0 {
		return &rawFdConn{fd: t.recvFd}, nil
	}
	if t.recvFd6 >= 0 {
		return &rawFdConn{fd: t.recvFd6}, nil
	}
	return nil, fmt.Errorf("no receive fd available")
}
