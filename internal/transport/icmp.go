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

// ICMPMode determines how ICMP packets are sent/received.
//
// The client and server use opposite modes so only one direction of the
// ICMP echo exchange is observed by each kernel:
//
//	ModeEcho  → send Echo Request  (type 8 IPv4 / 128 IPv6), recv Echo Reply
//	ModeReply → send Echo Reply    (type 0 IPv4 / 129 IPv6), recv Echo Request
//
// With this asymmetry, the kernel never sees an unsolicited Echo Request
// that it would auto-reply to (Echo Reply is never auto-answered).
// The peer must still disable net.ipv4.icmp_echo_ignore_all on the side
// that receives Echo Request (ModeReply), otherwise the kernel races us.
type ICMPMode int

const (
	ICMPModeEcho  ICMPMode = iota // client default
	ICMPModeReply                 // server default
)

// ICMP message type constants
const (
	icmpv4EchoRequest byte = 8
	icmpv4EchoReply   byte = 0
	icmpv6EchoRequest byte = 128
	icmpv6EchoReply   byte = 129

	icmpHL = 8 // type + code + checksum + id + seq
)

// ICMPTransport implements Transport using raw ICMP sockets with IP spoofing.
//
// Uses raw sockets directly (AF_INET, SOCK_RAW, IPPROTO_ICMP) rather than
// golang.org/x/net/icmp's PacketConn, so we can:
//   - expose SyscallConn for quic-go socket buffer tuning
//   - do zero-allocation ICMP header parsing on receive
//   - honor ICMPMode asymmetry on both send and receive
type ICMPTransport struct {
	cfg  *Config
	mode ICMPMode

	// Raw socket for sending spoofed packets (IPPROTO_RAW + IP_HDRINCL).
	// Closed when the matching sendmsg fast path is enabled.
	rawFd  int
	rawFd6 int

	// dualStack means both v4 and v6 source lists are configured and
	// the transport accepts/sends on both families. Implies parallel
	// recv loops on recvFd + recvFd6 (ICMP protocol numbers differ
	// between families so a single socket cannot cover both).
	dualStack bool

	// Raw socket for receiving (IPPROTO_ICMP / IPPROTO_ICMPV6).
	recvFd  int
	recvFd6 int

	// sendmsg fast path per family. When enabled the v4 send goes via
	// recvFd with IP_TRANSPARENT + IP_PKTINFO (kernel builds the v4
	// header, we only build ICMP header + payload + checksum). The v6
	// send goes via recvFd6 with IPV6_TRANSPARENT + IPV6_PKTINFO and
	// uses an IPPROTO_ICMPV6 socket so the KERNEL computes the
	// ICMPv6 checksum with the spoofed source — fixes a latent
	// silent-drop bug from the IPPROTO_RAW path where we computed the
	// checksum with the spoofed src but the kernel used the real
	// interface IP, producing invalid checksums on the wire.
	useSendmsg   bool
	useSendmsgV6 bool
	sendFd       int // recvFd alias when useSendmsg=true, NOT owned
	sendFd6      int // recvFd6 alias when useSendmsgV6=true, NOT owned

	// Cached source IPs (multi-spoof: randomly selected per packet)
	srcIPv4s [][4]byte
	srcIPv6s [][16]byte

	// peerSpoofSet4 / peerSpoofSet6 are receive-side IP filters built from
	// cfg.PeerSpoofIPs / cfg.PeerSpoofIPv6s. icmpID alone is a 16-bit
	// brute-forceable token; without an IP filter any host can drive
	// noise into the AEAD decrypt path. Empty set = filter disabled.
	peerSpoofSet4 map[[4]byte]struct{}
	peerSpoofSet6 map[[16]byte]struct{}

	// ICMP ID and sequence
	icmpID  uint16
	icmpSeq atomic.Uint32

	// State
	closed   atomic.Bool
	shutPipe [2]int // pipe used to unblock poll() on shutdown

	// pipeMu protects shutPipe[1] against the fd-reuse race between
	// Close() and SetReadDeadline(). Same pattern raw.go uses: once
	// Close has closed the write end, the same int could be reassigned
	// by the kernel to another fd, and writing to it would corrupt
	// that fd. Without this lock a concurrent SetReadDeadline could
	// race with Close.
	pipeMu sync.Mutex

	// Buffer pool for receive (raw socket gives us IP+ICMP+payload;
	// we strip headers before copying to caller)
	bufPool sync.Pool
}

// NewICMPTransport creates a new ICMP transport with IP spoofing.
func NewICMPTransport(cfg *Config, mode ICMPMode) (*ICMPTransport, error) {
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	t := &ICMPTransport{
		cfg:      cfg,
		mode:     mode,
		rawFd:    -1,
		rawFd6:   -1,
		recvFd:   -1,
		recvFd6:  -1,
		shutPipe: [2]int{-1, -1},
		icmpID:   cfg.icmpEchoID(),
		bufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Source / peer-spoof parsing shared with udp/raw/syn_udp.
	t.srcIPv4s, t.srcIPv6s = parseSourceLists(cfg)
	t.peerSpoofSet4, t.peerSpoofSet6 = parsePeerSpoofSets(cfg)

	// Family selection. dualStack when both source lists are
	// populated; otherwise single-stack on whichever family has
	// sources configured.
	hasV4 := len(t.srcIPv4s) > 0
	hasV6 := len(t.srcIPv6s) > 0
	t.dualStack = hasV4 && hasV6

	if err := assertSymmetricPeerSpoof("icmp", t.dualStack, t.peerSpoofSet4, t.peerSpoofSet6); err != nil {
		return nil, err
	}

	// IPv4 send + receive
	if hasV4 {
		// Send socket: IPPROTO_RAW with IP_HDRINCL so we build the full header
		sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("create raw send socket: %w (need root or CAP_NET_RAW)", err)
		}
		if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(sendFd)
			return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
		}
		t.rawFd = sendFd

		// Receive socket: AF_INET/SOCK_RAW/IPPROTO_ICMP
		recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			syscall.Close(sendFd)
			return nil, fmt.Errorf("create icmp recv socket: %w", err)
		}
		if cfg.ReadBuffer > 0 {
			SetSocketBufferSmart(recvFd, cfg.ReadBuffer, BufferDirRecv)
		}
		if cfg.WriteBuffer > 0 {
			SetSocketBufferSmart(sendFd, cfg.WriteBuffer, BufferDirSend)
		}
		t.recvFd = recvFd
	}

	// IPv6 send + receive. The send socket is IPPROTO_RAW (kernel
	// builds the v6 header from our payload + sockaddr_in6). The
	// recv socket is IPPROTO_ICMPV6 — receives just the ICMPv6
	// message (no IP header). Both are best-effort; if either fails
	// we fall back to v4-only when v4 is also configured.
	if hasV6 {
		sendFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err == nil {
			t.rawFd6 = sendFd
			if cfg.WriteBuffer > 0 {
				SetSocketBufferSmart(sendFd, cfg.WriteBuffer, BufferDirSend)
			}
		}

		recvFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
		if err == nil {
			t.recvFd6 = recvFd
			if cfg.ReadBuffer > 0 {
				SetSocketBufferSmart(recvFd, cfg.ReadBuffer, BufferDirRecv)
			}
		}
	}

	if t.rawFd < 0 && t.rawFd6 < 0 {
		return nil, errors.New("no ICMP send socket available (need root or CAP_NET_RAW)")
	}
	if t.recvFd < 0 && t.recvFd6 < 0 {
		t.Close()
		return nil, errors.New("no ICMP receive socket available")
	}

	// Probe sendmsg fast path per family. v4 uses IP_TRANSPARENT +
	// IP_PKTINFO on the IPPROTO_ICMP recv socket. v6 uses
	// IPV6_TRANSPARENT + IPV6_PKTINFO on the IPPROTO_ICMPV6 recv
	// socket — IPPROTO_ICMPV6 lets the kernel compute the ICMPv6
	// checksum with the actual (PKTINFO-overridden) source, which is
	// the fix for the bug where IPPROTO_RAW sends had a checksum
	// computed against the spoofed src but a real interface IP on
	// the wire (silent receiver-side drop).
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
		slog.Info("icmp transport: sendmsg mode enabled",
			"component", "transport",
			"v4_sendmsg", t.useSendmsg, "v6_sendmsg", t.useSendmsgV6,
			"dual_stack", t.dualStack)
	}

	// Shutdown pipe: writing to shutPipe[1] unblocks poll() in Receive.
	// Mark the write end non-blocking so a future caller that hammers
	// SetReadDeadline can't stall on a full pipe buffer — same
	// invariant raw.go and syn_udp.go uphold; ICMP missed it
	// previously and was a copy-paste regression risk.
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

// sendTypeIPv4 returns the ICMPv4 type we should emit for the configured mode.
func (t *ICMPTransport) sendTypeIPv4() byte {
	if t.mode == ICMPModeReply {
		return icmpv4EchoReply
	}
	return icmpv4EchoRequest
}

// recvTypeIPv4 returns the ICMPv4 type we should accept on receive.
// Since peers use opposite modes, if we send X the peer sends the complement.
func (t *ICMPTransport) recvTypeIPv4() byte {
	if t.mode == ICMPModeReply {
		return icmpv4EchoRequest
	}
	return icmpv4EchoReply
}

func (t *ICMPTransport) sendTypeIPv6() byte {
	if t.mode == ICMPModeReply {
		return icmpv6EchoReply
	}
	return icmpv6EchoRequest
}

func (t *ICMPTransport) recvTypeIPv6() byte {
	if t.mode == ICMPModeReply {
		return icmpv6EchoRequest
	}
	return icmpv6EchoReply
}

// SetICMPID overrides the default ICMP echo ID. Call before Send/Receive.
// Both client and server must use the same ID to filter each other's packets.
func (t *ICMPTransport) SetICMPID(id uint16) {
	t.icmpID = id
}

// Send sends a packet with spoofed source IP via ICMP.
func (t *ICMPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}
	_ = dstPort // ICMP has no port; the ICMP ID takes its place

	if dstIP.To4() == nil {
		if t.useSendmsgV6 {
			return t.sendIPv6Sendmsg(payload, dstIP)
		}
		return t.sendIPv6(payload, dstIP)
	}
	if t.useSendmsg {
		return t.sendIPv4Sendmsg(payload, dstIP)
	}
	return t.sendIPv4(payload, dstIP)
}

// sendIPv6Sendmsg sends an ICMPv6 message via the IPPROTO_ICMPV6 recv
// socket using sendmsg + IPV6_PKTINFO for source IP override. The
// kernel computes the ICMPv6 checksum with the spoofed source, fixing
// the silent-drop bug present in the IPPROTO_RAW path (which computed
// the checksum against the spoofed src but the kernel emitted a v6
// header with the real interface IP).
func (t *ICMPTransport) sendIPv6Sendmsg(payload []byte, dstIP net.IP) error {
	if len(t.srcIPv6s) == 0 {
		return errors.New("no IPv6 source IPs configured")
	}
	dstIP16 := dstIP.To16()
	if dstIP16 == nil {
		return errors.New("invalid IPv6 destination")
	}

	src := &t.srcIPv6s[mrand.IntN(len(t.srcIPv6s))]
	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	totalLen := icmpHL + len(payload)
	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	buf[0] = t.sendTypeIPv6()
	buf[1] = 0
	// Checksum field: leave at 0; the IPPROTO_ICMPV6 socket has the
	// kernel compute and insert the correct ICMPv6 checksum.
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint16(buf[4:6], t.icmpID)
	binary.BigEndian.PutUint16(buf[6:8], seq)
	copy(buf[icmpHL:], payload)

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

// sendIPv4Sendmsg sends an ICMP packet using the recv socket with
// sendmsg + IP_PKTINFO. The kernel builds the IP header; we only
// build the ICMP header + payload and compute the ICMP checksum.
func (t *ICMPTransport) sendIPv4Sendmsg(payload []byte, dstIP net.IP) error {
	if len(t.srcIPv4s) == 0 {
		return errors.New("no IPv4 source IPs configured")
	}
	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return errors.New("invalid IPv4 destination")
	}

	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]
	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	totalLen := icmpHL + len(payload)
	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	buf[0] = t.sendTypeIPv4()
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint16(buf[4:6], t.icmpID)
	binary.BigEndian.PutUint16(buf[6:8], seq)
	copy(buf[icmpHL:], payload)
	binary.BigEndian.PutUint16(buf[2:4], ipChecksum(buf[:totalLen]))

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

func (t *ICMPTransport) sendIPv4(payload []byte, dstIP net.IP) error {
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

	const ipHL = 20
	totalLen := ipHL + icmpHL + len(payload)
	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	// Random source IP selection for multi-spoof
	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	// ── IPv4 header ──
	buf[0] = 0x45
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	buf[8] = 64
	buf[9] = 1 // ICMP
	binary.BigEndian.PutUint16(buf[10:12], 0)
	copy(buf[12:16], src[:])
	copy(buf[16:20], dstIP4)
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHL]))

	// ── ICMP header ──
	icmpBuf := buf[ipHL:]
	icmpBuf[0] = t.sendTypeIPv4() // honors configured mode
	icmpBuf[1] = 0                // code
	binary.BigEndian.PutUint16(icmpBuf[2:4], 0)
	binary.BigEndian.PutUint16(icmpBuf[4:6], t.icmpID)
	binary.BigEndian.PutUint16(icmpBuf[6:8], seq)

	copy(icmpBuf[icmpHL:], payload)

	// Checksum covers the entire ICMP message
	binary.BigEndian.PutUint16(icmpBuf[2:4], ipChecksum(icmpBuf[:icmpHL+len(payload)]))

	var destAddr syscall.SockaddrInet4
	copy(destAddr.Addr[:], dstIP4)

	err := syscall.Sendto(t.rawFd, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

func (t *ICMPTransport) sendIPv6(payload []byte, dstIP net.IP) error {
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

	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)
	icmpLen := icmpHL + len(payload)

	// Random source IP selection for multi-spoof
	src := &t.srcIPv6s[mrand.IntN(len(t.srcIPv6s))]

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:icmpLen]

	// IPv6 raw sockets don't take an IP header — kernel builds it.
	buf[0] = t.sendTypeIPv6()
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint16(buf[4:6], t.icmpID)
	binary.BigEndian.PutUint16(buf[6:8], seq)

	copy(buf[icmpHL:], payload)

	// ICMPv6 checksum uses IPv6 pseudo-header
	binary.BigEndian.PutUint16(buf[2:4], icmp6Checksum(src[:], dstIP16, buf[:icmpLen]))

	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], dstIP16)

	err := syscall.Sendto(t.rawFd6, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto ipv6: %w", err)
	}
	return nil
}

// Receive reads one ICMP packet that matches our type/id/code into
// dst. The dual-poll dispatch (single goroutine, polls v4 + v6 +
// shutPipe, dispatches to the ready family) lives in dualpoll.go
// since it is shared with the raw transport.
func (t *ICMPTransport) Receive(dst []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	return dualPollRecv(t.recvFd, t.recvFd6, t.shutPipe[0],
		func() (int, net.IP, uint16, bool, error) { return t.tryRecvIPv4(dst, buf) },
		func() (int, net.IP, uint16, bool, error) { return t.tryRecvIPv6(dst, buf) },
	)
}

// tryRecvIPv4 does a single non-blocking read from recvFd and returns
// the matching packet, or retry=true when the read produced no usable
// packet (EAGAIN, wrong type/id, source not in peer-spoof set). Errors
// other than EAGAIN/EINTR propagate to the caller.
func (t *ICMPTransport) tryRecvIPv4(dst, buf []byte) (n int, ip net.IP, port uint16, retry bool, err error) {
	wantType := t.recvTypeIPv4()
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
	if ihl < 20 || rn < ihl+icmpHL {
		return 0, nil, 0, true, nil
	}
	icmpBuf := buf[ihl:rn]
	if icmpBuf[0] != wantType || icmpBuf[1] != 0 {
		return 0, nil, 0, true, nil
	}
	if binary.BigEndian.Uint16(icmpBuf[4:6]) != t.icmpID {
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
	srcIP := net.IP(make([]byte, 4))
	copy(srcIP, sa.Addr[:])
	payload := icmpBuf[icmpHL:]
	copied := copy(dst, payload)
	return copied, srcIP, t.icmpID, false, nil
}

// tryRecvIPv6 mirrors tryRecvIPv4 for the v6 ICMPv6 socket.
func (t *ICMPTransport) tryRecvIPv6(dst, buf []byte) (n int, ip net.IP, port uint16, retry bool, err error) {
	wantType := t.recvTypeIPv6()
	rn, from, rerr := syscall.Recvfrom(t.recvFd6, buf, syscall.MSG_DONTWAIT)
	if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
		return 0, nil, 0, true, nil
	}
	if rerr != nil {
		return 0, nil, 0, false, fmt.Errorf("recvfrom ipv6: %w", rerr)
	}
	if rn < icmpHL {
		return 0, nil, 0, true, nil
	}
	if buf[0] != wantType || buf[1] != 0 {
		return 0, nil, 0, true, nil
	}
	if binary.BigEndian.Uint16(buf[4:6]) != t.icmpID {
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
	srcIP := net.IP(make([]byte, 16))
	copy(srcIP, sa.Addr[:])
	payload := buf[icmpHL:rn]
	copied := copy(dst, payload)
	return copied, srcIP, t.icmpID, false, nil
}

// SetReadDeadline unblocks a pending Receive by signaling the shutdown pipe
// when the deadline is immediate or in the past. Holds pipeMu so the write
// can't race with Close and accidentally hit a recycled fd (same pattern
// raw.go uses).
func (t *ICMPTransport) SetReadDeadline(deadline time.Time) error {
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

// Close closes the transport
func (t *ICMPTransport) Close() error {
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

// LocalPort returns the ICMP ID as a pseudo-port
func (t *ICMPTransport) LocalPort() uint16 {
	return t.icmpID
}

// SetReadBuffer sets the receive socket buffer size via SetSocketBufferSmart
// so quic-go's post-dial SO_RCVBUF tuning gets BUFFORCE + halving fallback,
// matching the UDP transport behaviour. Without this, raw ICMP sockets get
// silently clamped at net.core.rmem_max (~208 KB on stock hosts) and become
// the throughput bottleneck above ~500 Mbps.
func (t *ICMPTransport) SetReadBuffer(size int) error {
	if t.recvFd >= 0 {
		SetSocketBufferSmart(t.recvFd, size, BufferDirRecv)
	}
	if t.recvFd6 >= 0 {
		SetSocketBufferSmart(t.recvFd6, size, BufferDirRecv)
	}
	return nil
}

// SetWriteBuffer mirrors SetReadBuffer for the send fds.
func (t *ICMPTransport) SetWriteBuffer(size int) error {
	if t.rawFd >= 0 {
		SetSocketBufferSmart(t.rawFd, size, BufferDirSend)
	}
	if t.rawFd6 >= 0 {
		SetSocketBufferSmart(t.rawFd6, size, BufferDirSend)
	}
	return nil
}

// SyscallConn exposes the receive fd so quic-go can set socket options.
// Wraps the raw fd in a minimal RawConn implementation because we never had
// a *net.UDPConn to delegate to.
func (t *ICMPTransport) SyscallConn() (syscall.RawConn, error) {
	if t.recvFd >= 0 {
		return &rawFdConn{fd: t.recvFd}, nil
	}
	if t.recvFd6 >= 0 {
		return &rawFdConn{fd: t.recvFd6}, nil
	}
	return nil, fmt.Errorf("no receive fd available")
}

// icmp6Checksum computes the ICMPv6 checksum with an IPv6 pseudo-header.
func icmp6Checksum(srcIP, dstIP []byte, icmpMsg []byte) uint16 {
	msgLen := len(icmpMsg)

	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	sum += uint32(msgLen)
	sum += 58 // next header = ICMPv6

	for i := 0; i+1 < msgLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(icmpMsg[i:]))
	}
	if msgLen%2 == 1 {
		sum += uint32(icmpMsg[msgLen-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
