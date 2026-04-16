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

	// Raw socket for sending spoofed packets (IPPROTO_RAW + IP_HDRINCL)
	rawFd  int
	rawFd6 int
	isIPv6 bool

	// Raw socket for receiving (IPPROTO_ICMP / IPPROTO_ICMPV6)
	recvFd  int
	recvFd6 int

	// sendmsg mode: use recvFd with IP_TRANSPARENT + IP_PKTINFO.
	// Kernel builds IP header; we only build ICMP header + payload.
	useSendmsg bool
	sendFd     int // recvFd alias, NOT separately owned

	// Cached source IPs (multi-spoof: randomly selected per packet)
	srcIPv4s [][4]byte
	srcIPv6s [][16]byte

	// ICMP ID and sequence
	icmpID  uint16
	icmpSeq atomic.Uint32

	// State
	closed   atomic.Bool
	shutPipe [2]int // pipe used to unblock poll() on shutdown

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

	// Determine IPv6 mode based on whether we have any v4 source IPs
	t.isIPv6 = len(t.srcIPv4s) == 0

	// IPv4 send + receive
	if len(t.srcIPv4s) > 0 {
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
			syscall.SetsockoptInt(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.ReadBuffer)
		}
		if cfg.WriteBuffer > 0 {
			syscall.SetsockoptInt(sendFd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, cfg.WriteBuffer)
		}
		t.recvFd = recvFd
	}

	// IPv6 send + receive
	if len(t.srcIPv6s) > 0 {
		sendFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err == nil {
			t.rawFd6 = sendFd
			if cfg.WriteBuffer > 0 {
				syscall.SetsockoptInt(sendFd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, cfg.WriteBuffer)
			}
		}

		recvFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
		if err == nil {
			t.recvFd6 = recvFd
			if cfg.ReadBuffer > 0 {
				syscall.SetsockoptInt(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.ReadBuffer)
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

	// Probe sendmsg: set IP_TRANSPARENT on the receive socket so we
	// can use sendmsg + IP_PKTINFO for per-packet source IP. The
	// kernel builds the IP header, we only build ICMP header + payload.
	if t.recvFd >= 0 {
		if err := syscall.SetsockoptInt(t.recvFd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err == nil {
			_ = syscall.SetsockoptInt(t.recvFd, syscall.SOL_IP, syscall.IP_FREEBIND, 1)
			t.useSendmsg = true
			t.sendFd = t.recvFd
			if t.rawFd >= 0 {
				syscall.Close(t.rawFd)
				t.rawFd = -1
			}
			slog.Info("icmp transport: sendmsg mode enabled", "component", "transport")
		}
	}

	// Shutdown pipe: writing to shutPipe[1] unblocks poll() in Receive
	var pipeFds [2]int
	if err := syscall.Pipe(pipeFds[:]); err != nil {
		t.Close()
		return nil, fmt.Errorf("create shutdown pipe: %w", err)
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
		return t.sendIPv6(payload, dstIP)
	}
	if t.useSendmsg {
		return t.sendIPv4Sendmsg(payload, dstIP)
	}
	return t.sendIPv4(payload, dstIP)
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

// Receive reads an ICMP packet into dst. Skips packets that don't match our
// expected type/id/code.
func (t *ICMPTransport) Receive(dst []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	if t.recvFd >= 0 && !t.isIPv6 {
		return t.recvIPv4(dst, buf)
	}
	if t.recvFd6 >= 0 {
		return t.recvIPv6(dst, buf)
	}
	return 0, nil, 0, errors.New("no receive socket available")
}

func (t *ICMPTransport) recvIPv4(dst, buf []byte) (int, net.IP, uint16, error) {
	pollFds := []unix.PollFd{
		{Fd: int32(t.recvFd), Events: unix.POLLIN},
		{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN},
	}
	wantType := t.recvTypeIPv4()

	for {
		_, err := unix.Poll(pollFds, -1)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return 0, nil, 0, fmt.Errorf("poll: %w", err)
		}
		if pollFds[1].Revents&unix.POLLIN != 0 {
			return 0, nil, 0, ErrConnectionClosed
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		n, from, err := syscall.Recvfrom(t.recvFd, buf, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, nil, 0, fmt.Errorf("recvfrom: %w", err)
		}

		// IPv4 raw socket: buf contains [IP header | ICMP message]
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+icmpHL {
			continue
		}

		icmpBuf := buf[ihl:n]
		if icmpBuf[0] != wantType {
			continue // wrong type: kernel echo reply, other tool's pings, etc.
		}
		if icmpBuf[1] != 0 {
			continue // wrong code
		}
		id := binary.BigEndian.Uint16(icmpBuf[4:6])
		if id != t.icmpID {
			continue // not our session
		}

		var srcIP net.IP
		if sa, ok := from.(*syscall.SockaddrInet4); ok {
			srcIP = net.IP(make([]byte, 4))
			copy(srcIP, sa.Addr[:])
		} else {
			continue
		}

		payload := icmpBuf[icmpHL:]
		copied := copy(dst, payload)

		// Return ICMP ID as stable port — QUIC needs consistent (IP, port) pairs
		return copied, srcIP, t.icmpID, nil
	}
}

func (t *ICMPTransport) recvIPv6(dst, buf []byte) (int, net.IP, uint16, error) {
	pollFds := []unix.PollFd{
		{Fd: int32(t.recvFd6), Events: unix.POLLIN},
		{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN},
	}
	wantType := t.recvTypeIPv6()

	for {
		_, err := unix.Poll(pollFds, -1)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return 0, nil, 0, fmt.Errorf("poll: %w", err)
		}
		if pollFds[1].Revents&unix.POLLIN != 0 {
			return 0, nil, 0, ErrConnectionClosed
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		n, from, err := syscall.Recvfrom(t.recvFd6, buf, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, nil, 0, fmt.Errorf("recvfrom ipv6: %w", err)
		}

		// IPv6 raw ICMP socket: no IP header in buf, just the ICMPv6 message
		if n < icmpHL {
			continue
		}
		if buf[0] != wantType || buf[1] != 0 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[4:6])
		if id != t.icmpID {
			continue
		}

		var srcIP net.IP
		if sa, ok := from.(*syscall.SockaddrInet6); ok {
			srcIP = net.IP(make([]byte, 16))
			copy(srcIP, sa.Addr[:])
		} else {
			continue
		}

		payload := buf[icmpHL:n]
		copied := copy(dst, payload)

		return copied, srcIP, t.icmpID, nil
	}
}

// SetReadDeadline unblocks a pending Receive by signaling the shutdown pipe
// when the deadline is immediate or in the past.
func (t *ICMPTransport) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		if t.shutPipe[1] >= 0 {
			syscall.Write(t.shutPipe[1], []byte{0})
		}
	}
	return nil
}

// Close closes the transport
func (t *ICMPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	// Signal shutdown pipe to unblock poll in Receive
	if t.shutPipe[1] >= 0 {
		syscall.Write(t.shutPipe[1], []byte{0})
		syscall.Close(t.shutPipe[1])
		t.shutPipe[1] = -1
	}
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

// SetReadBuffer sets the receive socket buffer size
func (t *ICMPTransport) SetReadBuffer(size int) error {
	var err error
	if t.recvFd >= 0 {
		err = syscall.SetsockoptInt(t.recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	}
	if t.recvFd6 >= 0 {
		err = syscall.SetsockoptInt(t.recvFd6, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	}
	return err
}

// SetWriteBuffer sets the send socket buffer size
func (t *ICMPTransport) SetWriteBuffer(size int) error {
	var err error
	if t.rawFd >= 0 {
		err = syscall.SetsockoptInt(t.rawFd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	}
	if t.rawFd6 >= 0 {
		err = syscall.SetsockoptInt(t.rawFd6, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	}
	return err
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
