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

	// Raw socket for sending spoofed packets (requires root/CAP_NET_RAW)
	rawFd  int
	rawFd6 int
	isIPv6 bool

	// sendmsg mode: use recvFd with IP_TRANSPARENT + IP_PKTINFO.
	useSendmsg bool
	sendFd     int // recvFd alias

	// Cached source IPs (multi-spoof)
	srcIPv4s [][4]byte
	srcIPv6s [][16]byte

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

	t.isIPv6 = len(t.srcIPv4s) == 0

	// Create raw socket for IPv4 sending with IP_HDRINCL
	if len(t.srcIPv4s) > 0 {
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

	// Create raw socket for IPv6
	if len(t.srcIPv6s) > 0 {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			// IPv6 raw might not be available
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}

		// Create IPv6 receive socket
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

	// Probe sendmsg: set IP_TRANSPARENT on recvFd so we can use
	// sendmsg + IP_PKTINFO. Kernel builds IP header with our custom
	// protocol number; we only build the 4-byte port header + payload.
	if t.recvFd >= 0 {
		if err := syscall.SetsockoptInt(t.recvFd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err == nil {
			_ = syscall.SetsockoptInt(t.recvFd, syscall.SOL_IP, syscall.IP_FREEBIND, 1)
			t.useSendmsg = true
			t.sendFd = t.recvFd
			if t.rawFd >= 0 {
				syscall.Close(t.rawFd)
				t.rawFd = -1
			}
			slog.Info("raw transport: sendmsg mode enabled", "component", "transport")
		}
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
		return t.sendIPv6(payload, dstIP, dstPort)
	}
	if t.useSendmsg {
		return t.sendIPv4Sendmsg(payload, dstIP, dstPort)
	}
	return t.sendIPv4(payload, dstIP, dstPort)
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

// Receive reads a packet into dst. Raw sockets require header stripping, so an
// internal pool buffer is used for the syscall read; the payload is then copied
// into dst to avoid exposing pool memory to the caller.
func (t *RawTransport) Receive(dst []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	var payloadStart, n int
	var srcIP net.IP
	var srcPort uint16
	var err error

	if t.recvFd >= 0 && !t.isIPv6 {
		payloadStart, n, srcIP, srcPort, err = t.recvIPv4(buf)
	} else if t.recvFd6 >= 0 {
		payloadStart, n, srcIP, srcPort, err = t.recvIPv6(buf)
	} else {
		return 0, nil, 0, errors.New("no receive socket available")
	}

	if err != nil {
		return 0, nil, 0, err
	}

	// Single copy from the pool buffer directly into the caller's destination.
	// recvIPv4/recvIPv6 deliberately skip the in-place shift so we save
	// ~MTU bytes of memcpy per packet on the hot path.
	copied := copy(dst, buf[payloadStart:n])
	return copied, srcIP, srcPort, nil
}

// recvIPv4 reads one packet into buf and returns the (payloadStart, n) range
// inside buf where the user payload lives, plus the source address. The
// caller copies the slice into its destination — we avoid the in-place
// memmove + second copy that the older revision had.
func (t *RawTransport) recvIPv4(buf []byte) (payloadStart, n int, srcIP net.IP, srcPort uint16, err error) {
	pollFds := []unix.PollFd{
		{Fd: int32(t.recvFd), Events: unix.POLLIN},
		{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN},
	}

	var from syscall.Sockaddr
	for {
		_, perr := unix.Poll(pollFds, -1)
		if perr != nil {
			if perr == syscall.EINTR {
				continue
			}
			if errors.Is(perr, syscall.EBADF) {
				return 0, 0, nil, 0, ErrConnectionClosed
			}
			return 0, 0, nil, 0, fmt.Errorf("poll: %w", perr)
		}
		if pollFds[1].Revents&unix.POLLIN != 0 {
			return 0, 0, nil, 0, ErrConnectionClosed
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		var rerr error
		n, from, rerr = syscall.Recvfrom(t.recvFd, buf, syscall.MSG_DONTWAIT)
		if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
			continue
		}
		if rerr != nil {
			return 0, 0, nil, 0, fmt.Errorf("recvfrom: %w", rerr)
		}
		break
	}

	// Parse source address
	if sa, ok := from.(*syscall.SockaddrInet4); ok {
		srcIP = net.IP(sa.Addr[:])
	} else {
		return 0, 0, nil, 0, errors.New("unexpected sockaddr type")
	}

	// Raw socket receives IP header + payload
	if n < 20 {
		return 0, 0, nil, 0, errors.New("packet too short")
	}

	// IP header length is in the lower 4 bits of first byte, in 32-bit words
	ihl := int(buf[0]&0x0f) * 4
	if n < ihl+4 {
		return 0, 0, nil, 0, errors.New("packet too short for header")
	}

	// Custom port header right after IP header: src port(2) + dst port(2)
	srcPort = binary.BigEndian.Uint16(buf[ihl : ihl+2])

	payloadStart = ihl + 4
	if payloadStart > n {
		return 0, 0, nil, 0, errors.New("no payload")
	}

	return payloadStart, n, srcIP, srcPort, nil
}

func (t *RawTransport) recvIPv6(buf []byte) (payloadStart, n int, srcIP net.IP, srcPort uint16, err error) {
	pollFds := []unix.PollFd{
		{Fd: int32(t.recvFd6), Events: unix.POLLIN},
		{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN},
	}

	var from syscall.Sockaddr
	for {
		_, perr := unix.Poll(pollFds, -1)
		if perr != nil {
			if perr == syscall.EINTR {
				continue
			}
			if errors.Is(perr, syscall.EBADF) {
				return 0, 0, nil, 0, ErrConnectionClosed
			}
			return 0, 0, nil, 0, fmt.Errorf("poll: %w", perr)
		}
		if pollFds[1].Revents&unix.POLLIN != 0 {
			return 0, 0, nil, 0, ErrConnectionClosed
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		var rerr error
		n, from, rerr = syscall.Recvfrom(t.recvFd6, buf, syscall.MSG_DONTWAIT)
		if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
			continue
		}
		if rerr != nil {
			return 0, 0, nil, 0, fmt.Errorf("recvfrom ipv6: %w", rerr)
		}
		break
	}

	if sa, ok := from.(*syscall.SockaddrInet6); ok {
		srcIP = net.IP(sa.Addr[:])
	} else {
		return 0, 0, nil, 0, errors.New("unexpected sockaddr type")
	}

	// IPv6 raw sockets don't include the IP header in received data
	if n < 4 {
		return 0, 0, nil, 0, errors.New("packet too short")
	}

	srcPort = binary.BigEndian.Uint16(buf[0:2])
	payloadStart = 4
	return payloadStart, n, srcIP, srcPort, nil
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
