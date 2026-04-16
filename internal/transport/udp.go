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

const pktinfo4Size = 12 // sizeof(struct in_pktinfo)

// UDPTransport implements Transport using raw UDP sockets with IP spoofing
type UDPTransport struct {
	cfg *Config

	// Raw socket for sending spoofed packets (requires root/CAP_NET_RAW).
	// Only used when sendmsg mode is unavailable (fallback path).
	rawFd  int
	rawFd6 int
	isIPv6 bool

	// sendmsg mode: use the recvConn's underlying fd with IP_TRANSPARENT
	// + sendmsg/IP_PKTINFO for per-packet source IP selection. Eliminates
	// manual IP/UDP header construction and checksum computation. The
	// kernel handles everything + TX checksum offload to NIC.
	useSendmsg bool
	sendFd     int // fd from recvConn, used for sendmsg (NOT owned — recvConn closes it)

	// Cached values to avoid per-packet conversions
	srcIPv4s  [][4]byte  // all IPv4 source IPs for multi-spoof
	srcIPv6s  [][16]byte // all IPv6 source IPs for multi-spoof
	localPort uint16     // cached local port (set after listen)

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

	// Determine IPv6 mode based on whether we have any v4 source IPs
	t.isIPv6 = len(t.srcIPv4s) == 0

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

	// Create UDP listener for receiving
	var listenAddr string
	if t.isIPv6 {
		listenAddr = fmt.Sprintf("[::]:%d", cfg.ListenPort)
	} else {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", cfg.ListenPort)
	}

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}

	recvConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	t.recvConn = recvConn
	t.localPort = uint16(recvConn.LocalAddr().(*net.UDPAddr).Port)

	// Set socket buffer sizes (separate read/write for tuning)
	if cfg.ReadBuffer > 0 {
		recvConn.SetReadBuffer(cfg.ReadBuffer)
	}
	if cfg.WriteBuffer > 0 {
		recvConn.SetWriteBuffer(cfg.WriteBuffer)
	}

	// Probe sendmsg path: set IP_TRANSPARENT on the recv socket's fd so
	// we can use sendmsg with IP_PKTINFO for per-packet source IP
	// selection. This eliminates manual IP/UDP header construction,
	// checksum computation, and the separate raw socket. The kernel
	// handles everything + TX checksum offload to NIC if available.
	// Requires CAP_NET_RAW or CAP_NET_ADMIN (already required).
	if rawConn, rawErr := recvConn.SyscallConn(); rawErr == nil {
		var sendFd int
		var probeErr error
		rawConn.Control(func(fd uintptr) {
			sendFd = int(fd)
			probeErr = syscall.SetsockoptInt(sendFd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			if probeErr == nil {
				_ = syscall.SetsockoptInt(sendFd, syscall.SOL_IP, syscall.IP_FREEBIND, 1)
			}
		})
		if probeErr == nil {
			t.useSendmsg = true
			t.sendFd = sendFd
			// Close the raw sockets — we don't need them anymore.
			if t.rawFd >= 0 {
				syscall.Close(t.rawFd)
				t.rawFd = -1
			}
			if t.rawFd6 >= 0 {
				syscall.Close(t.rawFd6)
				t.rawFd6 = -1
			}
			slog.Info("udp transport: sendmsg mode enabled", "component", "transport")
		} else {
			slog.Debug("udp transport: sendmsg probe failed, using raw sockets", "component", "transport", "error", probeErr)
		}
	}

	return t, nil
}

// Send sends a packet with spoofed source IP
func (t *UDPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	isIPv6 := dstIP.To4() == nil

	if t.useSendmsg {
		if isIPv6 {
			return t.sendIPv6Sendmsg(payload, dstIP, dstPort)
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

	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]

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

// sendIPv6Sendmsg sends a UDP packet using sendmsg with IPV6_PKTINFO.
// Falls back to raw socket path if IPV6_TRANSPARENT was not set.
func (t *UDPTransport) sendIPv6Sendmsg(payload []byte, dstIP net.IP, dstPort uint16) error {
	// IPv6 sendmsg with IPV6_PKTINFO requires IPV6_TRANSPARENT which
	// may not be set. Fall back to the raw socket path.
	return t.sendIPv6(payload, dstIP, dstPort)
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

// cmsgAlignOf rounds n up to the cmsg alignment boundary (same as
// CMSG_ALIGN in the kernel). On 64-bit Linux this is 8 bytes.
func cmsgAlignOf(n int) int {
	const align = unix.SizeofPtr
	return (n + align - 1) &^ (align - 1)
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

	// Randomly select a source IP from the pool
	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]

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

	// Randomly select a source IP from the pool
	src := &t.srcIPv6s[mrand.IntN(len(t.srcIPv6s))]

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
func (t *UDPTransport) Receive(buf []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}

	n, addr, err := t.recvConn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, 0, err
	}

	return n, addr.IP, uint16(addr.Port), nil
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

// SetReadBuffer sets the read buffer size
func (t *UDPTransport) SetReadBuffer(size int) error {
	if t.recvConn != nil {
		return t.recvConn.SetReadBuffer(size)
	}
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

// SetWriteBuffer sets the write buffer size
func (t *UDPTransport) SetWriteBuffer(size int) error {
	if t.recvConn != nil {
		return t.recvConn.SetWriteBuffer(size)
	}
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
