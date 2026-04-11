package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPMode determines how ICMP packets are sent/received
type ICMPMode int

const (
	// ICMPModeEcho uses ICMP Echo Request (type 8) for sending
	ICMPModeEcho ICMPMode = iota
	// ICMPModeReply uses ICMP Echo Reply (type 0) for sending
	ICMPModeReply
)

// ICMPTransport implements Transport using raw ICMP sockets with IP spoofing
type ICMPTransport struct {
	cfg  *Config
	mode ICMPMode

	// Raw socket for sending spoofed packets
	rawFd  int
	rawFd6 int
	isIPv6 bool

	// Cached source IPs
	srcIPv4 [4]byte
	srcIPv6 [16]byte

	// ICMP listener for receiving
	icmpConn4 *icmp.PacketConn
	icmpConn6 *icmp.PacketConn

	// Underlying net.PacketConn for setting socket options
	rawConn4 net.PacketConn
	rawConn6 net.PacketConn

	// ICMP ID and sequence
	icmpID  uint16
	icmpSeq atomic.Uint32

	// State
	closed atomic.Bool

	// Buffer pool for receive (ICMP needs parsing before copying to caller)
	bufPool sync.Pool
}

// NewICMPTransport creates a new ICMP transport with IP spoofing
func NewICMPTransport(cfg *Config, mode ICMPMode) (*ICMPTransport, error) {
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	t := &ICMPTransport{
		cfg:     cfg,
		mode:    mode,
		rawFd:   -1,
		rawFd6:  -1,
		icmpID:  cfg.icmpEchoID(),
		isIPv6: cfg.SourceIP == nil || cfg.SourceIP.To4() == nil,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Cache source IPs
	if cfg.SourceIP != nil {
		if v4 := cfg.SourceIP.To4(); v4 != nil {
			copy(t.srcIPv4[:], v4)
		}
	}
	if cfg.SourceIPv6 != nil {
		if v6 := cfg.SourceIPv6.To16(); v6 != nil {
			copy(t.srcIPv6[:], v6)
		}
	}

	// Create raw socket for IPv4 with IP_HDRINCL (for full control including IP header)
	if cfg.SourceIP != nil && cfg.SourceIP.To4() != nil {
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
	if cfg.SourceIPv6 != nil {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}
	}

	// Create ICMP listener for receiving
	if !t.isIPv6 {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("listen icmp4: %w", err)
		}
		t.icmpConn4 = conn

		// Try to set large socket buffers using SyscallConn
		if sc, ok := interface{}(conn).(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			if rawConn, err := sc.SyscallConn(); err == nil {
				rawConn.Control(func(fd uintptr) {
					// Set 8MB receive buffer
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)
					// Set 8MB send buffer
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
				})
			}
		}
	}

	if t.isIPv6 || cfg.SourceIPv6 != nil {
		conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			// IPv6 might not be available
			t.icmpConn6 = nil
		} else {
			t.icmpConn6 = conn

			// Try to set large socket buffers using SyscallConn
			if sc, ok := interface{}(conn).(interface {
				SyscallConn() (syscall.RawConn, error)
			}); ok {
				if rawConn, err := sc.SyscallConn(); err == nil {
					rawConn.Control(func(fd uintptr) {
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
					})
				}
			}
		}
	}

	return t, nil
}

// Send sends a packet with spoofed source IP via ICMP
// SetICMPID overrides the default ICMP echo ID. Call before Send/Receive.
// Both client and server must use the same ID to filter each other's packets.
func (t *ICMPTransport) SetICMPID(id uint16) {
	t.icmpID = id
}

func (t *ICMPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	_ = dstPort

	isIPv6 := dstIP.To4() == nil

	if isIPv6 {
		return t.sendIPv6(payload, dstIP)
	}
	return t.sendIPv4(payload, dstIP)
}

func (t *ICMPTransport) sendIPv4(payload []byte, dstIP net.IP) error {
	if t.rawFd < 0 {
		return errors.New("raw socket not available")
	}

	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return errors.New("invalid IPv4 destination")
	}

	const ipHL = 20
	const icmpHL = 8 // type(1) + code(1) + checksum(2) + id(2) + seq(2)
	totalLen := ipHL + icmpHL + len(payload)
	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	// ── IPv4 header (20 bytes) ──
	buf[0] = 0x45                                          // Version=4, IHL=5
	buf[1] = 0x00                                          // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen)) // Total length
	binary.BigEndian.PutUint16(buf[4:6], 0)                // Identification
	binary.BigEndian.PutUint16(buf[6:8], 0)                // Flags + Fragment offset
	buf[8] = 64                                            // TTL
	buf[9] = 1                                             // Protocol = ICMP
	binary.BigEndian.PutUint16(buf[10:12], 0)              // Checksum placeholder
	copy(buf[12:16], t.srcIPv4[:])                         // Source IP
	copy(buf[16:20], dstIP4)                               // Dest IP
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHL]))

	// ── ICMP header (8 bytes) ──
	icmpBuf := buf[ipHL:]
	icmpBuf[0] = 8                                     // Type = Echo Request
	icmpBuf[1] = 0                                     // Code = 0
	binary.BigEndian.PutUint16(icmpBuf[2:4], 0)        // Checksum placeholder
	binary.BigEndian.PutUint16(icmpBuf[4:6], t.icmpID) // Identifier
	binary.BigEndian.PutUint16(icmpBuf[6:8], seq)      // Sequence

	// ── Payload ──
	copy(icmpBuf[icmpHL:], payload)

	// ICMP checksum covers the entire ICMP message (header + payload)
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

	dstIP16 := dstIP.To16()
	if dstIP16 == nil {
		return errors.New("invalid IPv6 destination")
	}

	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	// ICMPv6: type(1) + code(1) + checksum(2) + id(2) + seq(2) + payload
	const icmpHL = 8
	icmpLen := icmpHL + len(payload)

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:icmpLen]

	// ── ICMPv6 Echo Request header ──
	buf[0] = 128                                   // Type = Echo Request (ICMPv6)
	buf[1] = 0                                     // Code = 0
	binary.BigEndian.PutUint16(buf[2:4], 0)        // Checksum placeholder
	binary.BigEndian.PutUint16(buf[4:6], t.icmpID) // Identifier
	binary.BigEndian.PutUint16(buf[6:8], seq)      // Sequence

	// ── Payload ──
	copy(buf[icmpHL:], payload)

	// ICMPv6 checksum with pseudo-header (uses same algorithm as UDP over IPv6)
	binary.BigEndian.PutUint16(buf[2:4], icmp6Checksum(t.srcIPv6[:], dstIP16, buf[:icmpLen]))

	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], dstIP16)

	err := syscall.Sendto(t.rawFd6, buf, 0, &destAddr)
	sendBufPool.Put(bufPtr)

	if err != nil {
		return fmt.Errorf("sendto ipv6: %w", err)
	}
	return nil
}

// Receive reads an ICMP packet into buf.
func (t *ICMPTransport) Receive(buf []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}

	if t.isIPv6 && t.icmpConn6 != nil {
		return t.receiveIPv6(buf)
	}
	return t.receiveIPv4(buf)
}

func (t *ICMPTransport) receiveIPv4(dst []byte) (int, net.IP, uint16, error) {
	if t.icmpConn4 == nil {
		return 0, nil, 0, errors.New("icmp4 listener not available")
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	recvBuf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	for {
		n, cm, src, err := t.icmpConn4.IPv4PacketConn().ReadFrom(recvBuf)
		if err != nil {
			return 0, nil, 0, err
		}

		var srcIP net.IP
		if cm != nil {
			srcIP = cm.Src
		} else if src != nil {
			srcIP = src.(*net.IPAddr).IP
		}

		msg, err := icmp.ParseMessage(1, recvBuf[:n]) // 1 = ICMPv4
		if err != nil {
			continue
		}

		// Both sides send Echo Request with spoofed IPs
		// Kernel must NOT auto-respond: sysctl net.ipv4.icmp_echo_ignore_all=1
		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if echo.ID != int(t.icmpID) {
			continue
		}

		copied := copy(dst, echo.Data)

		// Return ICMP ID as stable port — QUIC needs consistent (IP, port) pairs
		return copied, srcIP, t.icmpID, nil
	}
}

func (t *ICMPTransport) receiveIPv6(dst []byte) (int, net.IP, uint16, error) {
	if t.icmpConn6 == nil {
		return 0, nil, 0, errors.New("icmp6 listener not available")
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	recvBuf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	for {
		n, cm, src, err := t.icmpConn6.IPv6PacketConn().ReadFrom(recvBuf)
		if err != nil {
			return 0, nil, 0, err
		}

		// Parse ICMPv6 message
		msg, err := icmp.ParseMessage(58, recvBuf[:n]) // 58 = ICMPv6
		if err != nil {
			continue
		}

		// Both sides send Echo Request, so we listen for Echo Request
		if msg.Type != ipv6.ICMPTypeEchoRequest {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if echo.ID != int(t.icmpID) {
			continue
		}

		var srcIP net.IP
		if cm != nil {
			srcIP = cm.Src
		} else if src != nil {
			srcIP = src.(*net.IPAddr).IP
		}

		copied := copy(dst, echo.Data)

		// Return ICMP ID as stable port — QUIC needs consistent (IP, port) pairs
		return copied, srcIP, t.icmpID, nil
	}
}

// Close closes the transport
func (t *ICMPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	// Set immediate deadline to unblock any pending ReadFrom
	now := time.Now()
	if t.icmpConn4 != nil {
		t.icmpConn4.SetReadDeadline(now)
	}
	if t.icmpConn6 != nil {
		t.icmpConn6.SetReadDeadline(now)
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

	if t.icmpConn4 != nil {
		if err := t.icmpConn4.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if t.icmpConn6 != nil {
		if err := t.icmpConn6.Close(); err != nil {
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

// SetReadDeadline sets the read deadline on the underlying ICMP connection.
// This is needed by QUIC for timeout handling and for unblocking Receive on shutdown.
func (t *ICMPTransport) SetReadDeadline(deadline time.Time) error {
	if t.icmpConn4 != nil {
		t.icmpConn4.SetReadDeadline(deadline)
	}
	if t.icmpConn6 != nil {
		t.icmpConn6.SetReadDeadline(deadline)
	}
	return nil
}

// SetReadBuffer sets the read buffer size
func (t *ICMPTransport) SetReadBuffer(size int) error {
	if t.icmpConn4 != nil {
		// icmp.PacketConn wraps net.PacketConn which supports SetReadBuffer
		if conn, ok := interface{}(t.icmpConn4).(interface{ SetReadBuffer(int) error }); ok {
			return conn.SetReadBuffer(size)
		}
	}
	if t.icmpConn6 != nil {
		if conn, ok := interface{}(t.icmpConn6).(interface{ SetReadBuffer(int) error }); ok {
			return conn.SetReadBuffer(size)
		}
	}
	return nil
}

// SetWriteBuffer sets the write buffer size
func (t *ICMPTransport) SetWriteBuffer(size int) error {
	if t.icmpConn4 != nil {
		if conn, ok := interface{}(t.icmpConn4).(interface{ SetWriteBuffer(int) error }); ok {
			return conn.SetWriteBuffer(size)
		}
	}
	if t.icmpConn6 != nil {
		if conn, ok := interface{}(t.icmpConn6).(interface{ SetWriteBuffer(int) error }); ok {
			return conn.SetWriteBuffer(size)
		}
	}
	return nil
}

// icmp6Checksum computes the ICMPv6 checksum with an IPv6 pseudo-header.
func icmp6Checksum(srcIP, dstIP []byte, icmpMsg []byte) uint16 {
	msgLen := len(icmpMsg)

	// IPv6 pseudo-header: srcIP(16) + dstIP(16) + length(4) + zero(3) + nextHdr(1)
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	sum += uint32(msgLen)
	sum += 58 // next header = ICMPv6

	// Sum ICMP message
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
