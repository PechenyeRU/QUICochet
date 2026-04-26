package transport

import (
	"crypto/rand"
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

// SynUDPTransport implements an asymmetric Transport:
//   - Client mode: Send() = raw TCP SYN (spoofed), Receive() = plain UDP listen
//   - Server mode: Send() = raw UDP (spoofed), Receive() = raw TCP socket (filter SYN)
//
// This is designed for DPI evasion: uplink looks like TCP SYN flood,
// downlink looks like normal UDP traffic.
//
// Unlike the udp/icmp/raw transports, syn_udp does NOT use the
// sendmsg + IP_TRANSPARENT optimization. The client's send path
// requires full TCP header construction (SYN flag, seq, timestamp
// option, pseudo-header checksum) which cannot be expressed via
// SOCK_DGRAM. The server's UDP send could theoretically use sendmsg,
// but it would require creating a new SOCK_DGRAM + SO_REUSEPORT
// socket rather than reusing an existing one, and this transport is
// a niche DPI-evasion tool where raw throughput is not the bottleneck.
// Not worth the complexity.
type SynUDPTransport struct {
	cfg    *Config
	isServ bool // true = server mode

	// isIPv6 selects the v4 or v6 send/recv stack at init time.
	// Dual-stack syn_udp would need two recv sockets per role
	// (different IP protocol numbers per family) — out of scope for
	// this release; reject the config explicitly.
	isIPv6 bool

	// --- Client mode ---
	// Send: raw TCP SYN — v4 uses IPPROTO_RAW + IP_HDRINCL with a
	// hand-built v4 header; v6 uses IPPROTO_TCP raw and lets the
	// kernel build the v6 header (we provide source via IPV6_PKTINFO
	// cmsg, which requires IPV6_TRANSPARENT for spoofing).
	synFd  int
	synFd6 int
	seq    uint32
	synMu  sync.Mutex

	// Receive: standard UDP listener (udp4 in v4 mode, udp6 in v6).
	udpRecvConn *net.UDPConn

	// --- Server mode ---
	// Receive: raw TCP socket — v4 returns IP+TCP, v6 returns just
	// TCP (kernel strips the v6 header).
	tcpRecvFd  int
	tcpRecvFd6 int

	// Send: raw UDP with spoofed source. v4 builds full IPv4 header
	// via IP_HDRINCL; v6 lets the kernel build it (IPV6_PKTINFO).
	udpSendFd  int
	udpSendFd6 int

	// --- Common ---
	srcIPv4s      [][4]byte             // multi-spoof v4 source IPs
	srcIPv6s      [][16]byte            // multi-spoof v6 source IPs
	peerSpoofSet  map[[4]byte]struct{}  // O(1) v4 receive-side filter
	peerSpoofSet6 map[[16]byte]struct{} // O(1) v6 receive-side filter
	closed        atomic.Bool
	bufPool       sync.Pool

	// pipeMu protects shutPipe[1] against the fd-reuse race between
	// Close() and SetReadDeadline() — once Close has closed the write
	// end, the same int could be reassigned by the kernel to another
	// fd, and writing to it would corrupt that fd.
	pipeMu   sync.Mutex
	shutPipe [2]int
}

// NewSynUDPTransport creates a new asymmetric SYN+UDP transport. Role
// must be passed explicitly — server expects to receive raw TCP SYNs
// and send spoofed UDP, client does the opposite. The previous
// "isServer = ListenPort > 0" heuristic conflated two orthogonal
// concepts and broke any future client that needed a fixed listen
// port (NAT hole-punching, firewall pinning, etc.).
func NewSynUDPTransport(cfg *Config, role Role) (*SynUDPTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	isServer := role == RoleServer

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	t := &SynUDPTransport{
		cfg:        cfg,
		isServ:     isServer,
		synFd:      -1,
		synFd6:     -1,
		tcpRecvFd:  -1,
		tcpRecvFd6: -1,
		udpSendFd:  -1,
		udpSendFd6: -1,
		shutPipe:   [2]int{-1, -1},
		seq:        1,
		bufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Build multi-spoof source IP list — v4
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

	// Build multi-spoof source IP list — v6
	if len(cfg.SourceIPv6s) > 0 {
		t.srcIPv6s = make([][16]byte, 0, len(cfg.SourceIPv6s))
		for _, ip := range cfg.SourceIPv6s {
			if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
				var a [16]byte
				copy(a[:], v6)
				t.srcIPv6s = append(t.srcIPv6s, a)
			}
		}
	} else if cfg.SourceIPv6 != nil {
		if v6 := cfg.SourceIPv6.To16(); v6 != nil && cfg.SourceIPv6.To4() == nil {
			var a [16]byte
			copy(a[:], v6)
			t.srcIPv6s = [][16]byte{a}
		}
	}

	// Pick the family. Dual-stack syn_udp would need parallel recv
	// loops on two raw sockets per role (different IP protocol
	// numbers per family); reject it explicitly so the operator gets
	// a clear message instead of silent half-broken behaviour.
	hasV4 := len(t.srcIPv4s) > 0
	hasV6 := len(t.srcIPv6s) > 0
	switch {
	case hasV4 && hasV6:
		return nil, fmt.Errorf("syn_udp transport does not yet support dual-stack: configure source_ip(s) OR source_ipv6(s), not both")
	case hasV6:
		t.isIPv6 = true
	case hasV4:
		t.isIPv6 = false
	default:
		return nil, fmt.Errorf("syn_udp transport requires at least one source_ip or source_ipv6")
	}

	// Build peer spoof IP set for receive-side filtering — v4
	if len(cfg.PeerSpoofIPs) > 0 {
		t.peerSpoofSet = make(map[[4]byte]struct{}, len(cfg.PeerSpoofIPs))
		for _, ip := range cfg.PeerSpoofIPs {
			if v4 := ip.To4(); v4 != nil {
				var key [4]byte
				copy(key[:], v4)
				t.peerSpoofSet[key] = struct{}{}
			}
		}
	} else if cfg.PeerSpoofIP != nil {
		if v4 := cfg.PeerSpoofIP.To4(); v4 != nil {
			var key [4]byte
			copy(key[:], v4)
			t.peerSpoofSet = map[[4]byte]struct{}{key: {}}
		}
	}
	// v6 peer spoof set
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

	if isServer {
		var err error
		if t.isIPv6 {
			err = t.initServerV6()
		} else {
			err = t.initServer()
		}
		if err != nil {
			t.Close()
			return nil, err
		}
	} else {
		var err error
		if t.isIPv6 {
			err = t.initClientV6()
		} else {
			err = t.initClient()
		}
		if err != nil {
			t.Close()
			return nil, err
		}
	}

	return t, nil
}

// ── Client init ──

func (t *SynUDPTransport) initClient() error {
	// Raw socket for sending TCP SYN packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("create raw socket for SYN: %w (need root/CAP_NET_RAW)", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	t.synFd = fd

	// UDP listener for receiving server responses
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", t.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	t.udpRecvConn = conn

	if t.cfg.ReadBuffer > 0 {
		conn.SetReadBuffer(t.cfg.ReadBuffer)
	}
	if t.cfg.WriteBuffer > 0 {
		conn.SetWriteBuffer(t.cfg.WriteBuffer)
	}

	return nil
}

// ── Server init ──

func (t *SynUDPTransport) initServer() error {
	// Raw TCP socket for receiving SYN packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("create raw TCP recv socket: %w (need root/CAP_NET_RAW)", err)
	}
	if t.cfg.ReadBuffer > 0 {
		// Apply SO_RCVBUF via SetSocketBufferSmart so we get BUFFORCE +
		// halving fallback when net.core.rmem_max is too low — without
		// this the kernel silently clamps to ~208 KB and we drop packets
		// under burst regardless of the user's sysctl tuning.
		SetSocketBufferSmart(fd, t.cfg.ReadBuffer, BufferDirRecv)
	}
	t.tcpRecvFd = fd

	// Shutdown pipe: writing to shutPipe[1] unblocks the poll in receiveSyn
	var pipeFds [2]int
	if err := syscall.Pipe(pipeFds[:]); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("create shutdown pipe: %w", err)
	}
	if err := unix.SetNonblock(pipeFds[1], true); err != nil {
		syscall.Close(fd)
		syscall.Close(pipeFds[0])
		syscall.Close(pipeFds[1])
		return fmt.Errorf("set nonblock on shutdown pipe: %w", err)
	}
	t.shutPipe = pipeFds

	// Raw socket for sending UDP responses with spoofed source IP
	udpFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(fd)
		syscall.Close(pipeFds[0])
		syscall.Close(pipeFds[1])
		return fmt.Errorf("create raw UDP send socket: %w", err)
	}
	if err := syscall.SetsockoptInt(udpFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		syscall.Close(pipeFds[0])
		syscall.Close(pipeFds[1])
		syscall.Close(udpFd)
		return fmt.Errorf("set IP_HDRINCL on UDP send: %w", err)
	}
	if t.cfg.WriteBuffer > 0 {
		SetSocketBufferSmart(udpFd, t.cfg.WriteBuffer, BufferDirSend)
	}
	t.udpSendFd = udpFd

	return nil
}

// ── Send ──

func (t *SynUDPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}
	if t.isServ {
		if t.isIPv6 {
			return t.sendUDP6(payload, dstIP, dstPort)
		}
		return t.sendUDP(payload, dstIP, dstPort)
	}
	if t.isIPv6 {
		return t.sendSyn6(payload, dstIP, dstPort)
	}
	return t.sendSyn(payload, dstIP, dstPort)
}

// sendSyn builds and sends a raw TCP SYN packet with payload.
// Zero-allocation hot path: uses sendBufPool for the work buffer, writes IP
// header and TCP segment in place, computes the TCP checksum by streaming
// the pseudo-header directly into a running accumulator (no temp slice).
func (t *SynUDPTransport) sendSyn(payload []byte, dstIP net.IP, dstPort uint16) error {
	dst4 := dstIP.To4()
	if len(t.srcIPv4s) == 0 || dst4 == nil {
		return errors.New("SYN transport only supports IPv4")
	}
	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]
	srcIP := src[:]

	const ipHL = 20
	const tcpHL = 32 // 20 base + 12 timestamp option
	tcpSegLen := tcpHL + len(payload)
	fullSize := ipHL + tcpSegLen

	t.synMu.Lock()
	seq := t.seq
	t.seq += uint32(len(payload))
	t.synMu.Unlock()

	srcPort := t.LocalPort()

	mtu := t.cfg.MTU
	if mtu <= 0 || mtu > 1500 {
		mtu = 1500
	}

	var dest syscall.SockaddrInet4
	copy(dest.Addr[:], dst4)

	// Work buffer from pool: layout is [0:ipHL] IP header, [ipHL:] TCP segment.
	bufPtr := sendBufPool.Get().(*[]byte)
	defer sendBufPool.Put(bufPtr)
	buf := *bufPtr
	if fullSize > len(buf) {
		return fmt.Errorf("packet too large for send buffer: %d > %d", fullSize, len(buf))
	}

	tcpSeg := buf[ipHL : ipHL+tcpSegLen]

	// ── TCP header ──
	binary.BigEndian.PutUint16(tcpSeg[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpSeg[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpSeg[4:8], seq)
	binary.BigEndian.PutUint32(tcpSeg[8:12], 0) // ack = 0 on SYN
	tcpSeg[12] = byte(tcpHL/4) << 4             // data offset
	tcpSeg[13] = 0x02                           // flags: SYN only
	binary.BigEndian.PutUint16(tcpSeg[14:16], 65535)
	binary.BigEndian.PutUint16(tcpSeg[16:18], 0) // checksum placeholder
	binary.BigEndian.PutUint16(tcpSeg[18:20], 0) // urgent ptr

	// TCP timestamp option: NOP + NOP + Timestamps
	tcpSeg[20] = 0x01
	tcpSeg[21] = 0x01
	tcpSeg[22] = 0x08
	tcpSeg[23] = 0x0A
	binary.BigEndian.PutUint32(tcpSeg[24:28], seq)
	binary.BigEndian.PutUint32(tcpSeg[28:32], 0)

	// ── Payload ──
	copy(tcpSeg[tcpHL:], payload)

	// ── TCP checksum (alloc-free, with pseudo-header streamed in) ──
	binary.BigEndian.PutUint16(tcpSeg[16:18], tcpChecksumInPlace(srcIP, dst4, tcpSeg))

	if fullSize <= mtu {
		// Single packet: write IP header in place at buf[0:20]
		writeIPHeader(buf[:ipHL], srcIP, dst4, 0, 0, false, syscall.IPPROTO_TCP, tcpSegLen)
		return t.sendRaw(t.synFd, buf[:fullSize], &dest)
	}

	// Need IP fragmentation. Send the TCP segment across multiple fragments;
	// each fragment reuses a pool buffer for its [IP header | data] layout.
	return t.sendFragmentedInPlace(srcIP, dst4, tcpSeg, mtu, syscall.IPPROTO_TCP, t.synFd, &dest)
}

// sendUDP builds and sends a raw UDP packet with spoofed source IP.
func (t *SynUDPTransport) sendUDP(payload []byte, dstIP net.IP, dstPort uint16) error {
	dst4 := dstIP.To4()
	if len(t.srcIPv4s) == 0 || dst4 == nil {
		return errors.New("UDP send only supports IPv4")
	}

	src := &t.srcIPv4s[mrand.IntN(len(t.srcIPv4s))]

	const ipHL = 20
	const udpHL = 8
	totalLen := ipHL + udpHL + len(payload)
	srcPort := t.LocalPort()

	bufPtr := sendBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

	// ── IPv4 header ──
	buf[0] = 0x45
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	buf[8] = 64 // TTL
	buf[9] = 17 // Protocol = UDP
	binary.BigEndian.PutUint16(buf[10:12], 0)
	copy(buf[12:16], src[:])
	copy(buf[16:20], dst4)
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHL]))

	// ── UDP header ──
	udp := buf[ipHL:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHL+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0)

	// ── Payload ──
	copy(udp[udpHL:], payload)

	// UDP checksum
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src[:], dst4, udp[:udpHL+len(payload)]))

	var dest syscall.SockaddrInet4
	copy(dest.Addr[:], dst4)

	err := syscall.Sendto(t.udpSendFd, buf, 0, &dest)
	sendBufPool.Put(bufPtr)
	return err
}

// ── Receive ──

func (t *SynUDPTransport) Receive(buf []byte) (int, net.IP, uint16, error) {
	if t.closed.Load() {
		return 0, nil, 0, ErrConnectionClosed
	}
	if t.isServ {
		if t.isIPv6 {
			return t.receiveSyn6(buf)
		}
		return t.receiveSyn(buf)
	}
	return t.receiveUDP(buf)
}

// receiveUDP reads from the standard UDP socket (client mode).
func (t *SynUDPTransport) receiveUDP(buf []byte) (int, net.IP, uint16, error) {
	n, addr, err := t.udpRecvConn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, 0, err
	}

	return n, addr.IP, uint16(addr.Port), nil
}

// receiveSyn reads raw TCP packets and extracts payload from SYN packets.
// Uses poll to wait on both the raw socket and a shutdown pipe so Close()
// can unblock the read immediately.
func (t *SynUDPTransport) receiveSyn(dst []byte) (int, net.IP, uint16, error) {
	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	pollFds := []unix.PollFd{
		{Fd: int32(t.tcpRecvFd), Events: unix.POLLIN},
		{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFds, -1)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if errors.Is(err, syscall.EBADF) {
				// Race with Close — fd already gone, treat as clean shutdown
				return 0, nil, 0, ErrConnectionClosed
			}
			return 0, nil, 0, fmt.Errorf("poll: %w", err)
		}

		// Shutdown pipe signaled
		if pollFds[1].Revents&unix.POLLIN != 0 {
			return 0, nil, 0, ErrConnectionClosed
		}

		// No data on raw socket yet (spurious wakeup)
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		n, _, err := syscall.Recvfrom(t.tcpRecvFd, buf, syscall.MSG_DONTWAIT)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return 0, nil, 0, fmt.Errorf("recvfrom tcp: %w", err)
		}
		if n < 40 { // min IP(20) + TCP(20)
			continue
		}

		// Parse IP header
		ihl := int(buf[0]&0x0F) * 4
		if ihl < 20 || n < ihl+20 {
			continue
		}
		proto := buf[9]
		if proto != syscall.IPPROTO_TCP {
			continue
		}

		srcIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])

		// Filter by peer spoof IP set
		if len(t.peerSpoofSet) > 0 {
			var srcKey [4]byte
			copy(srcKey[:], srcIP.To4())
			if _, ok := t.peerSpoofSet[srcKey]; !ok {
				continue
			}
		}

		// Parse TCP header
		tcp := buf[ihl:]
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])

		// Filter by our listen port
		if dstPort != t.cfg.ListenPort {
			continue
		}

		// Check SYN flag (0x02)
		flags := tcp[13]
		if flags&0x02 == 0 {
			continue // Not a SYN packet
		}

		// Extract data offset
		dataOffset := int(tcp[12]>>4) * 4
		if dataOffset < 20 {
			continue
		}

		// Extract payload
		totalTCPLen := n - ihl
		if dataOffset >= totalTCPLen {
			continue // No payload (bare SYN, ignore)
		}

		payloadLen := totalTCPLen - dataOffset
		if payloadLen == 0 {
			continue
		}

		copied := copy(dst, tcp[dataOffset:dataOffset+payloadLen])
		return copied, srcIP, srcPort, nil
	}
}

// ── Helpers ──

// writeIPHeader writes a 20-byte IPv4 header into dst, including the header
// checksum. Zero-alloc version of the legacy buildIPPacket helper.
func writeIPHeader(dst []byte, srcIP, dstIP net.IP, ipID, fragOffset uint16, moreFragments bool, proto byte, dataLen int) {
	const ipHL = 20
	totalLen := ipHL + dataLen
	dst[0] = 0x45
	dst[1] = 0x00
	binary.BigEndian.PutUint16(dst[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(dst[4:6], ipID)

	flagsOffset := fragOffset / 8
	if moreFragments {
		flagsOffset |= 0x2000
	}
	binary.BigEndian.PutUint16(dst[6:8], flagsOffset)

	dst[8] = 64
	dst[9] = proto
	dst[10] = 0
	dst[11] = 0
	copy(dst[12:16], srcIP)
	copy(dst[16:20], dstIP)
	binary.BigEndian.PutUint16(dst[10:12], ipChecksum(dst[:ipHL]))
}

// tcpChecksumInPlace computes the TCP checksum without allocating the
// 12-byte pseudo-header slice — it streams the pseudo-header values directly
// into the running RFC 1071 sum, then continues with the TCP segment.
func tcpChecksumInPlace(srcIP, dstIP net.IP, tcpSeg []byte) uint16 {
	var sum uint32
	// Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + tcpLen(2)
	sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	sum += uint32(syscall.IPPROTO_TCP) // zero byte + proto byte
	sum += uint32(len(tcpSeg))

	// TCP segment (caller has already zeroed the checksum field)
	n := len(tcpSeg)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSeg[i:]))
	}
	if n%2 == 1 {
		sum += uint32(tcpSeg[n-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumRFC1071(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (t *SynUDPTransport) sendRaw(fd int, pkt []byte, dest *syscall.SockaddrInet4) error {
	for {
		err := syscall.Sendto(fd, pkt, 0, dest)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			slog.Error("sendto failed", "component", "syn_udp", "error", err, "bytes", len(pkt))
		}
		return err
	}
}

// sendFragmentedInPlace ships `segment` as one or more IPv4 fragments. Each
// fragment is built in a single sendBufPool buffer (one pool Get/Put for the
// whole operation) by writing the IP header into fragBuf[:20] and copying
// the fragment data into fragBuf[20:]. No heap allocations.
func (t *SynUDPTransport) sendFragmentedInPlace(srcIP, dstIP net.IP, segment []byte, mtu int, proto byte, fd int, dest *syscall.SockaddrInet4) error {
	const ipHL = 20
	maxData := ((mtu - ipHL) / 8) * 8

	var idBuf [2]byte
	rand.Read(idBuf[:])
	ipID := binary.BigEndian.Uint16(idBuf[:])

	fragBufPtr := sendBufPool.Get().(*[]byte)
	defer sendBufPool.Put(fragBufPtr)
	fragBuf := *fragBufPtr

	offset := 0
	for offset < len(segment) {
		end := offset + maxData
		moreFrags := true
		if end >= len(segment) {
			end = len(segment)
			moreFrags = false
		}
		dataLen := end - offset
		writeIPHeader(fragBuf[:ipHL], srcIP, dstIP, ipID, uint16(offset), moreFrags, proto, dataLen)
		copy(fragBuf[ipHL:ipHL+dataLen], segment[offset:end])
		if err := t.sendRaw(fd, fragBuf[:ipHL+dataLen], dest); err != nil {
			return fmt.Errorf("fragment offset=%d: %w", offset, err)
		}
		offset = end
	}
	return nil
}

// ── Interface methods ──

func (t *SynUDPTransport) Close() error {
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
	if t.synFd >= 0 {
		syscall.Close(t.synFd)
	}
	if t.synFd6 >= 0 {
		syscall.Close(t.synFd6)
	}
	if t.tcpRecvFd >= 0 {
		syscall.Close(t.tcpRecvFd)
	}
	if t.tcpRecvFd6 >= 0 {
		syscall.Close(t.tcpRecvFd6)
	}
	if t.udpSendFd >= 0 {
		syscall.Close(t.udpSendFd)
	}
	if t.udpSendFd6 >= 0 {
		syscall.Close(t.udpSendFd6)
	}
	if t.udpRecvConn != nil {
		t.udpRecvConn.Close()
	}
	return nil
}

// SetReadDeadline sets the read deadline on the receive socket.
// Client mode: delegates to UDPConn. Server mode: signals the shutdown pipe
// to unblock the poll in receiveSyn when deadline is immediate.
func (t *SynUDPTransport) SetReadDeadline(deadline time.Time) error {
	if t.udpRecvConn != nil {
		return t.udpRecvConn.SetReadDeadline(deadline)
	}
	// Server mode: signal pipe for immediate deadline. Hold pipeMu to avoid
	// the fd-reuse race against Close.
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

func (t *SynUDPTransport) LocalPort() uint16 {
	if t.udpRecvConn != nil {
		return uint16(t.udpRecvConn.LocalAddr().(*net.UDPAddr).Port)
	}
	return t.cfg.ListenPort
}

func (t *SynUDPTransport) SetReadBuffer(size int) error {
	if t.udpRecvConn != nil {
		return t.udpRecvConn.SetReadBuffer(size)
	}
	return nil
}

func (t *SynUDPTransport) SetWriteBuffer(size int) error {
	if t.udpRecvConn != nil {
		return t.udpRecvConn.SetWriteBuffer(size)
	}
	return nil
}

// SyscallConn exposes the underlying socket so quic-go can set buffer sizes.
// Client mode delegates to the UDP conn; server mode wraps the raw TCP recv fd
// (v4 or v6 depending on which family the transport was initialised in).
func (t *SynUDPTransport) SyscallConn() (syscall.RawConn, error) {
	if t.udpRecvConn != nil {
		return t.udpRecvConn.SyscallConn()
	}
	if t.tcpRecvFd >= 0 {
		return &rawFdConn{fd: t.tcpRecvFd}, nil
	}
	if t.tcpRecvFd6 >= 0 {
		return &rawFdConn{fd: t.tcpRecvFd6}, nil
	}
	return nil, fmt.Errorf("no receive socket available")
}
