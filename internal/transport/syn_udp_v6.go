package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// IPv6 syn_udp transport — single-stack v6 mirror of syn_udp.go.
//
// Design differences from v4:
//
//   - Send uses IPPROTO_RAW + IPV6_HDRINCL so we control the full
//     IPv6 header (40 bytes) — symmetric with the v4 path's
//     IPPROTO_RAW + IP_HDRINCL. This lets us put the spoofed source
//     directly in the IP header without relying on IPV6_PKTINFO
//     cmsg (which the kernel rejects with EINVAL for the IPPROTO_TCP
//     send-socket variant we tried first). The TCP checksum can then
//     be computed against the actual on-wire src.
//
//   - No fragmentation: IPv6 only fragments via the Fragment Header
//     (extension), which is rare on the public internet and breaks
//     with strict middleboxes. We reject oversized packets and rely
//     on QUIC's MTU-aware send path to keep us inside the link MTU.
//
//   - Receive path is simpler: AF_INET6 + SOCK_RAW + IPPROTO_TCP
//     returns just the TCP segment (kernel strips the IPv6 header
//     and any extension headers), so we go straight to TCP parsing.
//     The source address comes from the recvfrom sockaddr_in6, no
//     IP-header parsing of our own.
//
// Dual-stack syn_udp (one client/server speaking both v4 and v6) is
// out of scope for this release: it would need parallel recv loops on
// two raw sockets per role since the kernel routes the v4 and v6
// stacks to disjoint sockets. Tracked as Phase 5.

// initClientV6 sets up the client-side v6 sockets:
//   - synFd6: AF_INET6 raw, IPPROTO_RAW, IPV6_HDRINCL — used to send
//     a fully hand-built IPv6 + TCP SYN packet with a spoofed source.
//     IPV6_HDRINCL bypasses the kernel's source-address validation
//     so no extra capability beyond CAP_NET_RAW is required.
//   - udpRecvConn: standard udp6 listener for server replies.
func (t *SynUDPTransport) initClientV6() error {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("create raw IPv6 socket: %w (need root/CAP_NET_RAW)", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("set IPV6_HDRINCL on SYN socket: %w (need Linux ≥ 5.4)", err)
	}
	t.synFd6 = fd

	addr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[::]:%d", t.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("resolve UDP6 addr: %w", err)
	}
	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return fmt.Errorf("listen UDP6: %w", err)
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

// initServerV6 sets up the server-side v6 sockets:
//   - tcpRecvFd6: AF_INET6 raw, IPPROTO_TCP — receives TCP SYNs
//     (kernel strips the v6 header and any extension chains, so we
//     get just the TCP segment).
//   - udpSendFd6: AF_INET6 raw, IPPROTO_RAW, IPV6_HDRINCL — sends
//     UDP responses with a fully hand-built v6 header + UDP segment.
//     Same approach as the client SYN socket and as the v4 send path,
//     bypassing kernel source-validation without IPV6_TRANSPARENT.
//   - shutPipe: same shutdown signaller as v4.
func (t *SynUDPTransport) initServerV6() error {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("create raw IPv6 TCP recv socket: %w (need root/CAP_NET_RAW)", err)
	}
	if t.cfg.ReadBuffer > 0 {
		SetSocketBufferSmart(fd, t.cfg.ReadBuffer, BufferDirRecv)
	}
	t.tcpRecvFd6 = fd

	var pipeFds [2]int
	if err := syscall.Pipe(pipeFds[:]); err != nil {
		return fmt.Errorf("create shutdown pipe: %w", err)
	}
	if err := unix.SetNonblock(pipeFds[1], true); err != nil {
		syscall.Close(pipeFds[0])
		syscall.Close(pipeFds[1])
		return fmt.Errorf("set nonblock on shutdown pipe: %w", err)
	}
	t.shutPipe = pipeFds

	udpFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("create raw IPv6 UDP send socket: %w", err)
	}
	if err := syscall.SetsockoptInt(udpFd, syscall.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		syscall.Close(udpFd)
		return fmt.Errorf("set IPV6_HDRINCL on UDP6 send socket: %w (need Linux ≥ 5.4)", err)
	}
	if t.cfg.WriteBuffer > 0 {
		SetSocketBufferSmart(udpFd, t.cfg.WriteBuffer, BufferDirSend)
	}
	t.udpSendFd6 = udpFd

	return nil
}

// v6IPHL is the fixed IPv6 header size; v6WireCeiling is the link
// MTU we use as the no-fragment send ceiling. cfg.MTU is the QUIC +
// obfuscator payload size, NOT the wire MTU — wire adds the chosen
// upper-layer header + 40 (IPv6). Operators on tunnels with smaller
// link MTU should reduce performance.mtu so QUIC packets shrink.
const (
	v6IPHL        = 40
	v6WireCeiling = 1500
)

// sendSyn6 builds and sends a full IPv6 + TCP SYN packet with a
// spoofed source. Mirrors sendSyn (v4) but with the 40-byte v6 header
// and the v6 pseudo-header in the TCP checksum.
//
// Inlined (vs an extracted prepare/finish helper) because every
// abstraction layer here adds a heap escape per send — measured
// ~22% throughput regression on syn_udp v6 with a closure-based
// helper. The duplication with sendUDP6 is the price.
func (t *SynUDPTransport) sendSyn6(payload []byte, dstIP net.IP, dstPort uint16) error {
	dst16 := dstIP.To16()
	if len(t.srcIPv6s) == 0 || dst16 == nil || dstIP.To4() != nil {
		return errors.New("v6 SYN transport requires v6 destination and v6 source")
	}
	src := pickSourceIPv6(t.srcIPv6s, payload)

	const tcpHL = 32 // 20 base + 12 timestamp option
	tcpSegLen := tcpHL + len(payload)
	wireSize := v6IPHL + tcpSegLen
	if wireSize > v6WireCeiling {
		return fmt.Errorf("v6 SYN wire packet %d > link MTU %d (no v6 fragmentation in syn_udp; reduce performance.mtu)",
			wireSize, v6WireCeiling)
	}

	t.synMu.Lock()
	seq := t.seq
	t.seq += uint32(len(payload))
	t.synMu.Unlock()

	srcPort := t.LocalPort()

	bufPtr := sendBufPool.Get().(*[]byte)
	defer sendBufPool.Put(bufPtr)
	buf := *bufPtr
	if wireSize > len(buf) {
		return fmt.Errorf("v6 SYN packet too large for send buffer: %d > %d", wireSize, len(buf))
	}
	pkt := buf[:wireSize]

	writeIPv6Header(pkt[:v6IPHL], src[:], dst16, syscall.IPPROTO_TCP, tcpSegLen)

	tcpSeg := pkt[v6IPHL:wireSize]
	binary.BigEndian.PutUint16(tcpSeg[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpSeg[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpSeg[4:8], seq)
	binary.BigEndian.PutUint32(tcpSeg[8:12], 0)
	tcpSeg[12] = byte(tcpHL/4) << 4
	tcpSeg[13] = 0x02 // SYN flag
	binary.BigEndian.PutUint16(tcpSeg[14:16], 65535)
	binary.BigEndian.PutUint16(tcpSeg[16:18], 0)
	binary.BigEndian.PutUint16(tcpSeg[18:20], 0)
	tcpSeg[20] = 0x01
	tcpSeg[21] = 0x01
	tcpSeg[22] = 0x08
	tcpSeg[23] = 0x0A
	binary.BigEndian.PutUint32(tcpSeg[24:28], seq)
	binary.BigEndian.PutUint32(tcpSeg[28:32], 0)
	copy(tcpSeg[tcpHL:], payload)

	binary.BigEndian.PutUint16(tcpSeg[16:18], tcp6ChecksumInPlace(src[:], dst16, tcpSeg))

	dest := &syscall.SockaddrInet6{}
	copy(dest.Addr[:], dst16)
	return syscall.Sendto(t.synFd6, pkt, 0, dest)
}

// sendUDP6 builds and sends a full IPv6 + UDP packet with a spoofed
// source. Server-side reply path. Inlined for the same hot-path
// reasons as sendSyn6.
func (t *SynUDPTransport) sendUDP6(payload []byte, dstIP net.IP, dstPort uint16) error {
	dst16 := dstIP.To16()
	if len(t.srcIPv6s) == 0 || dst16 == nil || dstIP.To4() != nil {
		return errors.New("v6 UDP send requires v6 destination and v6 source")
	}
	src := pickSourceIPv6(t.srcIPv6s, payload)

	const udpHL = 8
	udpLen := udpHL + len(payload)
	wireSize := v6IPHL + udpLen
	if wireSize > v6WireCeiling {
		return fmt.Errorf("v6 UDP wire packet %d > link MTU %d", wireSize, v6WireCeiling)
	}

	srcPort := t.LocalPort()

	bufPtr := sendBufPool.Get().(*[]byte)
	defer sendBufPool.Put(bufPtr)
	buf := *bufPtr
	if wireSize > len(buf) {
		return fmt.Errorf("v6 UDP packet too large for send buffer: %d > %d", wireSize, len(buf))
	}
	pkt := buf[:wireSize]

	writeIPv6Header(pkt[:v6IPHL], src[:], dst16, syscall.IPPROTO_UDP, udpLen)

	udp := pkt[v6IPHL:wireSize]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[udpHL:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(src[:], dst16, udp))

	dest := &syscall.SockaddrInet6{}
	copy(dest.Addr[:], dst16)
	return syscall.Sendto(t.udpSendFd6, pkt, 0, dest)
}

// receiveSyn6 reads raw TCP packets on the v6 raw socket and extracts
// payload from SYN packets. Unlike v4 there is no IP header to parse —
// AF_INET6 raw with a non-IPPROTO_RAW protocol returns just the TCP
// segment, so the source address must come from the recvfrom
// sockaddr_in6.
func (t *SynUDPTransport) receiveSyn6(dst []byte) (int, net.IP, uint16, error) {
	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	pollFds := []unix.PollFd{
		{Fd: int32(t.tcpRecvFd6), Events: unix.POLLIN},
		{Fd: int32(t.shutPipe[0]), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFds, -1)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if errors.Is(err, syscall.EBADF) {
				return 0, nil, 0, ErrConnectionClosed
			}
			return 0, nil, 0, fmt.Errorf("poll v6: %w", err)
		}

		if pollFds[1].Revents&unix.POLLIN != 0 {
			return 0, nil, 0, ErrConnectionClosed
		}

		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		n, from, err := syscall.Recvfrom(t.tcpRecvFd6, buf, syscall.MSG_DONTWAIT)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return 0, nil, 0, fmt.Errorf("recvfrom v6 tcp: %w", err)
		}
		if n < 20 { // min TCP header
			continue
		}

		// Source address from sockaddr_in6.
		sa6, ok := from.(*syscall.SockaddrInet6)
		if !ok {
			continue
		}
		srcIP := net.IP(make([]byte, 16))
		copy(srcIP, sa6.Addr[:])

		// Reject v4-mapped-in-v6 sources reaching this socket.
		// The recv socket is AF_INET6 single-stack (IPV6_V6ONLY=1
		// kernel default for raw sockets), so this should not
		// happen — but defensive in case the kernel default
		// changes underfoot.
		if srcIP.To4() != nil {
			continue
		}

		// Filter by peer spoof IP set.
		if len(t.peerSpoofSet6) > 0 {
			var srcKey [16]byte
			copy(srcKey[:], srcIP.To16())
			if _, ok := t.peerSpoofSet6[srcKey]; !ok {
				continue
			}
		}

		// Parse TCP header — same layout as v4 (TCP is L4-family-agnostic).
		tcp := buf[:n]
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		srcPort := binary.BigEndian.Uint16(tcp[0:2])

		if dstPort != t.cfg.ListenPort {
			continue
		}

		flags := tcp[13]
		if flags&0x02 == 0 {
			continue // not a SYN
		}

		dataOffset := int(tcp[12]>>4) * 4
		if dataOffset < 20 || dataOffset >= n {
			continue
		}

		payloadLen := n - dataOffset
		if payloadLen <= 0 {
			continue
		}

		copied := copy(dst, tcp[dataOffset:dataOffset+payloadLen])
		return copied, srcIP, srcPort, nil
	}
}

