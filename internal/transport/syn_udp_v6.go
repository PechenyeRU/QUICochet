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
//   - No manual IPv6 header construction: AF_INET6 + SOCK_RAW with
//     IPPROTO_TCP / IPPROTO_UDP makes the kernel build the IPv6
//     header. Source IP override comes from IPV6_PKTINFO cmsg per
//     packet, which requires IPV6_TRANSPARENT (we already require
//     CAP_NET_RAW, this needs CAP_NET_ADMIN as well; both are set
//     for any deployment that uses raw transports).
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
//   - synFd6: AF_INET6 raw, IPPROTO_TCP, IPV6_TRANSPARENT — used to
//     send TCP SYN with a spoofed source via IPV6_PKTINFO cmsg.
//   - udpRecvConn: standard udp6 listener for server replies.
func (t *SynUDPTransport) initClientV6() error {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("create raw IPv6 TCP socket: %w (need root/CAP_NET_RAW)", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("set IPV6_TRANSPARENT on SYN socket: %w (need CAP_NET_ADMIN to spoof v6 source)", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
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
//     (kernel strips the v6 header).
//   - udpSendFd6: AF_INET6 raw, IPPROTO_UDP, IPV6_TRANSPARENT —
//     sends UDP responses with spoofed source via IPV6_PKTINFO cmsg.
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

	udpFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("create raw IPv6 UDP send socket: %w", err)
	}
	if err := syscall.SetsockoptInt(udpFd, syscall.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
		syscall.Close(udpFd)
		return fmt.Errorf("set IPV6_TRANSPARENT on UDP6 send socket: %w (need CAP_NET_ADMIN to spoof v6 source)", err)
	}
	_ = syscall.SetsockoptInt(udpFd, syscall.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
	if t.cfg.WriteBuffer > 0 {
		SetSocketBufferSmart(udpFd, t.cfg.WriteBuffer, BufferDirSend)
	}
	t.udpSendFd6 = udpFd

	return nil
}

// sendSyn6 builds and sends a raw TCP SYN packet with payload over IPv6.
// Mirrors sendSyn (v4) but kernel constructs the IPv6 header; we provide
// the TCP segment with checksum computed over the v6 pseudo-header and
// the spoofed source via IPV6_PKTINFO.
func (t *SynUDPTransport) sendSyn6(payload []byte, dstIP net.IP, dstPort uint16) error {
	dst16 := dstIP.To16()
	if len(t.srcIPv6s) == 0 || dst16 == nil || dstIP.To4() != nil {
		return errors.New("v6 SYN transport requires v6 destination and v6 source")
	}
	src := pickSourceIPv6(t.srcIPv6s, payload)

	const tcpHL = 32 // 20 base + 12 timestamp option
	tcpSegLen := tcpHL + len(payload)

	mtu := t.cfg.MTU
	if mtu <= 0 || mtu > 1500 {
		mtu = 1500
	}
	// IPv6 header is 40 bytes vs 20 for v4 — tighter ceiling.
	if tcpSegLen+40 > mtu {
		return fmt.Errorf("v6 SYN packet exceeds MTU: %d > %d (no v6 fragmentation in syn_udp)", tcpSegLen+40, mtu)
	}

	t.synMu.Lock()
	seq := t.seq
	t.seq += uint32(len(payload))
	t.synMu.Unlock()

	srcPort := t.LocalPort()

	bufPtr := sendBufPool.Get().(*[]byte)
	defer sendBufPool.Put(bufPtr)
	buf := *bufPtr
	if tcpSegLen > len(buf) {
		return fmt.Errorf("v6 SYN packet too large for send buffer: %d > %d", tcpSegLen, len(buf))
	}
	tcpSeg := buf[:tcpSegLen]

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

	oobPtr := oobPool6.Get().(*[]byte)
	oob := *oobPtr
	buildPktinfo6(oob, src)

	dest := &unix.SockaddrInet6{Port: int(dstPort)}
	copy(dest.Addr[:], dst16)

	err := unix.Sendmsg(t.synFd6, tcpSeg, oob, dest, 0)
	oobPool6.Put(oobPtr)
	return err
}

// sendUDP6 builds and sends a raw UDP packet over IPv6 with spoofed src.
// Server-side reply path. Like sendSyn6, the kernel builds the IPv6
// header; we provide the UDP segment and the source via IPV6_PKTINFO.
func (t *SynUDPTransport) sendUDP6(payload []byte, dstIP net.IP, dstPort uint16) error {
	dst16 := dstIP.To16()
	if len(t.srcIPv6s) == 0 || dst16 == nil || dstIP.To4() != nil {
		return errors.New("v6 UDP send requires v6 destination and v6 source")
	}
	src := pickSourceIPv6(t.srcIPv6s, payload)

	const udpHL = 8
	udpLen := udpHL + len(payload)

	srcPort := t.LocalPort()

	bufPtr := sendBufPool.Get().(*[]byte)
	defer sendBufPool.Put(bufPtr)
	buf := (*bufPtr)[:udpLen]

	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(buf[6:8], 0)
	copy(buf[udpHL:], payload)
	binary.BigEndian.PutUint16(buf[6:8], udp6Checksum(src[:], dst16, buf[:udpLen]))

	oobPtr := oobPool6.Get().(*[]byte)
	oob := *oobPtr
	buildPktinfo6(oob, src)

	dest := &unix.SockaddrInet6{Port: int(dstPort)}
	copy(dest.Addr[:], dst16)

	err := unix.Sendmsg(t.udpSendFd6, buf, oob, dest, 0)
	oobPool6.Put(oobPtr)
	return err
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

// tcp6ChecksumInPlace computes the TCP checksum with an IPv6
// pseudo-header. RFC 2460 §8.1: src(16) + dst(16) + upperLayerLen(4)
// + zeroes(3) + nextHeader(1).
func tcp6ChecksumInPlace(srcIP, dstIP []byte, tcpSeg []byte) uint16 {
	var sum uint32
	// src + dst (32 bytes total)
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	// upperLayerLen (32-bit, but for our sizes the high 16 bits are 0)
	sum += uint32(len(tcpSeg))
	// next header = TCP (6); upper 24 bits zero, low 8 bits is 6
	sum += uint32(syscall.IPPROTO_TCP)

	// TCP segment (caller has zeroed the checksum field).
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
