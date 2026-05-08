package spooftester

import "encoding/binary"

// checksumRFC1071 is the standard one's-complement 16-bit Internet
// checksum used by IP, ICMP, TCP, UDP. Independent copy of the helper
// in internal/transport/syn_udp.go so this package stays self-contained
// (the spoof tester deliberately bypasses the transport.Transport
// abstraction — see iplist.go header).
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

// pseudoHeaderSumV4 returns the partial RFC 1071 sum of an IPv4 TCP/UDP
// pseudo-header (src(4) + dst(4) + zero + proto + length).
func pseudoHeaderSumV4(srcIP, dstIP [4]byte, proto, length int) uint32 {
	var sum uint32
	sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

// pseudoHeaderSumV6 returns the partial RFC 1071 sum of an IPv6 TCP/UDP/
// ICMPv6 pseudo-header (src(16) + dst(16) + length(4) + zeroes(3) +
// next-header(1)).
func pseudoHeaderSumV6(srcIP, dstIP [16]byte, nextHeader, length int) uint32 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	sum += uint32(length)
	sum += uint32(nextHeader)
	return sum
}

// foldAndComplement finalises an RFC 1071 running sum into the wire
// 16-bit checksum.
func foldAndComplement(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// addBytes adds a byte slice to a running RFC 1071 sum (caller folds).
func addBytes(sum uint32, data []byte) uint32 {
	n := len(data)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	return sum
}
