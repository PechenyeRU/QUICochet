package spooftester

import (
	"encoding/binary"
	"syscall"
)

// BuildUDPv4 builds a complete IPv4 + UDP packet whose body is the
// standard MinPayloadSize spoof-tester payload.
func BuildUDPv4(srcIP, dstIP [4]byte, srcPort, dstPort uint16, runID uint16, seq uint32, ipID uint16) []byte {
	const ipHdr = 20
	const udpHdr = 8
	pkt := make([]byte, ipHdr+udpHdr+MinPayloadSize)

	buildIPv4Header(pkt, srcIP, dstIP, syscall.IPPROTO_UDP, ipID)

	udp := pkt[ipHdr:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdr+MinPayloadSize))
	binary.BigEndian.PutUint16(udp[6:8], 0) // checksum, set after

	payload := BuildPayload(runID, seq, 0)
	copy(udp[udpHdr:], payload)

	sum := pseudoHeaderSumV4(srcIP, dstIP, syscall.IPPROTO_UDP, udpHdr+MinPayloadSize)
	sum = addBytes(sum, udp)
	csum := foldAndComplement(sum)
	if csum == 0 {
		// RFC 768: a transmitted zero UDP checksum is encoded as 0xFFFF
		// because 0 means "no checksum". The wire ones'-complement
		// representation of zero is 0xFFFF, which is what we want here.
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)
	return pkt
}

// BuildUDPv6 builds a complete IPv6 + UDP packet.
func BuildUDPv6(srcIP, dstIP [16]byte, srcPort, dstPort uint16, runID uint16, seq uint32) []byte {
	const ipHdr = 40
	const udpHdr = 8
	pkt := make([]byte, ipHdr+udpHdr+MinPayloadSize)

	buildIPv6Header(pkt, srcIP, dstIP, syscall.IPPROTO_UDP)

	udp := pkt[ipHdr:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdr+MinPayloadSize))
	binary.BigEndian.PutUint16(udp[6:8], 0)

	payload := BuildPayload(runID, seq, 0)
	copy(udp[udpHdr:], payload)

	sum := pseudoHeaderSumV6(srcIP, dstIP, syscall.IPPROTO_UDP, udpHdr+MinPayloadSize)
	sum = addBytes(sum, udp)
	csum := foldAndComplement(sum)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)
	return pkt
}
