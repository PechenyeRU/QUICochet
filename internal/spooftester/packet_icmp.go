package spooftester

import (
	"encoding/binary"
	"syscall"
)

// ICMP type codes.
const (
	icmpEchoRequestV4 = 8   // ICMP Echo Request (proto 1)
	icmpEchoRequestV6 = 128 // ICMPv6 Echo Request (proto 58)
)

// IPProto numbers we support for the ICMP-style transports.
const (
	ipProtoICMPv4    = 1
	ipProtoICMPv6 = 58
)

// BuildICMPv4Echo builds a complete IPv4 + ICMP Echo Request packet
// using transport.type=icmp framing (proto 1, type 8).
//
// The payload (after the 8-byte ICMP header) is the standard
// MinPayloadSize spoof-tester payload, so receivers identify our
// packets by the same magic regardless of L4.
func BuildICMPv4Echo(srcIP, dstIP [4]byte, runID uint16, seq uint32, ipID uint16) []byte {
	return buildICMPv4Generic(srcIP, dstIP, ipProtoICMPv4, icmpEchoRequestV4, runID, seq, ipID)
}

// BuildICMPv6OverIPv4Echo builds an IPv4 packet whose Protocol field is
// 58 (ICMPv6) and whose body is an ICMPv6 Echo Request. This is the
// transport.type=icmpv6 trick spoof-tunnel v3 introduced — same wire
// shape as the production transport so we test what we'll deploy.
func BuildICMPv6OverIPv4Echo(srcIP, dstIP [4]byte, runID uint16, seq uint32, ipID uint16) []byte {
	return buildICMPv4Generic(srcIP, dstIP, ipProtoICMPv6, icmpEchoRequestV6, runID, seq, ipID)
}

// buildICMPv4Generic factors out the v4 frame with a parameterized
// IP-protocol byte and ICMP type byte. Both ICMP and the ICMPv6-over-v4
// trick use the same 8-byte ICMP-shaped header layout (type, code, csum,
// id, seq), only the protocol number and type code differ.
func buildICMPv4Generic(srcIP, dstIP [4]byte, ipProto, icmpType byte, runID uint16, seq uint32, ipID uint16) []byte {
	const ipHdr = 20
	const icmpHdr = 8
	pkt := make([]byte, ipHdr+icmpHdr+MinPayloadSize)

	buildIPv4Header(pkt, srcIP, dstIP, ipProto, ipID)

	body := pkt[ipHdr:]
	body[0] = icmpType
	body[1] = 0 // code
	binary.BigEndian.PutUint16(body[2:4], 0) // csum, set after
	binary.BigEndian.PutUint16(body[4:6], runID)
	binary.BigEndian.PutUint16(body[6:8], uint16(seq))

	payload := BuildPayload(runID, seq, 0)
	copy(body[icmpHdr:], payload)

	csum := checksumRFC1071(body)
	binary.BigEndian.PutUint16(body[2:4], csum)
	return pkt
}

// BuildICMPv6Echo builds a real IPv6 + ICMPv6 Echo Request (proto 58).
// Used when the operator selects an IPv6 destination, distinct from
// the ICMPv6-over-IPv4 trick above.
func BuildICMPv6Echo(srcIP, dstIP [16]byte, runID uint16, seq uint32) []byte {
	const ipHdr = 40
	const icmpHdr = 8
	pkt := make([]byte, ipHdr+icmpHdr+MinPayloadSize)

	buildIPv6Header(pkt, srcIP, dstIP, syscall.IPPROTO_ICMPV6)

	body := pkt[ipHdr:]
	body[0] = icmpEchoRequestV6
	body[1] = 0
	binary.BigEndian.PutUint16(body[2:4], 0)
	binary.BigEndian.PutUint16(body[4:6], runID)
	binary.BigEndian.PutUint16(body[6:8], uint16(seq))

	payload := BuildPayload(runID, seq, 0)
	copy(body[icmpHdr:], payload)

	sum := pseudoHeaderSumV6(srcIP, dstIP, syscall.IPPROTO_ICMPV6, icmpHdr+MinPayloadSize)
	sum = addBytes(sum, body)
	binary.BigEndian.PutUint16(body[2:4], foldAndComplement(sum))
	return pkt
}

// ParseInboundICMPv4 inspects a raw socket buffer (kernel strips L2
// but keeps the IP header). Returns srcIP + run-id + seq when the
// frame is a spoof-tester echo, ok=false otherwise.
//
// expectedICMPProto is 1 for transport.type=icmp and 58 for
// transport.type=icmpv6 — receivers run a separate listener per
// protocol so we don't mix counters.
//
// expectedICMPType is 8 for ICMP and 128 for ICMPv6-over-IPv4.
func ParseInboundICMPv4(buf []byte, expectedIPProto, expectedICMPType byte) (srcIP [4]byte, runID uint16, seq uint32, ok bool) {
	if len(buf) < 20+8+payloadHeaderSize {
		return srcIP, 0, 0, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl+8+payloadHeaderSize {
		return srcIP, 0, 0, false
	}
	if buf[9] != expectedIPProto {
		return srcIP, 0, 0, false
	}
	copy(srcIP[:], buf[12:16])
	body := buf[ihl:]
	if body[0] != expectedICMPType {
		return srcIP, 0, 0, false
	}
	rid, sq, err := ParsePayload(body[8:])
	if err != nil {
		return srcIP, 0, 0, false
	}
	return srcIP, rid, sq, true
}

// ParseInboundICMPv6 inspects an inbound IPv6 ICMPv6 frame (the kernel
// AF_INET6/SOCK_RAW gives us only the ICMPv6 message body, so the
// caller passes srcIP from recvfrom).
func ParseInboundICMPv6(body []byte, srcIP [16]byte) (out [16]byte, runID uint16, seq uint32, ok bool) {
	if len(body) < 8+payloadHeaderSize {
		return out, 0, 0, false
	}
	if body[0] != icmpEchoRequestV6 {
		return out, 0, 0, false
	}
	rid, sq, err := ParsePayload(body[8:])
	if err != nil {
		return out, 0, 0, false
	}
	return srcIP, rid, sq, true
}
