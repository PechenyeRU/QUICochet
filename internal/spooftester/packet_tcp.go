package spooftester

import (
	"encoding/binary"
	"hash/fnv"
	"syscall"
)

// MagicSeq16 is the upper 16 bits of the TCP SEQ for spoof-tester SYNs.
// Receivers use this constant to filter out the avalanche of unrelated
// SYNs they'd otherwise see on their listening port (port scanners,
// stale clients, deliberate background traffic).
//
// FNV-1a("QCST") truncated to 16 bits, so it stays stable across
// runs and machines while having ~0% collision rate with the
// near-uniform SEQ distribution real TCP stacks generate.
var MagicSeq16 = func() uint16 {
	h := fnv.New32a()
	h.Write(MagicTag[:])
	s := h.Sum32()
	return uint16(s ^ (s >> 16))
}()

// BuildTCPSYNv4 builds a complete IPv4+TCP SYN packet for the spoof
// tester. Layout:
//
//   IP(20) + TCP(20) + 0 payload
//
// The TCP SEQ field doubles as our magic + counter:
//   SEQ[31:16] = MagicSeq16
//   SEQ[15:0]  = seq counter (per src-IP)
// The TCP source port is set to runID so the receiver can separate
// concurrent runs without state.
//
// No TCP options. ACK=0, window=64240 (a normal Linux default).
func BuildTCPSYNv4(srcIP, dstIP [4]byte, dstPort, runID uint16, seq uint32, ipID uint16) []byte {
	const ipHdr = 20
	const tcpHdr = 20
	pkt := make([]byte, ipHdr+tcpHdr)

	buildIPv4Header(pkt, srcIP, dstIP, syscall.IPPROTO_TCP, ipID)

	tcp := pkt[ipHdr:]
	binary.BigEndian.PutUint16(tcp[0:2], runID)  // src port
	binary.BigEndian.PutUint16(tcp[2:4], dstPort) // dst port
	binary.BigEndian.PutUint32(tcp[4:8], (uint32(MagicSeq16)<<16)|(seq&0xFFFF))
	binary.BigEndian.PutUint32(tcp[8:12], 0) // ACK seq
	tcp[12] = 0x50                            // data offset = 5 (20 byte header)
	tcp[13] = 0x02                            // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window
	binary.BigEndian.PutUint16(tcp[16:18], 0)     // checksum (set below)
	binary.BigEndian.PutUint16(tcp[18:20], 0)     // urgent

	sum := pseudoHeaderSumV4(srcIP, dstIP, syscall.IPPROTO_TCP, tcpHdr)
	sum = addBytes(sum, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], foldAndComplement(sum))

	return pkt
}

// BuildTCPSYNv6 builds an IPv6+TCP SYN with the same encoding as v4.
// IPv6 has no embedded IP-level checksum; the TCP checksum picks up
// the v6 pseudo-header (RFC 2460 §8.1).
func BuildTCPSYNv6(srcIP, dstIP [16]byte, dstPort, runID uint16, seq uint32) []byte {
	const ipHdr = 40
	const tcpHdr = 20
	pkt := make([]byte, ipHdr+tcpHdr)

	buildIPv6Header(pkt, srcIP, dstIP, syscall.IPPROTO_TCP)

	tcp := pkt[ipHdr:]
	binary.BigEndian.PutUint16(tcp[0:2], runID)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], (uint32(MagicSeq16)<<16)|(seq&0xFFFF))
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)

	sum := pseudoHeaderSumV6(srcIP, dstIP, syscall.IPPROTO_TCP, tcpHdr)
	sum = addBytes(sum, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], foldAndComplement(sum))

	return pkt
}

// ParseInboundTCP inspects an inbound IPv4+TCP packet (as delivered by
// SOCK_RAW, IPPROTO_TCP — kernel strips the link layer but leaves the
// IP header intact). Returns the source IP, runID and packet sequence
// when the packet is a spoof-tester SYN; the second return tells the
// caller whether the magic matched.
func ParseInboundTCPv4(buf []byte, expectedDstPort uint16) (srcIP [4]byte, runID uint16, seq uint16, ok bool) {
	if len(buf) < 40 {
		return srcIP, 0, 0, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl+20 {
		return srcIP, 0, 0, false
	}
	if buf[9] != syscall.IPPROTO_TCP {
		return srcIP, 0, 0, false
	}
	copy(srcIP[:], buf[12:16])
	tcp := buf[ihl:]
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	if dstPort != expectedDstPort {
		return srcIP, 0, 0, false
	}
	flags := tcp[13]
	if flags&0x02 == 0 {
		return srcIP, 0, 0, false // not SYN
	}
	seqRaw := binary.BigEndian.Uint32(tcp[4:8])
	if uint16(seqRaw>>16) != MagicSeq16 {
		return srcIP, 0, 0, false
	}
	runID = binary.BigEndian.Uint16(tcp[0:2])
	seq = uint16(seqRaw & 0xffff)
	return srcIP, runID, seq, true
}

// ParseInboundTCPv6 is the v6 counterpart. Linux's
// AF_INET6/SOCK_RAW/IPPROTO_TCP delivers from the L4 header onward
// (no IPv6 fixed header in the buffer), so the parser is given the
// source IP separately by the recvfrom caller.
func ParseInboundTCPv6(tcp []byte, srcIP [16]byte, expectedDstPort uint16) (out [16]byte, runID uint16, seq uint16, ok bool) {
	if len(tcp) < 20 {
		return out, 0, 0, false
	}
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	if dstPort != expectedDstPort {
		return out, 0, 0, false
	}
	flags := tcp[13]
	if flags&0x02 == 0 {
		return out, 0, 0, false
	}
	seqRaw := binary.BigEndian.Uint32(tcp[4:8])
	if uint16(seqRaw>>16) != MagicSeq16 {
		return out, 0, 0, false
	}
	runID = binary.BigEndian.Uint16(tcp[0:2])
	seq = uint16(seqRaw & 0xffff)
	return srcIP, runID, seq, true
}
