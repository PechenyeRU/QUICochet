package spooftester

import (
	"encoding/binary"
)

// buildIPv4Header writes a minimal 20-byte IPv4 header (no options) into
// dst[:20]. Caller is responsible for filling in the remainder of the
// packet and for sizing dst correctly. proto is the IP protocol field
// (e.g. IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1, ICMPv6=58).
//
// The IP checksum is computed over the 20-byte header and stored in
// place. Total length is set to len(dst) (assumed equal to header +
// L4 length).
func buildIPv4Header(dst []byte, srcIP, dstIP [4]byte, proto byte, ipID uint16) {
	dst[0] = 0x45 // version=4, IHL=5
	dst[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(dst[2:4], uint16(len(dst)))
	binary.BigEndian.PutUint16(dst[4:6], ipID)
	dst[6] = 0x40 // DF flag
	dst[7] = 0
	dst[8] = 64 // TTL
	dst[9] = proto
	binary.BigEndian.PutUint16(dst[10:12], 0) // checksum, set after
	copy(dst[12:16], srcIP[:])
	copy(dst[16:20], dstIP[:])
	csum := checksumRFC1071(dst[:20])
	binary.BigEndian.PutUint16(dst[10:12], csum)
}

// buildIPv6Header writes a 40-byte IPv6 fixed header into dst[:40].
// nextHeader is the L4 protocol number (e.g. 6=TCP, 17=UDP, 58=ICMPv6).
// payloadLen must equal len(dst) - 40.
func buildIPv6Header(dst []byte, srcIP, dstIP [16]byte, nextHeader byte) {
	dst[0] = 0x60 // version=6
	dst[1] = 0
	dst[2] = 0
	dst[3] = 0
	binary.BigEndian.PutUint16(dst[4:6], uint16(len(dst)-40))
	dst[6] = nextHeader
	dst[7] = 64 // hop limit
	copy(dst[8:24], srcIP[:])
	copy(dst[24:40], dstIP[:])
}
