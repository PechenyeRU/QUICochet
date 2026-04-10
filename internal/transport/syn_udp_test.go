package transport

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func TestChecksumRFC1071(t *testing.T) {
	t.Run("RFC1071 example vector", func(t *testing.T) {
		// RFC 1071 section 3 example data
		data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
		got := checksumRFC1071(data)
		if got == 0 {
			t.Error("checksum of non-zero data should not be zero")
		}
		// One's complement sum of the 16-bit words, then inverted.
		want := uint16(0x220d)
		if got != want {
			t.Errorf("checksumRFC1071 = 0x%04x, want 0x%04x", got, want)
		}
	})

	t.Run("even-length data", func(t *testing.T) {
		data := []byte{0xAB, 0xCD, 0x12, 0x34}
		got := checksumRFC1071(data)
		if got == 0 {
			t.Error("checksum of non-zero data should not be zero")
		}
	})

	t.Run("odd-length data", func(t *testing.T) {
		// Single trailing byte should be treated as high byte with zero low byte
		data := []byte{0x01, 0x02, 0x03}
		got := checksumRFC1071(data)
		if got == 0 {
			t.Error("checksum of non-zero odd-length data should not be zero")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		got := checksumRFC1071([]byte{})
		// Sum is 0, complement is 0xFFFF
		if got != 0xFFFF {
			t.Errorf("checksumRFC1071(empty) = 0x%04x, want 0xFFFF", got)
		}
	})

	t.Run("all zeros", func(t *testing.T) {
		data := make([]byte, 16)
		got := checksumRFC1071(data)
		// Sum is 0, complement is 0xFFFF
		if got != 0xFFFF {
			t.Errorf("checksumRFC1071(all zeros) = 0x%04x, want 0xFFFF", got)
		}
	})

	t.Run("self-check property", func(t *testing.T) {
		// Compute checksum, append it to data, recompute — should get 0
		original := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00}
		csum := checksumRFC1071(original)

		// Append checksum as big-endian to original data
		withCsum := make([]byte, len(original)+2)
		copy(withCsum, original)
		binary.BigEndian.PutUint16(withCsum[len(original):], csum)

		recheck := checksumRFC1071(withCsum)
		if recheck != 0 {
			t.Errorf("self-check failed: recomputed = 0x%04x, want 0x0000", recheck)
		}
	})
}

func TestTcpChecksum(t *testing.T) {
	t.Run("known segment", func(t *testing.T) {
		srcIP := net.ParseIP("192.168.1.1").To4()
		dstIP := net.ParseIP("10.0.0.1").To4()

		// Build a minimal 20-byte TCP header (SYN, no options)
		tcpSeg := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpSeg[0:2], 12345)  // src port
		binary.BigEndian.PutUint16(tcpSeg[2:4], 80)     // dst port
		binary.BigEndian.PutUint32(tcpSeg[4:8], 100)    // seq
		binary.BigEndian.PutUint32(tcpSeg[8:12], 0)     // ack
		tcpSeg[12] = 5 << 4                              // data offset = 5 (20 bytes)
		tcpSeg[13] = 0x02                                // SYN flag
		binary.BigEndian.PutUint16(tcpSeg[14:16], 65535) // window
		// checksum at [16:18] is zero
		// urgent pointer at [18:20] is zero

		csum := tcpChecksum(srcIP, dstIP, tcpSeg)
		if csum == 0 {
			t.Error("TCP checksum should be non-zero for this segment")
		}
	})

	t.Run("self-check property", func(t *testing.T) {
		srcIP := net.ParseIP("10.0.0.5").To4()
		dstIP := net.ParseIP("10.0.0.10").To4()

		tcpSeg := make([]byte, 24) // 20 header + 4 payload
		binary.BigEndian.PutUint16(tcpSeg[0:2], 9999)
		binary.BigEndian.PutUint16(tcpSeg[2:4], 443)
		binary.BigEndian.PutUint32(tcpSeg[4:8], 1)
		tcpSeg[12] = 5 << 4
		tcpSeg[13] = 0x02
		binary.BigEndian.PutUint16(tcpSeg[14:16], 32768)
		// Payload
		tcpSeg[20] = 0xDE
		tcpSeg[21] = 0xAD
		tcpSeg[22] = 0xBE
		tcpSeg[23] = 0xEF

		// Compute and insert checksum
		csum := tcpChecksum(srcIP, dstIP, tcpSeg)
		binary.BigEndian.PutUint16(tcpSeg[16:18], csum)

		// Recompute — should fold to 0
		recheck := tcpChecksum(srcIP, dstIP, tcpSeg)
		if recheck != 0 {
			t.Errorf("self-check failed: recomputed TCP checksum = 0x%04x, want 0x0000", recheck)
		}
	})
}

func TestBuildIPPacket(t *testing.T) {
	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{10, 0, 0, 1}
	payload := []byte("hello world")

	t.Run("basic header fields", func(t *testing.T) {
		pkt := buildIPPacket(srcIP, dstIP, 0x1234, 0, false, syscall.IPPROTO_TCP, payload)

		// Version 4, IHL 5
		if pkt[0] != 0x45 {
			t.Errorf("pkt[0] = 0x%02x, want 0x45", pkt[0])
		}

		// Total length = 20 + len(payload)
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		want := uint16(20 + len(payload))
		if totalLen != want {
			t.Errorf("total length = %d, want %d", totalLen, want)
		}

		// Protocol
		if pkt[9] != syscall.IPPROTO_TCP {
			t.Errorf("protocol = %d, want %d", pkt[9], syscall.IPPROTO_TCP)
		}

		// Source IP at bytes [12:16]
		if !net.IP(pkt[12:16]).Equal(srcIP) {
			t.Errorf("source IP = %v, want %v", net.IP(pkt[12:16]), srcIP)
		}

		// Dest IP at bytes [16:20]
		if !net.IP(pkt[16:20]).Equal(dstIP) {
			t.Errorf("dest IP = %v, want %v", net.IP(pkt[16:20]), dstIP)
		}
	})

	t.Run("protocol byte UDP", func(t *testing.T) {
		pkt := buildIPPacket(srcIP, dstIP, 0, 0, false, syscall.IPPROTO_UDP, payload)
		if pkt[9] != syscall.IPPROTO_UDP {
			t.Errorf("protocol = %d, want %d (UDP)", pkt[9], syscall.IPPROTO_UDP)
		}
	})

	t.Run("fragment offset with MF flag", func(t *testing.T) {
		// moreFrags = true, fragOffset = 0
		pkt := buildIPPacket(srcIP, dstIP, 0x5678, 0, true, syscall.IPPROTO_TCP, payload)
		flagsOff := binary.BigEndian.Uint16(pkt[6:8])
		// MF flag is 0x2000
		if flagsOff&0x2000 == 0 {
			t.Error("MF flag should be set when moreFragments = true")
		}
		// Offset portion should be 0
		if flagsOff&0x1FFF != 0 {
			t.Errorf("fragment offset = %d, want 0", flagsOff&0x1FFF)
		}
	})

	t.Run("fragment offset without MF flag", func(t *testing.T) {
		// moreFrags = false, fragOffset = 160 (should be encoded as 160/8 = 20)
		pkt := buildIPPacket(srcIP, dstIP, 0x5678, 160, false, syscall.IPPROTO_TCP, payload)
		flagsOff := binary.BigEndian.Uint16(pkt[6:8])
		if flagsOff&0x2000 != 0 {
			t.Error("MF flag should not be set when moreFragments = false")
		}
		// Fragment offset in units of 8 bytes: 160/8 = 20
		if flagsOff&0x1FFF != 20 {
			t.Errorf("fragment offset = %d, want 20", flagsOff&0x1FFF)
		}
	})

	t.Run("IP checksum valid", func(t *testing.T) {
		pkt := buildIPPacket(srcIP, dstIP, 0xABCD, 0, false, syscall.IPPROTO_TCP, payload)
		// The header checksum field is at bytes [10:12].
		// buildIPPacket does NOT set the checksum itself (leaves it zero).
		// Compute it and verify it validates.
		header := pkt[:20]

		// First compute the checksum
		csum := ipChecksum(header)
		binary.BigEndian.PutUint16(header[10:12], csum)

		// Now verify: recalculating over the header with checksum should give 0
		verify := ipChecksum(header)
		if verify != 0 {
			t.Errorf("IP checksum validation failed: got 0x%04x, want 0x0000", verify)
		}
	})

	t.Run("payload integrity", func(t *testing.T) {
		pkt := buildIPPacket(srcIP, dstIP, 0, 0, false, syscall.IPPROTO_TCP, payload)
		got := pkt[20:]
		if string(got) != string(payload) {
			t.Errorf("payload = %q, want %q", got, payload)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		pkt := buildIPPacket(srcIP, dstIP, 0, 0, false, syscall.IPPROTO_TCP, []byte{})
		if len(pkt) != 20 {
			t.Errorf("packet length = %d, want 20 for empty payload", len(pkt))
		}
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		if totalLen != 20 {
			t.Errorf("total length = %d, want 20", totalLen)
		}
	})
}
