package transport

import (
	"encoding/binary"
	"net"
	"strings"
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

		csum := tcpChecksumInPlace(srcIP, dstIP, tcpSeg)
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
		csum := tcpChecksumInPlace(srcIP, dstIP, tcpSeg)
		binary.BigEndian.PutUint16(tcpSeg[16:18], csum)

		// Recompute — should fold to 0
		recheck := tcpChecksumInPlace(srcIP, dstIP, tcpSeg)
		if recheck != 0 {
			t.Errorf("self-check failed: recomputed TCP checksum = 0x%04x, want 0x0000", recheck)
		}
	})
}

func TestWriteIPHeader(t *testing.T) {
	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{10, 0, 0, 1}
	payload := []byte("hello world")

	// buildPkt emulates the legacy buildIPPacket signature on top of the new
	// writeIPHeader helper so the test assertions stay focused on header
	// contents, not on the caller layout.
	buildPkt := func(srcIP, dstIP net.IP, ipID, fragOffset uint16, moreFrags bool, proto byte, data []byte) []byte {
		pkt := make([]byte, 20+len(data))
		writeIPHeader(pkt[:20], srcIP, dstIP, ipID, fragOffset, moreFrags, proto, len(data))
		copy(pkt[20:], data)
		return pkt
	}

	t.Run("basic header fields", func(t *testing.T) {
		pkt := buildPkt(srcIP, dstIP, 0x1234, 0, false, syscall.IPPROTO_TCP, payload)

		if pkt[0] != 0x45 {
			t.Errorf("pkt[0] = 0x%02x, want 0x45", pkt[0])
		}
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		want := uint16(20 + len(payload))
		if totalLen != want {
			t.Errorf("total length = %d, want %d", totalLen, want)
		}
		if pkt[9] != syscall.IPPROTO_TCP {
			t.Errorf("protocol = %d, want %d", pkt[9], syscall.IPPROTO_TCP)
		}
		if !net.IP(pkt[12:16]).Equal(srcIP) {
			t.Errorf("source IP = %v, want %v", net.IP(pkt[12:16]), srcIP)
		}
		if !net.IP(pkt[16:20]).Equal(dstIP) {
			t.Errorf("dest IP = %v, want %v", net.IP(pkt[16:20]), dstIP)
		}
	})

	t.Run("protocol byte UDP", func(t *testing.T) {
		pkt := buildPkt(srcIP, dstIP, 0, 0, false, syscall.IPPROTO_UDP, payload)
		if pkt[9] != syscall.IPPROTO_UDP {
			t.Errorf("protocol = %d, want %d (UDP)", pkt[9], syscall.IPPROTO_UDP)
		}
	})

	t.Run("fragment offset with MF flag", func(t *testing.T) {
		pkt := buildPkt(srcIP, dstIP, 0x5678, 0, true, syscall.IPPROTO_TCP, payload)
		flagsOff := binary.BigEndian.Uint16(pkt[6:8])
		if flagsOff&0x2000 == 0 {
			t.Error("MF flag should be set when moreFragments = true")
		}
		if flagsOff&0x1FFF != 0 {
			t.Errorf("fragment offset = %d, want 0", flagsOff&0x1FFF)
		}
	})

	t.Run("fragment offset without MF flag", func(t *testing.T) {
		pkt := buildPkt(srcIP, dstIP, 0x5678, 160, false, syscall.IPPROTO_TCP, payload)
		flagsOff := binary.BigEndian.Uint16(pkt[6:8])
		if flagsOff&0x2000 != 0 {
			t.Error("MF flag should not be set when moreFragments = false")
		}
		if flagsOff&0x1FFF != 20 {
			t.Errorf("fragment offset = %d, want 20", flagsOff&0x1FFF)
		}
	})

	t.Run("IP checksum valid", func(t *testing.T) {
		// writeIPHeader sets the checksum itself, so verification across
		// the header should fold to zero.
		pkt := buildPkt(srcIP, dstIP, 0xABCD, 0, false, syscall.IPPROTO_TCP, payload)
		if verify := ipChecksum(pkt[:20]); verify != 0 {
			t.Errorf("IP checksum validation failed: got 0x%04x, want 0x0000", verify)
		}
	})

	t.Run("payload integrity", func(t *testing.T) {
		pkt := buildPkt(srcIP, dstIP, 0, 0, false, syscall.IPPROTO_TCP, payload)
		got := pkt[20:]
		if string(got) != string(payload) {
			t.Errorf("payload = %q, want %q", got, payload)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		pkt := buildPkt(srcIP, dstIP, 0, 0, false, syscall.IPPROTO_TCP, []byte{})
		if len(pkt) != 20 {
			t.Errorf("packet length = %d, want 20 for empty payload", len(pkt))
		}
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		if totalLen != 20 {
			t.Errorf("total length = %d, want 20", totalLen)
		}
	})
}

// TestTcp6Checksum pins the v6 TCP checksum: same RFC 1071 fold, but
// with the IPv6 pseudo-header (40 bytes: 16+16+4+3+1) instead of the
// 12-byte v4 one. A wrong layout would silently produce TCP segments
// the receiver discards as "bad checksum" and the syn_udp v6 path
// would look like a totally working transport that drops everything.
func TestTcp6Checksum(t *testing.T) {
	t.Run("known segment", func(t *testing.T) {
		srcIP := net.ParseIP("2001:db80::1").To16()
		dstIP := net.ParseIP("2001:db80::2").To16()

		tcpSeg := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpSeg[0:2], 12345)
		binary.BigEndian.PutUint16(tcpSeg[2:4], 80)
		binary.BigEndian.PutUint32(tcpSeg[4:8], 100)
		tcpSeg[12] = 5 << 4
		tcpSeg[13] = 0x02
		binary.BigEndian.PutUint16(tcpSeg[14:16], 65535)

		csum := tcp6ChecksumInPlace(srcIP, dstIP, tcpSeg)
		if csum == 0 {
			t.Error("v6 TCP checksum should be non-zero for this segment")
		}
	})

	t.Run("self-check property", func(t *testing.T) {
		srcIP := net.ParseIP("2001:db80::dead").To16()
		dstIP := net.ParseIP("2001:db80::beef").To16()

		tcpSeg := make([]byte, 24) // 20 header + 4 payload
		binary.BigEndian.PutUint16(tcpSeg[0:2], 9999)
		binary.BigEndian.PutUint16(tcpSeg[2:4], 443)
		binary.BigEndian.PutUint32(tcpSeg[4:8], 1)
		tcpSeg[12] = 5 << 4
		tcpSeg[13] = 0x02
		binary.BigEndian.PutUint16(tcpSeg[14:16], 32768)
		tcpSeg[20] = 0xCA
		tcpSeg[21] = 0xFE
		tcpSeg[22] = 0xBA
		tcpSeg[23] = 0xBE

		csum := tcp6ChecksumInPlace(srcIP, dstIP, tcpSeg)
		binary.BigEndian.PutUint16(tcpSeg[16:18], csum)

		recheck := tcp6ChecksumInPlace(srcIP, dstIP, tcpSeg)
		if recheck != 0 {
			t.Errorf("self-check failed: recomputed v6 TCP checksum = 0x%04x, want 0x0000", recheck)
		}
	})

	t.Run("differs from v4", func(t *testing.T) {
		// Same payload, both pseudo-headers using the same address
		// bytes (in their respective 4 vs 16 byte forms) — the
		// checksums must differ because the v6 pseudo-header
		// includes 12 extra header bytes per address plus a 32-bit
		// length and the next-header byte. A common bug is to copy
		// the v4 checksum into the v6 helper and ship it; this
		// catches that.
		srcV4 := net.ParseIP("10.0.0.1").To4()
		dstV4 := net.ParseIP("10.0.0.2").To4()
		srcV6 := net.ParseIP("2001:db80::1").To16()
		dstV6 := net.ParseIP("2001:db80::2").To16()

		tcpSeg := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpSeg[0:2], 1234)
		binary.BigEndian.PutUint16(tcpSeg[2:4], 5678)
		binary.BigEndian.PutUint32(tcpSeg[4:8], 0xdeadbeef)
		tcpSeg[12] = 5 << 4
		tcpSeg[13] = 0x02

		v4 := tcpChecksumInPlace(srcV4, dstV4, tcpSeg)
		// reset checksum field for the v6 run
		binary.BigEndian.PutUint16(tcpSeg[16:18], 0)
		v6 := tcp6ChecksumInPlace(srcV6, dstV6, tcpSeg)
		if v4 == v6 {
			t.Errorf("v4 and v6 checksums collided (0x%04x) — pseudo-header layouts may be confused", v4)
		}
	})
}

// TestSynUDPDualStackRejected pins that configuring source_ip AND
// source_ipv6 in syn_udp returns a clear error rather than silently
// half-initialising. dual-stack syn_udp is tracked as Phase 5.
func TestSynUDPDualStackRejected(t *testing.T) {
	cfg := &Config{
		SourceIP:   net.ParseIP("10.0.0.1"),
		SourceIPv6: net.ParseIP("2001:db80::1"),
		ListenPort: 0,
		BufferSize: 65535,
	}
	tr, err := NewSynUDPTransport(cfg, RoleClient)
	if err == nil {
		tr.Close()
		t.Fatal("dual-stack syn_udp not rejected — half-init risk")
	}
	if !strings.Contains(err.Error(), "dual-stack") {
		t.Errorf("error message should mention dual-stack: %v", err)
	}
}

// TestSynUDPV6FamilyDetection covers the family selection logic in
// NewSynUDPTransport: a v6-only source list flips isIPv6=true and
// the init path takes the v6 branch (which fails without
// CAP_NET_RAW, so we accept either nil or a permission/capability
// error and assert isIPv6 was set when init proceeded far enough).
func TestSynUDPV6FamilyDetection(t *testing.T) {
	cfg := &Config{
		SourceIPv6: net.ParseIP("2001:db80::1"),
		ListenPort: 0,
		BufferSize: 65535,
	}
	tr, err := NewSynUDPTransport(cfg, RoleClient)
	if err != nil {
		// Unprivileged run — the v6 raw socket creation fails;
		// that's fine, the test only needs to verify family
		// selection doesn't reject the config outright.
		if isPermissionDenied(err) {
			t.Skipf("skipping (need CAP_NET_RAW + CAP_NET_ADMIN): %v", err)
		}
		t.Fatalf("v6-only NewSynUDPTransport: %v", err)
	}
	defer tr.Close()
	if !tr.isIPv6 {
		t.Error("v6-only source did not flip isIPv6=true")
	}
}
