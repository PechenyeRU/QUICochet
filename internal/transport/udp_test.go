package transport

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIPChecksum(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
	}{
		{
			name: "simple header",
			header: []byte{
				0x45, 0x00, // version, IHL, TOS
				0x00, 0x28, // total length
				0x00, 0x00, // identification
				0x40, 0x00, // flags, fragment offset
				0x40, 0x11, // TTL, protocol (UDP)
				0x00, 0x00, // checksum (to be calculated)
				0x0a, 0x00, 0x00, 0x01, // source IP
				0x0a, 0x00, 0x00, 0x02, // dest IP
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate checksum with zero in checksum field
			result := ipChecksum(tt.header)
			if result == 0 {
				t.Error("checksum should not be zero")
			}

			// Verify the checksum is valid: when inserted into the header
			// and recalculated, it should produce 0 (identity property)
			hdr := make([]byte, len(tt.header))
			copy(hdr, tt.header)
			binary.BigEndian.PutUint16(hdr[10:12], result)

			// RFC 1071: checksum of a valid packet is 0
			// (all 16-bit words sum to 0xFFFF, then inverted is 0)
			check := ipChecksum(hdr)
			if check != 0 {
				t.Errorf("checksum validation failed: got 0x%04x, want 0x0000", check)
			}
		})
	}
}

func TestUDP4Checksum(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.2").To4()

	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 12345) // source port
	binary.BigEndian.PutUint16(udpHeader[2:4], 8080)  // dest port
	binary.BigEndian.PutUint16(udpHeader[4:6], 20)    // length
	// checksum at [6:8] calculated below

	udpPayload := []byte("test data")

	// Full UDP packet
	udpPacket := append(udpHeader, udpPayload...)
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)))

	// Calculate checksum (with checksum field currently 0)
	checksum := udpChecksum(srcIP, dstIP, udpPacket)

	// Verify checksum is non-zero (actual value depends on content)
	if checksum == 0 {
		t.Error("UDP checksum should not be zero for IPv4")
	}

	// Note: UDP checksum is optional for IPv4 but mandatory for IPv6
	// We always compute it for correctness
	t.Logf("UDP checksum: 0x%04x", checksum)
}

func TestUDP6Checksum(t *testing.T) {
	srcIP := net.ParseIP("::1")
	dstIP := net.ParseIP("::2")

	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 12345)
	binary.BigEndian.PutUint16(udpHeader[2:4], 8080)
	binary.BigEndian.PutUint16(udpHeader[4:6], 20)

	udpPayload := []byte("test data ipv6")
	udpPacket := append(udpHeader, udpPayload...)
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)))
	binary.BigEndian.PutUint16(udpPacket[6:8], udp6Checksum(srcIP, dstIP.To16(), udpPacket))

	checksum := binary.BigEndian.Uint16(udpPacket[6:8])
	// IPv6 requires UDP checksum (can't be 0)
	if checksum == 0 {
		t.Error("UDP checksum must not be zero for IPv6")
	}
}

func TestConfigValidation(t *testing.T) {
	t.Run("valid IPv4 config", func(t *testing.T) {
		cfg := &Config{
			SourceIP:    net.ParseIP("10.0.0.1"),
			PeerSpoofIP: net.ParseIP("10.0.0.2"),
			ListenPort:  8080,
			BufferSize:  65535,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid IPv4 config: %v", err)
		}
	})

	t.Run("valid IPv6 config", func(t *testing.T) {
		cfg := &Config{
			SourceIPv6:  net.ParseIP("::1"),
			PeerSpoofIP: net.ParseIP("::2"),
			ListenPort:  8080,
			BufferSize:  65535,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid IPv6 config: %v", err)
		}
	})

	t.Run("missing source IP returns error", func(t *testing.T) {
		cfg := &Config{
			PeerSpoofIP: net.ParseIP("10.0.0.2"),
			ListenPort:  8080,
			BufferSize:  65535,
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("Validate() should return error when no source IP is set")
		}
		if err != ErrNoSourceIP {
			t.Errorf("expected ErrNoSourceIP, got: %v", err)
		}
	})

	t.Run("zero BufferSize and MTU get defaults", func(t *testing.T) {
		cfg := &Config{
			SourceIP:   net.ParseIP("10.0.0.1"),
			BufferSize: 0,
			MTU:        0,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() returned error: %v", err)
		}
		if cfg.BufferSize == 0 {
			t.Error("BufferSize should have been set to a non-zero default")
		}
		if cfg.MTU == 0 {
			t.Error("MTU should have been set to a non-zero default")
		}
	})
}

func TestConfigIsIPv6(t *testing.T) {
	t.Run("IPv4 only", func(t *testing.T) {
		cfg := &Config{
			SourceIP: net.ParseIP("10.0.0.1").To4(),
		}
		if cfg.IsIPv6() {
			t.Error("IsIPv6() = true, want false for IPv4-only config")
		}
	})

	t.Run("IPv6 only", func(t *testing.T) {
		cfg := &Config{
			SourceIPv6: net.ParseIP("::1"),
		}
		if !cfg.IsIPv6() {
			t.Error("IsIPv6() = false, want true for IPv6-only config")
		}
	})

	t.Run("both set IPv4 primary", func(t *testing.T) {
		cfg := &Config{
			SourceIP:   net.ParseIP("10.0.0.1").To4(),
			SourceIPv6: net.ParseIP("::1"),
		}
		if cfg.IsIPv6() {
			t.Error("IsIPv6() = true, want false when IPv4 is set as primary")
		}
	})
}

func TestHeaderConstruction(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("192.168.1.200").To4()

	// Test IPv4 header construction logic
	ipHeader := make([]byte, 20)

	// Version (4) and IHL (5 = 20 bytes)
	ipHeader[0] = 0x45
	// TOS
	ipHeader[1] = 0x00

	// Total length (20 IP + 8 UDP + payload)
	totalLen := uint16(20 + 8 + 100)
	binary.BigEndian.PutUint16(ipHeader[2:4], totalLen)

	// ID
	binary.BigEndian.PutUint16(ipHeader[4:6], 0x1234)

	// Flags and fragment offset
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000) // Don't fragment

	// TTL and protocol
	ipHeader[8] = 64 // TTL
	ipHeader[9] = 17 // UDP protocol

	// Checksum (will be calculated)
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)

	// Source and destination IPs
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)

	// Calculate checksum
	checksum := ipChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	// Verify the checksum is non-zero
	if checksum == 0 {
		t.Error("checksum should not be zero")
	}

	// Verify checksum passes validation (checksum of valid packet is 0)
	ipHeader[10] = byte(checksum >> 8)
	ipHeader[11] = byte(checksum & 0xFF)
	verifyChecksum := ipChecksum(ipHeader)
	if verifyChecksum != 0 {
		t.Errorf("checksum validation failed: got 0x%04x, want 0x0000", verifyChecksum)
	}
}

// Benchmark for checksum calculation performance
func BenchmarkIPChecksum(b *testing.B) {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], 128)
	binary.BigEndian.PutUint16(header[4:6], 0x1234)
	binary.BigEndian.PutUint16(header[6:8], 0x4000)
	header[8] = 64
	header[9] = 17
	copy(header[12:16], net.ParseIP("10.0.0.1").To4())
	copy(header[16:20], net.ParseIP("10.0.0.2").To4())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipChecksum(header)
	}
}

func BenchmarkUDPChecksum(b *testing.B) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.2").To4()
	udpPacket := make([]byte, 1400)
	binary.BigEndian.PutUint16(udpPacket[0:2], 12345)
	binary.BigEndian.PutUint16(udpPacket[2:4], 8080)
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = udpChecksum(srcIP, dstIP, udpPacket)
	}
}

// Regression for C-16: pickSourceIPv6 must be sticky-by-flow like
// pickSourceIPv4 — every packet of a given QUIC connection (same
// DCID region in the payload) must map to the same source IP.
func TestPickSourceIPv6Sticky(t *testing.T) {
	srcs := [][16]byte{
		{0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		{0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3},
		{0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
	}

	// A QUIC short-header packet whose DCID region we hold constant.
	payload := []byte{0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0xde, 0xad}

	first := pickSourceIPv6(srcs, payload)
	for i := 0; i < 100; i++ {
		got := pickSourceIPv6(srcs, payload)
		if got != first {
			t.Fatalf("pickSourceIPv6 not sticky: iter %d picked %v, want %v", i, *got, *first)
		}
	}

	// Distribution sanity: many distinct DCIDs must cover more than one
	// bucket. With 4 sources and 256 distinct payloads the probability
	// of all landing on a single bucket is 4 * (1/4)^256, effectively zero.
	seen := make(map[*[16]byte]struct{})
	probe := []byte{0x40, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 256; i++ {
		probe[1] = byte(i)
		probe[2] = byte(i >> 8)
		seen[pickSourceIPv6(srcs, probe)] = struct{}{}
	}
	if len(seen) < 2 {
		t.Errorf("pickSourceIPv6 reached only %d/%d sources — distribution looks broken", len(seen), len(srcs))
	}
}

// Single-source IPv6 must trivially return the only entry.
func TestPickSourceIPv6Single(t *testing.T) {
	srcs := [][16]byte{{0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	got := pickSourceIPv6(srcs, []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	if got != &srcs[0] {
		t.Fatalf("single-source pickSourceIPv6 returned %v, want %v", *got, srcs[0])
	}
}
