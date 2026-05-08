package spooftester

import (
	"encoding/binary"
	"testing"
)

func TestPayloadRoundTrip(t *testing.T) {
	rid := uint16(0xCAFE)
	seq := uint32(0x12345678)
	buf := BuildPayload(rid, seq, 0xDEADBEEF)
	if len(buf) != MinPayloadSize {
		t.Fatalf("payload size: got %d want %d", len(buf), MinPayloadSize)
	}
	gotRid, gotSeq, err := ParsePayload(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if gotRid != rid || gotSeq != seq {
		t.Errorf("got (%d, %d), want (%d, %d)", gotRid, gotSeq, rid, seq)
	}
}

func TestPayloadRejectsBadMagic(t *testing.T) {
	buf := BuildPayload(1, 1, 0)
	buf[0] = 'X'
	if _, _, err := ParsePayload(buf); err == nil {
		t.Fatal("expected magic mismatch error")
	}
}

func TestPayloadRejectsBadVersion(t *testing.T) {
	buf := BuildPayload(1, 1, 0)
	buf[4] = 99
	if _, _, err := ParsePayload(buf); err == nil {
		t.Fatal("expected version mismatch error")
	}
}

func TestBuildTCPSYNv4_ChecksumValid(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{1, 2, 3, 4}
	pkt := BuildTCPSYNv4(src, dst, 443, 0xBEEF, 7, 1)
	if len(pkt) != 40 {
		t.Fatalf("got %d bytes, want 40", len(pkt))
	}
	// IP checksum
	ipsum := checksumRFC1071(pkt[:20])
	if ipsum != 0 {
		t.Errorf("IP checksum invalid: 0x%04x", ipsum)
	}
	// TCP checksum (verify by recomputing pseudo-header sum)
	tcp := pkt[20:]
	sum := pseudoHeaderSumV4(src, dst, 6, 20)
	sum = addBytes(sum, tcp)
	if foldAndComplement(sum) != 0 {
		t.Errorf("TCP checksum invalid: 0x%04x", foldAndComplement(sum))
	}
	// Magic check
	got := ParseInboundTCPv4Helper(t, pkt, 443)
	if got.runID != 0xBEEF || got.seq != 7 {
		t.Errorf("parse mismatch: %+v", got)
	}
}

func TestBuildICMPv4Echo_ChecksumValid(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{1, 2, 3, 4}
	pkt := BuildICMPv4Echo(src, dst, 0xCAFE, 42, 1)
	// IP header (20) + ICMP body must check
	ipsum := checksumRFC1071(pkt[:20])
	if ipsum != 0 {
		t.Errorf("IP checksum invalid: 0x%04x", ipsum)
	}
	icmpsum := checksumRFC1071(pkt[20:])
	if icmpsum != 0 {
		t.Errorf("ICMP checksum invalid: 0x%04x", icmpsum)
	}
	// Verify proto byte = 1
	if pkt[9] != 1 {
		t.Errorf("expected proto=1 (ICMP), got %d", pkt[9])
	}
	// Verify type byte = 8
	if pkt[20] != 8 {
		t.Errorf("expected ICMP type=8, got %d", pkt[20])
	}
	src2, rid, seq, ok := ParseInboundICMPv4(pkt, 1, 8)
	if !ok || rid != 0xCAFE || seq != 42 || src2 != src {
		t.Errorf("parse: ok=%v rid=%x seq=%d src=%v", ok, rid, seq, src2)
	}
}

func TestBuildICMPv6OverIPv4_ProtoIs58(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{1, 2, 3, 4}
	pkt := BuildICMPv6OverIPv4Echo(src, dst, 0xCAFE, 42, 1)
	if pkt[9] != 58 {
		t.Errorf("expected proto=58, got %d", pkt[9])
	}
	if pkt[20] != 128 {
		t.Errorf("expected type=128, got %d", pkt[20])
	}
	src2, rid, seq, ok := ParseInboundICMPv4(pkt, 58, 128)
	if !ok || rid != 0xCAFE || seq != 42 || src2 != src {
		t.Errorf("parse: ok=%v rid=%x seq=%d src=%v", ok, rid, seq, src2)
	}
}

func TestBuildUDPv4_ChecksumValid(t *testing.T) {
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{1, 2, 3, 4}
	pkt := BuildUDPv4(src, dst, 1234, 5678, 0xCAFE, 9, 1)
	if checksumRFC1071(pkt[:20]) != 0 {
		t.Errorf("IP checksum invalid")
	}
	udp := pkt[20:]
	sum := pseudoHeaderSumV4(src, dst, 17, 8+MinPayloadSize)
	sum = addBytes(sum, udp)
	if foldAndComplement(sum) != 0 {
		// non-zero is allowed only if the packet's stored csum is 0xFFFF
		stored := binary.BigEndian.Uint16(udp[6:8])
		if stored != 0xFFFF {
			t.Errorf("UDP checksum invalid: 0x%04x stored=0x%04x", foldAndComplement(sum), stored)
		}
	}
	if udp[0] != 0x04 || udp[1] != 0xD2 { // 1234 BE
		t.Errorf("src port wrong: %x%x", udp[0], udp[1])
	}
}

// helper: testing wrapper that splits the unwieldy 4-tuple result.
type parsedTCP struct {
	srcIP [4]byte
	runID uint16
	seq   uint16
}

func ParseInboundTCPv4Helper(t *testing.T, buf []byte, dstPort uint16) parsedTCP {
	t.Helper()
	src, rid, seq, ok := ParseInboundTCPv4(buf, dstPort)
	if !ok {
		t.Fatalf("parse not ok")
	}
	return parsedTCP{srcIP: src, runID: rid, seq: seq}
}
