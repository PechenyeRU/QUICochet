package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

type udpSendmsgCall struct {
	payload []byte
	oob     []byte
	dest    unix.Sockaddr
}

func makeGSOTestPayload(segmentSize, segments, finalSize int) []byte {
	payload := make([]byte, (segments-1)*segmentSize+finalSize)
	payload[0] = 0x40
	copy(payload[1:9], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	for i := 9; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	return payload
}

func makeGSOTestOOB(size uint16) []byte {
	oob := make([]byte, unix.CmsgSpace(2))
	buildUDPSegment(oob, size)
	return oob
}

func gsoTestTransport(sendIs6, nativeV6 bool, calls *[]udpSendmsgCall) *UDPTransport {
	t := &UDPTransport{
		useSendmsg: true,
		sendIs6:    sendIs6,
		srcIPv4s:   [][4]byte{{10, 0, 0, 1}, {10, 0, 0, 2}},
		srcIPv6s: [][16]byte{
			{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		},
	}
	t.pool = NewSrcPool(t.srcIPv4s, t.srcIPv6s, SrcPoolConfig{})
	t.sendmsg = func(_ int, p, oob []byte, to unix.Sockaddr, _ int) error {
		call := udpSendmsgCall{
			payload: append([]byte(nil), p...),
			oob:     append([]byte(nil), oob...),
			dest:    to,
		}
		*calls = append(*calls, call)
		return nil
	}
	if nativeV6 {
		t.srcIPv4s = nil
	} else {
		t.srcIPv6s = nil
	}
	t.pool = NewSrcPool(t.srcIPv4s, t.srcIPv6s, SrcPoolConfig{})
	return t
}

func gsoSentCount(transport *UDPTransport) uint64 {
	var total uint64
	if transport.pool.v4 != nil {
		for i := range transport.pool.v4.sentCount {
			total += transport.pool.v4.sentCount[i].Load()
		}
	}
	if transport.pool.v6 != nil {
		for i := range transport.pool.v6.sentCount {
			total += transport.pool.v6.sentCount[i].Load()
		}
	}
	return total
}

func TestUDPGSOControlMessages(t *testing.T) {
	payload := makeGSOTestPayload(1200, 2, 300)
	tests := []struct {
		name     string
		sendIs6  bool
		nativeV6 bool
		dst      net.IP
	}{
		{name: "IPv4", dst: net.ParseIP("203.0.113.10")},
		{name: "IPv6", sendIs6: true, nativeV6: true, dst: net.ParseIP("2001:db8::10")},
		{name: "IPv4 mapped on IPv6 socket", sendIs6: true, dst: net.ParseIP("203.0.113.10")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []udpSendmsgCall
			transport := gsoTestTransport(tc.sendIs6, tc.nativeV6, &calls)
			n, _, err := transport.WriteMsgUDP(payload, makeGSOTestOOB(1200), &net.UDPAddr{IP: tc.dst, Port: 443})
			if err != nil {
				t.Fatalf("WriteMsgUDP: %v", err)
			}
			if n != len(payload) {
				t.Fatalf("n = %d, want %d", n, len(payload))
			}
			if got := gsoSentCount(transport); got != 2 {
				t.Fatalf("sentCount = %d, want 2 segments", got)
			}
			if len(calls) != 1 {
				t.Fatalf("sendmsg calls = %d, want 1", len(calls))
			}
			messages, err := unix.ParseSocketControlMessage(calls[0].oob)
			if err != nil {
				t.Fatalf("parse cmsgs: %v", err)
			}
			if len(messages) != 2 {
				t.Fatalf("cmsg count = %d, want 2", len(messages))
			}
			if messages[0].Header.Type != unix.IP_PKTINFO && messages[0].Header.Type != unix.IPV6_PKTINFO {
				t.Fatalf("first cmsg type = %d, want pktinfo", messages[0].Header.Type)
			}
			segment := messages[1]
			if segment.Header.Level != unix.IPPROTO_UDP || segment.Header.Type != unix.UDP_SEGMENT {
				t.Fatalf("second cmsg = level %d type %d, want UDP_SEGMENT", segment.Header.Level, segment.Header.Type)
			}
			if got := binary.NativeEndian.Uint16(segment.Data); got != 1200 {
				t.Fatalf("UDP_SEGMENT = %d, want 1200", got)
			}
			for _, message := range messages {
				if (message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_TOS) ||
					(message.Header.Level == unix.IPPROTO_IPV6 && message.Header.Type == unix.IPV6_TCLASS) {
					t.Fatal("unexpected ECN control message")
				}
			}

			if tc.sendIs6 {
				if _, ok := calls[0].dest.(*unix.SockaddrInet6); !ok {
					t.Fatalf("destination type = %T, want *unix.SockaddrInet6", calls[0].dest)
				}
				if messages[0].Header.Level != unix.IPPROTO_IPV6 || messages[0].Header.Type != unix.IPV6_PKTINFO {
					t.Fatalf("first cmsg = level %d type %d, want IPV6_PKTINFO", messages[0].Header.Level, messages[0].Header.Type)
				}
			} else {
				if _, ok := calls[0].dest.(*unix.SockaddrInet4); !ok {
					t.Fatalf("destination type = %T, want *unix.SockaddrInet4", calls[0].dest)
				}
				if messages[0].Header.Level != unix.SOL_IP || messages[0].Header.Type != unix.IP_PKTINFO {
					t.Fatalf("first cmsg = level %d type %d, want IP_PKTINFO", messages[0].Header.Level, messages[0].Header.Type)
				}
			}

			expectedPool := NewSrcPool(transport.srcIPv4s, transport.srcIPv6s, SrcPoolConfig{})
			if tc.nativeV6 {
				want, _ := expectedPool.PickV6(payload[:1200])
				if !bytes.Equal(messages[0].Data[:16], want[:]) {
					t.Fatalf("source = %v, want first-datagram source %v", messages[0].Data[:16], want)
				}
			} else {
				want, _ := expectedPool.PickV4(payload[:1200])
				got := messages[0].Data[4:8]
				if tc.sendIs6 {
					got = messages[0].Data[12:16]
				}
				if !bytes.Equal(got, want[:]) {
					t.Fatalf("source = %v, want first-datagram source %v", got, want)
				}
			}
		})
	}
}

func TestUDPGSOErrorFallbackKeepsSourceAndShortFinalSegment(t *testing.T) {
	const segmentSize = 1200
	payload := makeGSOTestPayload(segmentSize, 3, 300)
	var calls []udpSendmsgCall
	transport := gsoTestTransport(false, false, &calls)
	failNext := true
	transport.sendmsg = func(_ int, p, oob []byte, to unix.Sockaddr, _ int) error {
		calls = append(calls, udpSendmsgCall{
			payload: append([]byte(nil), p...),
			oob:     append([]byte(nil), oob...),
			dest:    to,
		})
		if failNext {
			failNext = false
			return unix.EIO
		}
		return nil
	}

	if _, _, err := transport.WriteMsgUDP(payload, makeGSOTestOOB(segmentSize), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443}); err != nil {
		t.Fatalf("WriteMsgUDP fallback: %v", err)
	}
	if transport.SupportsGSO() {
		t.Fatal("GSO remains enabled after EIO")
	}
	if got := gsoSentCount(transport); got != 3 {
		t.Fatalf("sentCount = %d, want 3 segments", got)
	}
	wantLengths := []int{len(payload), segmentSize, segmentSize, 300}
	if len(calls) != len(wantLengths) {
		t.Fatalf("sendmsg calls = %d, want %d", len(calls), len(wantLengths))
	}
	var source [4]byte
	for i, call := range calls {
		if len(call.payload) != wantLengths[i] {
			t.Errorf("call %d payload length = %d, want %d", i, len(call.payload), wantLengths[i])
		}
		messages, err := unix.ParseSocketControlMessage(call.oob)
		if err != nil {
			t.Fatalf("call %d parse cmsgs: %v", i, err)
		}
		if i > 0 && len(messages) != 1 {
			t.Fatalf("fallback call %d cmsg count = %d, want 1", i, len(messages))
		}
		var current [4]byte
		copy(current[:], messages[0].Data[4:8])
		if i == 0 {
			source = current
		} else if current != source {
			t.Fatalf("call %d source = %v, want constant %v", i, current, source)
		}
	}

	joined := append(append(append([]byte(nil), calls[1].payload...), calls[2].payload...), calls[3].payload...)
	if string(joined) != string(payload) {
		t.Fatal("fallback changed or lost payload bytes")
	}

	calls = nil
	if _, _, err := transport.WriteMsgUDP(payload, makeGSOTestOOB(segmentSize), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443}); err != nil {
		t.Fatalf("WriteMsgUDP after disabling GSO: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("sendmsg calls with GSO disabled = %d, want 3", len(calls))
	}
	if got := gsoSentCount(transport); got != 6 {
		t.Fatalf("sentCount = %d, want 6 segments", got)
	}
	for i, call := range calls {
		messages, err := unix.ParseSocketControlMessage(call.oob)
		if err != nil {
			t.Fatalf("disabled-GSO call %d parse cmsgs: %v", i, err)
		}
		if len(messages) != 1 {
			t.Fatalf("disabled-GSO call %d used UDP_SEGMENT", i)
		}
		var current [4]byte
		copy(current[:], messages[0].Data[4:8])
		if current != source {
			t.Fatalf("disabled-GSO call %d source = %v, want %v", i, current, source)
		}
	}
}

func TestUDPGSOIPv6ErrorFallback(t *testing.T) {
	payload := makeGSOTestPayload(1200, 2, 300)
	var calls []udpSendmsgCall
	transport := gsoTestTransport(true, true, &calls)
	failNext := true
	transport.sendmsg = func(_ int, p, oob []byte, to unix.Sockaddr, _ int) error {
		calls = append(calls, udpSendmsgCall{
			payload: append([]byte(nil), p...),
			oob:     append([]byte(nil), oob...),
			dest:    to,
		})
		if failNext {
			failNext = false
			return unix.EIO
		}
		return nil
	}
	addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 443}
	if _, _, err := transport.WriteMsgUDP(payload, makeGSOTestOOB(1200), addr); err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("sendmsg calls = %d, want 3", len(calls))
	}
	var source [16]byte
	for i, call := range calls {
		messages, err := unix.ParseSocketControlMessage(call.oob)
		if err != nil {
			t.Fatal(err)
		}
		var current [16]byte
		copy(current[:], messages[0].Data[:16])
		if i == 0 {
			source = current
		} else if current != source {
			t.Fatalf("call %d source = %v, want %v", i, current, source)
		}
	}
	if len(calls[2].payload) != 300 {
		t.Fatalf("final segment length = %d, want 300", len(calls[2].payload))
	}
	if got := gsoSentCount(transport); got != 2 {
		t.Fatalf("sentCount = %d, want 2 segments", got)
	}
}

func TestUDPGSODisabledWithoutSendmsg(t *testing.T) {
	transport := &UDPTransport{}
	if transport.SupportsGSO() {
		t.Fatal("GSO enabled without sendmsg")
	}
	if _, _, err := transport.WriteMsgUDP([]byte("payload"), makeGSOTestOOB(4), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err == nil {
		t.Fatal("WriteMsgUDP succeeded without sendmsg")
	}
}

func TestUDPGSOPropagatesNonGSOError(t *testing.T) {
	var calls []udpSendmsgCall
	transport := gsoTestTransport(false, false, &calls)
	transport.sendmsg = func(_ int, _, _ []byte, _ unix.Sockaddr, _ int) error {
		return unix.EAGAIN
	}
	_, _, err := transport.WriteMsgUDP(makeGSOTestPayload(1200, 2, 300), makeGSOTestOOB(1200), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443})
	if !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("error = %v, want EAGAIN", err)
	}
	if !transport.SupportsGSO() {
		t.Fatal("non-GSO error disabled GSO")
	}
}

func TestUDPGSOEINVALSinglePacketKeepsEnabled(t *testing.T) {
	var calls []udpSendmsgCall
	transport := gsoTestTransport(false, false, &calls)
	transport.sendmsg = func(_ int, _, _ []byte, _ unix.Sockaddr, _ int) error {
		return unix.EINVAL
	}

	err := transport.Send([]byte("payload"), net.IPv4(203, 0, 113, 10), 443)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("error = %v, want EINVAL", err)
	}
	if !transport.SupportsGSO() {
		t.Fatal("single-packet EINVAL disabled GSO")
	}
}

func TestUDPGSOFailedFallbackKeepsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		sendIs6  bool
		nativeV6 bool
		dst      net.IP
	}{
		{name: "IPv4", dst: net.IPv4(203, 0, 113, 10)},
		{name: "IPv6", sendIs6: true, nativeV6: true, dst: net.ParseIP("2001:db8::10")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []udpSendmsgCall
			transport := gsoTestTransport(tc.sendIs6, tc.nativeV6, &calls)
			sendCalls := 0
			transport.sendmsg = func(_ int, _, _ []byte, _ unix.Sockaddr, _ int) error {
				sendCalls++
				if sendCalls == 1 {
					return unix.EINVAL
				}
				return unix.EAGAIN
			}

			payload := makeGSOTestPayload(1200, 2, 300)
			_, _, err := transport.WriteMsgUDP(payload, makeGSOTestOOB(1200), &net.UDPAddr{IP: tc.dst, Port: 443})
			if !errors.Is(err, unix.EAGAIN) {
				t.Fatalf("error = %v, want fallback EAGAIN", err)
			}
			if sendCalls != 2 {
				t.Fatalf("sendmsg calls = %d, want failed GSO and first fallback segment", sendCalls)
			}
			if !transport.SupportsGSO() {
				t.Fatal("failed single-packet fallback disabled GSO")
			}
			if got := gsoSentCount(transport); got != 0 {
				t.Fatalf("sentCount = %d after failed sends, want 0", got)
			}
		})
	}
}

func BenchmarkUDPTransportSendGSO(b *testing.B) {
	const (
		segmentSize = 1200
		segments    = 8
	)
	payload := makeGSOTestPayload(segmentSize, segments, segmentSize)
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443}
	transport := gsoTestTransport(false, false, new([]udpSendmsgCall))
	transport.sendmsg = func(_ int, _, _ []byte, _ unix.Sockaddr, _ int) error { return nil }

	b.ReportAllocs()
	b.Run("single", func(b *testing.B) {
		for b.Loop() {
			for offset := 0; offset < len(payload); offset += segmentSize {
				if err := transport.Send(payload[offset:offset+segmentSize], addr.IP, uint16(addr.Port)); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("GSO", func(b *testing.B) {
		oob := makeGSOTestOOB(segmentSize)
		for b.Loop() {
			if _, _, err := transport.WriteMsgUDP(payload, oob, addr); err != nil {
				b.Fatal(err)
			}
		}
	})
}
