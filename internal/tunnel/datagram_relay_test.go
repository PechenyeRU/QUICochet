package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
)

type fakeDirectReader struct {
	source  *net.UDPAddr
	packets [][]byte
	reads   int
	repeat  int
}

func (r *fakeDirectReader) ReadFromUDP(dst []byte) (int, *net.UDPAddr, error) {
	var packet []byte
	if r.reads < len(r.packets) {
		packet = r.packets[r.reads]
		r.reads++
	} else if r.repeat > 0 {
		r.repeat--
		packet = r.packets[len(r.packets)-1]
	} else {
		return 0, nil, io.EOF
	}
	return copy(dst, packet), r.source, nil
}

type recordingDatagramSender struct {
	packets [][]byte
	onSend  func(int)
}

func (s *recordingDatagramSender) SendDatagram(packet []byte) error {
	s.packets = append(s.packets, bytes.Clone(packet))
	if s.onSend != nil {
		s.onSend(len(s.packets))
	}
	return nil
}

type discardDatagramSender struct {
	datagrams int
	bytes     int
}

func (s *discardDatagramSender) SendDatagram(packet []byte) error {
	s.datagrams++
	s.bytes += len(packet)
	return nil
}

type fakeDatagramSession struct {
	remoteAddr net.Addr
	message    []byte
	remaining  int
}

func (s *fakeDatagramSession) ReceiveDatagram(context.Context) ([]byte, error) {
	if s.remaining == 0 {
		return nil, io.EOF
	}
	s.remaining--
	return s.message, nil
}

func (s *fakeDatagramSession) SendDatagram([]byte) error { return nil }

func (s *fakeDatagramSession) RemoteAddr() net.Addr { return s.remoteAddr }

func newDatagramRelayTestServer() *Server {
	blockPrivate := false
	return &Server{config: &config.Config{Security: config.SecurityConfig{
		BlockPrivateTargets: &blockPrivate,
	}}}
}

func directRelayTestMessage(assocID byte, port int, payload []byte) []byte {
	message := []byte{0, 0, 0, assocID, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	return append(message, payload...)
}

func expectedDirectReply(assocID byte, addrType byte, ip net.IP, port uint16, payload []byte) []byte {
	expected := []byte{0, 0, 0, assocID, addrType}
	expected = append(expected, ip...)
	expected = binary.BigEndian.AppendUint16(expected, port)
	return append(expected, payload...)
}

func TestHandleDatagramsIPv4LiteralIntegrity(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen target UDP: %v", err)
	}
	defer target.Close()

	payload := []byte("literal IPv4 payload")
	session := &fakeDatagramSession{
		remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		message:    directRelayTestMessage(7, target.LocalAddr().(*net.UDPAddr).Port, payload),
		remaining:  1,
	}
	server := newDatagramRelayTestServer()
	server.running.Store(true)
	server.handleDatagrams(session, "")

	if err := target.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set target deadline: %v", err)
	}
	buffer := make([]byte, 128)
	n, _, err := target.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read target payload: %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("target payload = %q, want %q", buffer[:n], payload)
	}
}

func TestReceiveDirectDatagramsIntegrity(t *testing.T) {
	ipv6 := net.ParseIP("2001:4860:4860::8888")
	tests := []struct {
		name     string
		sourceIP net.IP
		wireIP   net.IP
		addrType byte
	}{
		{name: "IPv4", sourceIP: net.IPv4(8, 8, 8, 8), wireIP: net.IPv4(8, 8, 8, 8).To4(), addrType: 1},
		{name: "IPv6", sourceIP: ipv6, wireIP: ipv6.To16(), addrType: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("response payload")
			reader := &fakeDirectReader{
				source:  &net.UDPAddr{IP: test.sourceIP, Port: 53},
				packets: [][]byte{payload},
			}
			sender := &recordingDatagramSender{}
			server := newDatagramRelayTestServer()
			route := &datagramRoute{}
			routes := map[uint32]*datagramRoute{9: route}
			server.udpRoutes.Add(1)

			server.receiveDirectDatagrams(sender, route, reader, []byte{0, 0, 0, 9}, 9, routes, &sync.Mutex{}, "")

			if len(sender.packets) != 1 {
				t.Fatalf("sent datagrams = %d, want 1", len(sender.packets))
			}
			expected := expectedDirectReply(9, test.addrType, test.wireIP, 53, payload)
			if !bytes.Equal(sender.packets[0], expected) {
				t.Fatalf("reply = %v, want %v", sender.packets[0], expected)
			}
			if got := server.udpRoutes.Load(); got != 0 {
				t.Fatalf("udpRoutes = %d, want 0", got)
			}
		})
	}
}

func TestReceiveDirectDatagramsQueueFullPreservesBuffer(t *testing.T) {
	reader := &fakeDirectReader{
		source:  &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
		packets: [][]byte{[]byte("first"), []byte("second")},
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSend := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseSend)
	sender := &recordingDatagramSender{}
	sender.onSend = func(count int) {
		if count == 1 {
			close(entered)
			<-release
		}
	}
	server := newDatagramRelayTestServer()
	route := &datagramRoute{}
	routes := map[uint32]*datagramRoute{1: route}
	server.udpRoutes.Add(1)
	done := make(chan struct{})
	go func() {
		server.receiveDirectDatagrams(sender, route, reader, []byte{0, 0, 0, 1}, 1, routes, &sync.Mutex{}, "")
		close(done)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first datagram was not blocked in SendDatagram")
	}
	readsWhileBlocked := reader.reads
	releaseSend()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive loop did not finish after releasing SendDatagram")
	}

	if readsWhileBlocked != 1 {
		t.Fatalf("reads while send queue full = %d, want 1", readsWhileBlocked)
	}
	if len(sender.packets) != 2 {
		t.Fatalf("sent datagrams = %d, want 2", len(sender.packets))
	}
	for i, payload := range [][]byte{[]byte("first"), []byte("second")} {
		expected := expectedDirectReply(1, 1, net.IPv4(8, 8, 8, 8).To4(), 53, payload)
		if !bytes.Equal(sender.packets[i], expected) {
			t.Fatalf("reply %d = %v, want %v", i, sender.packets[i], expected)
		}
	}
}

func TestValidDatagramAddress(t *testing.T) {
	validIPv6 := make([]byte, 19)
	validIPv6[0] = 4
	tests := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{name: "IPv4", data: []byte{1, 8, 8, 8, 8, 0, 53}, valid: true},
		{name: "IPv4 truncated", data: []byte{1, 8, 8, 8, 8, 0}, valid: false},
		{name: "IPv6", data: validIPv6, valid: true},
		{name: "IPv6 truncated", data: validIPv6[:18], valid: false},
		{name: "domain", data: []byte{3, 3, 'f', 'o', 'o', 0, 53}, valid: true},
		{name: "domain truncated", data: []byte{3, 3, 'f', 'o', 'o', 0}, valid: false},
		{name: "unknown type", data: []byte{2, 0}, valid: false},
		{name: "empty", data: nil, valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validDatagramAddress(test.data); got != test.valid {
				t.Fatalf("validDatagramAddress() = %v, want %v", got, test.valid)
			}
		})
	}
}

func BenchmarkHandleDatagramsIPv4Literal(b *testing.B) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen target UDP: %v", err)
	}
	defer target.Close()

	payload := bytes.Repeat([]byte{0x5a}, 1200)
	session := &fakeDatagramSession{
		remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		message:    directRelayTestMessage(1, target.LocalAddr().(*net.UDPAddr).Port, payload),
		remaining:  b.N,
	}
	server := newDatagramRelayTestServer()
	server.running.Store(true)
	b.ReportAllocs()
	b.ResetTimer()
	server.handleDatagrams(session, "")
}

func BenchmarkReceiveDirectDatagramsIPv4Literal(b *testing.B) {
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	reader := &fakeDirectReader{
		source:  &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53},
		packets: [][]byte{payload},
		repeat:  b.N - 1,
	}
	sender := &discardDatagramSender{}
	server := newDatagramRelayTestServer()
	route := &datagramRoute{}
	routes := map[uint32]*datagramRoute{1: route}
	server.udpRoutes.Add(1)
	b.ReportAllocs()
	b.ResetTimer()
	server.receiveDirectDatagrams(sender, route, reader, []byte{0, 0, 0, 1}, 1, routes, &sync.Mutex{}, "")
	if sender.datagrams != b.N {
		b.Fatalf("sent datagrams = %d, want %d", sender.datagrams, b.N)
	}
}
