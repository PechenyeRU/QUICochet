package tunnel

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
	"golang.org/x/sys/unix"
)

type gsoCapturedWrite struct {
	payload []byte
	oob     []byte
	ip      net.IP
	port    uint16
}

type gsoCapturingTransport struct {
	mu       sync.Mutex
	supports bool
	err      error
	singles  []gsoCapturedWrite
	batches  []gsoCapturedWrite
}

func (t *gsoCapturingTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.singles = append(t.singles, gsoCapturedWrite{payload: append([]byte(nil), payload...), ip: append(net.IP(nil), dstIP...), port: dstPort})
	return t.err
}
func (t *gsoCapturingTransport) Receive([]byte) (int, net.IP, uint16, error) {
	return 0, nil, 0, net.ErrClosed
}
func (t *gsoCapturingTransport) Close() error             { return nil }
func (t *gsoCapturingTransport) LocalPort() uint16        { return 0 }
func (t *gsoCapturingTransport) SetReadBuffer(int) error  { return nil }
func (t *gsoCapturingTransport) SetWriteBuffer(int) error { return nil }
func (t *gsoCapturingTransport) SupportsGSO() bool        { return t.supports }
func (t *gsoCapturingTransport) WriteMsgUDP(payload, oob []byte, addr *net.UDPAddr) (int, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.batches = append(t.batches, gsoCapturedWrite{
		payload: append([]byte(nil), payload...),
		oob:     append([]byte(nil), oob...),
		ip:      append(net.IP(nil), addr.IP...),
		port:    uint16(addr.Port),
	})
	if t.err != nil {
		return 0, 0, t.err
	}
	return len(payload), len(oob), nil
}

func TestTransportPacketConnGSOSharesRealPeerResolution(t *testing.T) {
	transport := &gsoCapturingTransport{supports: true}
	conn := newClientTransportConn(transport, net.IPv4(10, 0, 0, 1), nil)
	conn.clientRoute.storeRealPeer(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443})
	wireAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 9999}

	if _, err := conn.WriteTo([]byte("single"), wireAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if _, _, err := conn.WriteMsgUDP([]byte("batch"), makeUDPSegmentMsg(5), wireAddr); err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if !conn.SupportsGSO() {
		t.Fatal("compatible UDP transport did not publish GSO")
	}
	if len(transport.singles) != 1 || len(transport.batches) != 1 {
		t.Fatalf("writes = %d single, %d batch", len(transport.singles), len(transport.batches))
	}
	for name, write := range map[string]gsoCapturedWrite{"single": transport.singles[0], "batch": transport.batches[0]} {
		if !write.ip.Equal(net.IPv4(10, 0, 0, 1)) || write.port != 443 {
			t.Errorf("%s destination = %v:%d, want 10.0.0.1:443", name, write.ip, write.port)
		}
	}

	conn6 := newClientTransportConn(transport, nil, net.ParseIP("2001:db8::1"))
	conn6.clientRoute.storeRealPeer(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8443})
	wireAddr6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::20"), Port: 9999}
	if _, _, err := conn6.WriteMsgUDP([]byte("batch6"), makeUDPSegmentMsg(6), wireAddr6); err != nil {
		t.Fatalf("WriteMsgUDP IPv6: %v", err)
	}
	last := transport.batches[len(transport.batches)-1]
	if !last.ip.Equal(net.ParseIP("2001:db8::1")) || last.port != 8443 {
		t.Errorf("IPv6 destination = %v:%d, want [2001:db8::1]:8443", last.ip, last.port)
	}

	plain := newClientTransportConn(&capturingTransport{}, net.IPv4(10, 0, 0, 1), nil)
	if plain.SupportsGSO() {
		t.Fatal("non-UDP transport published GSO")
	}
}

func TestTransportPacketConnGSOAbsorbsTransientError(t *testing.T) {
	transport := &gsoCapturingTransport{supports: true, err: unix.EAGAIN}
	conn := newClientTransportConn(transport, net.IPv4(10, 0, 0, 1), nil)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 443}
	n, _, err := conn.WriteMsgUDP([]byte("payload"), makeUDPSegmentMsg(4), addr)
	if err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if n != len("payload") {
		t.Fatalf("n = %d, want %d", n, len("payload"))
	}
}

func newGSOTestCiphers(t testing.TB) (*crypto.Cipher, *crypto.Cipher) {
	t.Helper()
	kp1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sk1, rk1, err := crypto.DeriveSessionKeys(ss, true)
	if err != nil {
		t.Fatal(err)
	}
	sk2, rk2, err := crypto.DeriveSessionKeys(ss, false)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := crypto.NewCipher(sk1, rk1)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := crypto.NewCipher(sk2, rk2)
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver
}

func TestObfuscatedConnGSOEncryptsSegmentsIndependently(t *testing.T) {
	sender, receiver := newGSOTestCiphers(t)
	transport := &gsoCapturingTransport{supports: true}
	raw := newClientTransportConn(transport, net.IPv4(10, 0, 0, 1), nil)
	raw.clientRoute.storeRealPeer(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443})
	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
		Obfuscation: config.ObfuscationConfig{Mode: string(config.ObfuscationStandard)},
	}
	conn := NewObfuscatedConn(raw, sender, cfg)
	if !conn.SupportsGSO() {
		t.Fatal("obfuscation wrapper hid UDP GSO")
	}

	const segmentSize = 1200
	plaintext := make([]byte, 2700)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 9999}
	n, _, err := conn.WriteMsgUDP(plaintext, makeUDPSegmentMsg(segmentSize), addr)
	if err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("n = %d, want %d", n, len(plaintext))
	}
	if len(transport.batches) != 1 {
		t.Fatalf("underlying batches = %d, want 1", len(transport.batches))
	}
	wireWrite := transport.batches[0]
	if !wireWrite.ip.Equal(net.IPv4(10, 0, 0, 1)) || wireWrite.port != 443 {
		t.Fatalf("wire destination = %v:%d", wireWrite.ip, wireWrite.port)
	}
	messages, err := unix.ParseSocketControlMessage(wireWrite.oob)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Header.Type != unix.UDP_SEGMENT {
		t.Fatalf("obfuscator forwarded unexpected cmsgs: %+v", messages)
	}
	wireGSOSize, err := parseUDPSegmentSize(wireWrite.oob)
	if err != nil {
		t.Fatal(err)
	}
	if int(wireGSOSize) == segmentSize {
		t.Fatal("obfuscator did not replace UDP_SEGMENT with the wire size")
	}

	var decoded []byte
	for offset := 0; offset < len(wireWrite.payload); {
		segmentLen := min(int(wireGSOSize), len(wireWrite.payload)-offset)
		segment := wireWrite.payload[offset : offset+segmentLen]
		plainBuf := make([]byte, len(segment))
		plainLen, err := receiver.DecryptTo(plainBuf, segment)
		if err != nil {
			t.Fatalf("decrypt segment at %d: %v", offset, err)
		}
		plainBuf = plainBuf[:plainLen]
		if len(plainBuf) < 3 || plainBuf[0] != pktTypeData {
			t.Fatalf("invalid plaintext framing at %d", offset)
		}
		payloadLen := int(plainBuf[1])<<8 | int(plainBuf[2])
		decoded = append(decoded, plainBuf[3:3+payloadLen]...)
		offset += segmentLen
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("obfuscated GSO changed or lost plaintext segments")
	}
}

func TestObfuscatedConnGSOUsesDedicatedBufferPool(t *testing.T) {
	sender, _ := newGSOTestCiphers(t)
	transport := &gsoCapturingTransport{supports: true}
	raw := newClientTransportConn(transport, net.IPv4(10, 0, 0, 1), nil)
	raw.clientRoute.storeRealPeer(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443})
	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
		Obfuscation: config.ObfuscationConfig{Mode: string(config.ObfuscationStandard)},
	}
	conn := NewObfuscatedConn(raw, sender, cfg)
	plaintext := make([]byte, 16*1200)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 9999}
	if _, _, err := conn.WriteMsgUDP(plaintext, makeUDPSegmentMsg(1200), addr); err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if len(transport.batches) != 1 {
		t.Fatalf("underlying batches = %d, want 1", len(transport.batches))
	}
	wireLen := len(transport.batches[0].payload)

	gsoValue := conn.gsoBufPool.Get()
	gsoPtr, ok := gsoValue.(*[]byte)
	if !ok {
		t.Fatalf("GSO pool element type = %T, want *[]byte", gsoValue)
	}
	if cap(*gsoPtr) < wireLen {
		t.Fatalf("GSO buffer capacity = %d, want at least %d", cap(*gsoPtr), wireLen)
	}
	conn.gsoBufPool.Put(gsoPtr)

	singleValue := conn.bufPool.Get()
	singlePtr, ok := singleValue.(*[]byte)
	if !ok {
		t.Fatalf("single-packet pool element type = %T, want *[]byte", singleValue)
	}
	wantSingleCap := conn.bucket2PtSize + crypto.NonceSize + crypto.TagSize + 64
	if cap(*singlePtr) != wantSingleCap {
		t.Fatalf("single-packet buffer capacity = %d, want %d", cap(*singlePtr), wantSingleCap)
	}
	if cap(*singlePtr) >= wireLen {
		t.Fatalf("single-packet pool retained a GSO-sized buffer: capacity %d, wire length %d", cap(*singlePtr), wireLen)
	}
	conn.bufPool.Put(singlePtr)
}

func TestObfuscatedConnGSOWithJitterBuffer(t *testing.T) {
	sender, _ := newGSOTestCiphers(t)
	transport := &gsoCapturingTransport{supports: true}
	raw := newClientTransportConn(transport, net.IPv4(10, 0, 0, 1), nil)
	raw.clientRoute.storeRealPeer(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443})
	jitter := newJitterBuffer(raw, time.Millisecond, false)
	defer jitter.Close()
	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
		Obfuscation: config.ObfuscationConfig{Mode: string(config.ObfuscationStandard)},
	}
	conn := NewObfuscatedConn(jitter, sender, cfg)
	if !conn.SupportsGSO() {
		t.Fatal("active jitter buffer hid UDP GSO")
	}

	plaintext := make([]byte, 2700)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 9999}
	n, _, err := conn.WriteMsgUDP(plaintext, makeUDPSegmentMsg(1200), addr)
	if err != nil {
		t.Fatalf("WriteMsgUDP through jitter buffer: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("n = %d, want %d", n, len(plaintext))
	}
	if len(transport.batches) != 1 {
		t.Fatalf("underlying batches = %d, want 1", len(transport.batches))
	}
}

type gsoDiscardTransport struct{ gsoCapturingTransport }

func (t *gsoDiscardTransport) WriteMsgUDP(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
	return len(payload), len(oob), nil
}

func BenchmarkObfuscatedConnWriteMsgUDP(b *testing.B) {
	sender, _ := newGSOTestCiphers(b)
	transport := &gsoDiscardTransport{gsoCapturingTransport{supports: true}}
	raw := newClientTransportConn(transport, net.IPv4(10, 0, 0, 1), nil)
	raw.clientRoute.storeRealPeer(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443})
	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
		Obfuscation: config.ObfuscationConfig{Mode: string(config.ObfuscationStandard)},
	}
	conn := NewObfuscatedConn(raw, sender, cfg)
	payload := make([]byte, 8*1200)
	oob := makeUDPSegmentMsg(1200)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 9999}

	b.ReportAllocs()
	if _, _, err := conn.WriteMsgUDP(payload, oob, addr); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := conn.WriteMsgUDP(payload, oob, addr); err != nil {
			b.Fatal(err)
		}
	}
}
