package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

func TestObfuscationLogic(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)

	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	// Manual test of WriteTo logic (without network)
	msg := []byte("test message")
	// [Type:1][Len:2][Payload:variable]
	plaintext := make([]byte, 3+len(msg))
	plaintext[0] = pktTypeData
	plaintext[1] = byte(len(msg) >> 8)
	plaintext[2] = byte(len(msg) & 0xFF)
	copy(plaintext[3:], msg)

	buf1 := make([]byte, 2048)
	encLen, err := cipher1.EncryptTo(buf1, plaintext)
	if err != nil {
		t.Fatalf("EncryptTo failed: %v", err)
	}

	// Decrypt back
	buf2 := make([]byte, 2048)
	decLen, err := cipher2.DecryptTo(buf2, buf1[:encLen])
	if err != nil {
		t.Fatalf("DecryptTo failed: %v", err)
	}

	if !bytes.Equal(plaintext, buf2[:decLen]) {
		t.Errorf("Mismatch! Expected %x, got %x", plaintext, buf2[:decLen])
	}
}

func TestObfuscatedConn(t *testing.T) {
	// Setup real keys
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)

	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	// Local UDP pair
	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc1.Close()

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc2.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 100, // Force heavy padding for the test
		},
	}

	oc1 := NewObfuscatedConn(pc1, cipher1, cfg)
	oc2 := NewObfuscatedConn(pc2, cipher2, cfg)

	addr1 := oc1.LocalAddr()
	addr2 := oc2.LocalAddr()

	t.Run("DataPacket", func(t *testing.T) {
		msg := []byte("hello obfuscation")
		_, err := oc1.WriteTo(msg, addr2)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 2048)
		oc2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := oc2.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(msg, buf[:n]) {
			t.Errorf("expected %s, got %s", msg, buf[:n])
		}
		if addr.String() != addr1.String() {
			t.Errorf("expected addr %s, got %s", addr1, addr)
		}
	})

	// Regression for Q-10: verify that the on-wire packet size only ever
	// takes one of the two fixed bucket values, and that anything beyond
	// the second bucket is dropped (CBR invariant).
	t.Run("BucketSizing", func(t *testing.T) {
		// With MTU=100 the AEAD overhead (12+16) gives:
		//   targetPtSize  = 72   → wire size 100
		//   bucket2PtSize = 144  → wire size 172
		// Listener for direct (un-obfuscated) reads so we can measure
		// the raw on-wire size.
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()

		send := func(payloadLen int) int {
			payload := bytes.Repeat([]byte("x"), payloadLen)
			before := oc1.OversizeDrops()
			_, werr := oc1.WriteTo(payload, raw.LocalAddr())
			if werr != nil {
				t.Fatalf("WriteTo(%d): %v", payloadLen, werr)
			}
			if oc1.OversizeDrops() > before {
				return -1 // dropped
			}
			buf := make([]byte, 4096)
			_ = raw.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, rerr := raw.ReadFrom(buf)
			if rerr != nil {
				t.Fatalf("ReadFrom(%d): %v", payloadLen, rerr)
			}
			return n
		}

		// Tier-1 bucket: small payload should produce a 100-byte wire packet.
		if got := send(10); got != 100 {
			t.Errorf("small payload wire size = %d, want 100", got)
		}
		// Tier-1 boundary: payload that just fits in tier 1 (72-3 = 69).
		if got := send(69); got != 100 {
			t.Errorf("tier-1 boundary wire size = %d, want 100", got)
		}
		// Tier-2 bucket: payload that overflows tier 1 should land in tier 2.
		if got := send(70); got != 172 {
			t.Errorf("tier-2 lower wire size = %d, want 172", got)
		}
		if got := send(141); got != 172 {
			t.Errorf("tier-2 upper wire size = %d, want 172", got)
		}
		// Oversize: must be dropped; counter must increment; nothing on wire.
		dropsBefore := oc1.OversizeDrops()
		_, werr := oc1.WriteTo(bytes.Repeat([]byte("x"), 200), raw.LocalAddr())
		if werr != nil {
			t.Fatalf("WriteTo oversize unexpectedly errored: %v", werr)
		}
		if oc1.OversizeDrops() != dropsBefore+1 {
			t.Errorf("OversizeDrops = %d, want %d", oc1.OversizeDrops(), dropsBefore+1)
		}
		_ = raw.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := make([]byte, 4096)
		if _, _, err := raw.ReadFrom(buf); err == nil {
			t.Error("expected timeout on oversize drop, got a packet")
		}
	})

	t.Run("DummyPacket", func(t *testing.T) {
		// Send a dummy from 1 to 2
		err := oc1.SendChaff(addr2)
		if err != nil {
			t.Fatal(err)
		}

		// Send a real packet from 1 to 2
		msg := []byte("after dummy")
		go func() {
			time.Sleep(100 * time.Millisecond)
			oc1.WriteTo(msg, addr2)
		}()

		// oc2.ReadFrom should skip the dummy and return "after dummy"
		buf := make([]byte, 2048)
		oc2.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := oc2.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(msg, buf[:n]) {
			t.Errorf("expected %s, got %s", msg, buf[:n])
		}
	})
}

func BenchmarkObfuscatorWrite(b *testing.B) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	cipher, _ := crypto.NewCipher(sk1, rk1)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 1400,
		},
	}

	oc := NewObfuscatedConn(pc, cipher, cfg)
	addr := oc.LocalAddr()

	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oc.WriteTo(data, addr)
	}
}

func BenchmarkObfuscatorRead(b *testing.B) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	cipher1, _ := crypto.NewCipher(sk1, rk1)
	cipher2, _ := crypto.NewCipher(sk2, rk2)

	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc1.Close()

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc2.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			MTU: 1400,
		},
	}

	oc1 := NewObfuscatedConn(pc1, cipher1, cfg)
	oc2 := NewObfuscatedConn(pc2, cipher2, cfg)

	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}

	// Pre-send packets
	addr2 := oc2.LocalAddr()
	go func() {
		for {
			oc1.WriteTo(data, addr2)
		}
	}()

	buf := make([]byte, 2048)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		oc2.ReadFrom(buf)
	}
}

// BenchmarkObfuscatorReadMulti exercises the server-side hot path with
// the multi-cipher dispatcher (NewObfuscatedConnMulti) so a future change
// to the per-packet cipherFor lookup is visible in CI bench diffs.
//
// Compared with BenchmarkObfuscatorRead this adds:
//   - one map lookup keyed by netip.Addr per packet (cipherFor),
//   - one Unmap() call on a v4-mapped-v6 normalisation path.
//
// Both are O(1); the regression we want to catch is anyone introducing
// a per-packet allocation, lock, or linear scan.
func BenchmarkObfuscatorReadMulti(b *testing.B) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	ss, _ := crypto.ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	sk1, rk1, _ := crypto.DeriveSessionKeys(ss, true)
	sk2, rk2, _ := crypto.DeriveSessionKeys(ss, false)

	clientCipher, _ := crypto.NewCipher(sk1, rk1)
	serverCipher, _ := crypto.NewCipher(sk2, rk2)

	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc1.Close()
	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc2.Close()

	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
	}

	oc1 := NewObfuscatedConn(pc1, clientCipher, cfg)
	clientUDP := pc1.LocalAddr().(*net.UDPAddr)
	addr, _ := netip.AddrFromSlice(clientUDP.IP)
	addr = addr.Unmap()
	ciphers := map[netip.Addr]*crypto.Cipher{addr: serverCipher}
	oc2 := NewObfuscatedConnMulti(pc2, ciphers, cfg)

	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}

	addr2 := oc2.LocalAddr()
	go func() {
		for {
			oc1.WriteTo(data, addr2)
		}
	}()

	buf := make([]byte, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oc2.ReadFrom(buf)
	}
}

// obfuscatorBenchSizes are the payload sizes of the codec benchmarks: a
// small control packet, a mid-size packet and a near-MTU data packet.
var obfuscatorBenchSizes = []int{32, 512, 1200}

func obfuscatorTestConfig(mode config.ObfuscationMode) *config.Config {
	return &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
		Obfuscation: config.ObfuscationConfig{Mode: string(mode)},
	}
}

// obfuscatorKeys is makePeerKeys with testing.TB, so benchmarks can use it.
func obfuscatorKeys(tb testing.TB) peerKeys {
	tb.Helper()
	serverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		tb.Fatal(err)
	}
	clientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		tb.Fatal(err)
	}
	ss, err := crypto.ComputeSharedSecret(serverKP.PrivateKey, clientKP.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	csk, crk, err := crypto.DeriveSessionKeys(ss, true)
	if err != nil {
		tb.Fatal(err)
	}
	ssk, srk, err := crypto.DeriveSessionKeys(ss, false)
	if err != nil {
		tb.Fatal(err)
	}
	clientCipher, err := crypto.NewCipher(csk, crk)
	if err != nil {
		tb.Fatal(err)
	}
	serverCipher, err := crypto.NewCipher(ssk, srk)
	if err != nil {
		tb.Fatal(err)
	}
	return peerKeys{serverSide: serverCipher, clientSide: clientCipher}
}

func testPayload(size int) []byte {
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(i*7 + 1)
	}
	return p
}

// framePlaintext builds the plaintext that WriteTo seals for payload.
func framePlaintext(payload []byte, ptSize int) []byte {
	pt := make([]byte, ptSize)
	pt[0] = pktTypeData
	pt[1] = byte(len(payload) >> 8)
	pt[2] = byte(len(payload) & 0xFF)
	copy(pt[3:], payload)
	return pt
}

func wantWireSize(c *ObfuscatedConn, payloadLen int, mode config.ObfuscationMode) int {
	pt := 3 + payloadLen
	if mode != config.ObfuscationNone {
		if pt <= c.targetPtSize {
			pt = c.targetPtSize
		} else {
			pt = c.bucket2PtSize
		}
	}
	return pt + crypto.NonceSize + crypto.TagSize
}

// relayOne moves the single packet that src wrote to the inbox of dst,
// as if it arrived from addr, and returns its wire bytes.
func relayOne(t *testing.T, src, dst *injectablePacketConn, addr net.Addr) []byte {
	t.Helper()
	writes := src.takeWrites()
	if len(writes) != 1 {
		t.Fatalf("captured %d writes, want 1", len(writes))
	}
	dst.inject(writes[0].data, addr)
	return writes[0].data
}

// discardPacketConn accepts every write without copying it.
type discardPacketConn struct{ net.PacketConn }

func (discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

// benchReadConn serves packets that sender sealed in advance. Every packet
// has a fresh nonce counter, so the receiver replay window accepts all of
// them. refill reuses the ring storage and does not allocate.
type benchReadConn struct {
	net.PacketConn
	sender    *crypto.Cipher
	from      *net.UDPAddr
	plaintext []byte
	ring      [][]byte
	lens      []int
	next      int
}

func (c *benchReadConn) init(plaintext []byte) {
	const ringSize = 256
	c.plaintext = plaintext
	c.ring = make([][]byte, ringSize)
	c.lens = make([]int, ringSize)
	for i := range c.ring {
		c.ring[i] = make([]byte, len(plaintext)+crypto.NonceSize+crypto.TagSize)
	}
	c.refill()
}

func (c *benchReadConn) refill() {
	for i := range c.ring {
		n, err := c.sender.EncryptTo(c.ring[i], c.plaintext)
		if err != nil {
			panic(err)
		}
		c.lens[i] = n
	}
	c.next = 0
}

func (c *benchReadConn) exhausted() bool { return c.next == len(c.ring) }

func (c *benchReadConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.exhausted() {
		c.refill()
	}
	n := copy(p, c.ring[c.next][:c.lens[c.next]])
	c.next++
	return n, c.from, nil
}

// TestObfuscatorInPlaceSingleCipher checks the in-place seal and open path
// in single-cipher mode: payload integrity, unchanged caller buffer and
// on-wire size for every bucket boundary.
func TestObfuscatorInPlaceSingleCipher(t *testing.T) {
	for _, mode := range []config.ObfuscationMode{config.ObfuscationStandard, config.ObfuscationNone} {
		t.Run(string(mode), func(t *testing.T) {
			keys := obfuscatorKeys(t)
			cfg := obfuscatorTestConfig(mode)
			txConn := newInjectablePacketConn()
			defer txConn.Close()
			rxConn := newInjectablePacketConn()
			defer rxConn.Close()
			tx := NewObfuscatedConn(txConn, keys.clientSide, cfg)
			rx := NewObfuscatedConn(rxConn, keys.serverSide, cfg)
			dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4433}
			src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5555}

			sizes := []int{0, 1, 32, 512, 1200,
				tx.targetPtSize - 3, tx.targetPtSize - 2, tx.bucket2PtSize - 3}
			for _, size := range sizes {
				payload := testPayload(size)
				orig := bytes.Clone(payload)
				if _, err := tx.WriteTo(payload, dst); err != nil {
					t.Fatalf("WriteTo(%d): %v", size, err)
				}
				if !bytes.Equal(payload, orig) {
					t.Fatalf("WriteTo(%d) modified the caller payload", size)
				}
				wire := relayOne(t, txConn, rxConn, src)
				if want := wantWireSize(tx, size, mode); len(wire) != want {
					t.Fatalf("wire size for payload %d = %d, want %d", size, len(wire), want)
				}

				out := make([]byte, 4096)
				n, addr, err := rx.ReadFrom(out)
				if err != nil {
					t.Fatalf("ReadFrom(%d): %v", size, err)
				}
				if !bytes.Equal(out[:n], payload) {
					t.Fatalf("payload %d mismatch after round trip", size)
				}
				if addr.String() != src.String() {
					t.Fatalf("addr = %s, want %s", addr, src)
				}
			}
			if d := rx.InboundDrops(); d != 0 {
				t.Fatalf("InboundDrops = %d, want 0", d)
			}
		})
	}
}

// TestObfuscatorInPlaceMultiCipher checks both directions of the server
// side with two peers, plus the drop paths that run before and inside the
// in-place open.
func TestObfuscatorInPlaceMultiCipher(t *testing.T) {
	cfg := obfuscatorTestConfig(config.ObfuscationStandard)
	srvAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 254), Port: 443}

	type peer struct {
		keys peerKeys
		addr *net.UDPAddr
		conn *injectablePacketConn
		oc   *ObfuscatedConn
	}
	peers := []*peer{
		{keys: obfuscatorKeys(t), addr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111}},
		{keys: obfuscatorKeys(t), addr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222}},
	}
	ciphers := make(map[netip.Addr]*crypto.Cipher, len(peers))
	for _, p := range peers {
		p.conn = newInjectablePacketConn()
		defer p.conn.Close()
		p.oc = NewObfuscatedConn(p.conn, p.keys.clientSide, cfg)
		a, _ := netip.AddrFromSlice(p.addr.IP)
		ciphers[a.Unmap()] = p.keys.serverSide
	}
	srvConn := newInjectablePacketConn()
	defer srvConn.Close()
	srv := NewObfuscatedConnMulti(srvConn, ciphers, cfg)

	out := make([]byte, 4096)
	for _, size := range obfuscatorBenchSizes {
		for i, p := range peers {
			payload := testPayload(size + i)

			// Server write direction: per-peer cipher selected by dst.
			if _, err := srv.WriteTo(payload, p.addr); err != nil {
				t.Fatalf("server WriteTo: %v", err)
			}
			wire := relayOne(t, srvConn, p.conn, srvAddr)
			if want := wantWireSize(srv, len(payload), config.ObfuscationStandard); len(wire) != want {
				t.Fatalf("server wire size = %d, want %d", len(wire), want)
			}
			n, _, err := p.oc.ReadFrom(out)
			if err != nil || !bytes.Equal(out[:n], payload) {
				t.Fatalf("peer %d ReadFrom(%d): n=%d err=%v", i, size, n, err)
			}

			// Server read direction: per-peer cipher selected by src.
			if _, err := p.oc.WriteTo(payload, srvAddr); err != nil {
				t.Fatalf("peer WriteTo: %v", err)
			}
			relayOne(t, p.conn, srvConn, p.addr)
			n, addr, err := srv.ReadFrom(out)
			if err != nil || !bytes.Equal(out[:n], payload) {
				t.Fatalf("server ReadFrom(%d) from peer %d: n=%d err=%v", size, i, n, err)
			}
			if addr.String() != p.addr.String() {
				t.Fatalf("server ReadFrom addr = %s, want %s", addr, p.addr)
			}
		}
	}
	if d := srv.InboundDrops(); d != 0 {
		t.Fatalf("InboundDrops = %d, want 0", d)
	}

	// Peer A ciphertext from peer B source: AEAD fails in place.
	if _, err := peers[0].oc.WriteTo(testPayload(32), srvAddr); err != nil {
		t.Fatal(err)
	}
	relayOne(t, peers[0].conn, srvConn, peers[1].addr)
	// Shorter than nonce + tag: rejected before the in-place slice.
	srvConn.inject([]byte{1, 2, 3, 4, 5}, peers[0].addr)
	// Unknown source.
	srvConn.inject(make([]byte, 64), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 9})
	// A valid packet after the drops must still decode.
	payload := testPayload(512)
	if _, err := peers[1].oc.WriteTo(payload, srvAddr); err != nil {
		t.Fatal(err)
	}
	relayOne(t, peers[1].conn, srvConn, peers[1].addr)
	n, _, err := srv.ReadFrom(out)
	if err != nil || !bytes.Equal(out[:n], payload) {
		t.Fatalf("ReadFrom after drops: n=%d err=%v", n, err)
	}
	if d := srv.InboundDrops(); d != 3 {
		t.Fatalf("InboundDrops = %d, want 3", d)
	}
}

// TestObfuscatorInPlaceChaff checks that chaff built in place has the
// tier-1 wire size and that the receiver authenticates and skips it.
func TestObfuscatorInPlaceChaff(t *testing.T) {
	keys := obfuscatorKeys(t)
	cfg := obfuscatorTestConfig(config.ObfuscationParanoid)
	txConn := newInjectablePacketConn()
	defer txConn.Close()
	rxConn := newInjectablePacketConn()
	defer rxConn.Close()
	tx := NewObfuscatedConn(txConn, keys.clientSide, cfg)
	rx := NewObfuscatedConn(rxConn, keys.serverSide, cfg)
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4433}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5555}

	if err := tx.SendChaff(dst); err != nil {
		t.Fatal(err)
	}
	chaff := relayOne(t, txConn, rxConn, src)
	if want := tx.targetPtSize + crypto.NonceSize + crypto.TagSize; len(chaff) != want {
		t.Fatalf("chaff wire size = %d, want %d", len(chaff), want)
	}

	payload := testPayload(32)
	if _, err := tx.WriteTo(payload, dst); err != nil {
		t.Fatal(err)
	}
	if data := relayOne(t, txConn, rxConn, src); len(data) != len(chaff) {
		t.Fatalf("data wire size = %d, chaff wire size = %d", len(data), len(chaff))
	}
	out := make([]byte, 2048)
	n, _, err := rx.ReadFrom(out)
	if err != nil || !bytes.Equal(out[:n], payload) {
		t.Fatalf("ReadFrom after chaff: n=%d err=%v", n, err)
	}
	if d := rx.InboundDrops(); d != 0 {
		t.Fatalf("InboundDrops = %d, want 0", d)
	}
}

// TestObfuscatorInPlaceConcurrentWrites runs WriteTo from several
// goroutines on one conn. If a pool buffer went back to the pool while a
// write still used it, a packet would fail AEAD or carry a foreign payload.
func TestObfuscatorInPlaceConcurrentWrites(t *testing.T) {
	keys := obfuscatorKeys(t)
	cfg := obfuscatorTestConfig(config.ObfuscationStandard)
	txConn := newInjectablePacketConn()
	defer txConn.Close()
	rxConn := newInjectablePacketConn()
	defer rxConn.Close()
	tx := NewObfuscatedConn(txConn, keys.clientSide, cfg)
	rx := NewObfuscatedConn(rxConn, keys.serverSide, cfg)
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4433}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5555}

	const writers, perWriter = 8, 32
	want := make(map[string]int, writers*perWriter)
	payloadFor := func(w, seq int) []byte {
		p := testPayload(obfuscatorBenchSizes[seq%len(obfuscatorBenchSizes)])
		p[0], p[1] = byte(w), byte(seq)
		return p
	}
	for w := range writers {
		for seq := range perWriter {
			want[string(payloadFor(w, seq))]++
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range perWriter {
				if _, err := tx.WriteTo(payloadFor(w, seq), dst); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	writes := txConn.takeWrites()
	if len(writes) != writers*perWriter {
		t.Fatalf("captured %d writes, want %d", len(writes), writers*perWriter)
	}
	out := make([]byte, 2048)
	for _, w := range writes {
		rxConn.inject(w.data, src)
		n, _, err := rx.ReadFrom(out)
		if err != nil {
			t.Fatal(err)
		}
		key := string(out[:n])
		if want[key] == 0 {
			t.Fatalf("unexpected payload of %d bytes", n)
		}
		want[key]--
	}
	if d := rx.InboundDrops(); d != 0 {
		t.Fatalf("InboundDrops = %d, want 0", d)
	}
}

// TestObfuscatorInPlaceZeroAlloc checks that WriteTo and ReadFrom do not
// allocate per packet in single-cipher and multi-cipher mode.
func TestObfuscatorInPlaceZeroAlloc(t *testing.T) {
	cfg := obfuscatorTestConfig(config.ObfuscationStandard)
	peerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5555}
	peerIP := netip.MustParseAddr("10.0.0.1")

	for _, multi := range []bool{false, true} {
		for _, size := range obfuscatorBenchSizes {
			t.Run(fmt.Sprintf("multi=%t/size=%d", multi, size), func(t *testing.T) {
				keys := obfuscatorKeys(t)
				payload := testPayload(size)

				var w *ObfuscatedConn
				if multi {
					w = NewObfuscatedConnMulti(discardPacketConn{},
						map[netip.Addr]*crypto.Cipher{peerIP: keys.serverSide}, cfg)
				} else {
					w = NewObfuscatedConn(discardPacketConn{}, keys.serverSide, cfg)
				}
				_, _ = w.WriteTo(payload, peerAddr) // warm the pool
				if a := testing.AllocsPerRun(100, func() {
					_, _ = w.WriteTo(payload, peerAddr)
				}); a > 0.5 {
					t.Fatalf("WriteTo allocates %v per packet, want 0", a)
				}

				conn := &benchReadConn{sender: keys.clientSide, from: peerAddr}
				var r *ObfuscatedConn
				if multi {
					r = NewObfuscatedConnMulti(conn,
						map[netip.Addr]*crypto.Cipher{peerIP: keys.serverSide}, cfg)
				} else {
					r = NewObfuscatedConn(conn, keys.serverSide, cfg)
				}
				conn.init(framePlaintext(payload, r.targetPtSize))
				out := make([]byte, 2048)
				_, _, _ = r.ReadFrom(out) // warm the pool
				if a := testing.AllocsPerRun(100, func() {
					_, _, _ = r.ReadFrom(out)
				}); a > 0.5 {
					t.Fatalf("ReadFrom allocates %v per packet, want 0", a)
				}
			})
		}
	}
}

// BenchmarkObfuscatorCodecWrite measures WriteTo without a socket: frame,
// pad and seal, then a no-copy write. It uses only exported behaviour and
// pre-existing fields, so it also runs against the two-buffer version of
// obfuscator.go for a before/after comparison.
func BenchmarkObfuscatorCodecWrite(b *testing.B) {
	cfg := obfuscatorTestConfig(config.ObfuscationStandard)
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4433}
	dstIP := netip.MustParseAddr("10.0.0.1")

	for _, multi := range []bool{false, true} {
		for _, size := range obfuscatorBenchSizes {
			name := fmt.Sprintf("single/size=%d", size)
			if multi {
				name = fmt.Sprintf("multi/size=%d", size)
			}
			b.Run(name, func(b *testing.B) {
				keys := obfuscatorKeys(b)
				var oc *ObfuscatedConn
				if multi {
					oc = NewObfuscatedConnMulti(discardPacketConn{},
						map[netip.Addr]*crypto.Cipher{dstIP: keys.serverSide}, cfg)
				} else {
					oc = NewObfuscatedConn(discardPacketConn{}, keys.serverSide, cfg)
				}
				payload := testPayload(size)

				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := oc.WriteTo(payload, dst); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkObfuscatorCodecRead measures ReadFrom without a socket: copy of
// a pre-sealed packet, open, replay check and unframe. Sealing the ring
// runs with the timer stopped.
func BenchmarkObfuscatorCodecRead(b *testing.B) {
	cfg := obfuscatorTestConfig(config.ObfuscationStandard)
	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5555}
	fromIP := netip.MustParseAddr("10.0.0.1")

	for _, multi := range []bool{false, true} {
		for _, size := range obfuscatorBenchSizes {
			name := fmt.Sprintf("single/size=%d", size)
			if multi {
				name = fmt.Sprintf("multi/size=%d", size)
			}
			b.Run(name, func(b *testing.B) {
				// Fresh keys per run: each run starts with an empty
				// replay window.
				keys := obfuscatorKeys(b)
				conn := &benchReadConn{sender: keys.clientSide, from: from}
				var oc *ObfuscatedConn
				if multi {
					oc = NewObfuscatedConnMulti(conn,
						map[netip.Addr]*crypto.Cipher{fromIP: keys.serverSide}, cfg)
				} else {
					oc = NewObfuscatedConn(conn, keys.serverSide, cfg)
				}
				conn.init(framePlaintext(testPayload(size), oc.targetPtSize))
				out := make([]byte, 2048)

				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if conn.exhausted() {
						b.StopTimer()
						conn.refill()
						b.StartTimer()
					}
					n, _, err := oc.ReadFrom(out)
					if err != nil || n != size {
						b.Fatalf("ReadFrom = %d, %v; want %d", n, err, size)
					}
				}
			})
		}
	}
}
