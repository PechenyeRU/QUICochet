package tunnel

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// injectablePacketConn is a controllable net.PacketConn used by the
// multi-peer tests to inject inbound packets with arbitrary source
// addresses (which loopback UDP cannot do). Outbound writes are
// captured for assertion. Distinct from jitterbuf_test's fakePacketConn
// which only emits canned packets.
type injectablePacketConn struct {
	mu      sync.Mutex
	inbox   chan injectedPkt
	written []injectedWrite
	closed  bool
}

type injectedPkt struct {
	data []byte
	from net.Addr
}

type injectedWrite struct {
	data []byte
	to   net.Addr
}

func newInjectablePacketConn() *injectablePacketConn {
	return &injectablePacketConn{inbox: make(chan injectedPkt, 16)}
}

func (f *injectablePacketConn) inject(data []byte, from net.Addr) {
	f.inbox <- injectedPkt{data: data, from: from}
}

func (f *injectablePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-f.inbox
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, pkt.data), pkt.from, nil
}

func (f *injectablePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dup := make([]byte, len(p))
	copy(dup, p)
	f.written = append(f.written, injectedWrite{data: dup, to: addr})
	return len(p), nil
}

func (f *injectablePacketConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.inbox)
	return nil
}

func (f *injectablePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4zero} }
func (f *injectablePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *injectablePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *injectablePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (f *injectablePacketConn) takeWrites() []injectedWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.written
	f.written = nil
	return out
}

// peerKeys bundles the cipher pair for one peer in the 2-peer setup:
// the server's view (decrypts what the peer sends) and the peer's view
// (encrypts what the peer sends to the server). The tests focus on
// inbound dispatch + AEAD auth — the security-critical path of the
// source-IP routing model.
type peerKeys struct {
	serverSide *crypto.Cipher
	clientSide *crypto.Cipher
}

func makePeerKeys(t *testing.T) peerKeys {
	t.Helper()

	serverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}
	clientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}
	ss, err := crypto.ComputeSharedSecret(serverKP.PrivateKey, clientKP.PublicKey)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	csk, crk, err := crypto.DeriveSessionKeys(ss, true)
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	ssk, srk, err := crypto.DeriveSessionKeys(ss, false)
	if err != nil {
		t.Fatalf("server derive: %v", err)
	}
	clientCipher, err := crypto.NewCipher(csk, crk)
	if err != nil {
		t.Fatalf("client cipher: %v", err)
	}
	serverCipher, err := crypto.NewCipher(ssk, srk)
	if err != nil {
		t.Fatalf("server cipher: %v", err)
	}
	return peerKeys{serverSide: serverCipher, clientSide: clientCipher}
}

// TestMultiPeerInboundDispatchHappyPath verifies that two peers, each
// with a distinct keypair and a distinct wire source IP, can both send
// plaintext to a single multi-cipher server obfuscator and be decoded
// correctly. Baseline functionality of the v2.0.0 break.
func TestMultiPeerInboundDispatchHappyPath(t *testing.T) {
	cfg := &config.Config{Performance: config.PerformanceConfig{MTU: 1400}}

	peerA := makePeerKeys(t)
	peerB := makePeerKeys(t)

	ipA := netip.MustParseAddr("198.51.100.10")
	ipB := netip.MustParseAddr("198.51.100.20")
	addrA := &net.UDPAddr{IP: net.IP(ipA.AsSlice()), Port: 4444}
	addrB := &net.UDPAddr{IP: net.IP(ipB.AsSlice()), Port: 5555}

	ciphers := map[netip.Addr]*crypto.Cipher{
		ipA: peerA.serverSide,
		ipB: peerB.serverSide,
	}

	fake := newInjectablePacketConn()
	defer fake.Close()
	server := NewObfuscatedConnMulti(fake, ciphers, cfg)

	encrypt := func(c *crypto.Cipher, plaintext []byte, dst net.Addr) []byte {
		discard := newInjectablePacketConn()
		defer discard.Close()
		obf := NewObfuscatedConn(discard, c, cfg)
		if _, err := obf.WriteTo(plaintext, dst); err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		writes := discard.takeWrites()
		if len(writes) != 1 {
			t.Fatalf("expected 1 framed packet, got %d", len(writes))
		}
		return writes[0].data
	}

	plainA := []byte("hello from peer A")
	plainB := []byte("ciao from peer B")

	fake.inject(encrypt(peerA.clientSide, plainA, addrA), addrA)
	fake.inject(encrypt(peerB.clientSide, plainB, addrB), addrB)

	read := func(want []byte, wantAddr net.Addr) {
		buf := make([]byte, 2048)
		n, src, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		if string(buf[:n]) != string(want) {
			t.Fatalf("plaintext mismatch: got %q, want %q", buf[:n], want)
		}
		gotUDP, ok := src.(*net.UDPAddr)
		wantUDP := wantAddr.(*net.UDPAddr)
		if !ok || !gotUDP.IP.Equal(wantUDP.IP) {
			t.Fatalf("source addr mismatch: got %v, want %v", src, wantAddr)
		}
	}
	read(plainA, addrA)
	read(plainB, addrB)

	if drops := server.UnknownSrcDrops(); drops != 0 {
		t.Fatalf("unexpected unknown-src drops: %d", drops)
	}
}

// TestMultiPeerCrossInjectionDropped is the security-critical test for
// the source-IP routing model. A packet encrypted with peer A's key but
// injected from peer B's source IP must be rejected: the dispatcher
// selects peer B's cipher (because that's what the source IP maps to)
// and DecryptTo fails. The packet is silently dropped — it never
// surfaces to ReadFrom's caller, so the QUIC layer sees nothing.
//
// This is the AEAD-as-authenticator invariant: source-IP is a routing
// hint only; cipher mismatch is fatal. An attacker who knows peer A's
// spoof set cannot inject anything that surfaces unless they also have
// peer A's session key.
func TestMultiPeerCrossInjectionDropped(t *testing.T) {
	cfg := &config.Config{Performance: config.PerformanceConfig{MTU: 1400}}

	peerA := makePeerKeys(t)
	peerB := makePeerKeys(t)

	ipA := netip.MustParseAddr("198.51.100.10")
	ipB := netip.MustParseAddr("198.51.100.20")
	addrA := &net.UDPAddr{IP: net.IP(ipA.AsSlice()), Port: 4444}
	addrB := &net.UDPAddr{IP: net.IP(ipB.AsSlice()), Port: 5555}

	ciphers := map[netip.Addr]*crypto.Cipher{
		ipA: peerA.serverSide,
		ipB: peerB.serverSide,
	}

	fake := newInjectablePacketConn()
	server := NewObfuscatedConnMulti(fake, ciphers, cfg)

	encryptViaA := func(plaintext []byte) []byte {
		discard := newInjectablePacketConn()
		defer discard.Close()
		obf := NewObfuscatedConn(discard, peerA.clientSide, cfg)
		if _, err := obf.WriteTo(plaintext, addrA); err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		return discard.takeWrites()[0].data
	}
	cross := encryptViaA([]byte("smuggled payload"))
	legit := encryptViaA([]byte("legit from A"))

	fake.inject(cross, addrB)
	fake.inject(legit, addrA)

	buf := make([]byte, 2048)
	n, src, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if got := string(buf[:n]); got != "legit from A" {
		t.Fatalf("expected the cross-injected packet to be dropped, got plaintext %q", got)
	}
	if udp := src.(*net.UDPAddr); !udp.IP.Equal(addrA.IP) {
		t.Fatalf("expected source = peer A, got %v", src)
	}
	fake.Close()
}

// TestMultiPeerUnknownSourceDropped verifies that a packet from an
// unknown source IP (not in the cipher map) is discarded and counted in
// UnknownSrcDrops. Mirrors the case where a stray probe or a
// misconfigured peer hits the listener.
func TestMultiPeerUnknownSourceDropped(t *testing.T) {
	cfg := &config.Config{Performance: config.PerformanceConfig{MTU: 1400}}
	peerA := makePeerKeys(t)
	ipA := netip.MustParseAddr("198.51.100.10")
	addrA := &net.UDPAddr{IP: net.IP(ipA.AsSlice()), Port: 4444}
	stranger := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9999}

	ciphers := map[netip.Addr]*crypto.Cipher{ipA: peerA.serverSide}

	fake := newInjectablePacketConn()
	server := NewObfuscatedConnMulti(fake, ciphers, cfg)

	encryptA := func(pt []byte) []byte {
		discard := newInjectablePacketConn()
		defer discard.Close()
		obf := NewObfuscatedConn(discard, peerA.clientSide, cfg)
		if _, err := obf.WriteTo(pt, addrA); err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		return discard.takeWrites()[0].data
	}

	fake.inject(encryptA([]byte("garbage")), stranger)
	fake.inject(encryptA([]byte("legit")), addrA)

	buf := make([]byte, 2048)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != "legit" {
		t.Fatalf("unknown-source packet leaked through: got %q", buf[:n])
	}
	if drops := server.UnknownSrcDrops(); drops != 1 {
		t.Fatalf("expected 1 unknown-src drop, got %d", drops)
	}
	fake.Close()
}
