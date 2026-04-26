package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// sizeProbeConn wraps a net.PacketConn and records the size of every
// outbound packet so the test can inspect what really hits the wire.
type sizeProbeConn struct {
	net.PacketConn
	mu    sync.Mutex
	sizes []int
}

func (c *sizeProbeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sizes = append(c.sizes, len(p))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

// quic-go duck-types these — must forward so quic-go can tune buffers.
func (c *sizeProbeConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("no SyscallConn")
}

func (c *sizeProbeConn) SetReadBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return s.SetReadBuffer(n)
	}
	return nil
}
func (c *sizeProbeConn) SetWriteBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return s.SetWriteBuffer(n)
	}
	return nil
}

func (c *sizeProbeConn) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]int, len(c.sizes))
	copy(out, c.sizes)
	return out
}

// TestModeNoneDoesNotPadPackets is the empirical answer to "are mode=none
// packets really un-padded?". We run a real QUIC handshake + a small
// stream send (~100 bytes payload) over a probed PacketConn in both
// modes, then compare the on-wire size distribution. With mode=none and
// PMTUD off, quic-go must produce naturally-sized packets (small ACKs
// well below InitialPacketSize). With mode=standard the obfuscator pads
// every packet to its bucket so no small sizes appear.
func TestModeNoneDoesNotPadPackets(t *testing.T) {
	stdSizes := captureWireSizes(t, "standard")
	noneSizes := captureWireSizes(t, "none")

	t.Logf("standard: %d packets, distribution %v", len(stdSizes), summarize(stdSizes))
	t.Logf("none    : %d packets, distribution %v", len(noneSizes), summarize(noneSizes))

	// In mode=none we must see at least some packets significantly
	// smaller than the bucket size — empirical proof there is no
	// padding floor.
	const smallThreshold = 200
	smallNone := count(noneSizes, func(s int) bool { return s < smallThreshold })
	if smallNone == 0 {
		t.Fatalf("mode=none: no packets below %dB observed — looks like padding is in effect", smallThreshold)
	}

	// In mode=standard packets are bucketed: nothing below tier-1
	// bucket size (~MTU - AEAD overhead). For MTU=1400 the smallest
	// expected on-wire size is ~1400 (target plaintext + AEAD). We
	// allow some slack for handshake oddities; flag if more than a
	// trivial number of small packets sneak through.
	const stdMinExpected = 1000
	smallStd := count(stdSizes, func(s int) bool { return s < stdMinExpected })
	if smallStd > 5 {
		t.Errorf("mode=standard: %d packets below %dB — bucket invariant looks violated", smallStd, stdMinExpected)
	}
}

func captureWireSizes(t *testing.T, mode string) []int {
	t.Helper()

	var secret [crypto.KeySize]byte
	for i := range secret {
		secret[i] = byte(i + 7)
	}
	cert, err := crypto.DeriveTLSCertificate(secret)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := crypto.DeriveTLSCertHash(secret)

	cfg := &config.Config{
		Performance: config.PerformanceConfig{MTU: 1400},
		Obfuscation: config.ObfuscationConfig{Enabled: mode != "none", Mode: mode},
	}

	// Build matched cipher pair so the obfuscator wrap path can do
	// successful round-trip decrypt in standard mode.
	csk, crk, _ := crypto.DeriveSessionKeys(secret, true)
	ssk, srk, _ := crypto.DeriveSessionKeys(secret, false)
	cliCipher, _ := crypto.NewCipher(csk, crk)
	srvCipher, _ := crypto.NewCipher(ssk, srk)

	// Two raw UDP sockets on loopback — only the client side is
	// probed because that is where the test driver writes.
	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvPC.Close()
	cliBase, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliBase.Close()
	cliProbe := &sizeProbeConn{PacketConn: cliBase}

	// Wrap with the obfuscator only in non-none modes (mirrors the
	// production fast-path).
	var srvQUIC net.PacketConn = srvPC
	var cliQUIC net.PacketConn = cliProbe
	if mode != "none" {
		srvQUIC = NewObfuscatedConn(srvPC, srvCipher, cfg)
		cliQUIC = NewObfuscatedConn(cliProbe, cliCipher, cfg)
	}

	verify := crypto.MakeVerifyPeerCertificate(expected)
	srvTLS := &tls.Config{
		Certificates:          []tls.Certificate{*cert},
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"quic-test"},
		VerifyPeerCertificate: verify,
	}
	cliTLS := &tls.Config{
		Certificates:          []tls.Certificate{*cert},
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		ServerName:            "quiccochet.local",
		NextProtos:            []string{"quic-test"},
		VerifyPeerCertificate: verify,
	}
	quicConf := &quic.Config{
		InitialPacketSize:       1369,
		DisablePathMTUDiscovery: true,
		MaxIdleTimeout:          3 * time.Second,
		HandshakeIdleTimeout:    3 * time.Second,
	}

	ln, err := quic.Listen(srvQUIC, srvTLS, quicConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type res struct {
		sess *quic.Conn
		err  error
	}
	acceptCh := make(chan res, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s, e := ln.Accept(ctx)
		acceptCh <- res{s, e}
	}()

	cliTr := &quic.Transport{Conn: cliQUIC}
	defer cliTr.Close()
	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cConn, err := cliTr.Dial(dialCtx, srvPC.LocalAddr(), cliTLS, quicConf)
	if err != nil {
		t.Fatalf("[%s] dial: %v", mode, err)
	}
	defer cConn.CloseWithError(0, "test")

	ar := <-acceptCh
	if ar.err != nil {
		t.Fatalf("[%s] accept: %v", mode, ar.err)
	}
	defer ar.sess.CloseWithError(0, "test")

	// One short stream exchange (~100 bytes one way) so the
	// recording covers a representative mix of small ACKs and a
	// data-bearing packet.
	go func() {
		s, _ := ar.sess.AcceptStream(context.Background())
		if s != nil {
			io.ReadAll(s)
		}
	}()
	st, err := cConn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("[%s] OpenStreamSync: %v", mode, err)
	}
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = 0xAA
	}
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("[%s] write: %v", mode, err)
	}
	st.Close()
	// Give quic-go time to flush ACKs and the FIN.
	time.Sleep(150 * time.Millisecond)

	return cliProbe.snapshot()
}

func summarize(sizes []int) string {
	if len(sizes) == 0 {
		return "<empty>"
	}
	cp := append([]int(nil), sizes...)
	sort.Ints(cp)
	min, max := cp[0], cp[len(cp)-1]
	median := cp[len(cp)/2]
	var sum int64
	for _, s := range cp {
		sum += int64(s)
	}
	return fmt.Sprintf("min=%d median=%d max=%d avg=%d unique=%d",
		min, median, max, int(sum)/len(cp), uniqueCount(cp))
}

func uniqueCount(sortedSizes []int) int {
	if len(sortedSizes) == 0 {
		return 0
	}
	n := 1
	for i := 1; i < len(sortedSizes); i++ {
		if sortedSizes[i] != sortedSizes[i-1] {
			n++
		}
	}
	return n
}

func count(s []int, pred func(int) bool) int {
	var n int
	for _, x := range s {
		if pred(x) {
			n++
		}
	}
	return n
}
