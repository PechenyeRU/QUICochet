package tunnel

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

const (
	pktTypeData  byte = 0x01
	pktTypeDummy byte = 0x02
)

// ObfuscatedConn wraps a net.PacketConn and provides encryption,
// padding, and chaffing to evade DPI and AI-based traffic analysis.
//
// Two construction modes:
//
//   - Single-cipher (client mode): all packets use the same cipher.
//     Created by NewObfuscatedConn.
//
//   - Multi-cipher (server mode): inbound packets are dispatched to the
//     appropriate cipher by the wire source IP. The map is built from
//     peers[].peer_spoof_ips at server startup and is read-only
//     thereafter (no lock needed).
//     Created by NewObfuscatedConnMulti.
//
// Source-IP dispatch security model:
//
//	Source IP is a ROUTING HINT, not an authentication gate. The true
//	auth is the per-peer AEAD: if the source IP maps to cipher C but
//	the ciphertext was produced by a different key, DecryptTo fails and
//	the packet is dropped (same as today). The dispatch only selects
//	which cipher to TRY for decryption.
//
//	This design is safe against IP spoofing: a packet with a forged source
//	IP from peer-A's spoof range but encrypted with peer-B's key will fail
//	DecryptTo with peer-A's cipher and be dropped. The adversary learns
//	nothing useful.
type ObfuscatedConn struct {
	net.PacketConn

	// cipher is used in single-cipher mode (client side). Nil in
	// multi-cipher mode — use ciphers map instead.
	cipher *crypto.Cipher

	// ciphers maps each wire source IP (peer's spoof IP) to its cipher.
	// Read-only after init — plain map is concurrent-safe by Go memory
	// model. Use netip.Addr (16-byte value, no alloc) as key.
	// Nil in single-cipher mode.
	ciphers map[netip.Addr]*crypto.Cipher

	cfg *config.Config

	// Single pool shared by ciphertext and plaintext buffers. Both have the
	// same shape (MTU + headroom); unifying them halves the resident working
	// set and improves L1/L2 cache hit rate.
	bufPool sync.Pool

	// Pre-calculated bucket sizes for fixed-size padding. Plaintexts are
	// rounded up to one of two buckets so the on-wire packet size only
	// ever takes one of two values, preserving the size invariant against
	// length-based DPI heuristics. Anything larger than the second bucket
	// would introduce a third distinct size and is dropped.
	//
	//   targetPtSize  — tier-1 bucket (~MTU - AEAD overhead)
	//   bucket2PtSize — tier-2 bucket (2 * targetPtSize); covers rare
	//                   coalesced packets without doubling the wire
	//                   footprint of every flow
	//   maxPlaintext  — hard ceiling; oversize packets are dropped with
	//                   a warn so callers see the budget breach
	targetPtSize  int
	bucket2PtSize int
	maxPlaintext  int

	// paranoid is true when idle-gap chaffing is enabled — lastSendTime is
	// only read by chaffTicker in that mode, so we skip the atomic store in
	// WriteTo otherwise to save a time.Now() call per packet.
	paranoid bool

	// lastSendTime tracks the last real WriteTo so the chaff ticker can
	// fill idle gaps without piling extra packets onto an already-busy
	// link. NOTE: this is a rate FLOOR, not strict CBR — chaff is
	// suppressed while real traffic is flowing, so a determined observer
	// can still infer active vs idle from inter-arrival distribution.
	// The on-wire packet size invariant (two-bucket padding above) is
	// the strict guarantee; the rate is bounded below, not held flat.
	lastSendTime atomic.Int64

	// oversizeDrops counts plaintexts rejected for exceeding maxPlaintext.
	// Exposed via the admin endpoint so an operator can spot a misbehaving
	// upstream path without grepping logs.
	oversizeDrops atomic.Uint64

	// inboundDrops counts inbound packets that did not produce a decoded
	// plaintext: either the wire source IP did not map to any peer
	// (multi-cipher mode), or the AEAD verification failed. The two
	// classes are intentionally NOT distinguished in this counter — see
	// Sec-H2 in the v2.0.0 audit. An asymmetric counter (only one of the
	// two paths recorded) is a peer-membership oracle: an attacker sending
	// from an in-set IP with random ciphertext gets a different observable
	// signature than from an out-of-set IP. Conflating both classes makes
	// the lookup→AEAD pair a single "did this packet make it through"
	// indicator that reveals nothing about which check rejected it.
	inboundDrops atomic.Uint64
}

// newObfuscatedConnCommon initialises the shared fields. Called by both
// NewObfuscatedConn and NewObfuscatedConnMulti.
func newObfuscatedConnCommon(conn net.PacketConn, cfg *config.Config) *ObfuscatedConn {
	fixedSize := cfg.Performance.MTU
	if fixedSize <= 0 {
		fixedSize = 1350 // Fallback
	}

	// Pre-calculate the target plaintext size to avoid recalculating it
	// thousands of times per second inside the WriteTo hot path.
	// Minimum 3 bytes (Type + Len framing).
	targetPtSize := max(fixedSize-(crypto.NonceSize+crypto.TagSize), 3)
	bucket2PtSize := 2 * targetPtSize
	maxPlaintext := bucket2PtSize

	c := &ObfuscatedConn{
		PacketConn:    conn,
		cfg:           cfg,
		targetPtSize:  targetPtSize,
		bucket2PtSize: bucket2PtSize,
		maxPlaintext:  maxPlaintext,
		paranoid:      cfg.Obfuscation.Mode == string(config.ObfuscationParanoid),
	}
	c.bufPool = sync.Pool{
		New: func() any {
			// Must fit the largest plaintext bucket plus AEAD
			// overhead (nonce + tag) and a small framing slack.
			buf := make([]byte, bucket2PtSize+crypto.NonceSize+crypto.TagSize+64)
			return &buf
		},
	}
	return c
}

// NewObfuscatedConn creates a new ObfuscatedConn for client mode
// (single cipher — all packets use the same key).
func NewObfuscatedConn(conn net.PacketConn, cipher *crypto.Cipher, cfg *config.Config) *ObfuscatedConn {
	c := newObfuscatedConnCommon(conn, cfg)
	c.cipher = cipher
	return c
}

// NewObfuscatedConnMulti creates a new ObfuscatedConn for server mode
// (multi-cipher — cipher is selected by the wire source IP of each
// inbound packet).
//
// ciphers maps every peer wire spoof IP (from peers[].peer_spoof_ips and
// peers[].peer_spoof_ipv6s) to the cipher derived from
// ECDH(server_priv, peer_pub). The map MUST be read-only after this
// call — do not modify it from any goroutine.
//
// A packet whose wire source IP is not in the map is silently dropped
// and counted in inboundDrops alongside AEAD-failure drops. This is the
// expected outcome for probes, noise, and multi-peer config mistakes.
func NewObfuscatedConnMulti(conn net.PacketConn, ciphers map[netip.Addr]*crypto.Cipher, cfg *config.Config) *ObfuscatedConn {
	c := newObfuscatedConnCommon(conn, cfg)
	c.ciphers = ciphers
	return c
}

// cipherFor returns the cipher to use for a packet from/to the given
// wire source IP.
//
//   - Single-cipher mode (c.cipher != nil): always returns c.cipher.
//   - Multi-cipher mode: looks up by normalised netip.Addr; returns nil
//     when the IP is unknown (packet should be dropped).
func (c *ObfuscatedConn) cipherFor(ip net.IP) *crypto.Cipher {
	if c.cipher != nil {
		return c.cipher
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	addr = addr.Unmap() // normalise v4-mapped → plain v4
	return c.ciphers[addr]
}

// WriteTo encrypts, formats, and writes a packet to the underlying connection.
func (c *ObfuscatedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	minRequired := 3 + len(p)

	// In standard / paranoid mode every plaintext is rounded to one of two
	// fixed buckets. Anything larger than the second bucket would emit a
	// third distinct on-wire size and break the size invariant the
	// obfuscator promises, so silently drop with a counter + warn rather
	// than expand the bucket set. quic-go retransmits or fragments the
	// payload at a smaller boundary on its own.
	plaintextSize := minRequired
	if c.cfg.Obfuscation.Mode != string(config.ObfuscationNone) {
		switch {
		case minRequired <= c.targetPtSize:
			plaintextSize = c.targetPtSize
		case minRequired <= c.bucket2PtSize:
			plaintextSize = c.bucket2PtSize
		default:
			drops := c.oversizeDrops.Add(1)
			// Warn at the first drop and then every 1000th so a
			// pathological path is visible without log-flooding.
			if drops == 1 || drops%1000 == 0 {
				slog.Warn("obfuscator dropped oversize packet to preserve size invariant",
					"component", "obfuscator",
					"size", len(p),
					"max_payload", c.maxPlaintext-3,
					"drops", drops)
			}
			// Pretend success so quic-go's transport layer does not
			// tear down the whole pool. The packet is lost; quic-go
			// will retransmit at the next ack-eliciting opportunity.
			return len(p), nil
		}
	}

	// Determine cipher for this destination. In server mode the addr is
	// the spoofed IP quic-go derived from a prior ReadFrom, so it maps
	// to the correct peer cipher.
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("obfuscator WriteTo: expected *net.UDPAddr, got %T", addr)
	}
	cipher := c.cipherFor(udpAddr.IP)
	if cipher == nil {
		// This should not happen in normal operation (server would only
		// WriteTo an addr it received from); log + drop rather than panic.
		slog.Warn("obfuscator WriteTo: no cipher for destination IP — dropping",
			"component", "obfuscator", "dst", udpAddr.IP)
		return len(p), nil
	}

	bufPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufPtr)
	buf := *bufPtr

	ptPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(ptPtr)
	fullPtBuf := *ptPtr

	plaintext := fullPtBuf[:plaintextSize]

	plaintext[0] = pktTypeData
	plaintext[1] = byte(len(p) >> 8)
	plaintext[2] = byte(len(p) & 0xFF)
	copy(plaintext[3:], p)

	encLen, err := cipher.EncryptTo(buf, plaintext)
	if err != nil {
		// Avoid using fmt.Errorf here to prevent slow string allocations in the hot path
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(buf[:encLen], addr)
	if err != nil {
		return 0, err
	}

	// Only paranoid mode needs lastSendTime for the chaff ticker. Skip the
	// atomic store + time.Now() syscall on every packet otherwise.
	if c.paranoid {
		c.lastSendTime.Store(time.Now().UnixNano())
	}
	return len(p), nil
}

// ReadFrom reads, decrypts, and removes padding from a packet.
//
// Multi-cipher dispatch: when the conn was created with NewObfuscatedConnMulti,
// the cipher is selected by the wire source IP of each incoming packet. A
// source IP not in the peer map causes the packet to be silently dropped.
// An AEAD failure with the selected cipher is also silently dropped.
// Both classes share a single inboundDrops counter — see the field doc
// for the rationale (peer-membership oracle).
//
// Security note: source-IP lookup is the ROUTING step only. Authentication
// is the subsequent AEAD: both gates must pass for the packet to be accepted.
func (c *ObfuscatedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufPtr)
	buf := *bufPtr

	ptPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(ptPtr)
	ptBuf := *ptPtr

	type peerUpdater interface{ MaybeUpdatePeer(net.Addr) }

	for {
		rawN, rawAddr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		// Multi-cipher: select cipher by wire source IP.
		// POST-AEAD-ONLY comment applies here: MaybeUpdatePeer is only
		// called AFTER DecryptTo succeeds below, never before.
		var activeCipher *crypto.Cipher
		if c.ciphers != nil {
			udpSrc, ok := rawAddr.(*net.UDPAddr)
			if !ok {
				continue
			}
			activeCipher = c.cipherFor(udpSrc.IP)
			if activeCipher == nil {
				// Source IP not in any peer's spoof set — could be a probe
				// or misconfigured peer. Count and drop silently. The same
				// counter is bumped on AEAD-fail below: an asymmetric log
				// or counter here would be a peer-membership oracle.
				c.inboundDrops.Add(1)
				continue
			}
		} else {
			activeCipher = c.cipher
		}

		ptLen, err := activeCipher.DecryptTo(ptBuf, buf[:rawN])
		if err != nil {
			// Probe, noise, or wrong-key-from-known-IP: silently discard.
			// Bump the same counter as the unknown-src path so the two
			// classes are indistinguishable from outside.
			c.inboundDrops.Add(1)
			continue
		}

		// AEAD verified: it is now safe to teach the underlying transport
		// the peer's current ephemeral port. Doing this before decrypt
		// would let any spoofed UDP packet hijack our egress (Q-05).
		//
		// POST-AEAD-ONLY: MaybeUpdatePeer is called here and ONLY here,
		// after a successful DecryptTo.
		if u, ok := c.PacketConn.(peerUpdater); ok {
			u.MaybeUpdatePeer(rawAddr)
		}

		plaintext := ptBuf[:ptLen]
		if len(plaintext) < 3 {
			continue
		}

		packetType := plaintext[0]

		switch packetType {
		case pktTypeData:
			payloadLen := int(plaintext[1])<<8 | int(plaintext[2])
			if 3+payloadLen > len(plaintext) {
				continue
			}

			n = copy(p, plaintext[3:3+payloadLen])
			return n, rawAddr, nil

		case pktTypeDummy:
			// Chaff packet: silently discard
			continue

		default:
			continue
		}
	}
}

// OversizeDrops returns the number of plaintexts that exceeded the
// fixed-size bucket budget and were dropped to preserve the size
// invariant. Useful for admin telemetry and tests.
func (c *ObfuscatedConn) OversizeDrops() uint64 {
	return c.oversizeDrops.Load()
}

// InboundDrops returns the number of inbound packets that did not
// produce a decoded plaintext, conflating two classes:
//
//   - the wire source IP did not map to any peer (multi-cipher mode),
//   - the AEAD verification failed (any mode).
//
// The two classes share one counter on purpose; see the inboundDrops
// field doc for the security rationale.
func (c *ObfuscatedConn) InboundDrops() uint64 {
	return c.inboundDrops.Load()
}

// SendChaff sends a dummy packet to deceive burst analysis.
// Only valid in paranoid mode — guard here as defense-in-depth
// in case future code adds call sites outside chaffTicker.
//
// In multi-cipher mode the cipher is selected from addr (the peer's
// spoofed IP), so chaff uses the same per-peer key as real traffic.
//
// Concurrency: WriteTo and SendChaff can run on independent goroutines.
// They share only sync.Pool (concurrent-safe) and the underlying
// PacketConn (UDP send is concurrent-safe), so no mutex is needed.
func (c *ObfuscatedConn) SendChaff(addr net.Addr) error {
	if c.cfg.Obfuscation.Mode != string(config.ObfuscationParanoid) {
		return nil
	}

	// Determine cipher.
	var activeCipher *crypto.Cipher
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		activeCipher = c.cipherFor(udpAddr.IP)
	}
	if activeCipher == nil {
		activeCipher = c.cipher // fallback for single-cipher / addr without IP
	}
	if activeCipher == nil {
		return nil // no cipher available (misconfigured addr) — skip chaff
	}

	bufPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufPtr)
	buf := *bufPtr

	ptPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(ptPtr)

	// Use the pre-calculated size
	plaintext := (*ptPtr)[:c.targetPtSize]

	plaintext[0] = pktTypeDummy
	plaintext[1] = 0 // Length: 0
	plaintext[2] = 0

	// Fill padding with pseudorandom data — after AEAD encryption any
	// plaintext is indistinguishable from random, so CSPRNG is not needed
	for i := 3; i < len(plaintext); i += 8 {
		v := rand.Uint64()
		for j := 0; j < 8 && i+j < len(plaintext); j++ {
			plaintext[i+j] = byte(v >> (j * 8))
		}
	}

	encLen, err := activeCipher.EncryptTo(buf, plaintext)
	if err != nil {
		return err
	}

	_, err = c.PacketConn.WriteTo(buf[:encLen], addr)
	return err
}

func (c *ObfuscatedConn) Close() error                       { return c.PacketConn.Close() }
func (c *ObfuscatedConn) LocalAddr() net.Addr                { return c.PacketConn.LocalAddr() }
func (c *ObfuscatedConn) SetDeadline(t time.Time) error      { return c.PacketConn.SetDeadline(t) }
func (c *ObfuscatedConn) SetReadDeadline(t time.Time) error  { return c.PacketConn.SetReadDeadline(t) }
func (c *ObfuscatedConn) SetWriteDeadline(t time.Time) error { return c.PacketConn.SetWriteDeadline(t) }

// SetReadBuffer / SetWriteBuffer forward to the underlying conn so
// quic-go can set SO_RCVBUF / SO_SNDBUF via duck-typing.
func (c *ObfuscatedConn) SetReadBuffer(size int) error {
	type setter interface{ SetReadBuffer(int) error }
	if s, ok := c.PacketConn.(setter); ok {
		return s.SetReadBuffer(size)
	}
	return nil
}

func (c *ObfuscatedConn) SetWriteBuffer(size int) error {
	type setter interface{ SetWriteBuffer(int) error }
	if s, ok := c.PacketConn.(setter); ok {
		return s.SetWriteBuffer(size)
	}
	return nil
}

// SyscallConn delegates to the underlying conn so quic-go can set socket
// buffer sizes (SO_RCVBUF/SO_SNDBUF) on the real UDP socket.
func (c *ObfuscatedConn) SyscallConn() (syscall.RawConn, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if sc, ok := c.PacketConn.(syscallConner); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("underlying conn does not support SyscallConn")
}
