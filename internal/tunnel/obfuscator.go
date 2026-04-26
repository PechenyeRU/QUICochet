package tunnel

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
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
type ObfuscatedConn struct {
	net.PacketConn
	cipher *crypto.Cipher
	cfg    *config.Config

	// Single pool shared by ciphertext and plaintext buffers. Both have the
	// same shape (MTU + headroom); unifying them halves the resident working
	// set and improves L1/L2 cache hit rate.
	bufPool sync.Pool

	sendMu sync.Mutex

	// Pre-calculated bucket sizes for fixed-size padding. Plaintexts are
	// rounded up to one of two buckets so the on-wire packet size only
	// ever takes one of two values, preserving the CBR invariant against
	// DPI / AI traffic analysis. Anything larger than the second bucket
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

	// paranoid is true when CBR chaffing is enabled — lastSendTime is only
	// read by chaffTicker in that mode, so we skip the atomic store in
	// WriteTo otherwise to save a time.Now() call per packet.
	paranoid bool

	// lastSendTime tracks the last real WriteTo for CBR mode.
	// The chaff ticker checks this to fill idle gaps with dummy packets.
	lastSendTime atomic.Int64

	// oversizeDrops counts plaintexts rejected for exceeding maxPlaintext.
	// Exposed via the admin endpoint so an operator can spot a misbehaving
	// upstream path without grepping logs.
	oversizeDrops atomic.Uint64
}

// NewObfuscatedConn creates a new ObfuscatedConn wrapper.
func NewObfuscatedConn(conn net.PacketConn, cipher *crypto.Cipher, cfg *config.Config) *ObfuscatedConn {
	fixedSize := cfg.Performance.MTU
	if fixedSize <= 0 {
		fixedSize = 1350 // Fallback
	}

	// Pre-calculate the target plaintext size to avoid recalculating it
	// thousands of times per second inside the WriteTo hot path.
	targetPtSize := fixedSize - (crypto.NonceSize + crypto.TagSize)
	if targetPtSize < 3 {
		targetPtSize = 3 // Minimum limit (Type + Len)
	}
	bucket2PtSize := 2 * targetPtSize
	maxPlaintext := bucket2PtSize

	return &ObfuscatedConn{
		PacketConn:    conn,
		cipher:        cipher,
		cfg:           cfg,
		targetPtSize:  targetPtSize,
		bucket2PtSize: bucket2PtSize,
		maxPlaintext:  maxPlaintext,
		paranoid:      cfg.Obfuscation.Mode == string(config.ObfuscationParanoid),
		bufPool: sync.Pool{
			New: func() any {
				// Must fit the largest plaintext bucket plus AEAD
				// overhead (nonce + tag) and a small framing slack.
				buf := make([]byte, bucket2PtSize+crypto.NonceSize+crypto.TagSize+64)
				return &buf
			},
		},
	}
}

// WriteTo encrypts, formats, and writes a packet to the underlying connection.
func (c *ObfuscatedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	minRequired := 3 + len(p)

	// In standard / paranoid mode every plaintext is rounded to one of two
	// fixed buckets. Anything larger than the second bucket would emit a
	// third distinct on-wire size and break the CBR invariant the
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
				slog.Warn("obfuscator dropped oversize packet to preserve CBR invariant",
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

	encLen, err := c.cipher.EncryptTo(buf, plaintext)
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

		ptLen, err := c.cipher.DecryptTo(ptBuf, buf[:rawN])
		if err != nil {
			// Malicious probe or noise: silently discard
			continue
		}

		// AEAD verified: it is now safe to teach the underlying transport
		// the peer's current ephemeral port. Doing this before decrypt
		// would let any spoofed UDP packet hijack our egress (Q-05).
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
// fixed-size bucket budget and were dropped to preserve the CBR
// invariant. Useful for admin telemetry and tests.
func (c *ObfuscatedConn) OversizeDrops() uint64 {
	return c.oversizeDrops.Load()
}

// SendChaff sends a dummy packet to deceive burst analysis.
// Only valid in paranoid mode — guard here as defense-in-depth
// in case future code adds call sites outside chaffTicker.
func (c *ObfuscatedConn) SendChaff(addr net.Addr) error {
	if c.cfg.Obfuscation.Mode != string(config.ObfuscationParanoid) {
		return nil
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

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

	encLen, err := c.cipher.EncryptTo(buf, plaintext)
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
