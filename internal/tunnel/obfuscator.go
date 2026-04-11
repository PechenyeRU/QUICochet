package tunnel

import (
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
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

	bufPool sync.Pool
	ptPool  sync.Pool

	sendMu sync.Mutex

	// Pre-calculated target plaintext size for extreme performance
	// Calculated only once at startup to avoid repeated overhead
	targetPtSize int

	// lastSendTime tracks the last real WriteTo for CBR mode.
	// The chaff ticker checks this to fill idle gaps with dummy packets.
	lastSendTime atomic.Int64
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

	return &ObfuscatedConn{
		PacketConn:   conn,
		cipher:       cipher,
		cfg:          cfg,
		targetPtSize: targetPtSize,
		bufPool: sync.Pool{
			New: func() interface{} {
				// Must fit the largest QUIC packet (1200 initial) + our framing (3) + crypto overhead
				buf := make([]byte, fixedSize+1024)
				return &buf
			},
		},
		ptPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, fixedSize+1024)
				return &buf
			},
		},
	}
}

// WriteTo encrypts, formats, and writes a packet to the underlying connection.
func (c *ObfuscatedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	bufPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufPtr)
	buf := *bufPtr

	ptPtr := c.ptPool.Get().(*[]byte)
	defer c.ptPool.Put(ptPtr)
	fullPtBuf := *ptPtr

	minRequired := 3 + len(p)
	plaintextSize := minRequired

	// Pad to fixed MTU size only if obfuscation is enabled (standard/paranoid).
	// In "none" mode, use minimum size — no padding overhead.
	if c.cfg.Obfuscation.Mode != "none" {
		if c.targetPtSize > plaintextSize {
			plaintextSize = c.targetPtSize
		}
	}

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

	c.lastSendTime.Store(time.Now().UnixNano())
	return len(p), nil
}

// ReadFrom reads, decrypts, and removes padding from a packet.
func (c *ObfuscatedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufPtr)
	buf := *bufPtr

	ptPtr := c.ptPool.Get().(*[]byte)
	defer c.ptPool.Put(ptPtr)
	ptBuf := *ptPtr

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

// SendChaff sends a dummy packet to deceive burst analysis.
func (c *ObfuscatedConn) SendChaff(addr net.Addr) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	bufPtr := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bufPtr)
	buf := *bufPtr

	ptPtr := c.ptPool.Get().(*[]byte)
	defer c.ptPool.Put(ptPtr)

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
