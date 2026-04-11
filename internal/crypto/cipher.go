package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// NonceSize is the size of the nonce for ChaCha20-Poly1305
	NonceSize = chacha20poly1305.NonceSize // 12 bytes
	// TagSize is the authentication tag size
	TagSize = chacha20poly1305.Overhead // 16 bytes
	// MaxPayloadSize is the maximum size of encrypted payload
	MaxPayloadSize = 65535 - NonceSize - TagSize
)

var (
	ErrPayloadTooLarge = errors.New("payload too large")
	ErrDecryptFailed   = errors.New("decryption failed: authentication error")
	ErrReplayedPacket  = errors.New("replayed packet")
	ErrInvalidNonce    = errors.New("invalid nonce")
)

const replayWindowSize = 2048

// Cipher handles ChaCha20-Poly1305 encryption/decryption
type Cipher struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	// Nonce = [noncePrefix:4][counter:8]
	// noncePrefix is random per session — prevents nonce reuse across restarts
	noncePrefix [4]byte
	sendNonce   uint64

	// Replay protection: sliding window on peer's nonce counter.
	// Tracks the peer's session prefix to auto-reset on restart.
	replayMu     sync.Mutex
	peerPrefix   [4]byte
	prefixSet    bool
	replayMax    uint64
	replayBitmap [replayWindowSize / 64]uint64

	// Buffer pool for efficiency
	bufPool sync.Pool
}

// NewCipher creates a new cipher with send and receive keys.
// NOTE: Replay protection is handled by QUIC's packet number mechanism,
// so we don't need manual replay filtering at this layer.
func NewCipher(sendKey, recvKey [KeySize]byte) (*Cipher, error) {
	sendAEAD, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, fmt.Errorf("create send cipher: %w", err)
	}

	recvAEAD, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		return nil, fmt.Errorf("create recv cipher: %w", err)
	}

	var prefix [4]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, fmt.Errorf("generate nonce prefix: %w", err)
	}

	return &Cipher{
		sendAEAD:    sendAEAD,
		recvAEAD:    recvAEAD,
		noncePrefix: prefix,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 65535)
				return &buf
			},
		},
	}, nil
}

// Encrypt encrypts plaintext and returns ciphertext with nonce prepended.
// Format: [nonce:12][ciphertext+tag:variable]
// Nonce = [sessionPrefix:4][counter:8] — unique per session, no reuse across restarts.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	out := make([]byte, NonceSize+len(plaintext)+TagSize)
	c.writeNonce(out[:NonceSize])
	c.sendAEAD.Seal(out[NonceSize:NonceSize], out[:NonceSize], plaintext, nil)

	return out, nil
}

// EncryptTo encrypts plaintext into the provided buffer.
// Returns the number of bytes written.
// Nonce = [sessionPrefix:4][counter:8] — same scheme as Encrypt, zero-alloc.
func (c *Cipher) EncryptTo(dst, plaintext []byte) (int, error) {
	if len(plaintext) > MaxPayloadSize {
		return 0, ErrPayloadTooLarge
	}

	needed := NonceSize + len(plaintext) + TagSize
	if len(dst) < needed {
		return 0, fmt.Errorf("buffer too small: need %d, have %d", needed, len(dst))
	}

	c.writeNonce(dst[:NonceSize])
	c.sendAEAD.Seal(dst[NonceSize:NonceSize], dst[:NonceSize], plaintext, nil)

	return needed, nil
}

// writeNonce writes [noncePrefix:4][counter:8] into dst (must be NonceSize bytes).
func (c *Cipher) writeNonce(dst []byte) {
	copy(dst[:4], c.noncePrefix[:])
	counter := atomic.AddUint64(&c.sendNonce, 1)
	binary.BigEndian.PutUint64(dst[4:NonceSize], counter)
}

// Decrypt decrypts ciphertext with prepended nonce.
// AEAD authentication is verified first, then the replay filter is checked.
// Authentic packets from a restarted peer (new prefix) auto-reset the filter.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrInvalidNonce
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	plaintext, err := c.recvAEAD.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	if !c.replayCheck(nonce) {
		return nil, ErrReplayedPacket
	}

	return plaintext, nil
}

// DecryptTo decrypts ciphertext into the provided buffer.
func (c *Cipher) DecryptTo(dst, ciphertext []byte) (int, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return 0, ErrInvalidNonce
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]
	plaintextLen := len(encrypted) - TagSize

	if len(dst) < plaintextLen {
		return 0, fmt.Errorf("buffer too small: need %d, have %d", plaintextLen, len(dst))
	}

	_, err := c.recvAEAD.Open(dst[:0], nonce, encrypted, nil)
	if err != nil {
		return 0, ErrDecryptFailed
	}

	if !c.replayCheck(nonce) {
		return 0, ErrReplayedPacket
	}

	return plaintextLen, nil
}

// GetBuffer gets a buffer from the pool
func (c *Cipher) GetBuffer() *[]byte {
	return c.bufPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool
func (c *Cipher) PutBuffer(buf *[]byte) {
	c.bufPool.Put(buf)
}

// replayCheck checks a nonce against the sliding window.
// Returns true if the packet is fresh, false if replayed.
// Auto-resets the window when the peer's session prefix changes (restart).
func (c *Cipher) replayCheck(nonce []byte) bool {
	var prefix [4]byte
	copy(prefix[:], nonce[:4])
	counter := binary.BigEndian.Uint64(nonce[4:NonceSize])

	c.replayMu.Lock()
	defer c.replayMu.Unlock()

	// Peer restarted (new session prefix) → reset the window
	if !c.prefixSet || prefix != c.peerPrefix {
		c.peerPrefix = prefix
		c.prefixSet = true
		c.replayMax = counter
		c.replayBitmap = [replayWindowSize / 64]uint64{}
		// Mark this counter as seen
		c.replayBitmap[counter%replayWindowSize/64] |= 1 << (counter % 64)
		return true
	}

	if counter > c.replayMax {
		// New high: shift the window
		diff := counter - c.replayMax
		if diff >= replayWindowSize {
			// Entire window is stale, clear it
			c.replayBitmap = [replayWindowSize / 64]uint64{}
		} else {
			// Clear bits that fell out of the window
			for i := c.replayMax + 1; i <= counter; i++ {
				idx := i % replayWindowSize
				c.replayBitmap[idx/64] &^= 1 << (idx % 64)
			}
		}
		c.replayMax = counter
		// Mark as seen
		idx := counter % replayWindowSize
		c.replayBitmap[idx/64] |= 1 << (idx % 64)
		return true
	}

	// Below window — too old
	if c.replayMax-counter >= replayWindowSize {
		return false
	}

	// Within window — check bitmap
	idx := counter % replayWindowSize
	bit := uint64(1) << (idx % 64)
	if c.replayBitmap[idx/64]&bit != 0 {
		return false // already seen
	}
	c.replayBitmap[idx/64] |= bit
	return true
}

// EncryptedSize returns the size of ciphertext for given plaintext size
func EncryptedSize(plaintextSize int) int {
	return NonceSize + plaintextSize + TagSize
}

// PlaintextSize returns the size of plaintext for given ciphertext size
func PlaintextSize(ciphertextSize int) int {
	return ciphertextSize - NonceSize - TagSize
}
