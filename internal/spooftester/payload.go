package spooftester

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// MagicTag identifies spoof-tester traffic on the wire. Receivers
// silently drop anything that doesn't start with this byte sequence
// so we don't tally unrelated noise (real ICMP echoes, port scanners,
// stray DNS, ...).
//
// Constant chosen to be:
//   - 4 bytes (visible to humans on a hex dump)
//   - ASCII (greppable via tcpdump -A: "QCST")
//   - non-conflicting with any IETF reserved 4-byte header
var MagicTag = [4]byte{'Q', 'C', 'S', 'T'}

// PayloadVersion increases when the wire layout below changes in a way
// that older receivers can't ignore. Receivers reject mismatched
// versions to avoid silent miscounts during partial rollouts.
const PayloadVersion uint8 = 1

// payload format:
//
//	offset  size  field
//	------  ----  ------------------------------------------------
//	0       4     magic ("QCST")
//	4       1     version (1)
//	5       1     reserved (0)
//	6       2     run-id (random nonce, identifies one --packets
//	               burst across protocols so a long run + a stray
//	               rerun don't merge)
//	8       4     seq-number (per-IP, big-endian)
//	12      4     timestamp-ms (low 32 bits of unix ms, info only)
//	16      ...   zero padding up to MinPayloadSize
//
// MinPayloadSize = 32 keeps the L4 length comfortably above any
// minimum required by the transport (TCP-SYN goes through with even
// less, but a fat payload helps tcpdump-grep workflows).
const (
	payloadHeaderSize = 16
	MinPayloadSize    = 32
)

// NewRunID returns a fresh 16-bit random nonce for a sender run.
func NewRunID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// BuildPayload formats a Spoof-Tester payload for the given run-id +
// per-IP sequence. The buffer is exactly MinPayloadSize bytes.
func BuildPayload(runID uint16, seq uint32, unixMillis uint64) []byte {
	out := make([]byte, MinPayloadSize)
	copy(out[0:4], MagicTag[:])
	out[4] = PayloadVersion
	out[5] = 0
	binary.BigEndian.PutUint16(out[6:8], runID)
	binary.BigEndian.PutUint32(out[8:12], seq)
	binary.BigEndian.PutUint32(out[12:16], uint32(unixMillis))
	// trailing bytes are already zero
	return out
}

// ParsePayload validates the magic + version of an inbound payload and
// extracts run-id + seq. Returns an error on tag mismatch or short
// buffer; callers use this both as a parser and as a presence filter
// (any error → silently ignore the datagram).
func ParsePayload(buf []byte) (runID uint16, seq uint32, err error) {
	if len(buf) < payloadHeaderSize {
		return 0, 0, errShortPayload
	}
	if buf[0] != MagicTag[0] || buf[1] != MagicTag[1] || buf[2] != MagicTag[2] || buf[3] != MagicTag[3] {
		return 0, 0, errBadMagic
	}
	if buf[4] != PayloadVersion {
		return 0, 0, errBadVersion
	}
	runID = binary.BigEndian.Uint16(buf[6:8])
	seq = binary.BigEndian.Uint32(buf[8:12])
	return runID, seq, nil
}

var (
	errShortPayload = errors.New("payload too short")
	errBadMagic     = errors.New("magic tag mismatch")
	errBadVersion   = errors.New("payload version mismatch")
)
