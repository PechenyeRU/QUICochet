package quic

import "github.com/quic-go/quic-go/internal/ackhandler"

// SetPacketThreshold overrides the packet-reorder threshold used by the
// loss-detection fast path (RFC 9002 §6.1.1). A packet is considered lost
// when at least `n` later packets have been acknowledged. The upstream
// default is 3, which is too aggressive on real-world WAN paths where
// µs-level jitter combined with user-space send bursts routinely reorders
// 30+ packets — each burst triggers a spurious-loss cascade that collapses
// cwnd to near zero.
//
// Larger values make detection slower for genuine loss (time threshold,
// 9/8 × RTT, is still the primary safety net), but eliminate cwnd
// collapses from harmless reorder.
//
// Must be called BEFORE any quic.Transport is created, and applies
// process-wide. n <= 0 is ignored.
//
// This is a QUICochet-specific extension, not upstream.
func SetPacketThreshold(n int64) { ackhandler.SetPacketThreshold(n) }
