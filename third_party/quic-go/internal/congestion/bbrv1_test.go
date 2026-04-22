package congestion

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// TestBBRv1_SentTimesPrunedOnLoss guards against a regression of the
// production leak where OnCongestionEvent did not delete the lost packet
// from sentTimes. On a long-lived connection with modest loss this caused
// hundreds of MB of heap to accumulate in the BBR sender over hours.
func TestBBRv1_SentTimesPrunedOnLoss(t *testing.T) {
	b := NewBBRv1Sender(1200)

	// Simulate 10000 packets sent, all declared lost. Without the fix,
	// sentTimes would retain every entry.
	const n = 10000
	for i := range n {
		b.OnPacketSent(monotime.Now(), 0, protocol.PacketNumber(i), 1200, true)
	}
	if got := len(b.sentTimes); got != n {
		t.Fatalf("after OnPacketSent × %d: sentTimes len = %d, want %d", n, got, n)
	}

	for i := range n {
		b.OnCongestionEvent(protocol.PacketNumber(i), 1200, 0)
	}
	if got := len(b.sentTimes); got != 0 {
		t.Fatalf("after OnCongestionEvent for every sent packet: sentTimes len = %d, want 0 (leak)", got)
	}
}

// TestBBRv1_SentTimesPrunedOnAck is the happy-path counterpart: ACK must
// prune too (already worked, but pinned here so the symmetric invariant
// between OnPacketAcked and OnCongestionEvent stays visible in tests).
func TestBBRv1_SentTimesPrunedOnAck(t *testing.T) {
	b := NewBBRv1Sender(1200)
	now := monotime.Now()

	for i := range 1000 {
		b.OnPacketSent(now, 0, protocol.PacketNumber(i), 1200, true)
	}
	for i := range 1000 {
		b.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, now+monotime.Time(1e6))
	}
	if got := len(b.sentTimes); got != 0 {
		t.Fatalf("after OnPacketAcked for every sent packet: sentTimes len = %d, want 0", got)
	}
}
