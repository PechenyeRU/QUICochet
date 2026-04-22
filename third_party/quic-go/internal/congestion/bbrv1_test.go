package congestion

import (
	"testing"
	"time"

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

// TestBBRv1_SentTimesSkipsNonAckEliciting guards the second half of the
// production leak: non-ack-eliciting packets (pure ACKs, PATH_CHALLENGE,
// CONNECTION_CLOSE) never trigger OnPacketAcked nor OnCongestionEvent in
// the sent packet handler. If OnPacketSent unconditionally stores them,
// the map grows forever. At 600 pooled connections each emitting ~1-2
// ACKs/sec over hours this compounds to hundreds of MB of map buckets.
func TestBBRv1_SentTimesSkipsNonAckEliciting(t *testing.T) {
	b := NewBBRv1Sender(1200)

	const n = 10000
	for i := range n {
		b.OnPacketSent(monotime.Now(), 0, protocol.PacketNumber(i), 1200, false)
	}
	if got := len(b.sentTimes); got != 0 {
		t.Fatalf("non-ack-eliciting OnPacketSent × %d: sentTimes len = %d, want 0 (leak)", n, got)
	}
}

// TestBBRv1_SentTimesSweepsStaleEntries covers the residual leak: packets
// declared lost via sent_packet_handler that skip OnCongestionEvent (PathMTU
// probes, per RFC 9002 §3). The periodic sweep in OnPacketSent should evict
// anything older than sentTimesStaleAge.
func TestBBRv1_SentTimesSweepsStaleEntries(t *testing.T) {
	b := NewBBRv1Sender(1200)
	t0 := monotime.Now()

	// Inject a stale entry simulating a PMTU probe declared lost long ago.
	b.sentTimes[99999] = t0

	// Drive OnPacketSent with monotonically advancing times past the stale
	// threshold, enough iterations to trigger at least one sweep tick.
	future := t0 + monotime.Time(sentTimesStaleAge+time.Second)
	for i := range sentTimesSweepInterval + 1 {
		b.OnPacketSent(future+monotime.Time(i), 0, protocol.PacketNumber(i), 1200, true)
	}

	if _, stillThere := b.sentTimes[99999]; stillThere {
		t.Fatalf("stale sentTimes entry not swept after %d OnPacketSent calls", sentTimesSweepInterval+1)
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
