package congestion

import (
	"fmt"
	"slices"
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

func updateLastBandwidthFilterReference(b *BBRv1Sender, eventTime monotime.Time) (delivery_rate protocol.ByteCount) {
	keep_start_index, expire_sum := 0, 0
	for i := range b.ackinfo {
		if time.Duration(eventTime)-b.ackinfo[i].recordTime > b.lastNewMinRTT {
			keep_start_index = i + 1
			expire_sum += int(b.ackinfo[i].ackedBytes)
		}
	}
	b.ackinfo = b.ackinfo[keep_start_index:]
	b.delivered -= protocol.ByteCount(expire_sum)
	return protocol.ByteCount(float64(b.delivered) / (float64(b.lastNewMinRTT) / float64(time.Second)))
}

func bandwidthFilterRecords(eventTime monotime.Time, ages ...time.Duration) []ackInfo {
	records := make([]ackInfo, len(ages))
	for i, age := range ages {
		records[i] = ackInfo{
			ackedBytes: protocol.ByteCount(1000 + i),
			recordTime: time.Duration(eventTime) - age,
		}
	}
	return records
}

func checkLastBandwidthFilterDifferential(t *testing.T, records []ackInfo, eventTime monotime.Time, minRTT time.Duration, unordered ...bool) {
	t.Helper()

	var delivered protocol.ByteCount
	for _, record := range records {
		delivered += record.ackedBytes
	}
	const extraDelivered = protocol.ByteCount(777)
	delivered += extraDelivered

	got := &BBRv1Sender{
		lastNewMinRTT:    minRTT,
		delivered:        delivered,
		ackinfo:          slices.Clone(records),
		ackinfoUnordered: len(unordered) > 0 && unordered[0],
	}
	want := &BBRv1Sender{
		lastNewMinRTT: minRTT,
		delivered:     delivered,
		ackinfo:       slices.Clone(records),
	}

	gotRate := got.update_lastbandwidth_filter(eventTime)
	wantRate := updateLastBandwidthFilterReference(want, eventTime)

	if !slices.Equal(got.ackinfo, want.ackinfo) {
		t.Errorf("ackinfo = %v, want %v", got.ackinfo, want.ackinfo)
	}
	if got.delivered != want.delivered {
		t.Errorf("delivered = %d, want %d", got.delivered, want.delivered)
	}
	gotExpireSum := delivered - got.delivered
	wantExpireSum := delivered - want.delivered
	if gotExpireSum != wantExpireSum {
		t.Errorf("expire sum = %d, want %d", gotExpireSum, wantExpireSum)
	}
	if gotRate != wantRate {
		t.Errorf("delivery rate = %d, want %d", gotRate, wantRate)
	}
}

func TestBBRv1_UpdateLastBandwidthFilterDifferential(t *testing.T) {
	const minRTT = 100 * time.Millisecond
	eventTime := monotime.Time(time.Second)
	tests := []struct {
		name string
		ages []time.Duration
	}{
		{name: "empty"},
		{name: "none", ages: []time.Duration{100 * time.Millisecond, 50 * time.Millisecond, 0}},
		{name: "all", ages: []time.Duration{500 * time.Millisecond, 250 * time.Millisecond, 101 * time.Millisecond}},
		{name: "mixed", ages: []time.Duration{500 * time.Millisecond, 250 * time.Millisecond, 101 * time.Millisecond, 100 * time.Millisecond, 50 * time.Millisecond, 0}},
		{name: "boundary", ages: []time.Duration{101 * time.Millisecond, 100 * time.Millisecond, 99 * time.Millisecond}},
		{name: "duplicates", ages: []time.Duration{500 * time.Millisecond, 200 * time.Millisecond, 200 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond, 50 * time.Millisecond}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := bandwidthFilterRecords(eventTime, tt.ages...)
			checkLastBandwidthFilterDifferential(t, records, eventTime, minRTT)
		})
	}
}

func TestBBRv1_UpdateLastBandwidthFilterOutOfOrderEvent(t *testing.T) {
	const minRTT = 10 * time.Millisecond
	now := monotime.Time(15 * time.Millisecond)
	records := []ackInfo{
		{ackedBytes: 1000, recordTime: 0},
		{ackedBytes: 1001, recordTime: time.Duration(20 * time.Millisecond)},
		{ackedBytes: 1002, recordTime: time.Duration(10 * time.Millisecond)},
	}
	checkLastBandwidthFilterDifferential(t, records, now, minRTT, true)
}

func TestBBRv1_OnPacketAckedMarksOutOfOrderEvent(t *testing.T) {
	sender := NewBBRv1Sender(1200)
	now := monotime.Now()
	sender.OnPacketAcked(0, 1200, 0, now.Add(20*time.Millisecond))
	sender.OnPacketAcked(1, 1200, 0, now.Add(10*time.Millisecond))
	if !sender.ackinfoUnordered {
		t.Fatal("out-of-order ACK did not disable the prefix fast path")
	}
}

func TestBBRv1_UpdateLastBandwidthFilterMonotonicSequences(t *testing.T) {
	const minRTT = 10 * time.Millisecond
	for _, count := range []int{1, 2, 16, 64, 257} {
		records := make([]ackInfo, count)
		for i := range records {
			records[i] = ackInfo{
				ackedBytes: protocol.ByteCount(1000 + i),
				recordTime: time.Duration(i) * time.Millisecond,
			}
		}
		for _, offset := range []time.Duration{0, 5 * time.Millisecond, 50 * time.Millisecond} {
			eventTime := monotime.Time(time.Duration(count-1)*time.Millisecond + offset)
			t.Run(fmt.Sprintf("records_%d/offset_%s", count, offset), func(t *testing.T) {
				checkLastBandwidthFilterDifferential(t, records, eventTime, minRTT)
			})
		}
	}
}

func BenchmarkBBRv1UpdateLastBandwidthFilter(b *testing.B) {
	const recordCount = 5208
	const ackedBytes = protocol.ByteCount(1200)
	records := make([]ackInfo, recordCount)
	for i := range records {
		records[i] = ackInfo{ackedBytes: ackedBytes, recordTime: time.Duration(i)}
	}

	b.Run("steady_state", func(b *testing.B) {
		sender := &BBRv1Sender{
			lastNewMinRTT: time.Duration(recordCount - 1),
			delivered:     recordCount * ackedBytes,
			ackinfo:       slices.Clone(records),
		}
		originalRecords := sender.ackinfo
		originalDelivered := sender.delivered
		eventTime := monotime.Time(recordCount)
		for b.Loop() {
			sender.update_lastbandwidth_filter(eventTime)
			// The filter changes only the slice header and delivered counter.
			sender.ackinfo = originalRecords
			sender.delivered = originalDelivered
		}
	})

	b.Run("polling_no_expiry", func(b *testing.B) {
		sender := &BBRv1Sender{
			lastNewMinRTT: time.Duration(recordCount),
			delivered:     recordCount * ackedBytes,
			ackinfo:       slices.Clone(records),
		}
		eventTime := monotime.Time(recordCount - 1)
		for b.Loop() {
			sender.update_lastbandwidth_filter(eventTime)
		}
	})
}
