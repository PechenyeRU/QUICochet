package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func newTestBBR3Sender(clock Clock, rttStats *utils.RTTStats, connStats *utils.ConnectionStats) *bbr3Sender {
	const mss = protocol.ByteCount(1200)
	return NewBBR3Sender(clock, rttStats, connStats, mss, 32*mss, 10000*mss)
}

func TestBBR3PacingRateHasNoExtraAdjustment(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	sender := newTestBBR3Sender(&clock, rttStats, nil)

	for pn := protocol.PacketNumber(0); pn < maxBurstSizePackets; pn++ {
		require.True(t, sender.HasPacingBudget(now))
		sender.OnPacketSent(now, 0, pn, sender.mss, true)
	}
	require.False(t, sender.HasPacingBudget(now))
	want := time.Duration((uint64(time.Second)*uint64(sender.mss) + sender.pacingRate - 1) / sender.pacingRate)
	require.Greater(t, want, protocol.MinPacingDelay)
	require.Equal(t, want, sender.TimeUntilSend(0).Sub(now))
}

func TestBBR3ConnectionStatsAndQlog(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	var eventRecorder events.Recorder
	sender := newTestBBR3Sender(&clock, rttStats, connStats)
	sender.SetConnectionParameters(rttStats, connStats, &eventRecorder)

	sender.OnPacketSent(now, 0, 1, sender.mss, true)
	sender.OnPacketSent(now, sender.mss, 2, sender.mss, true)
	sender.OnCongestionEvent(1, sender.mss, 2*sender.mss)
	require.Equal(t, uint64(1), connStats.PacketsLost.Load())
	require.Equal(t, uint64(sender.mss), connStats.BytesLost.Load())
	require.True(t, sender.InRecovery())
	sender.OnPacketSent(now, 0, 3, sender.mss, true)

	now = now.Add(10 * time.Millisecond)
	clock = mockClock(now)
	sender.OnPacketAcked(3, sender.mss, sender.mss, now)
	sender.GetCongestionWindow()
	require.False(t, sender.InRecovery())

	sender.OnCongestionEvent(2, 0, sender.mss)
	require.Equal(t, uint64(2), connStats.PacketsLost.Load())
	require.Equal(t, uint64(sender.mss), connStats.BytesLost.Load())
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateApplicationLimited},
		},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
}

func TestBBR3SpuriousLossUndo(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	sender.OnPacketSent(now, 0, 1, sender.mss, true)
	sender.OnCongestionEvent(1, sender.mss, sender.mss)
	require.True(t, sender.epValid)

	sender.OnSpuriousLoss(1)
	require.False(t, sender.epValid)
	require.Equal(t, 1, sender.epSpurious)
	require.Equal(t, b3UndoNone, sender.undoState)
}

func TestBBR3SpuriousLossIgnoresPacketsOutsideEpisode(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	sender.OnPacketSent(now, 0, 1, sender.mss, true)
	sender.OnPacketSent(now, sender.mss, 2, sender.mss, true)
	sender.OnCongestionEvent(1, sender.mss, 2*sender.mss)

	sender.OnSpuriousLoss(2)
	require.True(t, sender.epValid)
	require.Zero(t, sender.epSpurious)
	require.Len(t, sender.epPackets, 1)

	sender.OnSpuriousLoss(1)
	require.False(t, sender.epValid)
	require.Equal(t, 1, sender.epSpurious)
	require.Empty(t, sender.epPackets)
}

func TestBBR3PTOReset(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	sender := newTestBBR3Sender(&clock, rttStats, connStats)
	sender.OnPacketSent(now, 0, 1, sender.mss, true)
	sender.OnCongestionEvent(1, sender.mss, sender.mss)
	sender.OnPacketSent(now, 0, 2, sender.mss, true)
	initialCwnd := sender.initialCwnd
	cwndClamp := sender.cwndClamp

	sender.OnRetransmissionTimeout(false)
	require.Len(t, sender.pkts, 1)
	sender.OnRetransmissionTimeout(true)
	require.Empty(t, sender.pkts)
	require.Equal(t, initialCwnd, sender.cwnd)
	require.Equal(t, cwndClamp, sender.cwndClamp)
	require.Equal(t, b3Startup, sender.mode)
	require.Equal(t, b3CAOpen, sender.caState)
	require.Zero(t, sender.delivered)
	require.Zero(t, sender.lost)
	require.Zero(t, sender.inflight)
	require.Zero(t, sender.appLimited)
	require.Same(t, rttStats, sender.rttStats)
	require.Same(t, connStats, sender.connStats)
}

func TestBBR3PTOResetRebindsPacer(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	oldPacer := sender.pacer

	sender.OnRetransmissionTimeout(true)
	require.NotSame(t, oldPacer, sender.pacer)
	require.Equal(t, sender.mss, sender.pacer.maxDatagramSize)

	sender.pacingRate = uint64(sender.mss)
	for pn := protocol.PacketNumber(0); pn < maxBurstSizePackets; pn++ {
		sender.OnPacketSent(now, 0, pn, sender.mss, true)
	}
	require.False(t, sender.HasPacingBudget(now))
	require.Equal(t, time.Second, sender.TimeUntilSend(0).Sub(now))
}

func TestBBR3SetConnectionParametersUsesConnectionRTTStats(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}

	sender.SetConnectionParameters(rttStats, connStats, nil)
	require.Same(t, rttStats, sender.rttStats)
	require.Same(t, connStats, sender.connStats)
	bw := mulDiv(sender.cwnd, 1000*1000, uint64(rttStats.SmoothedRTT().Microseconds()))
	require.Equal(t, sender.bwToPacingRate(bw, b3StartupPacingGain), sender.pacingRate)
	require.Equal(t, rttStats.MinRTT().Microseconds(), sender.minRTTUS)
}

func TestBBR3PacketNumberSpacesHaveIndependentState(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	initialKey := newB3PacketKey(1, protocol.EncryptionInitial)
	appDataKey := newB3PacketKey(1, protocol.Encryption1RTT)

	sender.OnPacketSentWithEncryptionLevel(now, 0, 1, sender.mss, true, protocol.EncryptionInitial)
	sender.OnPacketSentWithEncryptionLevel(now, sender.mss, 1, sender.mss, true, protocol.Encryption1RTT)
	require.Len(t, sender.pkts, 2)

	sender.OnPacketAckedWithEncryptionLevel(1, sender.mss, 2*sender.mss, now, protocol.EncryptionInitial)
	require.NotContains(t, sender.pkts, initialKey)
	require.Contains(t, sender.pkts, appDataKey)
	require.Equal(t, uint64(sender.mss), sender.delivered)

	sender.OnPacketAckedWithEncryptionLevel(1, sender.mss, sender.mss, now, protocol.Encryption1RTT)
	require.Empty(t, sender.pkts)
}

func TestBBR3RecoveryEndIsScopedToPacketNumberSpace(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	sender.OnPacketSentWithEncryptionLevel(now, 0, 1, sender.mss, true, protocol.EncryptionInitial)
	sender.OnPacketSentWithEncryptionLevel(now, sender.mss, 2, sender.mss, true, protocol.EncryptionInitial)
	sender.OnCongestionEventWithEncryptionLevel(1, sender.mss, 2*sender.mss, protocol.EncryptionInitial)
	require.Equal(t, newB3PacketKey(2, protocol.EncryptionInitial), sender.recoveryEnd)

	sender.OnPacketSentWithEncryptionLevel(now, sender.mss, 1, sender.mss, true, protocol.Encryption1RTT)
	sender.OnPacketSentWithEncryptionLevel(now, 2*sender.mss, 10, sender.mss, true, protocol.Encryption1RTT)
	sender.OnPacketSentWithEncryptionLevel(now, 3*sender.mss, 3, sender.mss, true, protocol.EncryptionInitial)

	sender.OnPacketAckedWithEncryptionLevel(10, sender.mss, 4*sender.mss, now, protocol.Encryption1RTT)
	require.False(t, sender.exitRecov)
	sender.OnPacketAckedWithEncryptionLevel(3, sender.mss, 3*sender.mss, now, protocol.EncryptionInitial)
	require.True(t, sender.exitRecov)
}

func TestBBR3RecoveryOpenedAfterCrossSpaceSendUsesLossSpace(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	connStats := &utils.ConnectionStats{}
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), connStats)
	initialLostKey := newB3PacketKey(1, protocol.EncryptionInitial)
	appDataKey := newB3PacketKey(10, protocol.Encryption1RTT)

	sender.OnPacketSentWithEncryptionLevel(now, 0, 1, sender.mss, true, protocol.EncryptionInitial)
	sender.OnPacketSentWithEncryptionLevel(now, sender.mss, 2, sender.mss, true, protocol.EncryptionInitial)
	sender.OnPacketSentWithEncryptionLevel(now, 2*sender.mss, 10, sender.mss, true, protocol.Encryption1RTT)
	sender.OnCongestionEventWithEncryptionLevel(1, sender.mss, 3*sender.mss, protocol.EncryptionInitial)

	require.Equal(t, newB3PacketKey(2, protocol.EncryptionInitial), sender.recoveryEnd)
	require.Equal(t, map[b3PacketKey]struct{}{initialLostKey: {}}, sender.epPackets)
	require.Equal(t, 1, sender.epLost)
	require.Zero(t, sender.epSpurious)
	require.True(t, sender.epValid)
	require.NotContains(t, sender.pkts, initialLostKey)
	require.Contains(t, sender.pkts, appDataKey)
	require.Equal(t, uint64(1), connStats.PacketsLost.Load())
	require.Equal(t, uint64(sender.mss), connStats.BytesLost.Load())

	sender.OnPacketSentWithEncryptionLevel(now, 2*sender.mss, 11, sender.mss, true, protocol.Encryption1RTT)
	sender.OnPacketAckedWithEncryptionLevel(11, sender.mss, 3*sender.mss, now, protocol.Encryption1RTT)
	require.False(t, sender.exitRecov)

	sender.OnPacketSentWithEncryptionLevel(now, 2*sender.mss, 3, sender.mss, true, protocol.EncryptionInitial)
	sender.OnPacketAckedWithEncryptionLevel(3, sender.mss, 3*sender.mss, now, protocol.EncryptionInitial)
	require.True(t, sender.exitRecov)
}

func TestBBR3DropPacketNumberSpaceExitsRecovery(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	var eventRecorder events.Recorder
	sender := newTestBBR3Sender(&clock, rttStats, nil)
	sender.SetConnectionParameters(rttStats, nil, &eventRecorder)
	mss := sender.mss

	sender.OnPacketSentWithEncryptionLevel(now, mss, 1, mss, true, protocol.EncryptionInitial)
	sender.OnPacketSentWithEncryptionLevel(now, 2*mss, 2, mss, true, protocol.EncryptionInitial)
	sender.OnPacketSentWithEncryptionLevel(now, 3*mss, 10, mss, true, protocol.Encryption1RTT)
	sender.OnCongestionEventWithEncryptionLevel(1, mss, 3*mss, protocol.EncryptionInitial)
	require.True(t, sender.InRecovery())
	require.Equal(t, newB3PacketKey(2, protocol.EncryptionInitial), sender.recoveryEnd)
	require.Len(t, sender.epPackets, 1)

	sender.DropPacketNumberSpace(protocol.EncryptionInitial)
	require.False(t, sender.InRecovery())
	require.False(t, sender.lossYetInRecovery)
	require.Len(t, sender.pkts, 1)
	require.Contains(t, sender.pkts, newB3PacketKey(10, protocol.Encryption1RTT))
	require.Empty(t, sender.epPackets)
	require.False(t, sender.epValid)
	require.Zero(t, sender.epLost)
	require.Equal(t, uint64(mss), sender.inflight)
	require.Equal(t, b3PacketKey{}, sender.lastSent[protocol.EncryptionInitial])
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart},
		},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)

	// 1-RTT traffic goes on, and a new loss opens and closes a new episode.
	sender.OnPacketSentWithEncryptionLevel(now, 2*mss, 11, mss, true, protocol.Encryption1RTT)
	now = now.Add(10 * time.Millisecond)
	clock = mockClock(now)
	sender.OnPacketAckedWithEncryptionLevel(10, mss, 2*mss, now, protocol.Encryption1RTT)
	sender.OnPacketAckedWithEncryptionLevel(11, mss, 2*mss, now, protocol.Encryption1RTT)
	sender.GetCongestionWindow()
	require.Empty(t, sender.pkts)
	require.Equal(t, uint64(2*mss), sender.delivered)

	sender.OnPacketSentWithEncryptionLevel(now, mss, 12, mss, true, protocol.Encryption1RTT)
	sender.OnPacketSentWithEncryptionLevel(now, 2*mss, 13, mss, true, protocol.Encryption1RTT)
	sender.OnCongestionEventWithEncryptionLevel(12, mss, 2*mss, protocol.Encryption1RTT)
	require.True(t, sender.InRecovery())
	require.True(t, sender.epValid)
	require.Equal(t, newB3PacketKey(13, protocol.Encryption1RTT), sender.recoveryEnd)
	sender.OnPacketSentWithEncryptionLevel(now, 2*mss, 14, mss, true, protocol.Encryption1RTT)
	now = now.Add(10 * time.Millisecond)
	clock = mockClock(now)
	sender.OnPacketAckedWithEncryptionLevel(14, mss, 2*mss, now, protocol.Encryption1RTT)
	sender.GetCongestionWindow()
	require.False(t, sender.InRecovery())
	require.Equal(t, uint64(3*mss), sender.delivered)
}

func TestBBR3DropPacketNumberSpaceKeepsOtherSpaceRecovery(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	mss := sender.mss
	lostKey := newB3PacketKey(10, protocol.Encryption1RTT)

	sender.OnPacketSentWithEncryptionLevel(now, mss, 1, mss, true, protocol.EncryptionHandshake)
	sender.OnPacketSentWithEncryptionLevel(now, 2*mss, 10, mss, true, protocol.Encryption1RTT)
	sender.OnPacketSentWithEncryptionLevel(now, 3*mss, 11, mss, true, protocol.Encryption1RTT)
	sender.OnCongestionEventWithEncryptionLevel(10, mss, 3*mss, protocol.Encryption1RTT)

	sender.DropPacketNumberSpace(protocol.EncryptionHandshake)
	require.True(t, sender.InRecovery())
	require.Equal(t, newB3PacketKey(11, protocol.Encryption1RTT), sender.recoveryEnd)
	require.Equal(t, map[b3PacketKey]struct{}{lostKey: {}}, sender.epPackets)
	require.True(t, sender.epValid)
	require.Len(t, sender.pkts, 1)
	require.Equal(t, uint64(mss), sender.inflight)

	sender.OnSpuriousLoss(10)
	require.False(t, sender.epValid)
}

func BenchmarkBBR3SendAck(b *testing.B) {
	const window = 32
	now := monotime.Time(1e9)
	clock := mockClock(now)
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	sender := newTestBBR3Sender(&clock, rttStats, nil)
	mss := sender.mss
	for pn := protocol.PacketNumber(0); pn < window; pn++ {
		sender.OnPacketSent(now, protocol.ByteCount(pn+1)*mss, pn, mss, true)
	}

	b.ReportAllocs()
	var pn protocol.PacketNumber
	for b.Loop() {
		now = now.Add(10 * time.Microsecond)
		sender.OnPacketSent(now, (window+1)*mss, pn+window, mss, true)
		sender.OnPacketAcked(pn, mss, (window+1)*mss, now)
		pn++
	}
}

func TestBBR3SetMaxDatagramSizeRescalesLimits(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	oldMSS := sender.mss
	oldInitialCwnd := sender.initialCwnd
	oldInitCwnd := sender.initCwnd
	oldClamp := sender.cwndClamp

	sender.SetMaxDatagramSize(2 * oldMSS)
	require.Equal(t, 2*oldMSS, sender.mss)
	require.Equal(t, 2*oldMSS, sender.pacer.maxDatagramSize)
	require.Equal(t, 2*oldInitialCwnd, sender.initialCwnd)
	require.Equal(t, 2*oldInitCwnd, sender.initCwnd)
	require.Equal(t, 2*oldClamp, sender.cwndClamp)
	require.LessOrEqual(t, sender.cwnd, sender.cwndClamp)
}

func TestBBR3SetMaxDatagramSizeRaisesMinimumCwnd(t *testing.T) {
	now := monotime.Time(1e9)
	clock := mockClock(now)
	sender := newTestBBR3Sender(&clock, utils.NewRTTStats(), nil)
	sender.cwnd = sender.minCwnd()
	oldMSS := sender.mss
	oldMinCwnd := sender.cwnd
	newMSS := 2 * oldMSS
	require.Less(t, oldMSS, newMSS)

	sender.SetMaxDatagramSize(newMSS)
	require.Equal(t, 2*oldMinCwnd, sender.cwnd)
	require.Equal(t, sender.minCwnd(), sender.cwnd)
}

func TestBBR3LossThresholdRejectsInvalidPercentage(t *testing.T) {
	defaultThreshold := uint64(b3Unit * 2 / 100)
	previous := b3LossThresh
	t.Cleanup(func() { b3LossThresh = previous })

	for _, value := range []string{"100", "100.1"} {
		t.Run(value, func(t *testing.T) {
			b3LossThresh = defaultThreshold
			t.Setenv("QG_BBR_LOSS_THRESH", value)
			setLossThresholdFromEnv()
			require.Equal(t, defaultThreshold, b3LossThresh)
		})
	}
}
