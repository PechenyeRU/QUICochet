package ackhandler

import (
	"reflect"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func newBBR3TestAlgorithm() congestion.SendAlgorithmWithDebugInfos {
	const mss = protocol.ByteCount(1200)
	return congestion.NewBBR3Sender(
		congestion.DefaultClock{},
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		mss,
		32*mss,
		protocol.MaxCongestionWindowPackets*mss,
	)
}

func newBBR3TestHandler(
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	qlogger qlogwriter.Recorder,
	algorithm congestion.SendAlgorithmWithDebugInfos,
) SentPacketHandler {
	return NewSentPacketHandler(
		0,
		1200,
		rttStats,
		connStats,
		true,
		false,
		nil,
		protocol.PerspectiveClient,
		qlogger,
		utils.DefaultLogger,
		algorithm,
	)
}

func TestBBR3AckHandlerBindsConnection(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	var eventRecorder events.Recorder
	algorithm := newBBR3TestAlgorithm()
	sph := newBBR3TestHandler(rttStats, connStats, &eventRecorder, algorithm)

	require.Same(t, algorithm, sph.(*sentPacketHandler).Congestion)
	require.Equal(t,
		[]qlogwriter.Event{qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart}},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
}

type bbr3SpuriousLossTracker struct {
	congestion.SendAlgorithmWithDebugInfos
	spurious    []protocol.PacketNumber
	sentLevels  []protocol.EncryptionLevel
	ackedLevels []protocol.EncryptionLevel
}

func (s *bbr3SpuriousLossTracker) SetConnectionParameters(rttStats *utils.RTTStats, connStats *utils.ConnectionStats, qlogger qlogwriter.Recorder) {
	s.SendAlgorithmWithDebugInfos.(interface {
		SetConnectionParameters(*utils.RTTStats, *utils.ConnectionStats, qlogwriter.Recorder)
	}).SetConnectionParameters(rttStats, connStats, qlogger)
}

func (s *bbr3SpuriousLossTracker) OnSpuriousLoss(pn protocol.PacketNumber) {
	s.spurious = append(s.spurious, pn)
	s.SendAlgorithmWithDebugInfos.(interface{ OnSpuriousLoss(protocol.PacketNumber) }).OnSpuriousLoss(pn)
}

func (s *bbr3SpuriousLossTracker) OnSpuriousLossWithEncryptionLevel(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
	s.spurious = append(s.spurious, pn)
	s.SendAlgorithmWithDebugInfos.(interface {
		OnSpuriousLossWithEncryptionLevel(protocol.PacketNumber, protocol.EncryptionLevel)
	}).OnSpuriousLossWithEncryptionLevel(pn, encLevel)
}

func (s *bbr3SpuriousLossTracker) OnPacketSentWithEncryptionLevel(sentTime monotime.Time, bytesInFlight protocol.ByteCount, pn protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool, encLevel protocol.EncryptionLevel) {
	s.sentLevels = append(s.sentLevels, encLevel)
	s.SendAlgorithmWithDebugInfos.OnPacketSent(sentTime, bytesInFlight, pn, bytes, isRetransmittable)
}

func (s *bbr3SpuriousLossTracker) OnPacketAckedWithEncryptionLevel(pn protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time, encLevel protocol.EncryptionLevel) {
	s.ackedLevels = append(s.ackedLevels, encLevel)
	s.SendAlgorithmWithDebugInfos.OnPacketAcked(pn, ackedBytes, priorInFlight, eventTime)
}

func TestBBR3AckHandlerPropagatesEncryptionLevels(t *testing.T) {
	tracker := &bbr3SpuriousLossTracker{SendAlgorithmWithDebugInfos: newBBR3TestAlgorithm()}
	sph := newBBR3TestHandler(utils.NewRTTStats(), &utils.ConnectionStats{}, nil, tracker)
	start := monotime.Now()
	levels := []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.Encryption1RTT}
	var pns []protocol.PacketNumber

	for i, encLevel := range levels {
		pn := sph.PopPacketNumber(encLevel)
		pns = append(pns, pn)
		sph.SentPacket(start, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1200, false, false)
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: ackRanges(pn)},
			encLevel,
			start.Add(time.Duration(i+1)*time.Millisecond),
		)
		require.NoError(t, err)
	}
	require.Equal(t, pns[0], pns[1])
	require.Equal(t, levels, tracker.sentLevels)
	require.Equal(t, levels, tracker.ackedLevels)
}

func TestBBR3AckHandlerReportsSpuriousLosses(t *testing.T) {
	usePacketThreshold3(t)
	connStats := &utils.ConnectionStats{}
	tracker := &bbr3SpuriousLossTracker{SendAlgorithmWithDebugInfos: newBBR3TestAlgorithm()}
	sph := newBBR3TestHandler(utils.NewRTTStats(), connStats, nil, tracker)

	var packets packetTracker
	start := monotime.Now()
	pns := make([]protocol.PacketNumber, 6)
	for i := range pns {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		pns[i] = pn
		sph.SentPacket(start, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
	}

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[5])},
		protocol.Encryption1RTT,
		start.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2]}, packets.Lost)
	require.Equal(t, uint64(3), connStats.PacketsLost.Load())

	packets.Reset()
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(append([]protocol.PacketNumber(nil), pns...)...)},
		protocol.Encryption1RTT,
		start.Add(time.Second+50*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[3], pns[4]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2]}, tracker.spurious)
}

func TestBBR3AckHandlerPMTUProbeSpuriousLossDoesNotUndoRecovery(t *testing.T) {
	usePacketThreshold3(t)
	connStats := &utils.ConnectionStats{}
	algorithm := newBBR3TestAlgorithm()
	tracker := &bbr3SpuriousLossTracker{SendAlgorithmWithDebugInfos: algorithm}
	sph := newBBR3TestHandler(utils.NewRTTStats(), connStats, nil, tracker)

	var packets packetTracker
	start := monotime.Now()
	pns := make([]protocol.PacketNumber, 6)
	for i := range pns {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		pns[i] = pn
		sph.SentPacket(start, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, i == 1, false)
	}

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[5])},
		protocol.Encryption1RTT,
		start.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2]}, packets.Lost)
	require.Equal(t, uint64(2), connStats.PacketsLost.Load())

	requireEpisodeState := func(lost, spurious int) {
		t.Helper()
		sender := reflect.ValueOf(algorithm).Elem()
		require.Equal(t, lost, int(sender.FieldByName("epLost").Int()))
		require.Equal(t, spurious, int(sender.FieldByName("epSpurious").Int()))
		require.True(t, sender.FieldByName("epValid").Bool())
		require.True(t, algorithm.InRecovery())
	}
	requireEpisodeState(2, 0)

	packets.Reset()
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[1], pns[3], pns[4], pns[5])},
		protocol.Encryption1RTT,
		start.Add(time.Second+50*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[3], pns[4]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[1]}, tracker.spurious)
	require.Equal(t, uint64(2), connStats.PacketsLost.Load())
	requireEpisodeState(2, 0)
}

func TestBBR3AckHandlerDropPacketsEndsRecovery(t *testing.T) {
	usePacketThreshold3(t)
	var eventRecorder events.Recorder
	algorithm := newBBR3TestAlgorithm()
	sph := newBBR3TestHandler(utils.NewRTTStats(), &utils.ConnectionStats{}, &eventRecorder, algorithm)
	sender := reflect.ValueOf(algorithm).Elem()

	var packets packetTracker
	start := monotime.Now()
	pns := make([]protocol.PacketNumber, 6)
	for i := range pns {
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		pns[i] = pn
		sph.SentPacket(start, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1200, false, false)
	}
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[5])},
		protocol.EncryptionInitial,
		start.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, pns[:3], packets.Lost)
	require.True(t, algorithm.InRecovery())
	require.Equal(t, 2, sender.FieldByName("pkts").Len())
	require.Equal(t, 3, sender.FieldByName("epPackets").Len())

	sph.DropPackets(protocol.EncryptionInitial, start.Add(time.Second))
	require.False(t, algorithm.InRecovery())
	require.Zero(t, sender.FieldByName("pkts").Len())
	require.Zero(t, sender.FieldByName("epPackets").Len())
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateApplicationLimited},
		},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)

	pn := sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(start.Add(time.Second), pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
	require.Equal(t, 1, sender.FieldByName("pkts").Len())
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn)},
		protocol.Encryption1RTT,
		start.Add(2*time.Second),
	)
	require.NoError(t, err)
	algorithm.GetCongestionWindow()
	require.False(t, algorithm.InRecovery())
	require.Zero(t, sender.FieldByName("pkts").Len())
	require.Equal(t, []protocol.PacketNumber{pns[5], pn}, packets.Acked)
}

func TestBBR3AckHandlerMigrationResetsSender(t *testing.T) {
	algorithm := newBBR3TestAlgorithm()
	sph := newBBR3TestHandler(utils.NewRTTStats(), &utils.ConnectionStats{}, nil, algorithm)
	initialCwnd := algorithm.GetCongestionWindow()
	algorithm.OnCongestionEvent(99, 1200, 1200)
	require.True(t, algorithm.InRecovery())

	sph.MigratedPath(monotime.Now(), 1200)
	require.False(t, algorithm.InRecovery())
	require.True(t, algorithm.InSlowStart())
	require.Equal(t, initialCwnd, algorithm.GetCongestionWindow())
}
