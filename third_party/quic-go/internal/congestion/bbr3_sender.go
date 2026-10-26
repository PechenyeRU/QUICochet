package congestion

// A port of Google's BBRv3 (net/ipv4/tcp_bbr3.c, branch bbr-v3-2026-09-16-01) to quic-go's
// SendAlgorithm interface. The state machine, the model (bw_hi, bw_lo, bw_latest, inflight_hi,
// inflight_lo, inflight_latest), the loss handling, the gains and the constants follow the C
// source function for function. The names keep the C names in camel case.
//
// Differences from the kernel module:
//   - Quantities are in bytes, not packets. Bandwidth is in bytes per second, not packets per
//     microsecond scaled by 2^24.
//   - The delivery rate sample is built the way net/ipv4/tcp_rate.c builds it, from the
//     per-packet send state, and runs once per ACK frame (the OnPacketAcked calls that share one
//     receive time form one ACK).
//   - Not ported: the fast path (an optimisation that skips work), fast ACK mode (a setting of
//     the kernel's receiving TCP stack), the tail-loss-probe recovery event (QUIC has no
//     equivalent) and the CA_Loss state (quic-go never reports an RTO). The source has no ECN code.
//   - "Recovery" starts at the first lost packet and ends when a packet sent after it is acked.
//   - There is no application-limited signal from quic-go. A flow is treated as application
//     limited from the moment its packets in flight drop to zero until it delivers new data.
//   - Spurious loss undo (bbr3_undo_cwnd) runs when every packet lost in the latest episode has
//     been reported spurious.

import (
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	b3Scale = 8
	b3Unit  = 1 << b3Scale

	b3MinRTTWinUS    = 10 * 1000 * 1000
	b3ProbeRTTModeUS = 200 * 1000
	b3ProbeRTTWinUS  = 5000 * 1000

	b3ProbeRTTCwndGain  = b3Unit * 1 / 2
	b3PacingMarginPct   = 1
	b3StartupPacingGain = b3Unit*277/100 + 1
	b3StartupCwndGain   = b3Unit * 2
	b3DrainGain         = b3Unit * 1 / 2
	b3CwndGain          = b3Unit * 2

	b3CwndMinTarget = 4
	b3FullBwThresh  = b3Unit * 5 / 4
	b3FullBwCnt     = 3
	b3MaxDrainRound = 3

	b3ExtraAckedGain      = b3Unit
	b3ExtraAckedWinRTTs   = 5
	b3ExtraAckedMaxUS     = 100 * 1000
	b3Beta                = b3Unit * 30 / 100
	b3FullLossCnt         = 6
	b3InflightHeadroom    = b3Unit * 15 / 100
	b3BwProbeCwndGain     = b3Unit / 4
	b3BwProbeMaxRounds    = 63
	b3BwProbeRandRounds   = 2
	b3BwProbeBaseUS       = 2 * 1000 * 1000
	b3BwProbeRandUS       = 1 * 1000 * 1000
	b3NoRTT               = int64(1) << 60
	b3Inf                 = math.MaxUint64
	b3AckEpochResetPkts   = 1 << 20
	b3PacingShift         = 10
	b3GSOLegacyMaxSize    = 65536
	b3MinTSOSegs          = 2
	b3DefaultInitialRTTUS = 1000
)

const (
	b3PruneEvery = 4096             // sends between scans of the packet table
	b3PruneAge   = 10 * time.Second // older records belong to packets quic-go dropped silently
)

type b3Mode int

const (
	b3Startup b3Mode = iota
	b3Drain
	b3ProbeBW
	b3ProbeRTT
)

type b3AckPhase int

const (
	b3AcksInit b3AckPhase = iota
	b3AcksRefilling
	b3AcksProbeStarting
	b3AcksProbeFeedback
	b3AcksProbeStopping
)

type b3Undo int

const (
	b3UndoNone b3Undo = iota
	b3UndoStartup
	b3UndoProbeBWUp
)

const (
	b3ProbeUp = iota
	b3ProbeDown
	b3ProbeCruise
	b3ProbeRefill
)

var b3PacingGains = [4]uint64{b3Unit * 5 / 4, b3Unit * 91 / 100, b3Unit, b3Unit}

const (
	b3CAOpen = iota
	b3CARecovery
)

type b3PacketKey struct {
	encLevel protocol.EncryptionLevel
	pn       protocol.PacketNumber
}

func newB3PacketKey(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) b3PacketKey {
	if encLevel == protocol.Encryption0RTT {
		encLevel = protocol.Encryption1RTT
	}
	return b3PacketKey{encLevel: encLevel, pn: pn}
}

// b3Pkt is the send state kept per packet (struct tcp_skb_cb's tx fields).
type b3Pkt struct {
	size          uint64
	sentTime      monotime.Time
	delivered     uint64
	deliveredTime monotime.Time
	firstTxTime   monotime.Time
	txInFlight    uint64
	txLost        uint64
	appLimited    bool
}

// b3RS is struct rate_sample.
type b3RS struct {
	havePrior      bool
	lastPN         protocol.PacketNumber
	priorDelivered uint64
	priorTime      monotime.Time
	priorLost      uint64
	sendElapsedUS  int64
	priorInFlight  uint64
	txInFlight     uint64
	ackedSacked    uint64
	delivered      int64
	intervalUS     int64
	lost           uint64
	losses         uint64
	rttUS          int64
	isAppLimited   bool
}

type bbr3Sender struct {
	clock     Clock
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	pacer     *pacer
	mss       protocol.ByteCount
	qlogger   qlogwriter.Recorder
	lastState qlog.CongestionState

	// tcp_sock rate state
	delivered      uint64
	deliveredTime  monotime.Time
	firstTxTime    monotime.Time
	lost           uint64
	appLimited     uint64
	inflight       uint64
	cwnd           uint64
	initialCwnd    uint64
	cwndClamp      uint64
	cwndLimited    bool
	pkts           map[b3PacketKey]b3Pkt
	sentSincePrune int
	lastSent       [protocol.Encryption1RTT + 1]b3PacketKey // indexed by b3PacketKey.encLevel
	now            monotime.Time
	pacingRate     uint64

	// ACK batching
	batchActive   bool
	batchTime     monotime.Time
	batchEncLevel protocol.EncryptionLevel
	rs            b3RS
	batchLosses   uint64
	exitRecov     bool

	// CA state and recovery episode
	caState     int
	recoveryEnd b3PacketKey
	epPackets   map[b3PacketKey]struct{}
	epLost      int
	epSpurious  int
	epValid     bool
	prevCAState int
	initCwnd    uint64
	initialized bool

	// struct bbr3
	minRTTUS          int64
	minRTTStamp       int64
	probeRTTDoneStamp int64
	probeRTTMinUS     int64
	probeRTTMinStamp  int64
	nextRttDelivered  uint64
	cycleMstamp       int64
	mode              b3Mode
	roundStart        bool
	bwProbeUpRounds   uint32
	idleRestart       bool
	probeRTTRoundDone bool
	pacingGain        uint64
	cwndGain          uint64
	fullBwReached     bool
	fullBwCnt         uint32
	cycleIdx          int
	hasSeenRTT        bool
	undoState         b3Undo
	priorCwnd         uint64
	fullBw            uint64

	ackEpochMstamp    int64
	extraAcked        [2]uint64
	ackEpochAcked     uint64
	extraAckedWinRTTs uint32
	extraAckedWinIdx  int
	fullBwNow         bool
	lossYetInRecovery bool
	drainRounds       uint32

	lossRoundDelivered uint64
	undoBwLo           uint64
	undoInflightLo     uint64
	undoInflightHi     uint64
	bwLatest           uint64
	bwLo               uint64
	bwHi               [2]uint64
	inflightLatest     uint64
	inflightLo         uint64
	inflightHi         uint64
	bwProbeUpCnt       uint64
	bwProbeUpAcks      uint64
	probeWaitUS        int64
	bwProbeSamples     bool
	prevProbeTooHigh   bool
	stoppedRiskyProbe  bool
	roundsSinceProbe   uint32
	lossRoundStart     bool
	lossInRound        bool
	ackPhase           b3AckPhase
	lossEventsInRound  uint32

	sampleBw uint64

	dbg     bool
	dbgLast monotime.Time
	dbgBIF  uint64
}

var _ SendAlgorithmWithDebugInfos = &bbr3Sender{}

func NewBBR3Sender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	initialCongestionWindow protocol.ByteCount,
	maxCongestionWindow protocol.ByteCount,
) *bbr3Sender {
	b := &bbr3Sender{
		clock:       clock,
		rttStats:    rttStats,
		connStats:   connStats,
		mss:         initialMaxDatagramSize,
		pkts:        make(map[b3PacketKey]b3Pkt, 4096),
		epPackets:   make(map[b3PacketKey]struct{}),
		cwnd:        uint64(initialCongestionWindow),
		initialCwnd: uint64(initialCongestionWindow),
		cwndClamp:   uint64(maxCongestionWindow),
		dbg:         os.Getenv("QG_BBR_DEBUG") != "",
	}
	b.pacer = newPacerWithoutAdjustment(b.effectivePacingRate)
	b.pacer.SetMaxDatagramSize(initialMaxDatagramSize)
	b.init()
	return b
}

// SetConnectionParameters binds a factory-created sender to its connection.
func (b *bbr3Sender) SetConnectionParameters(rttStats *utils.RTTStats, connStats *utils.ConnectionStats, qlogger qlogwriter.Recorder) {
	b.rttStats = rttStats
	b.connStats = connStats
	b.qlogger = qlogger
	b.init()
	b.updateQlogState()
}

func usOf(t monotime.Time) int64 { return int64(t) / 1000 }

func (b *bbr3Sender) nowUS() int64 { return usOf(b.now) }

func mulDivUp(a, m, d uint64) uint64 {
	hi, lo := bits.Mul64(a, m)
	if hi >= d {
		return math.MaxUint64
	}
	q, r := bits.Div64(hi, lo, d)
	if r > 0 && q < math.MaxUint64 {
		q++
	}
	return q
}

func mulDiv(a, m, d uint64) uint64 {
	hi, lo := bits.Mul64(a, m)
	if hi >= d {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, d)
	return q
}

func (b *bbr3Sender) minCwnd() uint64 { return b3CwndMinTarget * uint64(b.mss) }

func (b *bbr3Sender) minRTTNow() int64 {
	if m := b.rttStats.MinRTT(); m > 0 {
		return m.Microseconds()
	}
	return b3NoRTT
}

// bbr3_init
func (b *bbr3Sender) init() {
	b.now = b.clock.Now()
	b.initialized = true
	b.initCwnd = min(0x7F*uint64(b.mss), b.cwnd)
	b.priorCwnd = 0
	b.nextRttDelivered = b.delivered
	b.prevCAState = b3CAOpen
	b.probeRTTDoneStamp = 0
	b.probeRTTRoundDone = false
	b.probeRTTMinUS = b.minRTTNow()
	b.probeRTTMinStamp = b.nowUS()
	b.minRTTUS = b.minRTTNow()
	b.minRTTStamp = b.nowUS()
	b.hasSeenRTT = false
	b.initPacingRateFromRTT()
	b.roundStart = false
	b.idleRestart = false
	b.fullBwReached = false
	b.fullBw = 0
	b.fullBwCnt = 0
	b.drainRounds = 0
	b.cycleMstamp = 0
	b.cycleIdx = 0
	b.mode = b3Startup
	b.ackEpochMstamp = b.nowUS()
	b.ackEpochAcked = 0
	b.extraAckedWinRTTs = 0
	b.extraAckedWinIdx = 0
	b.extraAcked = [2]uint64{}
	b.lossRoundDelivered = b.delivered + 1
	b.lossRoundStart = false
	b.undoBwLo, b.undoInflightLo, b.undoInflightHi = 0, 0, 0
	b.undoState = b3UndoNone
	b.lossYetInRecovery = false
	b.lossEventsInRound = 0
	b.resetCongestionSignals()
	b.bwLo = b3Inf
	b.bwHi = [2]uint64{}
	b.inflightLo = b3Inf
	b.inflightHi = b3Inf
	b.resetFullBw()
	b.bwProbeUpCnt = b3Inf
	b.bwProbeUpAcks = 0
	b.bwProbeUpRounds = 0
	b.probeWaitUS = 0
	b.stoppedRiskyProbe = false
	b.ackPhase = b3AcksInit
	b.roundsSinceProbe = 0
	b.bwProbeSamples = false
	b.prevProbeTooHigh = false
	b.pacingGain = b3StartupPacingGain
	b.cwndGain = b3StartupCwndGain
}

// ---- helpers from the C source ----

func (b *bbr3Sender) maxBw() uint64 { return max(b.bwHi[0], b.bwHi[1]) }
func (b *bbr3Sender) bw() uint64    { return min(b.maxBw(), b.bwLo) }
func (b *bbr3Sender) extraAckedMax() uint64 {
	return max(b.extraAcked[0], b.extraAcked[1])
}

func (b *bbr3Sender) bwToPacingRate(bw, gain uint64) uint64 {
	rate := (bw * gain) >> b3Scale
	rate = rate / 100 * (100 - b3PacingMarginPct)
	return max(rate, 1)
}

func (b *bbr3Sender) initPacingRateFromRTT() {
	var rttUS int64
	if b.rttStats.HasMeasurement() {
		rttUS = max(b.rttStats.SmoothedRTT().Microseconds(), 1)
		b.hasSeenRTT = true
	} else {
		rttUS = b3DefaultInitialRTTUS
	}
	bw := mulDiv(b.cwnd, 1000*1000, uint64(rttUS))
	b.pacingRate = b.bwToPacingRate(bw, b3StartupPacingGain)
}

func (b *bbr3Sender) setPacingRate(bw, gain uint64) {
	rate := b.bwToPacingRate(bw, gain)
	if !b.hasSeenRTT && b.rttStats.HasMeasurement() {
		b.initPacingRateFromRTT()
	}
	if b.fullBwReached || rate > b.pacingRate {
		b.pacingRate = rate
	}
}

func (b *bbr3Sender) tsoSegsGoal() uint64 {
	bytes := b.pacingRate >> b3PacingShift
	if b.minRTTUS != b3NoRTT {
		if r := uint64(b.minRTTUS) >> 9; r < 32 {
			bytes += b3GSOLegacyMaxSize >> r
		}
	}
	bytes = min(bytes, b3GSOLegacyMaxSize)
	return max(bytes/uint64(b.mss), b3MinTSOSegs)
}

func (b *bbr3Sender) saveCwnd() {
	if b.prevCAState < b3CARecovery && b.mode != b3ProbeRTT {
		b.priorCwnd = b.cwnd
	} else {
		b.priorCwnd = max(b.priorCwnd, b.cwnd)
	}
}

func (b *bbr3Sender) bdp(bw, gain uint64) uint64 {
	if b.minRTTUS == b3NoRTT {
		return b.initCwnd
	}
	return mulDivUp(bw*gain, uint64(b.minRTTUS), 1000*1000*b3Unit)
}

func (b *bbr3Sender) quantizationBudget(cwnd uint64) uint64 {
	tso := 3 * b.tsoSegsGoal() * uint64(b.mss)
	cwnd = max(cwnd, tso)
	cwnd = max(cwnd, b.minCwnd())
	if b.mode == b3ProbeBW && b.cycleIdx == b3ProbeUp {
		cwnd += 2 * uint64(b.mss)
	}
	return cwnd
}

func (b *bbr3Sender) inflightFor(bw, gain uint64) uint64 {
	return b.quantizationBudget(b.bdp(bw, gain))
}

func (b *bbr3Sender) packetsInNetAtEdt(inflightNow uint64) uint64 {
	nowNS := b.now
	edt := b.pacer.TimeUntilSend()
	if edt < nowNS {
		edt = nowNS
	}
	intervalUS := uint64(usOf(edt) - usOf(nowNS))
	intervalDelivered := mulDiv(b.bw(), intervalUS, 1000*1000)
	inflightAtEdt := inflightNow
	if b.pacingGain > b3Unit {
		inflightAtEdt += b.tsoSegsGoal() * uint64(b.mss)
	}
	if intervalDelivered >= inflightAtEdt {
		return 0
	}
	return inflightAtEdt - intervalDelivered
}

func (b *bbr3Sender) ackAggregationCwnd() uint64 {
	maxAggr := mulDiv(b.bw(), b3ExtraAckedMaxUS, 1000*1000)
	aggr := (b3ExtraAckedGain * b.extraAckedMax()) >> b3Scale
	return min(aggr, maxAggr)
}

func (b *bbr3Sender) probeRTTCwnd() uint64 {
	return max(b.minCwnd(), b.bdp(b.bw(), b3ProbeRTTCwndGain))
}

func (b *bbr3Sender) setCwnd(rs *b3RS, acked, bw, gain, cwnd uint64) {
	if acked != 0 {
		target := b.bdp(bw, gain)
		target += b.ackAggregationCwnd()
		target = b.quantizationBudget(target)
		if b.fullBwReached {
			cwnd += acked
			if cwnd >= target {
				cwnd = target
			}
		} else if cwnd < target || cwnd < 2*b.initCwnd {
			cwnd += acked
		}
		cwnd = max(cwnd, b.minCwnd())
	}
	b.cwnd = min(cwnd, b.cwndClamp)
	if b.mode == b3ProbeRTT {
		b.cwnd = min(b.cwnd, b.probeRTTCwnd())
	}
}

func (b *bbr3Sender) updateRoundStart(rs *b3RS) {
	b.roundStart = false
	if rs.intervalUS > 0 && !(rs.priorDelivered < b.nextRttDelivered) {
		b.nextRttDelivered = b.delivered
		b.roundStart = true
	}
}

func (b *bbr3Sender) calculateBwSample(rs *b3RS) {
	var bw uint64
	if rs.intervalUS > 0 && rs.delivered >= 0 {
		bw = mulDivUp(uint64(rs.delivered), 1000*1000, uint64(rs.intervalUS))
	}
	b.sampleBw = bw
}

func (b *bbr3Sender) updateAckAggregation(rs *b3RS) {
	if rs.ackedSacked == 0 || rs.delivered < 0 || rs.intervalUS <= 0 {
		return
	}
	thresh := uint32(b3ExtraAckedWinRTTs)
	if b.roundStart {
		b.extraAckedWinRTTs = min(0x1F, b.extraAckedWinRTTs+1)
		if !b.fullBwReached {
			thresh = 1
		}
		if b.extraAckedWinRTTs >= thresh {
			b.extraAckedWinRTTs = 0
			b.extraAckedWinIdx ^= 1
			b.extraAcked[b.extraAckedWinIdx] = 0
		}
	}
	epochUS := uint64(max(usOf(b.deliveredTime)-b.ackEpochMstamp, 0))
	expected := mulDiv(b.bw(), epochUS, 1000*1000)
	if b.ackEpochAcked <= expected || b.ackEpochAcked+rs.ackedSacked >= b3AckEpochResetPkts*uint64(b.mss) {
		b.ackEpochAcked = 0
		b.ackEpochMstamp = usOf(b.deliveredTime)
		expected = 0
	}
	b.ackEpochAcked = min(b.ackEpochAcked+rs.ackedSacked, b3AckEpochResetPkts*uint64(b.mss))
	extra := b.ackEpochAcked - expected
	extra = min(extra, b.cwnd)
	if extra > b.extraAcked[b.extraAckedWinIdx] {
		b.extraAcked[b.extraAckedWinIdx] = extra
	}
}

func (b *bbr3Sender) checkProbeRTTDone() {
	if !(b.probeRTTDoneStamp != 0 && b.nowUS() > b.probeRTTDoneStamp) {
		return
	}
	b.probeRTTMinStamp = b.nowUS()
	b.cwnd = max(b.cwnd, b.priorCwnd)
	b.exitProbeRTT()
}

func (b *bbr3Sender) updateMinRTT(rs *b3RS) {
	now := b.nowUS()
	probeRTTExpired := now > b.probeRTTMinStamp+b3ProbeRTTWinUS
	if rs.rttUS >= 0 && (rs.rttUS < b.probeRTTMinUS || probeRTTExpired) {
		b.probeRTTMinUS = rs.rttUS
		b.probeRTTMinStamp = now
	}
	minRTTExpired := now > b.minRTTStamp+b3MinRTTWinUS
	if b.probeRTTMinUS <= b.minRTTUS || minRTTExpired {
		b.minRTTUS = b.probeRTTMinUS
		b.minRTTStamp = b.probeRTTMinStamp
	}
	if probeRTTExpired && !b.idleRestart && b.mode != b3ProbeRTT {
		b.mode = b3ProbeRTT
		b.saveCwnd()
		b.probeRTTDoneStamp = 0
		b.ackPhase = b3AcksProbeStopping
		b.nextRttDelivered = b.delivered
	}
	if b.mode == b3ProbeRTT {
		b.appLimited = max(b.delivered+b.inflight, 1)
		if b.probeRTTDoneStamp == 0 && b.inflight <= b.probeRTTCwnd() {
			b.probeRTTDoneStamp = now + b3ProbeRTTModeUS
			b.probeRTTRoundDone = false
			b.nextRttDelivered = b.delivered
		} else if b.probeRTTDoneStamp != 0 {
			if b.roundStart {
				b.probeRTTRoundDone = true
			}
			if b.probeRTTRoundDone {
				b.checkProbeRTTDone()
			}
		}
	}
	if rs.delivered > 0 {
		b.idleRestart = false
	}
}

func (b *bbr3Sender) updateGains() {
	switch b.mode {
	case b3Startup:
		b.pacingGain = b3StartupPacingGain
		b.cwndGain = b3StartupCwndGain
	case b3Drain:
		b.pacingGain = b3DrainGain
		b.cwndGain = b3StartupCwndGain
	case b3ProbeBW:
		b.pacingGain = b3PacingGains[b.cycleIdx]
		b.cwndGain = b3CwndGain
		if b.cycleIdx == b3ProbeUp {
			b.cwndGain = min(0x3FF, b.cwndGain+b3BwProbeCwndGain)
		}
	case b3ProbeRTT:
		b.pacingGain = b3Unit
		b.cwndGain = b3Unit
	}
}

func (b *bbr3Sender) takeMaxBwSample(bw uint64) { b.bwHi[1] = max(bw, b.bwHi[1]) }

func (b *bbr3Sender) advanceMaxBwFilter() {
	if b.bwHi[1] == 0 {
		return
	}
	b.bwHi[0] = b.bwHi[1]
	b.bwHi[1] = 0
}

func (b *bbr3Sender) resetFullBw() {
	b.fullBw = 0
	b.fullBwCnt = 0
	b.fullBwNow = false
}

func (b *bbr3Sender) targetInflight() uint64 {
	return min(b.inflightFor(b.bw(), b3Unit), b.cwnd)
}

func (b *bbr3Sender) isProbingBandwidth() bool {
	return b.mode == b3Startup ||
		(b.mode == b3ProbeBW && (b.cycleIdx == b3ProbeRefill || b.cycleIdx == b3ProbeUp))
}

func (b *bbr3Sender) hasElapsedInPhase(intervalUS int64) bool {
	return b.nowUS()-(b.cycleMstamp+intervalUS) > 0
}

func (b *bbr3Sender) handleQueueTooHighInStartup() {
	b.fullBwReached = true
	bdp := b.inflightFor(b.maxBw(), b3Unit)
	b.inflightHi = max(bdp, b.inflightLatest)
}

func (b *bbr3Sender) raiseInflightHiSlope() {
	growth := uint64(1) << b.bwProbeUpRounds
	b.bwProbeUpRounds = min(b.bwProbeUpRounds+1, 30)
	cnt := b.cwnd / growth
	b.bwProbeUpCnt = max(cnt, 1)
}

func (b *bbr3Sender) probeInflightHiUpward(rs *b3RS) {
	if !b.cwndLimited || b.cwnd < b.inflightHi {
		return
	}
	b.bwProbeUpAcks += rs.ackedSacked
	if b.bwProbeUpAcks >= b.bwProbeUpCnt {
		delta := b.bwProbeUpAcks / b.bwProbeUpCnt
		b.bwProbeUpAcks -= delta * b.bwProbeUpCnt
		b.inflightHi += delta * uint64(b.mss)
	}
	if b.roundStart {
		b.raiseInflightHiSlope()
	}
}

func (b *bbr3Sender) isInflightTooHigh(rs *b3RS) (tooHigh, lossTooHigh bool) {
	if rs.lost > 0 && rs.txInFlight != 0 {
		lossThresh := (rs.txInFlight * b3LossThresh) >> b3Scale
		if rs.lost > lossThresh {
			return true, true
		}
	}
	return false, false
}

func (b *bbr3Sender) inflightHiFromLostPkt(rs *b3RS, size uint64) uint64 {
	inflightPrev := int64(rs.txInFlight) - int64(size)
	if inflightPrev < 0 {
		return b3Inf
	}
	lostPrev := int64(rs.lost) - int64(size)
	if lostPrev < 0 {
		return b3Inf
	}
	lossBudget := (uint64(inflightPrev)*b3LossThresh + b3Unit - 1) >> b3Scale
	var lostPrefix uint64
	if uint64(lostPrev) >= lossBudget {
		lostPrefix = 0
	} else {
		lostPrefix = (lossBudget - uint64(lostPrev)) << b3Scale
		lostPrefix /= (b3Unit - b3LossThresh)
	}
	return uint64(inflightPrev) + lostPrefix
}

func (b *bbr3Sender) inflightWithHeadroom() uint64 {
	if b.inflightHi == b3Inf {
		return b3Inf
	}
	headroom := (b.inflightHi * b3InflightHeadroom) >> b3Scale
	headroom = max(headroom, 1)
	if b.inflightHi < headroom {
		return b.minCwnd()
	}
	return max(b.inflightHi-headroom, b.minCwnd())
}

func (b *bbr3Sender) boundCwndForInflightModel() {
	if !b.initialized {
		return
	}
	capv := uint64(b3Inf)
	if b.mode == b3ProbeBW && b.cycleIdx != b3ProbeCruise {
		capv = b.inflightHi
	} else if b.mode == b3ProbeRTT || (b.mode == b3ProbeBW && b.cycleIdx == b3ProbeCruise) {
		capv = b.inflightWithHeadroom()
	}
	capv = min(capv, b.inflightLo)
	capv = max(capv, b.minCwnd())
	b.cwnd = min(capv, b.cwnd)
}

func (b *bbr3Sender) initLowerBounds(initBw bool) {
	if initBw && b.bwLo == b3Inf {
		b.bwLo = b.maxBw()
	}
	if b.inflightLo == b3Inf {
		b.inflightLo = b.cwnd
	}
}

func (b *bbr3Sender) lossLowerBounds() (bw, inflight uint64) {
	lossCut := uint64(b3Unit - b3Beta)
	bw = max(b.bwLatest, (b.bwLo*lossCut)>>b3Scale)
	inflight = max(b.inflightLatest, (b.inflightLo*lossCut)>>b3Scale)
	return
}

func (b *bbr3Sender) adaptLowerBounds(rs *b3RS) {
	if b3NoLower || b.isProbingBandwidth() {
		return
	}
	if b.lossInRound {
		b.initLowerBounds(true)
		b.bwLo, b.inflightLo = b.lossLowerBounds()
	}
	b.bwLo = max(1, b.bwLo)
}

func (b *bbr3Sender) resetLowerBounds() {
	b.bwLo = b3Inf
	b.inflightLo = b3Inf
}

func (b *bbr3Sender) resetCongestionSignals() {
	b.lossInRound = false
	b.bwLatest = 0
	b.inflightLatest = 0
}

func (b *bbr3Sender) updateLatestDeliverySignals(rs *b3RS) {
	b.lossRoundStart = false
	if rs.intervalUS <= 0 || rs.ackedSacked == 0 {
		return
	}
	b.bwLatest = max(b.bwLatest, b.sampleBw)
	b.inflightLatest = max(b.inflightLatest, uint64(max(rs.delivered, 0)))
	if !(rs.priorDelivered < b.lossRoundDelivered) {
		b.lossRoundDelivered = b.delivered
		b.lossRoundStart = true
	}
}

func (b *bbr3Sender) advanceLatestDeliverySignals(rs *b3RS) {
	if b.lossRoundStart {
		b.bwLatest = b.sampleBw
		b.inflightLatest = uint64(max(rs.delivered, 0))
	}
}

func (b *bbr3Sender) updateCongestionSignals(rs *b3RS) {
	if rs.intervalUS <= 0 || rs.ackedSacked == 0 {
		return
	}
	bw := b.sampleBw
	if !rs.isAppLimited || bw >= b.maxBw() {
		b.takeMaxBwSample(bw)
	}
	b.lossInRound = b.lossInRound || rs.losses > 0
	if !b.lossRoundStart {
		return
	}
	b.adaptLowerBounds(rs)
	b.lossInRound = false
}

func (b *bbr3Sender) isRenoCoexistenceProbeTime() bool {
	rounds := min(uint64(b3BwProbeMaxRounds), b.targetInflight()/uint64(b.mss))
	return uint64(b.roundsSinceProbe) >= rounds
}

func (b *bbr3Sender) pickProbeWait() {
	b.roundsSinceProbe = uint32(rand.Intn(b3BwProbeRandRounds))
	b.probeWaitUS = b3BwProbeBaseUS + int64(rand.Intn(b3BwProbeRandUS))
}

func (b *bbr3Sender) setCycleIdx(idx int) { b.cycleIdx = idx }

func (b *bbr3Sender) startBwProbeRefill(upRounds uint32) {
	b.resetLowerBounds()
	b.bwProbeUpRounds = upRounds
	b.bwProbeUpAcks = 0
	b.stoppedRiskyProbe = false
	b.ackPhase = b3AcksRefilling
	b.nextRttDelivered = b.delivered
	b.setCycleIdx(b3ProbeRefill)
}

func (b *bbr3Sender) startBwProbeUp() {
	b.ackPhase = b3AcksProbeStarting
	b.nextRttDelivered = b.delivered
	b.cycleMstamp = b.nowUS()
	b.resetFullBw()
	b.fullBw = b.sampleBw
	b.setCycleIdx(b3ProbeUp)
	b.raiseInflightHiSlope()
}

func (b *bbr3Sender) startBwProbeDown() {
	b.resetCongestionSignals()
	b.bwProbeUpCnt = b3Inf
	b.pickProbeWait()
	b.cycleMstamp = b.nowUS()
	b.ackPhase = b3AcksProbeStopping
	b.nextRttDelivered = b.delivered
	b.setCycleIdx(b3ProbeDown)
}

func (b *bbr3Sender) startBwProbeCruise() {
	if b.inflightLo != b3Inf {
		b.inflightLo = min(b.inflightLo, b.inflightHi)
	}
	b.setCycleIdx(b3ProbeCruise)
}

func (b *bbr3Sender) handleInflightTooHigh(rs *b3RS, lossTooHigh bool) {
	b.prevProbeTooHigh = true
	b.bwProbeSamples = false
	if !rs.isAppLimited {
		b.inflightHi = max(rs.txInFlight, (b.targetInflight()*(b3Unit-b3Beta))>>b3Scale)
	}
	if b.mode == b3ProbeBW && b.cycleIdx == b3ProbeUp {
		if lossTooHigh {
			b.undoState = b3UndoProbeBWUp
		}
		b.startBwProbeDown()
	}
}

func (b *bbr3Sender) adaptUpperBounds(rs *b3RS) bool {
	if b.ackPhase == b3AcksProbeStarting && b.roundStart {
		b.ackPhase = b3AcksProbeFeedback
	}
	if b.ackPhase == b3AcksProbeStopping && b.roundStart {
		b.bwProbeSamples = false
		b.ackPhase = b3AcksInit
		if b.mode == b3ProbeBW && !rs.isAppLimited {
			b.advanceMaxBwFilter()
		}
		if b.mode == b3ProbeBW && b.stoppedRiskyProbe && !b.prevProbeTooHigh {
			b.startBwProbeRefill(0)
			return true
		}
	}
	if tooHigh, lossTooHigh := b.isInflightTooHigh(rs); tooHigh {
		if b.bwProbeSamples {
			b.handleInflightTooHigh(rs, lossTooHigh)
		}
	} else {
		if b.inflightHi == b3Inf {
			return false
		}
		if rs.txInFlight > b.inflightHi {
			b.inflightHi = rs.txInFlight
		}
		if b.mode == b3ProbeBW && b.cycleIdx == b3ProbeUp {
			b.probeInflightHiUpward(rs)
		}
	}
	return false
}

func (b *bbr3Sender) checkTimeToProbeBw(rs *b3RS) bool {
	if b.hasElapsedInPhase(b.probeWaitUS) || b.isRenoCoexistenceProbeTime() {
		b.startBwProbeRefill(0)
		return true
	}
	return false
}

func (b *bbr3Sender) checkTimeToCruise(inflight, bw uint64) bool {
	if inflight > b.inflightWithHeadroom() {
		return false
	}
	return inflight <= b.inflightFor(bw, b3Unit)
}

func (b *bbr3Sender) updateCyclePhase(rs *b3RS) {
	if !b.fullBwReached {
		return
	}
	if b.adaptUpperBounds(rs) {
		return
	}
	if b.mode != b3ProbeBW {
		return
	}
	inflight := b.packetsInNetAtEdt(rs.priorInFlight)
	bw := b.maxBw()
	switch b.cycleIdx {
	case b3ProbeCruise:
		if b.checkTimeToProbeBw(rs) {
			return
		}
	case b3ProbeRefill:
		if b.roundStart {
			b.bwProbeSamples = true
			b.startBwProbeUp()
		}
	case b3ProbeUp:
		done := false
		if b.prevProbeTooHigh && inflight >= b.inflightHi {
			b.stoppedRiskyProbe = true
			done = true
		} else {
			if b.cwndLimited && b.cwnd >= b.inflightHi {
				b.resetFullBw()
				b.fullBw = b.sampleBw
			} else if b.fullBwNow {
				done = true
			}
		}
		if done {
			b.prevProbeTooHigh = false
			b.startBwProbeDown()
		}
	case b3ProbeDown:
		if b.checkTimeToProbeBw(rs) {
			return
		}
		if b.checkTimeToCruise(inflight, bw) {
			b.startBwProbeCruise()
		}
	}
}

func (b *bbr3Sender) exitProbeRTT() {
	b.resetLowerBounds()
	if b.fullBwReached {
		b.mode = b3ProbeBW
		b.startBwProbeDown()
		b.startBwProbeCruise()
	} else {
		b.mode = b3Startup
	}
}

func (b *bbr3Sender) checkLossTooHighInStartup(rs *b3RS) {
	if b.fullBwReached {
		return
	}
	if rs.losses > 0 && b.lossEventsInRound < 0xf {
		b.lossEventsInRound++
	}
	if b3FullLossCnt != 0 && b.lossRoundStart && b.caState == b3CARecovery &&
		b.lossEventsInRound >= b3FullLossCnt {
		if tooHigh, lossTooHigh := b.isInflightTooHigh(rs); tooHigh && lossTooHigh {
			b.undoState = b3UndoStartup
			b.handleQueueTooHighInStartup()
			return
		}
	}
	if b.lossRoundStart {
		b.lossEventsInRound = 0
	}
}

func (b *bbr3Sender) checkFullBwReached(rs *b3RS) {
	if b.fullBwNow || rs.isAppLimited {
		return
	}
	bwThresh := (b.fullBw * b3FullBwThresh) >> b3Scale
	if b.sampleBw >= bwThresh {
		b.resetFullBw()
		b.fullBw = b.sampleBw
		return
	}
	if !b.roundStart {
		return
	}
	b.fullBwCnt++
	b.fullBwNow = b.fullBwCnt >= b3FullBwCnt
	b.fullBwReached = b.fullBwReached || b.fullBwNow
}

func (b *bbr3Sender) checkDrain(rs *b3RS) {
	if b.mode == b3Startup && b.fullBwReached {
		b.mode = b3Drain
		b.drainRounds = 0
		b.resetCongestionSignals()
	}
	if b.mode == b3Drain {
		if b.roundStart {
			b.drainRounds++
		}
		if b.packetsInNetAtEdt(b.inflight) <= b.inflightFor(b.maxBw(), b3Unit) ||
			b.drainRounds > b3MaxDrainRound {
			b.mode = b3ProbeBW
			b.startBwProbeDown()
		}
	}
}

func (b *bbr3Sender) updateModel(rs *b3RS) {
	b.updateCongestionSignals(rs)
	b.updateAckAggregation(rs)
	b.checkLossTooHighInStartup(rs)
	b.checkFullBwReached(rs)
	b.checkDrain(rs)
	b.updateCyclePhase(rs)
	b.updateMinRTT(rs)
}

// bbr3_main (the cong_control hook), run once per ACK.
func (b *bbr3Sender) main(rs *b3RS) {
	b.updateRoundStart(rs)
	if b.roundStart {
		b.roundsSinceProbe = min(b.roundsSinceProbe+1, 0xFF)
	}
	b.calculateBwSample(rs)
	b.updateLatestDeliverySignals(rs)
	b.updateModel(rs)
	b.updateGains()
	bw := b.bw()
	b.setPacingRate(bw, b.pacingGain)
	b.setCwnd(rs, rs.ackedSacked, bw, b.cwndGain, b.cwnd)
	b.boundCwndForInflightModel()
	b.advanceLatestDeliverySignals(rs)
	b.prevCAState = b.caState
	if b.roundStart {
		b.cwndLimited = false
	}
}

// ---- loss handling ----

func (b *bbr3Sender) noteLoss() {
	if !b.lossInRound {
		b.lossRoundDelivered = b.delivered
	}
	b.lossInRound = true
}

func (b *bbr3Sender) saveForLaterUndo() {
	b.saveCwnd()
	b.undoBwLo = b.bwLo
	b.undoInflightLo = b.inflightLo
	b.undoInflightHi = b.inflightHi
	b.undoState = b3UndoNone
}

func (b *bbr3Sender) pktMarkedLost(p *b3Pkt) {
	if !b.lossYetInRecovery {
		b.lossYetInRecovery = true
		b.saveForLaterUndo()
	}
	b.noteLoss()
	if !b.bwProbeSamples {
		return
	}
	var rs b3RS
	rs.txInFlight = p.txInFlight
	rs.lost = b.lost - p.txLost
	rs.isAppLimited = p.appLimited
	if tooHigh, lossTooHigh := b.isInflightTooHigh(&rs); tooHigh {
		rs.txInFlight = b.inflightHiFromLostPkt(&rs, p.size)
		b.handleInflightTooHigh(&rs, lossTooHigh)
	}
}

func (b *bbr3Sender) undoCwnd() {
	rs := b3RS{rttUS: -1, delivered: -1, intervalUS: -1, priorInFlight: b.inflight}
	b.resetFullBw()
	b.lossInRound = false
	b.lossEventsInRound = 0
	b.lossRoundStart = false
	b.lossRoundDelivered = b.delivered
	b.bwLo = max(b.bwLo, b.undoBwLo)
	b.inflightLo = max(b.inflightLo, b.undoInflightLo)
	b.inflightHi = max(b.inflightHi, b.undoInflightHi)
	if b.undoState == b3UndoStartup && b.mode != b3Startup {
		b.fullBwReached = false
		if b.mode != b3ProbeRTT {
			b.mode = b3Startup
		}
	} else if b.undoState == b3UndoProbeBWUp && !(b.mode == b3ProbeBW && b.cycleIdx == b3ProbeUp) {
		if b.mode != b3ProbeRTT {
			b.mode = b3ProbeBW
			b.startBwProbeRefill(0)
		}
	}
	b.undoState = b3UndoNone
	b.cwnd = max(b.cwnd, b.priorCwnd)
	b.main(&rs)
}

// ---- rate sampling and ACK batching ----

// flush runs bbr3_main for the ACK collected so far (tcp_rate_gen, then cong_control).
func (b *bbr3Sender) flush() {
	if !b.batchActive {
		return
	}
	b.batchActive = false
	rs := &b.rs
	b.now = b.batchTime
	if b.exitRecov {
		b.exitRecov = false
		b.caState = b3CAOpen
		b.lossYetInRecovery = false
		b.cwnd = max(b.cwnd, b.priorCwnd)
	}
	rs.losses = b.batchLosses
	b.batchLosses = 0
	if b.appLimited != 0 && b.delivered > b.appLimited {
		b.appLimited = 0
	}
	if !rs.havePrior {
		rs.delivered = -1
		rs.intervalUS = -1
	} else {
		rs.delivered = int64(b.delivered - rs.priorDelivered)
		rs.lost = b.lost - rs.priorLost
		ackUS := usOf(b.batchTime) - usOf(rs.priorTime)
		rs.intervalUS = max(rs.sendElapsedUS, ackUS)
		if minRTT := b.rttStats.MinRTT(); minRTT > 0 && rs.intervalUS < minRTT.Microseconds() {
			rs.intervalUS = -1
		}
	}
	b.main(rs)
	if b.inflight == 0 {
		b.appLimited = max(b.delivered, 1)
	}
	b.updateQlogState()
	b.debugLine()
}

func (b *bbr3Sender) debugLine() {
	if !b.dbg || b.now.Sub(b.dbgLast) < time.Second {
		return
	}
	b.dbgLast = b.now
	lo := func(v uint64) string {
		if v == b3Inf {
			return "inf"
		}
		return fmt.Sprint(v / 1000)
	}
	fmt.Fprintf(os.Stderr, "bbr3 mode=%d cyc=%d bw=%.1fMB/s hi=%.1f lo=%s infl_hi=%sK infl_lo=%sK cwnd=%dK minrtt=%dus pace=%.1fMB/s full=%v lost=%d own_infl=%d qg_infl=%d npkts=%d\n",
		b.mode, b.cycleIdx, float64(b.bw())/1e6, float64(b.maxBw())/1e6, lo(b.bwLo), lo(b.inflightHi), lo(b.inflightLo),
		b.cwnd/1000, b.minRTTUS, float64(b.pacingRate)/1e6, b.fullBwReached, b.lost, b.inflight, b.dbgBIF, len(b.pkts))
}

// ---- SendAlgorithm ----

func (b *bbr3Sender) updateQlogState() {
	if b.qlogger == nil {
		return
	}
	state := qlog.CongestionStateCongestionAvoidance
	if b.caState == b3CARecovery {
		state = qlog.CongestionStateRecovery
	} else if b.appLimited != 0 {
		state = qlog.CongestionStateApplicationLimited
	} else if b.mode == b3Startup {
		state = qlog.CongestionStateSlowStart
	}
	if state == b.lastState {
		return
	}
	b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: state})
	b.lastState = state
}

func (b *bbr3Sender) effectivePacingRate() Bandwidth {
	return Bandwidth(max(b.pacingRate, 1)) * BytesPerSecond
}

func (b *bbr3Sender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	b.flush()
	return b.pacer.TimeUntilSend()
}

func (b *bbr3Sender) HasPacingBudget(now monotime.Time) bool {
	b.flush()
	return b.pacer.Budget(now) >= b.mss
}

func (b *bbr3Sender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, pn protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.OnPacketSentWithEncryptionLevel(sentTime, bytesInFlight, pn, bytes, isRetransmittable, protocol.Encryption1RTT)
}

func (b *bbr3Sender) OnPacketSentWithEncryptionLevel(sentTime monotime.Time, bytesInFlight protocol.ByteCount, pn protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool, encLevel protocol.EncryptionLevel) {
	b.flush()
	b.pacer.SentPacket(sentTime, bytes)
	key := newB3PacketKey(pn, encLevel)
	b.lastSent[key.encLevel] = key
	if !isRetransmittable {
		return
	}
	b.now = sentTime
	if b.inflight == 0 {
		// tcp_rate_skb_sent: restart of the delivery clocks after idle
		b.firstTxTime = sentTime
		b.deliveredTime = sentTime
		// bbr3_cwnd_event_tx_start
		if b.appLimited != 0 {
			b.idleRestart = true
			b.ackEpochMstamp = usOf(sentTime)
			b.ackEpochAcked = 0
			if b.mode == b3ProbeBW {
				b.setPacingRate(b.bw(), b3Unit)
			} else if b.mode == b3ProbeRTT {
				b.checkProbeRTTDone()
			}
		}
	}
	b.inflight = uint64(bytesInFlight) // quic-go's count; it drops probe packets without telling the sender
	if b.inflight+uint64(b.mss) > b.cwnd {
		b.cwndLimited = true
	}
	b.pkts[key] = b3Pkt{
		size:          uint64(bytes),
		sentTime:      sentTime,
		delivered:     b.delivered,
		deliveredTime: b.deliveredTime,
		firstTxTime:   b.firstTxTime,
		txInFlight:    b.inflight,
		txLost:        b.lost,
		appLimited:    b.appLimited != 0,
	}
	b.sentSincePrune++
	if b.sentSincePrune >= b3PruneEvery {
		b.pruneStale(sentTime)
	}
}

// pruneStale drops records of packets quic-go removed from flight without an
// ack or loss callback (probe timeouts, lost MTU probes). A late ack for a
// pruned packet finds no record and is skipped, as for any unknown packet.
func (b *bbr3Sender) pruneStale(now monotime.Time) {
	b.sentSincePrune = 0
	for pn, p := range b.pkts {
		if now.Sub(p.sentTime) > b3PruneAge {
			delete(b.pkts, pn)
		}
	}
}

func (b *bbr3Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	b.flush()
	b.dbgBIF = uint64(bytesInFlight)
	return uint64(bytesInFlight) < b.cwnd
}

func (b *bbr3Sender) MaybeExitSlowStart() { b.flush() }

func (b *bbr3Sender) OnPacketAcked(pn protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	b.OnPacketAckedWithEncryptionLevel(pn, ackedBytes, priorInFlight, eventTime, protocol.Encryption1RTT)
}

func (b *bbr3Sender) OnPacketAckedWithEncryptionLevel(pn protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time, encLevel protocol.EncryptionLevel) {
	key := newB3PacketKey(pn, encLevel)
	if b.batchActive && (b.batchTime != eventTime || b.batchEncLevel != key.encLevel) {
		b.flush()
	}
	if !b.batchActive {
		b.batchActive = true
		b.batchTime = eventTime
		b.batchEncLevel = key.encLevel
		b.rs = b3RS{rttUS: -1, priorInFlight: uint64(priorInFlight)}
	}
	rs := &b.rs
	rs.ackedSacked += uint64(ackedBytes)
	b.delivered += uint64(ackedBytes)
	b.deliveredTime = eventTime
	b.inflight -= min(b.inflight, uint64(ackedBytes))
	if b.caState == b3CARecovery && key.encLevel == b.recoveryEnd.encLevel && key.pn > b.recoveryEnd.pn {
		b.exitRecov = true
	}
	p, ok := b.pkts[key]
	if !ok {
		return
	}
	delete(b.pkts, key)
	if !rs.havePrior || pn > rs.lastPN {
		rs.havePrior = true
		rs.lastPN = pn
		rs.priorDelivered = p.delivered
		rs.priorTime = p.deliveredTime
		rs.priorLost = p.txLost
		rs.isAppLimited = p.appLimited
		rs.txInFlight = p.txInFlight
		rs.sendElapsedUS = usOf(p.sentTime) - usOf(p.firstTxTime)
		rs.rttUS = usOf(eventTime) - usOf(p.sentTime)
		b.firstTxTime = p.sentTime
	}
}

func (b *bbr3Sender) OnCongestionEvent(pn protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	b.OnCongestionEventWithEncryptionLevel(pn, lostBytes, priorInFlight, protocol.Encryption1RTT)
}

func (b *bbr3Sender) OnCongestionEventWithEncryptionLevel(pn protocol.PacketNumber, lostBytes protocol.ByteCount, _ protocol.ByteCount, encLevel protocol.EncryptionLevel) {
	if b.connStats != nil {
		b.connStats.PacketsLost.Add(1)
		b.connStats.BytesLost.Add(uint64(lostBytes))
	}
	if lostBytes == 0 {
		return // ECN congestion signal, not ported
	}
	b.flush()
	b.now = b.clock.Now()
	key := newB3PacketKey(pn, encLevel)
	b.inflight -= min(b.inflight, uint64(lostBytes))
	b.lost += uint64(lostBytes)
	b.batchLosses++
	if b.caState != b3CARecovery {
		b.caState = b3CARecovery
		b.recoveryEnd = b.lastSent[key.encLevel]
		clear(b.epPackets)
		b.epLost, b.epSpurious = 0, 0
		b.epValid = true
	}
	b.epPackets[key] = struct{}{}
	b.epLost++
	b.updateQlogState()
	p, ok := b.pkts[key]
	if !ok {
		return
	}
	delete(b.pkts, key)
	b.pktMarkedLost(&p)
}

func (b *bbr3Sender) OnSpuriousLoss(pn protocol.PacketNumber) {
	b.OnSpuriousLossWithEncryptionLevel(pn, protocol.Encryption1RTT)
}

func (b *bbr3Sender) OnSpuriousLossWithEncryptionLevel(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
	if !b.epValid {
		return
	}
	key := newB3PacketKey(pn, encLevel)
	if _, ok := b.epPackets[key]; !ok {
		return
	}
	delete(b.epPackets, key)
	b.epSpurious++
	if b.epSpurious >= b.epLost {
		b.epValid = false
		b.flush()
		b.now = b.clock.Now()
		b.undoCwnd()
	}
}

// DropPacketNumberSpace forgets the Initial or Handshake packets that quic-go
// discards with their keys. They get no ack or loss callback after this.
func (b *bbr3Sender) DropPacketNumberSpace(encLevel protocol.EncryptionLevel) {
	if encLevel != protocol.EncryptionInitial && encLevel != protocol.EncryptionHandshake {
		return
	}
	b.flush()
	b.now = b.clock.Now()
	for key, p := range b.pkts {
		if key.encLevel == encLevel {
			b.inflight -= min(b.inflight, p.size)
			delete(b.pkts, key)
		}
	}
	b.lastSent[encLevel] = b3PacketKey{}
	// Losses in this space can never be reported spurious, so the episode
	// could not be undone before the drop either.
	for key := range b.epPackets {
		if key.encLevel == encLevel {
			b.epValid = false
			break
		}
	}
	if !b.epValid {
		clear(b.epPackets)
		b.epLost, b.epSpurious = 0, 0
	}
	// The packet that ends recovery can never be acked now.
	if b.caState == b3CARecovery && b.recoveryEnd.encLevel == encLevel {
		b.caState = b3CAOpen
		b.lossYetInRecovery = false
		b.cwnd = max(b.cwnd, b.priorCwnd)
		b.recoveryEnd = b3PacketKey{}
	}
	if b.inflight == 0 {
		b.appLimited = max(b.delivered, 1)
	}
	b.updateQlogState()
}

func (b *bbr3Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	qlogger := b.qlogger
	reset := NewBBR3Sender(
		b.clock,
		b.rttStats,
		b.connStats,
		b.mss,
		protocol.ByteCount(b.initialCwnd),
		protocol.ByteCount(b.cwndClamp),
	)
	reset.qlogger = qlogger
	*b = *reset
	b.pacer = newPacerWithoutAdjustment(b.effectivePacingRate)
	b.pacer.SetMaxDatagramSize(b.mss)
	b.updateQlogState()
}

func (b *bbr3Sender) SetMaxDatagramSize(s protocol.ByteCount) {
	oldMSS := uint64(b.mss)
	cwndAtMin := b.cwnd == b.minCwnd()
	b.initialCwnd = mulDivUp(b.initialCwnd, uint64(s), oldMSS)
	b.cwndClamp = mulDivUp(b.cwndClamp, uint64(s), oldMSS)
	b.mss = s
	b.initCwnd = min(0x7F*uint64(s), b.initialCwnd)
	if cwndAtMin {
		b.cwnd = b.minCwnd()
	} else {
		b.cwnd = min(b.cwnd, b.cwndClamp)
	}
	b.pacer.SetMaxDatagramSize(s)
}

func (b *bbr3Sender) InSlowStart() bool { return b.mode == b3Startup }

func (b *bbr3Sender) InRecovery() bool { return b.caState == b3CARecovery }

func (b *bbr3Sender) GetCongestionWindow() protocol.ByteCount {
	b.flush()
	return protocol.ByteCount(b.cwnd)
}

// b3LossThresh is the per-round loss rate above which the model lowers inflight_hi (2%). QG_BBR_LOSS_THRESH=<percent>
// overrides it, and QG_BBR_NO_LOWER=1 turns off the loss-driven lowering of bw_lo and inflight_lo. Both are
// measurement knobs for the loss-response experiment, not part of the reference.
var b3LossThresh uint64 = b3Unit * 2 / 100

var b3NoLower = os.Getenv("QG_BBR_NO_LOWER") != ""

func init() {
	setLossThresholdFromEnv()
}

func setLossThresholdFromEnv() {
	if v, err := strconv.ParseFloat(os.Getenv("QG_BBR_LOSS_THRESH"), 64); err == nil && v > 0 && v < 100 {
		b3LossThresh = uint64(float64(b3Unit) * v / 100)
	}
}
