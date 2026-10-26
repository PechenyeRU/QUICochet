package congestion

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type simEv struct {
	t    monotime.Time
	pn   protocol.PacketNumber
	lost bool
	sent monotime.Time
}

// simulate runs the sender against one FIFO bottleneck. rate in bytes/s.
func simulate(t *testing.T, rate float64, rtt time.Duration, bufBytes int, randLoss float64, dur time.Duration) (delivered float64, s *bbr3Sender) {
	rs := &utils.RTTStats{}
	mss := protocol.ByteCount(1252)
	start := monotime.Time(1e9)
	clock := mockClock(start)
	s = NewBBR3Sender(&clock, rs, nil, mss, 32*mss, 10000*mss)
	var events []simEv
	var queueFree monotime.Time = start
	inflight := protocol.ByteCount(0)
	pn := protocol.PacketNumber(0)
	var totalAcked float64
	var drops int
	rngState := uint64(12345)
	rnd := func() float64 {
		rngState = rngState*6364136223846793005 + 1442695040888963407
		return float64(rngState>>11) / float64(1<<53)
	}
	end := start.Add(dur)
	for now := start; now < end; now = now.Add(50 * time.Microsecond) {
		clock = mockClock(now)
		for len(events) > 0 && events[0].t <= now {
			e := events[0]
			events = events[1:]
			if e.lost {
				inflight -= mss
				s.OnCongestionEvent(e.pn, mss, inflight+mss)
			} else {
				rs.UpdateRTT(e.t.Sub(e.sent), 0)
				prior := inflight
				inflight -= mss
				s.OnPacketAcked(e.pn, mss, prior, e.t)
				totalAcked += float64(mss)
			}
		}
		for s.CanSend(inflight) && s.HasPacingBudget(now) {
			pn++
			s.OnPacketSent(now, inflight, pn, mss, true)
			inflight += mss
			arrive := now.Add(rtt / 2)
			qdelay := queueFree.Sub(arrive)
			dropped := false
			if qdelay < 0 {
				qdelay = 0
			}
			if int(float64(qdelay)/1e9*rate) > bufBytes || rnd() < randLoss {
				dropped = true
			}
			if dropped {
				drops++
				events = insert(events, simEv{t: now.Add(rtt + rtt/2), pn: pn, lost: true})
				continue
			}
			dep := arrive
			if queueFree > dep {
				dep = queueFree
			}
			dep = dep.Add(time.Duration(float64(mss) / rate * 1e9))
			queueFree = dep
			events = insert(events, simEv{t: dep.Add(rtt / 2), pn: pn, sent: now})
		}
	}
	fmt.Fprintf(os.Stderr, "sim rate=%.0fMB/s rtt=%v buf=%dK loss=%.4f -> goodput %.1f MB/s, drops=%d mode=%d cyc=%d bw=%.1f cwnd=%dK\n",
		rate/1e6, rtt, bufBytes/1000, randLoss, totalAcked/dur.Seconds()/1e6, drops, s.mode, s.cycleIdx, float64(s.bw())/1e6, s.cwnd/1000)
	return totalAcked / dur.Seconds(), s
}

func insert(evs []simEv, e simEv) []simEv {
	i := len(evs)
	for i > 0 && evs[i-1].t > e.t {
		i--
	}
	evs = append(evs, simEv{})
	copy(evs[i+1:], evs[i:])
	evs[i] = e
	return evs
}

func TestBBR3Sim(t *testing.T) {
	for _, c := range []struct {
		rate float64
		rtt  time.Duration
		buf  int
		loss float64
	}{
		{50e6, 40 * time.Millisecond, 2000000, 0},
		{50e6, 40 * time.Millisecond, 500000, 0},
		{50e6, 40 * time.Millisecond, 2000000, 0.001},
		{10e6, 20 * time.Millisecond, 100000, 0},
	} {
		got, s := simulate(t, c.rate, c.rtt, c.buf, c.loss, 20*time.Second)
		if got < 0.5*c.rate && c.loss == 0 {
			t.Errorf("goodput %.1f MB/s is below half of %.1f", got/1e6, c.rate/1e6)
		}
		_ = s
	}
}

// Records of packets quic-go drops without a callback are pruned, and the
// records of recent packets stay.
func TestBBR3PrunesStaleRecords(t *testing.T) {
	rs := &utils.RTTStats{}
	mss := protocol.ByteCount(1252)
	s := NewBBR3Sender(DefaultClock{}, rs, nil, mss, 32*mss, 10000*mss)
	now := monotime.Time(1e9)
	for pn := protocol.PacketNumber(0); pn < b3PruneEvery; pn++ {
		s.OnPacketSent(now, mss, pn, mss, true)
	}
	if got := len(s.pkts); got != b3PruneEvery {
		t.Fatalf("recent records pruned: %d left of %d", got, b3PruneEvery)
	}
	now = now.Add(b3PruneAge + time.Second)
	for pn := protocol.PacketNumber(b3PruneEvery); pn < 2*b3PruneEvery; pn++ {
		s.OnPacketSent(now, mss, pn, mss, true)
	}
	if got := len(s.pkts); got != b3PruneEvery {
		t.Fatalf("stale records kept: %d records, want %d", got, b3PruneEvery)
	}
}
