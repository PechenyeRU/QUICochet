package tui

import (
	"fmt"
	"time"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// dashSample is one point in the dashboard's rolling history.
// Bytes / packets are cumulative gauges as emitted by the daemon;
// the per-second rates are derived in dashSeries.rates() by taking
// successive deltas. PoolAlive / PoolTotal are direct copies — they
// describe instantaneous pool state, not deltas.
type dashSample struct {
	at          time.Time
	bytesSent   uint64
	bytesRecv   uint64
	packetsSent uint64
	packetsLost uint64
	poolAlive   int
	poolTotal   int
}

// dashSeries is a fixed-capacity ring of dashSamples plus the
// derived per-second views the dashboard renders. Capacity sized
// for two minutes at the default 1 s poll cadence — enough history
// for a btop-style sparkline without growing unbounded across a
// long session.
type dashSeries struct {
	samples []dashSample
	cap     int
}

func newDashSeries(cap int) *dashSeries {
	return &dashSeries{cap: cap}
}

// push appends a new sample, evicting the oldest when the buffer is
// full. Detects a daemon-restart (cumulative counters going
// backwards) and resets the series so the derived rate sparkline
// doesn't show a giant negative spike.
func (s *dashSeries) push(p dashSample) {
	if n := len(s.samples); n > 0 {
		prev := s.samples[n-1]
		if p.bytesSent < prev.bytesSent || p.bytesRecv < prev.bytesRecv {
			s.samples = s.samples[:0]
		}
	}
	s.samples = append(s.samples, p)
	if len(s.samples) > s.cap {
		s.samples = s.samples[len(s.samples)-s.cap:]
	}
}

// rates returns three parallel slices of len(samples)-1 giving the
// per-sample bandwidth and loss derived from successive deltas.
//   - sentBps / recvBps: bytes per second over the inter-sample dt
//   - lossPct: packets lost / packets sent in the same interval, in
//     percent (0..100). When no packets were sent, lossPct stays 0
//     rather than NaN so the sparkline renderer doesn't have to
//     special-case missing data.
func (s *dashSeries) rates() (sentBps, recvBps, lossPct []float64) {
	if len(s.samples) < 2 {
		return nil, nil, nil
	}
	n := len(s.samples) - 1
	sentBps = make([]float64, n)
	recvBps = make([]float64, n)
	lossPct = make([]float64, n)
	for i := 1; i < len(s.samples); i++ {
		prev, cur := s.samples[i-1], s.samples[i]
		dt := cur.at.Sub(prev.at).Seconds()
		if dt <= 0 {
			dt = 1 // avoid divide-by-zero on coincident timestamps
		}
		sentBps[i-1] = float64(cur.bytesSent-prev.bytesSent) / dt
		recvBps[i-1] = float64(cur.bytesRecv-prev.bytesRecv) / dt
		dPkts := cur.packetsSent - prev.packetsSent
		dLost := cur.packetsLost - prev.packetsLost
		if dPkts > 0 {
			lossPct[i-1] = float64(dLost) * 100 / float64(dPkts)
		}
	}
	return sentBps, recvBps, lossPct
}

// last returns the most recent sample, or the zero value when the
// series is empty. Callers should check len() > 0 separately if
// they need to distinguish "no data" from "all zeros".
func (s *dashSeries) last() dashSample {
	if len(s.samples) == 0 {
		return dashSample{}
	}
	return s.samples[len(s.samples)-1]
}

// sparkline renders values as a fixed-width row of unicode block
// elements. The values are linearly scaled to the maximum in the
// slice so a flat-line series doesn't consume the full vertical
// range visually.
//
// width is the cell count of the output. When the data has fewer
// points than width, the right side is left-padded with empty
// space so the sparkline grows as the session collects history.
func sparkline(values []float64, width int) string {
	const chars = " ▁▂▃▄▅▆▇█"
	if width <= 0 {
		return ""
	}
	runes := []rune(chars)
	bins := len(runes) - 1
	out := make([]rune, width)
	for i := range out {
		out[i] = ' '
	}
	if len(values) == 0 {
		return string(out)
	}
	maxV := 0.0
	for _, v := range values {
		if v > maxV {
			maxV = v
		}
	}
	// Map each value to its slot at the right edge of the row so
	// the most recent sample is always visible at the rightmost
	// cell, with history scrolling left as new data arrives.
	start := width - len(values)
	if start < 0 {
		start = 0
	}
	skip := 0
	if len(values) > width {
		skip = len(values) - width
	}
	for i := skip; i < len(values); i++ {
		col := start + (i - skip)
		if col < 0 || col >= width {
			continue
		}
		bin := 0
		if maxV > 0 {
			bin = int(values[i] / maxV * float64(bins))
			if bin < 0 {
				bin = 0
			} else if bin > bins {
				bin = bins
			}
		}
		out[col] = runes[bin]
	}
	return string(out)
}

// connState is the dashboard's coarse health grade. Driven by the
// pool ratio and the most recent loss reading; reachability is
// folded in by callers (an unreachable daemon short-circuits to
// connDown before this is consulted).
type connState int

const (
	connHealthy connState = iota
	connDegraded
	connDown
)

func (c connState) String() string {
	switch c {
	case connHealthy:
		return "healthy"
	case connDegraded:
		return "degraded"
	case connDown:
		return "down"
	}
	return "unknown"
}

// classify returns the connection state based on the most recent
// pool ratio and rolling loss. Thresholds are pragmatic: any pool
// member down counts as degraded; sustained loss over 1 % counts
// as degraded too even when the pool is full.
func classify(s dashSample, recentLossPct []float64) connState {
	if s.poolTotal > 0 && s.poolAlive == 0 {
		return connDown
	}
	if s.poolTotal > 0 && s.poolAlive < s.poolTotal {
		return connDegraded
	}
	avg := averageNonzero(recentLossPct)
	if avg > 1 {
		return connDegraded
	}
	return connHealthy
}

// averageNonzero filters out the leading run of zero samples (which
// dominate a quiet idle tunnel) and averages the rest. When every
// value is zero, returns zero. Used by the loss classifier so brief
// idle periods don't artificially mark the connection healthy.
func averageNonzero(xs []float64) float64 {
	sum, n := 0.0, 0
	for _, v := range xs {
		if v == 0 {
			continue
		}
		sum += v
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// fromSnapshot builds a dashSample from an admin.Snapshot. Kept as
// a free function rather than a method on dashSeries so the call
// site reads clearly: sample := fromSnapshot(snap, at).
func fromSnapshot(snap *admin.Snapshot, at time.Time) dashSample {
	return dashSample{
		at:          at,
		bytesSent:   snap.BytesSent,
		bytesRecv:   snap.BytesReceived,
		packetsSent: snap.PacketsSent,
		packetsLost: snap.PacketsLost,
		poolAlive:   snap.PoolAlive,
		poolTotal:   snap.PoolTotal,
	}
}

// rateLabel formats a bytes-per-second value with a fixed-width
// prefix so successive renders don't reflow as the magnitude
// changes (12 KiB/s → 8 MiB/s would otherwise jitter the layout).
func rateLabel(bps float64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
	)
	switch {
	case bps >= GB:
		return formatBps(bps/GB, "GiB")
	case bps >= MB:
		return formatBps(bps/MB, "MiB")
	case bps >= KB:
		return formatBps(bps/KB, "KiB")
	default:
		return formatBps(bps, "B")
	}
}

// formatBps renders v with precision that scales by magnitude (so
// "3.42" doesn't become "3" when the value drops below 10) plus a
// stable 6-cell right-aligned column so the layout never shifts as
// the rate moves between buckets.
func formatBps(v float64, unit string) string {
	prec := 2
	switch {
	case v >= 100:
		prec = 0
	case v >= 10:
		prec = 1
	}
	return fmt.Sprintf("%6.*f %s/s", prec, v, unit)
}
