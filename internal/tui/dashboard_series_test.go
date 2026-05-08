package tui

import (
	"testing"
	"time"
)

// TestDashSeriesPushEvictsOnCap confirms the ring buffer drops the
// oldest sample once the configured capacity is reached, so a
// long-running TUI session keeps memory bounded.
func TestDashSeriesPushEvictsOnCap(t *testing.T) {
	s := newDashSeries(3)
	now := time.Now()
	for i := 0; i < 5; i++ {
		s.push(dashSample{at: now.Add(time.Duration(i) * time.Second), bytesSent: uint64(i)})
	}
	if len(s.samples) != 3 {
		t.Fatalf("len = %d, want 3", len(s.samples))
	}
	// Oldest two evicted; the remaining bytesSent values are 2, 3, 4.
	want := []uint64{2, 3, 4}
	for i, v := range want {
		if s.samples[i].bytesSent != v {
			t.Errorf("samples[%d].bytesSent = %d, want %d", i, s.samples[i].bytesSent, v)
		}
	}
}

// TestDashSeriesResetsOnRestart confirms the buffer flushes itself
// when the cumulative counter goes backwards (the daemon was
// restarted). Without this the rate sparkline would render a giant
// negative spike at the discontinuity.
func TestDashSeriesResetsOnRestart(t *testing.T) {
	s := newDashSeries(10)
	now := time.Now()
	s.push(dashSample{at: now, bytesSent: 1000, bytesRecv: 500})
	s.push(dashSample{at: now.Add(time.Second), bytesSent: 2000, bytesRecv: 800})
	// Counter goes backwards → restart detected, buffer reset to
	// just the new sample.
	s.push(dashSample{at: now.Add(2 * time.Second), bytesSent: 100, bytesRecv: 50})
	if len(s.samples) != 1 {
		t.Fatalf("post-restart len = %d, want 1", len(s.samples))
	}
	if s.samples[0].bytesSent != 100 {
		t.Errorf("kept sample bytesSent = %d, want 100", s.samples[0].bytesSent)
	}
}

// TestDashSeriesRates checks the per-sample bandwidth and loss
// derivations. With a 1-second sample interval, sentBps equals the
// bytes delta directly; loss is (delta_lost / delta_sent) * 100.
func TestDashSeriesRates(t *testing.T) {
	s := newDashSeries(10)
	now := time.Now()
	s.push(dashSample{at: now, bytesSent: 0, bytesRecv: 0, packetsSent: 0, packetsLost: 0})
	s.push(dashSample{at: now.Add(time.Second), bytesSent: 1000, bytesRecv: 500, packetsSent: 100, packetsLost: 1})
	s.push(dashSample{at: now.Add(2 * time.Second), bytesSent: 3000, bytesRecv: 1500, packetsSent: 300, packetsLost: 6})

	sent, recv, loss := s.rates()
	if len(sent) != 2 {
		t.Fatalf("rates len = %d, want 2", len(sent))
	}
	if sent[0] != 1000 || sent[1] != 2000 {
		t.Errorf("sent = %v, want [1000 2000]", sent)
	}
	if recv[0] != 500 || recv[1] != 1000 {
		t.Errorf("recv = %v, want [500 1000]", recv)
	}
	// Sample 1: 1 lost / 100 sent = 1%.
	// Sample 2: 5 lost / 200 sent = 2.5%.
	if loss[0] != 1.0 {
		t.Errorf("loss[0] = %f, want 1.0", loss[0])
	}
	if loss[1] != 2.5 {
		t.Errorf("loss[1] = %f, want 2.5", loss[1])
	}
}

// TestSparklineHandlesEmptyAndZero confirms the sparkline helper
// produces a width-N output even on edge cases (no values, all
// zero) — the dashboard uses it inside a fixed-width row, so a
// shorter return would shift the trailing value column.
func TestSparklineHandlesEmptyAndZero(t *testing.T) {
	got := sparkline(nil, 10)
	if len(got) != 10 {
		t.Errorf("nil input width = %d, want 10", lenRunes(got))
	}
	got = sparkline([]float64{0, 0, 0, 0}, 10)
	if lenRunes(got) != 10 {
		t.Errorf("zero input width = %d, want 10", lenRunes(got))
	}
}

// TestSparklineMapsToBins checks a simple ramp ends with the
// "full" block at the rightmost cell and the "empty" block at the
// leftmost — the most recent sample is always the rightmost cell.
func TestSparklineMapsToBins(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8}
	got := sparkline(values, 8)
	runes := []rune(got)
	if runes[7] != '█' {
		t.Errorf("rightmost cell = %q, want '█'", runes[7])
	}
	if runes[0] != '▁' {
		t.Errorf("leftmost cell = %q, want '▁'", runes[0])
	}
}

// TestClassify covers the three branches of the connection-state
// classifier so adding a new threshold doesn't silently regress one.
func TestClassify(t *testing.T) {
	healthy := dashSample{poolAlive: 8, poolTotal: 8}
	if got := classify(healthy, []float64{0, 0, 0}); got != connHealthy {
		t.Errorf("full pool + no loss = %v, want healthy", got)
	}

	partial := dashSample{poolAlive: 3, poolTotal: 8}
	if got := classify(partial, nil); got != connDegraded {
		t.Errorf("partial pool = %v, want degraded", got)
	}

	dead := dashSample{poolAlive: 0, poolTotal: 8}
	if got := classify(dead, nil); got != connDown {
		t.Errorf("dead pool = %v, want down", got)
	}

	lossy := dashSample{poolAlive: 8, poolTotal: 8}
	if got := classify(lossy, []float64{2.5, 1.5, 1.2}); got != connDegraded {
		t.Errorf("full pool but >1%% loss = %v, want degraded", got)
	}
}

func lenRunes(s string) int { return len([]rune(s)) }
