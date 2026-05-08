package tui

import (
	"errors"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/tui/ipc"
)

// TestApplyBenchResultPushesHistory exercises the result-handling
// path: a successful run flips running back off, populates last,
// and pushes onto history. catches the failure mode where
// running stays true (the spinner would loop forever).
func TestApplyBenchResultPushesHistory(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(b, 0, 0)
	app.benchCtx.running = true

	res := admin.BenchResult{Mode: "latency", DurationSec: 5, Samples: 100, MeanNs: 1234567, P99Ns: 4567890}
	app.applyBenchResult(benchResultMsg{result: res})

	if app.benchCtx.running {
		t.Error("running stayed true after result")
	}
	if app.benchCtx.last == nil || app.benchCtx.last.Mode != "latency" {
		t.Errorf("last result not stored, got %+v", app.benchCtx.last)
	}
	if len(app.benchCtx.history) != 1 {
		t.Errorf("history len = %d, want 1", len(app.benchCtx.history))
	}
}

// TestApplyBenchResultRespectsCap pushes more than benchHistoryCap
// entries and asserts the oldest are evicted, so a long-running
// session doesn't grow memory unbounded.
func TestApplyBenchResultRespectsCap(t *testing.T) {
	b, _ := NewBundle()
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(b, 0, 0)

	for i := 0; i < benchHistoryCap+5; i++ {
		app.applyBenchResult(benchResultMsg{
			result: admin.BenchResult{Mode: "latency", DurationSec: 1, MeanNs: int64(i)},
		})
	}
	if len(app.benchCtx.history) != benchHistoryCap {
		t.Errorf("history len = %d, want %d", len(app.benchCtx.history), benchHistoryCap)
	}
	// First retained entry should be index 5 (i.e. MeanNs == 5).
	if first := app.benchCtx.history[0].result.MeanNs; first != 5 {
		t.Errorf("oldest retained MeanNs = %d, want 5", first)
	}
}

// TestApplyBenchResultStoresError: a failed run records the error,
// keeps running=false, and does not overwrite a previously-good
// last result so the operator's panel still shows the most recent
// successful numbers.
func TestApplyBenchResultStoresError(t *testing.T) {
	b, _ := NewBundle()
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(b, 0, 0)
	prior := admin.BenchResult{Mode: "throughput", BytesPerSec: 1e9}
	app.benchCtx.last = &prior

	app.applyBenchResult(benchResultMsg{err: errors.New("dial unix: refused")})

	if app.benchCtx.lastErr == nil || app.benchCtx.lastErr.Error() != "dial unix: refused" {
		t.Errorf("lastErr = %v, want refused error", app.benchCtx.lastErr)
	}
	if app.benchCtx.last == nil || app.benchCtx.last.BytesPerSec != 1e9 {
		t.Errorf("prior good result was overwritten by error, got %+v", app.benchCtx.last)
	}
}

// TestNewBenchStateDefaults documents the values an operator sees
// the first time they open the Bench tab: latency mode, 3 s
// duration, daemon-default fan-out. Keeps the defaults pinned so a
// refactor that breaks the seed values gets caught.
func TestNewBenchStateDefaults(t *testing.T) {
	b, _ := NewBundle()
	bs := newBenchState(b, 0, 0)
	if bs.mode != "latency" {
		t.Errorf("default mode = %q, want latency", bs.mode)
	}
	if bs.durationStr != "3s" {
		t.Errorf("default duration = %q, want 3s", bs.durationStr)
	}
	if _, err := time.ParseDuration(bs.durationStr); err != nil {
		t.Errorf("default duration %q does not parse: %v", bs.durationStr, err)
	}
	if bs.parallelStr != "0" {
		t.Errorf("default parallel = %q, want 0", bs.parallelStr)
	}
}

// TestSyncModeDefaultsAutoFlips verifies the mode-change auto-flip:
// switching from latency to throughput while the duration is still
// at the latency default upgrades to the throughput default, and
// vice versa.
func TestSyncModeDefaultsAutoFlips(t *testing.T) {
	b, _ := NewBundle()
	bs := newBenchState(b, 0, 0)
	if bs.durationStr != "3s" {
		t.Fatalf("setup: durationStr = %q, want 3s", bs.durationStr)
	}
	bs.mode = "throughput"
	bs.syncModeDefaults()
	if bs.durationStr != "30s" {
		t.Errorf("latency→throughput auto-flip: durationStr = %q, want 30s", bs.durationStr)
	}
	if bs.modePrev != "throughput" {
		t.Errorf("modePrev = %q, want throughput", bs.modePrev)
	}
	bs.mode = "latency"
	bs.syncModeDefaults()
	if bs.durationStr != "3s" {
		t.Errorf("throughput→latency auto-flip: durationStr = %q, want 3s", bs.durationStr)
	}
}

// TestSyncModeDefaultsRespectsCustom: when the operator typed a
// custom duration (anything other than the previous mode's
// default), switching mode does NOT clobber it.
func TestSyncModeDefaultsRespectsCustom(t *testing.T) {
	b, _ := NewBundle()
	bs := newBenchState(b, 0, 0)
	bs.durationStr = "12s" // operator-typed value
	bs.mode = "throughput"
	bs.syncModeDefaults()
	if bs.durationStr != "12s" {
		t.Errorf("custom duration overwritten on mode flip: durationStr = %q, want 12s", bs.durationStr)
	}
}
