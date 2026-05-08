package tui

import (
	"errors"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/tui/ipc"
)

// TestApplyBenchResultRoutesPerMode: a latency result lands in the
// latency slot and not the throughput slot, and vice versa. Catches
// the failure mode where a single shared `last` field would let one
// mode's result blank the other panel.
func TestApplyBenchResultRoutesPerMode(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(0, 0)
	app.benchCtx.running = true
	app.benchCtx.runningMode = "latency"

	res := admin.BenchResult{Mode: "latency", DurationSec: 3, Samples: 100, MeanNs: 1234567, P99Ns: 4567890}
	app.applyBenchResult(benchResultMsg{result: res})

	if app.benchCtx.running {
		t.Error("running stayed true after result")
	}
	if app.benchCtx.lastLatency == nil || app.benchCtx.lastLatency.Mode != "latency" {
		t.Errorf("lastLatency not stored, got %+v", app.benchCtx.lastLatency)
	}
	if app.benchCtx.lastThroughput != nil {
		t.Errorf("throughput slot got polluted by latency result: %+v", app.benchCtx.lastThroughput)
	}
	if len(app.benchCtx.history) != 1 {
		t.Errorf("history len = %d, want 1", len(app.benchCtx.history))
	}
}

// TestApplyBenchResultErrorPreservesPriorGood: a failed run records
// the error against its mode but keeps a previously-good result
// available so the panel still shows the most recent successful
// numbers while the operator figures out why the new run failed.
func TestApplyBenchResultErrorPreservesPriorGood(t *testing.T) {
	b, _ := NewBundle()
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(0, 0)
	prior := admin.BenchResult{Mode: "throughput", BytesPerSec: 1e9}
	app.benchCtx.lastThroughput = &prior
	app.benchCtx.running = true
	app.benchCtx.runningMode = "throughput"

	app.applyBenchResult(benchResultMsg{err: errors.New("dial unix: refused")})

	if app.benchCtx.lastThroughputErr == nil ||
		app.benchCtx.lastThroughputErr.Error() != "dial unix: refused" {
		t.Errorf("lastThroughputErr = %v, want refused error", app.benchCtx.lastThroughputErr)
	}
	if app.benchCtx.lastThroughput == nil || app.benchCtx.lastThroughput.BytesPerSec != 1e9 {
		t.Errorf("prior good result was overwritten by error, got %+v", app.benchCtx.lastThroughput)
	}
}

// TestApplyBenchResultRespectsCap: long sessions don't grow memory
// unbounded — old entries get evicted past benchHistoryCap.
func TestApplyBenchResultRespectsCap(t *testing.T) {
	b, _ := NewBundle()
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(0, 0)

	for i := 0; i < benchHistoryCap+5; i++ {
		app.benchCtx.runningMode = "latency"
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

// TestBenchHandleKeyFallsThroughForNav: tab / shift+tab / digit keys
// must NOT be consumed by benchHandleKey, otherwise the operator
// would be trapped on the Bench tab. Regression guard for the form-
// driven design that swallowed every keypress.
func TestBenchHandleKeyFallsThroughForNav(t *testing.T) {
	b, _ := NewBundle()
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(0, 0)

	for _, key := range []string{"tab", "shift+tab", "1", "2", "3", "right", "left"} {
		handled, _ := app.benchHandleKey(tea.KeyPressMsg{Code: 0, Text: key})
		// KeyPressMsg.String() depends on Code/Mod, so build the msg
		// the way tea would deliver it for these keys: the Text path
		// isn't enough. Use a dedicated helper below.
		_ = handled
	}
	// Direct check via the synthetic key strings benchHandleKey reads
	// from msg.String(). KeyPressMsg's zero-value String() is empty,
	// so the switch falls through to default → handled=false. That
	// alone proves the fall-through path; the negative cases above
	// are belt-and-braces.
	for _, k := range []string{"tab", "shift+tab", "1", "right", "esc"} {
		var msg tea.KeyPressMsg
		switch k {
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
		case "1":
			msg = tea.KeyPressMsg{Code: '1', Text: "1"}
		case "right":
			msg = tea.KeyPressMsg{Code: tea.KeyRight}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		}
		handled, _ := app.benchHandleKey(msg)
		// esc is handled only when running; default state is idle.
		if k == "esc" {
			if handled {
				t.Errorf("esc consumed while idle (should fall through to global)")
			}
			continue
		}
		if handled {
			t.Errorf("nav key %q was consumed by Bench handler — would trap the operator", k)
		}
	}
}

// TestBenchHandleKeyHotkeysStartRun: pressing l (resp. t) when idle
// flips running=true, sets the right runningMode, and returns a Cmd
// the runtime can invoke. Catches a regression where the new design
// would silently no-op the hotkeys.
func TestBenchHandleKeyHotkeysStartRun(t *testing.T) {
	b, _ := NewBundle()
	app := &App{i18n: b, ipc: ipc.New("")}
	app.benchCtx = newBenchState(0, 0)

	handled, cmd := app.benchHandleKey(tea.KeyPressMsg{Code: 'l', Text: "l"})
	if !handled {
		t.Fatal("l was not consumed by the Bench handler")
	}
	if cmd == nil {
		t.Fatal("l did not produce a Cmd")
	}
	if !app.benchCtx.running || app.benchCtx.runningMode != "latency" {
		t.Errorf("after l: running=%v mode=%q, want true+latency",
			app.benchCtx.running, app.benchCtx.runningMode)
	}

	// While running, l/t are swallowed (handled=true, cmd=nil) so the
	// operator can't queue a second request that would race the first.
	handled, cmd = app.benchHandleKey(tea.KeyPressMsg{Code: 't', Text: "t"})
	if !handled || cmd != nil {
		t.Errorf("t while running: handled=%v cmd=%v, want true/nil", handled, cmd)
	}

	// esc detaches from the wait so the panels unlock immediately.
	handled, _ = app.benchHandleKey(tea.KeyPressMsg{Code: tea.KeyEscape})
	if !handled {
		t.Error("esc was not consumed during a run")
	}
	if app.benchCtx.running {
		t.Error("running stayed true after esc — panels would stay locked")
	}
}

// TestBenchPanelDurationsAreFixed pins the per-mode preset durations
// so a future tweak that breaks them gets caught — the user picked
// these specific values (latency=3s, throughput=30s) and a silent
// regression would change benchmark numbers across runs.
func TestBenchPanelDurationsAreFixed(t *testing.T) {
	if benchDurLatency != 3*time.Second {
		t.Errorf("benchDurLatency = %s, want 3s", benchDurLatency)
	}
	if benchDurThroughput != 30*time.Second {
		t.Errorf("benchDurThroughput = %s, want 30s", benchDurThroughput)
	}
}
