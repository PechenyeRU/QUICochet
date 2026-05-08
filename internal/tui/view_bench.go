package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// benchHistoryCap is how many past runs the tab keeps in memory so
// the operator can compare a tweak side-by-side with the previous
// runs without juggling tmux scrollback. ~10 entries fit on a
// reasonable terminal without scrolling.
const benchHistoryCap = 10

// Per-mode preset durations. Latency converges fast on a quiet path
// (3 s is enough for the histogram to stabilise); throughput needs
// long enough for cwnd to ramp on a high-RTT path (BBR/CUBIC takes
// ~5 s to open up), so 30 s gives a meaningful average rate.
//
// These are intentionally hard-coded rather than form-driven —
// surfacing them as editable inputs trapped tab/digit nav inside the
// form, which made the tab unusable. If a future caller needs other
// durations they can land via CLI flag or a dedicated knob; the
// daily-driver case is one keystroke per preset.
const (
	benchDurLatency    = 3 * time.Second
	benchDurThroughput = 30 * time.Second
)

// benchState holds per-session bench state. There is intentionally
// no form: the tab runs on two hotkeys (l, t) and surfaces results
// in two side-by-side panels styled like the Tools tab. Removing
// the form removes the trap where huh consumed every keypress —
// tab / shift+tab / digits / esc now reach the global router so
// the operator can leave the tab without reaching for the mouse.
type benchState struct {
	width, height int

	running     bool
	runningMode string // "latency" or "throughput" while a run is in flight
	startAt     time.Time

	// Per-mode last result so each panel can render its own latest
	// summary independently. A latency error doesn't blank the
	// throughput panel and vice versa.
	lastLatency       *admin.BenchResult
	lastLatencyAt     time.Time
	lastLatencyErr    error
	lastThroughput    *admin.BenchResult
	lastThroughputAt  time.Time
	lastThroughputErr error

	// history is a unified ring of recent runs across both modes,
	// rendered as a compact table below the panels. Failures are
	// kept too so a parameter sweep with transient errors still
	// shows up in the timeline.
	history []benchHistoryEntry
}

type benchHistoryEntry struct {
	at     time.Time
	result admin.BenchResult
	err    error
}

// benchResultMsg carries the outcome of a single async bench run
// back to App.Update, where it's folded into the bench state.
type benchResultMsg struct {
	result admin.BenchResult
	err    error
}

// benchView lays out the Bench tab as two button-panels (Latency,
// Throughput) plus a recent-runs table. Mirrors the Tools tab so
// the muscle-memory transfers — single hotkey to act, no form.
func (a *App) benchView() string {
	b := a.i18n
	theme := a.theme

	if a.benchCtx == nil {
		a.benchCtx = newBenchState(a.bodyWidth(), a.formHeight())
	}
	bs := a.benchCtx

	title := theme.Title.Render(b.S("bench.title"))

	half := a.benchPanelWidth()
	left := renderBenchPanel(theme, b, "latency", bs, half)
	right := renderBenchPanel(theme, b, "throughput", bs, half)
	side := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)

	parts := []string{title, "", side}
	if len(bs.history) > 0 {
		parts = append(parts, "", renderBenchHistory(theme, b, bs.history))
	}
	parts = append(parts, "", theme.Muted.Render(b.S("bench.hint")))
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// benchPanelWidth budgets half the body width per panel minus the
// two-cell gap between them. Same shape as toolsPanelWidth so a long
// error string wraps inside the border instead of bleeding past it.
func (a *App) benchPanelWidth() int {
	w := a.bodyWidth()
	if w <= 0 {
		return 0
	}
	half := (w - 2) / 2
	if half < 30 {
		return 30
	}
	return half
}

// newBenchState seeds an empty state. There are no editable defaults
// to pick — the durations are mode-fixed constants — so this just
// stashes the dimensions.
func newBenchState(width, height int) *benchState {
	return &benchState{width: width, height: height}
}

// renderBenchPanel renders one of the two mode panels. A panel shows
// its title, a hotkey hint (or running spinner), the duration that
// will be used, and the most recent result for that mode. Errors
// render in the warn colour without overwriting a prior good result
// so the operator can still see the last successful numbers while
// they figure out why the new run failed.
func renderBenchPanel(theme *Theme, b *Bundle, mode string, bs *benchState, width int) string {
	var (
		title   string
		hotkey  string
		dur     time.Duration
		last    *admin.BenchResult
		lastAt  time.Time
		lastErr error
	)
	switch mode {
	case "latency":
		title = b.S("bench.panel.latency.title")
		hotkey = "l"
		dur = benchDurLatency
		last = bs.lastLatency
		lastAt = bs.lastLatencyAt
		lastErr = bs.lastLatencyErr
	case "throughput":
		title = b.S("bench.panel.throughput.title")
		hotkey = "t"
		dur = benchDurThroughput
		last = bs.lastThroughput
		lastAt = bs.lastThroughputAt
		lastErr = bs.lastThroughputErr
	}
	isRunning := bs.running && bs.runningMode == mode
	otherRunning := bs.running && bs.runningMode != mode

	header := theme.PanelTitle.Render(title)

	var status string
	switch {
	case isRunning:
		elapsed := time.Since(bs.startAt).Round(time.Second)
		status = theme.Success.Render("● "+b.S("bench.panel.running")) + "   " +
			theme.Muted.Render(fmt.Sprintf(b.S("bench.panel.elapsed"), elapsed))
	case otherRunning:
		status = theme.Muted.Render("○ " + b.S("bench.panel.locked"))
	default:
		status = theme.Subtitle.Render(fmt.Sprintf(b.S("bench.panel.run.hint"), strings.ToUpper(hotkey)))
	}

	durLine := theme.Label.Render(b.S("bench.panel.dur")+": ") + theme.Value.Render(dur.String())

	var resultBlock string
	switch {
	case lastErr != nil:
		resultBlock = theme.Warn.Render(b.S("bench.fail")+": "+lastErr.Error()) + "\n" +
			theme.Muted.Render(lastAt.Local().Format("15:04:05"))
	case last != nil:
		resultBlock = renderBenchResultCompact(theme, b, *last) + "\n" +
			theme.Muted.Render(lastAt.Local().Format("15:04:05"))
	default:
		resultBlock = theme.Muted.Render(b.S("bench.panel.no.run"))
	}

	style := theme.Panel
	if width > 0 {
		style = style.Width(width)
	}
	return style.Render(strings.Join([]string{header, "", status, durLine, "", resultBlock}, "\n"))
}

// renderBenchResultCompact is the per-panel summary: tighter than
// renderBenchHistory's table row but laid out as multiple lines so
// the percentile triplet stays scannable in a narrow panel.
func renderBenchResultCompact(theme *Theme, b *Bundle, r admin.BenchResult) string {
	switch r.Mode {
	case "latency":
		return strings.Join([]string{
			theme.Label.Render(b.S("bench.lat.mean")+" ") + theme.Value.Render(humanDur(r.MeanNs)) + "   " +
				theme.Label.Render(b.S("bench.lat.samples")+" ") + theme.Value.Render(fmt.Sprintf("%d", r.Samples)),
			theme.Label.Render("p50 ") + theme.Value.Render(humanDur(r.P50Ns)) + "   " +
				theme.Label.Render("p90 ") + theme.Value.Render(humanDur(r.P90Ns)) + "   " +
				theme.Label.Render("p99 ") + theme.Value.Render(humanDur(r.P99Ns)),
		}, "\n")
	case "throughput":
		return strings.Join([]string{
			theme.Label.Render(b.S("bench.tput.rate")+" ") + theme.Success.Render(rateLabel(r.BytesPerSec)),
			theme.Label.Render(b.S("bench.tput.total")+" ") + theme.Value.Render(humanBytes(r.Bytes)) + "   " +
				theme.Label.Render(b.S("bench.tput.streams")+" ") + theme.Value.Render(fmt.Sprintf("%d", r.Streams)),
		}, "\n")
	}
	return ""
}

// benchHandleKey routes Bench-tab keys. Only `l`, `t`, and `esc`
// (during a run) are consumed; everything else returns handled=false
// so the global router gets to handle tab/shift+tab/digit nav. This
// is the inverse of the previous form-based design where huh trapped
// every keypress and made it impossible to leave the tab without the
// mouse.
//
// While a run is in flight, l/t are no-ops (return handled=true to
// suppress the global digit/tab interpretation of the same key) so
// the operator can't queue a second run that would race the first.
// Tab nav is still allowed during a run — the result will land via
// applyBenchResult regardless of which tab the operator drifts to.
func (a *App) benchHandleKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if a.benchCtx == nil {
		a.benchCtx = newBenchState(a.bodyWidth(), a.formHeight())
	}
	bs := a.benchCtx
	switch msg.String() {
	case "l":
		if bs.running {
			return true, nil
		}
		return true, a.startBench("latency", benchDurLatency)
	case "t":
		if bs.running {
			return true, nil
		}
		return true, a.startBench("throughput", benchDurThroughput)
	case "esc":
		if bs.running {
			// Detach from the wait: the daemon-side run continues but
			// the TUI stops blocking the panels. The eventual result
			// still folds into history when applyBenchResult fires.
			bs.running = false
			return true, nil
		}
	}
	return false, nil
}

// startBench flips running=true and returns the async cmd that
// dials admin.sock. Result lands in App.Update as benchResultMsg.
func (a *App) startBench(mode string, dur time.Duration) tea.Cmd {
	bs := a.benchCtx
	bs.running = true
	bs.runningMode = mode
	bs.startAt = time.Now()

	client := a.ipc
	return func() tea.Msg {
		res, err := client.Bench(mode, dur, 0)
		return benchResultMsg{result: res, err: err}
	}
}

// applyBenchResult folds the async result into the per-mode last
// fields and pushes onto the unified history ring. Mode is read off
// the result so a panel that wasn't the originator (e.g. the daemon
// returned an empty Mode on error) doesn't mistakenly clobber state.
func (a *App) applyBenchResult(m benchResultMsg) {
	if a.benchCtx == nil {
		return
	}
	bs := a.benchCtx
	bs.running = false
	now := time.Now()

	// Pick the destination by the mode the operator actually launched.
	// On error the result.Mode field can be empty, so falling back to
	// runningMode keeps the error attached to the right panel.
	mode := m.result.Mode
	if mode == "" {
		mode = bs.runningMode
	}
	switch mode {
	case "latency":
		bs.lastLatencyErr = m.err
		bs.lastLatencyAt = now
		if m.err == nil {
			r := m.result
			bs.lastLatency = &r
		}
	case "throughput":
		bs.lastThroughputErr = m.err
		bs.lastThroughputAt = now
		if m.err == nil {
			r := m.result
			bs.lastThroughput = &r
		}
	}
	bs.runningMode = ""

	// History row keeps the originating mode even on error so the
	// table renders the LAT/TPUT badge correctly.
	entry := benchHistoryEntry{at: now, result: m.result, err: m.err}
	if entry.result.Mode == "" {
		entry.result.Mode = mode
	}
	bs.history = append(bs.history, entry)
	if len(bs.history) > benchHistoryCap {
		bs.history = bs.history[len(bs.history)-benchHistoryCap:]
	}
}

// renderBenchHistory shows the last few runs as a tight table so
// the operator can compare a parameter sweep at a glance. Latency
// runs report mean+p99, throughput runs report rate; an error in a
// row gets the warn colour and replaces the value column with the
// error message.
func renderBenchHistory(theme *Theme, b *Bundle, hist []benchHistoryEntry) string {
	title := theme.PanelTitle.Render(b.S("bench.history.title"))
	rows := []string{title}
	for i := len(hist) - 1; i >= 0; i-- {
		e := hist[i]
		ts := e.at.Local().Format("15:04:05")
		switch {
		case e.err != nil:
			rows = append(rows, fmt.Sprintf("  %s  %s  %s",
				theme.Subtitle.Render(ts),
				theme.Error.Render(strings.ToUpper(e.result.Mode)),
				theme.Warn.Render(e.err.Error())))
		case e.result.Mode == "latency":
			rows = append(rows, fmt.Sprintf("  %s  %s  mean %s  p99 %s",
				theme.Subtitle.Render(ts),
				theme.Accent.Render("LAT "),
				theme.Value.Render(humanDur(e.result.MeanNs)),
				theme.Value.Render(humanDur(e.result.P99Ns))))
		case e.result.Mode == "throughput":
			rows = append(rows, fmt.Sprintf("  %s  %s  %s",
				theme.Subtitle.Render(ts),
				theme.Accent.Render("TPUT"),
				theme.Value.Render(rateLabel(e.result.BytesPerSec))))
		}
	}
	return strings.Join(rows, "\n")
}

// humanDur formats a nanosecond duration for the result panel.
// Sub-µs durations stay in ns; sub-ms in µs; otherwise ms with
// two decimals so 1.23 ms reads cleanly.
func humanDur(ns int64) string {
	switch {
	case ns < 1000:
		return fmt.Sprintf("%d ns", ns)
	case ns < 1000_000:
		return fmt.Sprintf("%.2f µs", float64(ns)/1000)
	case ns < 1000_000_000:
		return fmt.Sprintf("%.2f ms", float64(ns)/1000_000)
	default:
		return fmt.Sprintf("%.2f s", float64(ns)/1000_000_000)
	}
}
