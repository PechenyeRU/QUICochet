package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// benchHistoryCap is how many past runs the tab keeps in memory so
// the operator can compare a tweak side-by-side with the previous
// runs without juggling tmux scrollback. ~10 entries fit on a
// reasonable terminal without scrolling.
const benchHistoryCap = 10

// Per-mode default durations. Latency runs are short because the
// histogram converges fast on a quiet path; throughput runs need
// long enough for cwnd to open and stabilise (BBR/CUBIC ramps over
// the first ~5 s on a high-RTT path), so 30 s gives a meaningful
// rate. Operators can still type any duration into the input.
const (
	defaultDurLatency    = "3s"
	defaultDurThroughput = "30s"
)

// defaultDurationFor returns the seed duration for a given mode.
// Used by newBenchState (initial seed) and benchView (auto-flip
// when the operator switches mode and the duration field is still
// untouched at the previous mode's default).
func defaultDurationFor(mode string) string {
	if mode == "throughput" {
		return defaultDurThroughput
	}
	return defaultDurLatency
}

// benchState is the per-session state of the Bench tab. The form
// drives input collection; runOutcome is populated once a run
// completes and pushed into history. running guards against double-
// submitting while a run is in flight.
type benchState struct {
	form *huh.Form

	mode          string
	modePrev      string // tracked so benchView's auto-flip can detect a change
	durationStr   string
	parallelStr   string
	width, height int

	running bool
	startAt time.Time
	last    *admin.BenchResult
	lastErr error
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

// benchView renders the Bench tab: a form for picking mode +
// duration + parallel on top, the latest run summary in the middle,
// and a small history table of recent runs at the bottom. While a
// run is in flight the form is hidden behind a "running…" banner
// so the operator can't queue a second request that would race
// the first.
func (a *App) benchView() string {
	b := a.i18n
	theme := a.theme

	if a.benchCtx == nil {
		a.benchCtx = newBenchState(a.i18n, a.bodyWidth(), a.formHeight())
	}
	bs := a.benchCtx
	bs.syncModeDefaults()

	title := theme.Title.Render(b.S("bench.title"))

	var middle string
	switch {
	case bs.running:
		elapsed := time.Since(bs.startAt).Round(time.Second)
		middle = theme.Subtitle.Render(b.S("bench.running")) + "   " +
			theme.Muted.Render(fmt.Sprintf(b.S("bench.elapsed"), elapsed))
	case bs.lastErr != nil:
		middle = theme.Error.Render(b.S("bench.fail") + ": " + bs.lastErr.Error())
	case bs.last != nil:
		middle = renderBenchResult(theme, b, *bs.last)
	default:
		middle = theme.Muted.Render(b.S("bench.intro"))
	}

	parts := []string{title, ""}
	if !bs.running {
		parts = append(parts, bs.form.View(), "")
	}
	parts = append(parts, middle)
	if len(bs.history) > 0 {
		parts = append(parts, "", renderBenchHistory(theme, b, bs.history))
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// newBenchState seeds defaults that match what an operator would
// reach for first: latency, the per-mode default duration (3s),
// daemon-default parallelism. The form lives on the state so a
// re-render between key strokes preserves typing.
func newBenchState(b *Bundle, width, height int) *benchState {
	bs := &benchState{
		mode:        "latency",
		modePrev:    "latency",
		durationStr: defaultDurationFor("latency"),
		parallelStr: "0",
		width:       width,
		height:      height,
	}
	bs.form = bs.buildForm(b)
	return bs
}

// syncModeDefaults watches for a mode change driven by the form's
// Select field. When the operator flips between latency and
// throughput, the duration auto-updates to the new mode's default
// — but only when the existing value is still the previous mode's
// default. A custom duration the operator typed manually is
// respected. Called once per benchView render so the flip is
// visible the moment the form refreshes.
func (bs *benchState) syncModeDefaults() {
	if bs.mode == bs.modePrev {
		return
	}
	if bs.durationStr == defaultDurationFor(bs.modePrev) {
		bs.durationStr = defaultDurationFor(bs.mode)
	}
	bs.modePrev = bs.mode
}

func (bs *benchState) buildForm(b *Bundle) *huh.Form {
	f := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(b.S("bench.field.mode")).
				Description(b.S("bench.field.mode.desc")).
				Options(
					huh.NewOption("latency (RTT histogram)", "latency"),
					huh.NewOption("throughput (bytes/sec)", "throughput"),
				).
				Value(&bs.mode),
			huh.NewInput().
				Title(b.S("bench.field.duration")).
				Description(b.S("bench.field.duration.desc")).
				Value(&bs.durationStr).
				Validate(func(s string) error {
					if _, err := time.ParseDuration(s); err != nil {
						return fmt.Errorf("invalid duration: %v", err)
					}
					return nil
				}),
			huh.NewInput().
				Title(b.S("bench.field.parallel")).
				Description(b.S("bench.field.parallel.desc")).
				Value(&bs.parallelStr).
				Validate(func(s string) error {
					if s == "" {
						bs.parallelStr = "0"
						return nil
					}
					n, err := strconv.Atoi(s)
					if err != nil || n < 0 {
						return fmt.Errorf("must be a non-negative integer")
					}
					return nil
				}),
		),
	).WithShowHelp(false).WithShowErrors(true).WithKeyMap(customFormKeyMap())
	if bs.width > 0 {
		f = f.WithWidth(bs.width)
	}
	if bs.height > 0 {
		f = f.WithHeight(bs.height)
	}
	return f
}

// benchHandleKey routes Bench-tab keys. The form owns most of the
// keyboard while it has focus — the only handler-level binding is
// ctrl+enter to submit (the form's enter advances fields, so a
// dedicated submit chord avoids accidentally launching a run when
// the operator is mid-edit).
//
// Returns (handled, cmd). handled = true short-circuits the global
// digit-tab dispatcher so digit keys don't yank the operator out of
// a numeric field.
func (a *App) benchHandleKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if a.benchCtx == nil {
		a.benchCtx = newBenchState(a.i18n, a.bodyWidth(), a.formHeight())
	}
	bs := a.benchCtx
	if bs.running {
		// Ignore everything except esc-aborting the wait. Since the
		// admin protocol has no cancel, we leave the daemon-side run
		// to finish on its own; the result is just discarded by
		// flipping running=false here.
		if msg.String() == "esc" {
			bs.running = false
			return true, nil
		}
		return true, nil
	}
	if msg.String() == "ctrl+s" {
		return true, a.startBench()
	}
	model, c := bs.form.Update(msg)
	if f, ok := model.(*huh.Form); ok {
		bs.form = f
	}
	return true, c
}

// startBench validates the form fields, flips running=true, and
// returns the async cmd that talks to admin.sock. The result lands
// in App.Update as benchResultMsg.
func (a *App) startBench() tea.Cmd {
	bs := a.benchCtx
	dur, err := time.ParseDuration(bs.durationStr)
	if err != nil {
		bs.lastErr = err
		return nil
	}
	parallel, _ := strconv.Atoi(bs.parallelStr) // validated by the form
	bs.running = true
	bs.startAt = time.Now()
	bs.lastErr = nil

	mode := bs.mode
	client := a.ipc
	return func() tea.Msg {
		res, err := client.Bench(mode, dur, parallel)
		return benchResultMsg{result: res, err: err}
	}
}

// applyBenchResult folds the async result into the state and
// pushes it onto the bounded history ring. Called from App.Update
// on benchResultMsg.
func (a *App) applyBenchResult(m benchResultMsg) {
	if a.benchCtx == nil {
		return
	}
	bs := a.benchCtx
	bs.running = false
	bs.lastErr = m.err
	if m.err == nil {
		r := m.result
		bs.last = &r
	}
	bs.history = append(bs.history, benchHistoryEntry{
		at:     time.Now(),
		result: m.result,
		err:    m.err,
	})
	if len(bs.history) > benchHistoryCap {
		bs.history = bs.history[len(bs.history)-benchHistoryCap:]
	}
}

// renderBenchResult turns a successful run into a one-paragraph
// summary. Latency mode shows percentiles; throughput mode shows
// bytes/sec + total bytes + stream fan-out. Both modes lead with
// the duration so the operator can sanity-check the parameters.
func renderBenchResult(theme *Theme, b *Bundle, r admin.BenchResult) string {
	header := theme.PanelTitle.Render(b.S("bench.result.title")) + "  " +
		theme.Subtitle.Render(fmt.Sprintf(b.S("bench.result.dur"), r.DurationSec))
	switch r.Mode {
	case "latency":
		return strings.Join([]string{
			header,
			fmt.Sprintf("  %s  %s   %s  %s",
				theme.Label.Render(b.S("bench.lat.samples")), theme.Value.Render(fmt.Sprintf("%d", r.Samples)),
				theme.Label.Render(b.S("bench.lat.mean")), theme.Value.Render(humanDur(r.MeanNs))),
			fmt.Sprintf("  %s  %s   %s  %s   %s  %s",
				theme.Label.Render("p50"), theme.Value.Render(humanDur(r.P50Ns)),
				theme.Label.Render("p90"), theme.Value.Render(humanDur(r.P90Ns)),
				theme.Label.Render("p99"), theme.Value.Render(humanDur(r.P99Ns))),
			fmt.Sprintf("  %s  %s   %s  %s",
				theme.Label.Render("min"), theme.Value.Render(humanDur(r.MinNs)),
				theme.Label.Render("max"), theme.Value.Render(humanDur(r.MaxNs))),
		}, "\n")
	case "throughput":
		return strings.Join([]string{
			header,
			fmt.Sprintf("  %s  %s   %s  %s   %s  %d",
				theme.Label.Render(b.S("bench.tput.rate")), theme.Success.Render(rateLabel(r.BytesPerSec)),
				theme.Label.Render(b.S("bench.tput.total")), theme.Value.Render(humanBytes(r.Bytes)),
				theme.Label.Render(b.S("bench.tput.streams")), r.Streams),
		}, "\n")
	default:
		return theme.Warn.Render(fmt.Sprintf("unknown mode %q", r.Mode))
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
