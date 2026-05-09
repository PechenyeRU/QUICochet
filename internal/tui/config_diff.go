package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// differ is the Config tab's "Diff vs running" sub-app. Two
// phases: phase 0 prompts for a path; phase 1 fetches the running
// daemon's config via admin.sock, computes a line-by-line diff
// against the file, and renders it. The result panel scrolls as
// the operator advances focus past the visible window via the
// huh.Form viewport — same scroll behaviour as the wizard
// tunables step.
type differ struct {
	path string

	step int // 0 = path prompt, 1 = result

	width, height int
	form          *huh.Form

	fileCfg    *config.Config
	runningCfg *config.Config

	loadErr   error // file-read failure
	fetchErr  error // admin.sock failure
	diff      []diffLine
	added     int
	removed   int
}

func newDiffer(b *Bundle, width, height int) (*differ, tea.Cmd) {
	d := &differ{width: width, height: height}
	d.form = d.applySize(d.buildPathPrompt(b))
	return d, d.form.Init()
}

func (d *differ) applySize(f *huh.Form) *huh.Form {
	f = f.WithKeyMap(customFormKeyMap())
	if d.width > 0 {
		f = f.WithWidth(d.width)
	}
	if d.height > 0 {
		f = f.WithHeight(d.height)
	}
	return f
}

func (d *differ) buildPathPrompt(b *Bundle) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(b.S("config.diff.path.title")).
				Description(b.S("config.diff.path.desc")).
				Value(&d.path).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("required")
					}
					return nil
				}),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// updateForm advances the differ. Phase 0 ends on submit: we load
// the file and (on success) immediately fetch the running daemon
// config, then transition to phase 1 with the rendered diff. Phase
// 1 has no form — the operator hits esc to exit, handled at the
// dispatcher level.
func (d *differ) updateForm(msg tea.Msg, _ *Bundle, ipc configFetcher) (tea.Cmd, bool) {
	if d.step != 0 {
		return nil, false
	}
	model, c := d.form.Update(msg)
	if f, ok := model.(*huh.Form); ok {
		d.form = f
	}
	if d.form.State != huh.StateCompleted {
		return c, false
	}

	cfg, err := config.Load(d.path)
	if err != nil {
		d.loadErr = err
		d.step = 1
		return c, true
	}
	d.fileCfg = cfg

	running, fetchErr := ipc.ConfigGet()
	if fetchErr != nil {
		d.fetchErr = fetchErr
		d.step = 1
		return c, true
	}
	d.runningCfg = running

	d.computeDiff()
	d.step = 1
	return c, true
}

// computeDiff marshals both sides as pretty JSON, splits on
// newlines, and runs the LCS differ. Stored on the differ for the
// view to render without recomputing each frame.
func (d *differ) computeDiff() {
	if d.fileCfg == nil || d.runningCfg == nil {
		return
	}
	left := jsonLines(d.fileCfg)
	right := jsonLines(d.runningCfg)
	d.diff = diffLines(left, right)
	d.added, d.removed = diffCounts(d.diff)
}

// jsonLines marshals cfg as indented JSON and splits on newlines.
// Marshal failures fall back to a single-line "error: ..." entry
// so the diff still renders something useful instead of empty.
func jsonLines(cfg *config.Config) []string {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return []string{"error: " + err.Error()}
	}
	return strings.Split(string(data), "\n")
}

// configFetcher is the minimum surface the differ needs out of
// ipc.Client. Defining it here (instead of importing the concrete
// type) keeps the differ unit-testable with a stub fetcher and
// avoids a circular import down the line.
type configFetcher interface {
	ConfigGet() (*config.Config, error)
}
