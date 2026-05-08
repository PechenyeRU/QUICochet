package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// tailWindow is how many bytes off the tail of the log file the
// Logs tab reads on each refresh. ~64 KB covers a few hundred
// lines on the daemon's typical message density without making
// the tab pay a multi-MB read on every poll cycle.
const tailWindow int64 = 64 * 1024

// logsCtx is the per-session state for the Logs tab. Allocated
// lazily on first visit. The level filter persists across tab
// switches so an operator who hits 'e' to focus errors stays
// filtered when they leave and come back.
type logsCtx struct {
	filePath  string
	resolved  bool // path resolved from config.Load at least once
	resolveErr error

	entries []logEntry
	readErr error
	readAt  time.Time

	filter string // "" / DEBUG / INFO / WARN / ERROR / RAW
}

// logsView renders the tail of logging.file with the active level
// filter applied. The header lists the file path + filter state
// so it's obvious what window the operator is looking at.
func (a *App) logsView() string {
	b := a.i18n
	theme := a.theme

	if a.logsState == nil {
		a.logsState = &logsCtx{}
	}
	lc := a.logsState
	a.ensureLogsResolved(lc)

	title := theme.Title.Render(b.S("logs.title"))

	if !lc.resolved || lc.filePath == "" {
		hint := lc.resolveErr
		msg := b.S("logs.unconfigured")
		if hint != nil {
			msg = b.S("logs.config.fail", hint.Error())
		}
		return lipgloss.JoinVertical(lipgloss.Left,
			title,
			"",
			theme.Warn.Render(msg),
		)
	}

	header := theme.Subtitle.Render(b.S("logs.file")+": ") +
		theme.Value.Render(lc.filePath) + "   " +
		theme.Subtitle.Render(b.S("logs.filter")+": ") +
		theme.Accent.Render(filterLabel(lc.filter))

	if lc.readErr != nil {
		return lipgloss.JoinVertical(lipgloss.Left,
			title,
			header,
			"",
			theme.Error.Render(b.S("logs.read.fail", lc.readErr.Error())),
		)
	}

	rows := filterByLevel(lc.entries, lc.filter)
	if len(rows) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left,
			title,
			header,
			"",
			theme.Muted.Render(b.S("logs.empty")),
		)
	}

	// Show only the last bodyHeight()-3 rows so the tail stays
	// pinned to the bottom of the visible area, mirroring `tail
	// -f` behaviour. The 3-line subtraction accounts for title +
	// header + blank line composed above.
	maxRows := a.bodyHeight() - 3
	if maxRows < 1 {
		maxRows = 1
	}
	if len(rows) > maxRows {
		rows = rows[len(rows)-maxRows:]
	}

	lines := make([]string, 0, len(rows))
	for _, e := range rows {
		lines = append(lines, formatLogLine(theme, e))
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		header,
		"",
		strings.Join(lines, "\n"),
	)
}

// ensureLogsResolved loads the active config (when needed) and
// extracts logging.file. Cached after the first successful resolve
// so we don't hit disk on every tick. The operator can re-trigger
// resolution by toggling the tab off and on if they edit the
// config out-of-band.
func (a *App) ensureLogsResolved(lc *logsCtx) {
	if lc.resolved {
		return
	}
	lc.resolved = true
	if a.configPath == "" {
		return
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		lc.resolveErr = err
		return
	}
	lc.filePath = cfg.Logging.File
}

// refreshLogs re-reads the tail window. Called from the tick
// handler when the Logs tab is active. Errors stay on the ctx so
// the view can render them; reads that succeed but find no new
// content are silent.
func (a *App) refreshLogs() {
	if a.logsState == nil {
		return
	}
	lc := a.logsState
	a.ensureLogsResolved(lc)
	if lc.filePath == "" {
		return
	}
	entries, err := tailLog(lc.filePath, tailWindow)
	lc.entries = entries
	lc.readErr = err
	lc.readAt = time.Now()
}

// logsHandleKey routes Logs-tab specific filter keys. d / i / w /
// e / r / a select level filters; pressing the same key twice has
// no observable effect (filter is idempotent). Returns handled =
// true so the global digit-tab dispatcher doesn't claim the key.
func (a *App) logsHandleKey(s string) bool {
	if a.logsState == nil {
		a.logsState = &logsCtx{}
	}
	lc := a.logsState
	switch s {
	case "a":
		lc.filter = ""
	case "d":
		lc.filter = "DEBUG"
	case "i":
		lc.filter = "INFO"
	case "w":
		lc.filter = "WARN"
	case "e":
		lc.filter = "ERROR"
	default:
		return false
	}
	return true
}

// formatLogLine renders one entry as "HH:MM:SS LEVEL message" with
// the level coloured by severity so the operator's eye finds the
// errors fast. The message column is intentionally not truncated
// — the bodyBox clip in App.View will cut overflow if a single
// line wraps, so a long stack trace stays grep-able.
func formatLogLine(theme *Theme, e logEntry) string {
	ts := ""
	if !e.Time.IsZero() {
		ts = e.Time.Local().Format("15:04:05")
	}
	level := e.Level
	if level == "" {
		level = "RAW"
	}
	level = padOrTrunc(level, 5)

	var styledLevel string
	switch e.Level {
	case "DEBUG":
		styledLevel = theme.Muted.Render(level)
	case "INFO":
		styledLevel = theme.Value.Render(level)
	case "WARN":
		styledLevel = theme.Warn.Render(level)
	case "ERROR":
		styledLevel = theme.Error.Render(level)
	default:
		styledLevel = theme.Muted.Render(level)
	}
	return fmt.Sprintf("%s %s  %s", theme.Subtitle.Render(ts), styledLevel, e.Msg)
}

func filterLabel(f string) string {
	if f == "" {
		return "all"
	}
	return strings.ToLower(f)
}
