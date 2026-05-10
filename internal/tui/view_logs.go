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
	filePath   string
	resolved   bool // path resolved from config.Load at least once
	resolveErr error

	entries []logEntry
	readErr error
	readAt  time.Time

	filter     string // "" / DEBUG / INFO / WARN / ERROR / RAW
	peerFilter string // "" = no peer filter (server role only)
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

	// Peer filter is server-only; on client logs the field is always
	// empty so showing the filter would be operator-confusing. The
	// guard keys off the live snapshot's role rather than re-parsing
	// the config (snapshot is authoritative for the running daemon).
	isServer := a.lastSnapshot != nil && a.lastSnapshot.Role == "server"
	if isServer {
		header += "   " +
			theme.Subtitle.Render(b.S("logs.peer")+": ") +
			theme.Accent.Render(peerFilterLabel(lc.peerFilter, b.S("logs.peer.all")))
	}

	if lc.readErr != nil {
		return lipgloss.JoinVertical(lipgloss.Left,
			title,
			header,
			"",
			theme.Error.Render(b.S("logs.read.fail", lc.readErr.Error())),
		)
	}

	rows := filterByLevel(lc.entries, lc.filter)
	if isServer {
		rows = filterByPeer(rows, lc.peerFilter)
	}
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
	maxRows := max(a.bodyHeight()-3, 1)
	if len(rows) > maxRows {
		rows = rows[len(rows)-maxRows:]
	}

	lines := make([]string, 0, len(rows))
	for _, e := range rows {
		lines = append(lines, formatLogLine(theme, e))
	}

	sections := []string{title, header}
	if isServer {
		sections = append(sections, theme.Muted.Render(b.S("logs.peer.hint")))
	}
	sections = append(sections, "", strings.Join(lines, "\n"))
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
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
// no observable effect (filter is idempotent). p cycles through
// peer names seen in the current tail (or in the live snapshot if
// available); P clears the peer filter. The peer keys are accepted
// regardless of role — on client they simply never match anything.
// Returns handled = true so the global digit-tab dispatcher doesn't
// claim the key.
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
	case "p":
		lc.peerFilter = a.cyclePeerFilter(lc.peerFilter)
	case "P":
		lc.peerFilter = ""
	default:
		return false
	}
	return true
}

// cyclePeerFilter advances the active peer filter to the next
// known peer name. The candidate set is the live snapshot's
// configured peers if present, falling back to peers actually
// observed in the current log tail. "" maps to the first
// candidate; the last candidate wraps back to "".
func (a *App) cyclePeerFilter(cur string) string {
	candidates := a.knownPeerNames()
	if len(candidates) == 0 {
		return ""
	}
	if cur == "" {
		return candidates[0]
	}
	for i, name := range candidates {
		if name == cur {
			if i+1 >= len(candidates) {
				return ""
			}
			return candidates[i+1]
		}
	}
	// Current filter no longer in the candidate set (peer removed
	// from config / observation window slid past it) — restart from
	// the top so the operator isn't stuck on a stale name.
	return candidates[0]
}

// knownPeerNames returns the union of configured peers (from the
// live snapshot) and peers observed in the current log tail,
// alphabetically sorted. The snapshot is preferred because it
// includes peers that have not yet logged anything (so the cycle
// surfaces them too).
func (a *App) knownPeerNames() []string {
	seen := make(map[string]struct{})
	if a.lastSnapshot != nil {
		for _, p := range a.lastSnapshot.Peers {
			if p.Name != "" {
				seen[p.Name] = struct{}{}
			}
		}
	}
	if a.logsState != nil {
		for _, n := range observedPeers(a.logsState.entries) {
			seen[n] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// peerFilterLabel renders the active peer filter for the header,
// using the localized "all" placeholder when no filter is set.
func peerFilterLabel(cur, allLabel string) string {
	if cur == "" {
		return allLabel
	}
	return cur
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
