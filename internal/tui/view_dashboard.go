package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// dashboardView renders the live snapshot. When no snapshot is
// available it shows the "configure --socket" hint instead of empty
// metric panels — empty zeros would imply a healthy idle daemon.
func (a *App) dashboardView() string {
	b := a.i18n
	theme := a.theme

	title := theme.Title.Render(b.S("dashboard.title"))

	if a.lastSnapshot == nil {
		var msg string
		if a.lastReachErr != nil {
			msg = b.S("err.cannot_connect", a.ipc.SocketPath(), a.lastReachErr.Error())
		} else {
			msg = b.S("dashboard.unavail")
		}
		return lipgloss.JoinVertical(lipgloss.Left,
			title,
			"",
			theme.Warn.Render(msg),
		)
	}

	s := a.lastSnapshot
	role := s.Role
	if loc := b.S("status.role." + role); loc != "status.role."+role {
		role = loc
	}
	header := theme.Subtitle.Render(b.S("dashboard.role")+": ") + theme.Value.Render(role)

	live := a.dashLiveBlock(s)
	left := a.dashLeftBlock(s)
	right := a.dashRightBlock(s)
	side := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)

	last := theme.Muted.Render(b.S("dashboard.refresh.last") + ": " + a.lastPollAt.Format(time.RFC3339))

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		header,
		"",
		live,
		"",
		side,
		"",
		last,
	)
}

// dashLiveBlock renders the btop-style live panel: connection
// state badge, three sparklines (sent / recv / loss) with their
// most-recent value and peak. The sparkline width adapts to the
// terminal width minus the label and trailing-value columns so the
// graph occupies all available space. Empty until the second
// successful poll: the first poll only seeds the cumulative
// counters; rates need a delta from the second sample.
func (a *App) dashLiveBlock(s *admin.Snapshot) string {
	b := a.i18n
	theme := a.theme

	state := connDown
	if a.lastReachErr == nil {
		series := a.series
		if series != nil {
			_, _, lossPct := series.rates()
			state = classify(series.last(), lossPct)
		}
	}
	badge := dashStateBadge(theme, b, state)

	statusLine := badge + "   " +
		theme.Subtitle.Render(b.S("dashboard.pool")+": ") +
		theme.Value.Render(fmt.Sprintf("%d/%d", s.PoolAlive, s.PoolTotal)) + "   " +
		theme.Subtitle.Render(b.S("dashboard.up")+": ") +
		theme.Value.Render(humanUptime(s.UptimeSec))

	if a.series == nil || len(a.series.samples) < 2 {
		hint := theme.Muted.Render(b.S("dashboard.live.warmup"))
		return theme.Panel.Render(lipgloss.JoinVertical(lipgloss.Left,
			theme.PanelTitle.Render(b.S("dashboard.live.title")),
			"",
			statusLine,
			"",
			hint,
		))
	}

	sentBps, recvBps, lossPct := a.series.rates()
	sparkW := a.dashSparkWidth()

	sentLine := dashSparkLine(theme,
		"↑ "+b.S("dashboard.bytes.sent"),
		sparkline(sentBps, sparkW),
		rateLabel(lastNonzero(sentBps)),
		rateLabel(maxOf(sentBps)))
	recvLine := dashSparkLine(theme,
		"↓ "+b.S("dashboard.bytes.recv"),
		sparkline(recvBps, sparkW),
		rateLabel(lastNonzero(recvBps)),
		rateLabel(maxOf(recvBps)))
	lossLine := dashSparkLine(theme,
		"× "+b.S("dashboard.loss"),
		sparkline(lossPct, sparkW),
		fmt.Sprintf("%6.2f %%   ", lastValue(lossPct)),
		fmt.Sprintf("%6.2f %%/s", maxOf(lossPct)))

	return theme.Panel.Render(lipgloss.JoinVertical(lipgloss.Left,
		theme.PanelTitle.Render(b.S("dashboard.live.title")),
		"",
		statusLine,
		"",
		sentLine,
		recvLine,
		lossLine,
	))
}

// dashSparkWidth budgets the cells available for the sparkline glyphs
// after subtracting the fixed label column (~14) and the two trailing
// value columns (~14 each). Floors at 16 so a narrow terminal still
// shows something rather than an empty row.
func (a *App) dashSparkWidth() int {
	const (
		labelW = 14
		valueW = 14
		gap    = 4
	)
	w := a.bodyWidth() - labelW - valueW*2 - gap
	if w < 16 {
		return 16
	}
	if w > 80 {
		return 80
	}
	return w
}

// dashSparkLine assembles one sparkline row: label | bars | last |
// peak. Columns are right-padded to fixed widths so the four pieces
// align across the three rows even though the labels (sent / recv /
// loss) have different lengths.
func dashSparkLine(theme *Theme, label, bars, last, peak string) string {
	const labelW = 14
	if w := lipgloss.Width(label); w < labelW {
		label += strings.Repeat(" ", labelW-w)
	}
	return theme.Label.Render(label) +
		theme.Accent.Render(bars) +
		"  " + theme.Value.Render(last) +
		"   " + theme.Muted.Render("peak "+peak)
}

// dashStateBadge maps a connState to a coloured tag the operator
// can spot at a glance: green ✓ healthy, yellow ⚠ degraded, red ✗
// down. Rendered as a single styled token rather than a Lipgloss
// border so it composes cleanly inside the status line.
func dashStateBadge(theme *Theme, b *Bundle, c connState) string {
	switch c {
	case connHealthy:
		return theme.Success.Render("✓ " + b.S("dashboard.state.healthy"))
	case connDegraded:
		return theme.Warn.Render("⚠ " + b.S("dashboard.state.degraded"))
	default:
		return theme.Error.Render("✗ " + b.S("dashboard.state.down"))
	}
}

// lastNonzero returns the rightmost non-zero entry of xs (or 0 if
// every entry is zero or the slice is empty). Used by the live
// block so the trailing value reads as the most recent meaningful
// sample even during a brief idle period at the end of the window.
func lastNonzero(xs []float64) float64 {
	for i := len(xs) - 1; i >= 0; i-- {
		if xs[i] != 0 {
			return xs[i]
		}
	}
	return 0
}

func lastValue(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	return xs[len(xs)-1]
}

func maxOf(xs []float64) float64 {
	m := 0.0
	for _, v := range xs {
		if v > m {
			m = v
		}
	}
	return m
}

// dashLeftBlock packs the role-agnostic and client-only metrics. The
// label column is sized so the values align across rows even when the
// terminal switches font widths between Latin and Persian glyphs.
func (a *App) dashLeftBlock(s *admin.Snapshot) string {
	b := a.i18n
	theme := a.theme

	rows := [][2]string{
		{b.S("dashboard.bytes.sent"), humanBytes(s.BytesSent)},
		{b.S("dashboard.bytes.recv"), humanBytes(s.BytesReceived)},
		{b.S("dashboard.fds"), fmt.Sprintf("%d", s.OpenFDs)},
		{b.S("dashboard.up"), humanUptime(s.UptimeSec)},
	}
	if s.Role == "client" {
		rows = append([][2]string{
			{b.S("dashboard.pool"), fmt.Sprintf("%d / %d", s.PoolAlive, s.PoolTotal)},
			{b.S("dashboard.udp.assocs"), fmt.Sprintf("%d", s.UDPAssocs)},
			{b.S("dashboard.loss"), humanLoss(s.PacketsLost, s.PacketsSent)},
		}, rows...)
	}
	if s.Role == "server" {
		rows = append([][2]string{
			{b.S("dashboard.sessions"), fmt.Sprintf("%d", s.ActiveSessions)},
			{b.S("dashboard.udp.routes"), fmt.Sprintf("%d", s.UDPRoutes)},
		}, rows...)
	}
	return theme.Panel.Render(formatKV(theme, rows))
}

// dashRightBlock surfaces the spoof-IP health-check digest. When the
// transport doesn't expose a SrcPool (server role today, or non-spoof
// transports) the panel shows a single muted line so the layout stays
// stable.
func (a *App) dashRightBlock(s *admin.Snapshot) string {
	b := a.i18n
	theme := a.theme

	title := theme.PanelTitle.Render(b.S("dashboard.spoof.healthy"))
	if len(s.SpoofIPs) == 0 {
		return theme.Panel.Render(title + "\n" + theme.Muted.Render("—"))
	}

	healthy := 0
	for _, ip := range s.SpoofIPs {
		if ip.Healthy {
			healthy++
		}
	}
	summary := fmt.Sprintf("%d / %d", healthy, len(s.SpoofIPs))
	rows := [][2]string{{b.S("dashboard.spoof.healthy"), summary}}
	for _, ip := range s.SpoofIPs {
		val := theme.Success.Render("✓")
		if !ip.Healthy {
			val = theme.Error.Render(fmt.Sprintf("✗ %.0fs", ip.CooldownLeftS))
		}
		rows = append(rows, [2]string{ip.IP, val})
	}
	return theme.Panel.Render(title + "\n" + formatKV(theme, rows))
}

// formatKV right-pads labels so values align inside a panel. The
// padding length is recomputed per call rather than hard-coded so
// translated labels (longer in Farsi) still line up.
func formatKV(theme *Theme, rows [][2]string) string {
	maxLbl := 0
	for _, r := range rows {
		if w := lipgloss.Width(r[0]); w > maxLbl {
			maxLbl = w
		}
	}
	var lines []string
	for _, r := range rows {
		pad := max(maxLbl-lipgloss.Width(r[0]), 0)
		lines = append(lines,
			theme.Label.Render(r[0])+
				strings.Repeat(" ", pad)+
				"  "+
				theme.Value.Render(r[1]))
	}
	return strings.Join(lines, "\n")
}

func humanBytes(n uint64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
		TB = 1 << 40
	)
	switch {
	case n >= TB:
		return fmt.Sprintf("%.2f TiB", float64(n)/float64(TB))
	case n >= GB:
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.2f MiB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.2f KiB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func humanUptime(sec float64) string {
	switch {
	case sec < 60:
		return fmt.Sprintf("%.0fs", sec)
	case sec < 3600:
		return fmt.Sprintf("%.0fm", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%.1fh", sec/3600)
	default:
		return fmt.Sprintf("%.1fd", sec/86400)
	}
}

// humanLoss matches the format used by `quiccochet admin stats -H` so
// operators see the same number across the CLI and the TUI.
func humanLoss(lost, sent uint64) string {
	if sent == 0 {
		return fmt.Sprintf("%d/0", lost)
	}
	pct := float64(lost) * 100 / float64(sent)
	switch {
	case pct == 0:
		return fmt.Sprintf("%d/%d (0%%)", lost, sent)
	case pct < 0.1:
		return fmt.Sprintf("%d/%d (%.3f%%)", lost, sent, pct)
	case pct < 1:
		return fmt.Sprintf("%d/%d (%.2f%%)", lost, sent, pct)
	default:
		return fmt.Sprintf("%d/%d (%.1f%%)", lost, sent, pct)
	}
}
