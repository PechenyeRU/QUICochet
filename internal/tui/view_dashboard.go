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

	left := a.dashLeftBlock(s)
	right := a.dashRightBlock(s)
	side := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)

	last := theme.Muted.Render(b.S("dashboard.refresh.last") + ": " + a.lastPollAt.Format(time.RFC3339))

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		header,
		"",
		side,
		"",
		last,
	)
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
