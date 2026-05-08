package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// spoofView renders the per-source-IP runtime state as a fixed-width
// table. Data comes straight from admin.Snapshot.SpoofIPs (already
// emitted by the daemon for transports that expose a SrcPool).
//
// Force-resurrect (R hotkey, all IPs in one shot) issues a
// `srcpool resurrect` admin command and surfaces the result in a
// banner above the table.
func (a *App) spoofView() string {
	b := a.i18n
	theme := a.theme

	if a.lastSnapshot == nil {
		return lipgloss.JoinVertical(lipgloss.Left,
			theme.Title.Render(b.S("spoof.title")),
			"",
			theme.Muted.Render(b.S("spoof.unavail")),
		)
	}
	ips := a.lastSnapshot.SpoofIPs
	if len(ips) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left,
			theme.Title.Render(b.S("spoof.title")),
			"",
			theme.Muted.Render(b.S("spoof.empty")),
		)
	}

	// Stable order: healthy first, then by death-streak descending so
	// the most-degraded IPs surface near the bottom for easy spotting.
	rows := append([]admin.SpoofIPStatus(nil), ips...)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Healthy != rows[j].Healthy {
			return rows[i].Healthy
		}
		return rows[i].DeathStreak < rows[j].DeathStreak
	})

	header := []string{"IP", "STATE", "STREAK", "COOLDOWN", "SENT", "LAST"}
	lines := []string{spoofRow(theme, header, true, false)}
	for _, r := range rows {
		lines = append(lines, spoofRow(theme, formatSpoofRow(r), false, !r.Healthy))
	}

	healthy := 0
	for _, r := range rows {
		if r.Healthy {
			healthy++
		}
	}
	summary := theme.Subtitle.Render(fmt.Sprintf(b.S("spoof.summary"), healthy, len(rows)))
	hint := theme.Muted.Render(b.S("spoof.hint"))

	parts := []string{theme.Title.Render(b.S("spoof.title")), summary}
	if a.spoofResurrectMsg != "" {
		parts = append(parts, a.spoofResurrectStyle(theme))
	}
	parts = append(parts, "", strings.Join(lines, "\n"), "", hint)
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// spoofHandleKey routes Spoof-tab specific keys. Currently the
// only binding is `R` → force-resurrect every cooldown via admin.
// Returns handled=true so the global digit-tab dispatcher doesn't
// also consume the key.
func (a *App) spoofHandleKey(s string) bool {
	switch s {
	case "R":
		res, err := a.ipc.SrcpoolResurrect("")
		if err != nil {
			a.spoofResurrectMsg = "✗ " + err.Error()
			a.spoofResurrectErr = true
		} else {
			a.spoofResurrectMsg = fmt.Sprintf("✓ resurrected %d entries", res.Resurrected)
			a.spoofResurrectErr = false
		}
		a.spoofResurrectAt = time.Now()
		return true
	}
	return false
}

// spoofResurrectStyle picks the colour for the resurrect-result
// banner: success green or warn yellow. The banner stays sticky
// (no auto-dismiss) so an operator who hits R and switches tabs
// still sees the outcome on return.
func (a *App) spoofResurrectStyle(theme *Theme) string {
	if a.spoofResurrectErr {
		return theme.Warn.Render(a.spoofResurrectMsg)
	}
	return theme.Success.Render(a.spoofResurrectMsg)
}

// formatSpoofRow turns one SrcPool entry into the six column strings
// the view shows. Cooldown displays as "—" when there is none active
// so the table doesn't read as a wall of zeros.
func formatSpoofRow(r admin.SpoofIPStatus) []string {
	state := "ok"
	if !r.Healthy {
		state = "dead"
	}
	cooldown := "—"
	if r.CooldownLeftS > 0 {
		cooldown = (time.Duration(r.CooldownLeftS) * time.Second).String()
		if r.CooldownLevel > 0 {
			cooldown = fmt.Sprintf("%s (lvl %d)", cooldown, r.CooldownLevel)
		}
	}
	last := "—"
	if r.LastSentAgoS > 0 {
		last = (time.Duration(r.LastSentAgoS) * time.Second).String() + " ago"
	}
	return []string{
		r.IP,
		state,
		fmt.Sprintf("%d", r.DeathStreak),
		cooldown,
		fmt.Sprintf("%d", r.SentCount),
		last,
	}
}

// spoofRow renders one logical row to a single styled line. The
// header gets the panel-title style, dead rows get the warn colour,
// healthy rows the muted value style. Column widths are fixed so
// the table aligns regardless of locale.
func spoofRow(theme *Theme, cols []string, header, dead bool) string {
	widths := []int{18, 6, 6, 14, 10, 12}
	parts := make([]string, len(cols))
	for i, c := range cols {
		w := widths[i]
		if i >= len(widths) {
			w = 12
		}
		parts[i] = padOrTrunc(c, w)
	}
	line := strings.Join(parts, "  ")
	switch {
	case header:
		return theme.PanelTitle.Render(line)
	case dead:
		return theme.Warn.Render(line)
	default:
		return theme.Value.Render(line)
	}
}

// padOrTrunc right-pads s with spaces to width w, or trims it (with
// a trailing "…") if it overflows. Used by the table renderer to
// keep columns aligned even on long IPv6 strings.
func padOrTrunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if len(s) > w {
		if w >= 2 {
			return s[:w-1] + "…"
		}
		return s[:w]
	}
	return s + strings.Repeat(" ", w-len(s))
}
