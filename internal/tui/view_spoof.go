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
// emitted by the daemon for transports that expose a SrcPool), so
// this view is read-only and needs no admin protocol enrichment.
//
// Stage 3.1 ships read-only. Stage 3.5 (admin enrichment) will add
// the `R` resurrect hotkey.
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

	return lipgloss.JoinVertical(lipgloss.Left,
		theme.Title.Render(b.S("spoof.title")),
		summary,
		"",
		strings.Join(lines, "\n"),
	)
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
