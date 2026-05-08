package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// renderTabBar produces a single-line tab strip with the active tab
// highlighted. Each tab is rendered through a lipgloss style and the
// row is composed via lipgloss.JoinHorizontal — the same pattern as
// the upstream charmbracelet/bubbletea tabs example.
//
// We do NOT use lipgloss.Style.Padding combined with Background:
// when those are layered on a styled run, lipgloss expands the
// background to the padding cells, and Bubble Tea v2's diff renderer
// has trouble erasing those cells when the active tab moves — they
// stick around as ghost-highlight residue at tab boundaries. The
// inner string carries its own leading/trailing space instead, and
// the active style only flips Foreground + Bold so a single SGR pair
// covers the whole label without padding cells in play.
//
// Bidi isolate marks (LRI/RLI/PDI) are also avoided. They're zero-
// width per Unicode but libvte renders them as visible glyphs, which
// surfaced as a small block at the start of every tab.
func renderTabBar(theme *Theme, b *Bundle, active TabID, width int) string {
	parts := make([]string, 0, len(AllTabs))
	for i, t := range AllTabs {
		inner := " " + numberPrefix(i+1) + " " + b.S(t.titleKey()) + " "
		if t == active {
			parts = append(parts, theme.TabActive.Render(inner))
		} else {
			parts = append(parts, theme.TabInactive.Render(inner))
		}
	}
	div := theme.TabDivider.Render("│")
	bar := parts[0]
	for _, p := range parts[1:] {
		bar = lipgloss.JoinHorizontal(lipgloss.Top, bar, div, p)
	}
	if width > 0 {
		barW := lipgloss.Width(bar)
		if barW < width {
			bar += strings.Repeat(" ", width-barW)
		}
	}
	return bar
}

// numberPrefix returns "1".."9" for indices 1-9 and a single space
// beyond. Tabs past the ninth are still navigable via arrow keys.
func numberPrefix(i int) string {
	if i < 1 || i > 9 {
		return " "
	}
	return string(rune('0' + i))
}
