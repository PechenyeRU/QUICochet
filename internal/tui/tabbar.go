package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// renderTabBar produces a single-line tab strip with the active tab
// highlighted. The strip width is capped at the terminal width; longer
// labels overflow rather than truncating, since AllTabs is a known
// closed set and the labels are short by design.
//
// In Farsi, each tab label combines a Latin digit (weak directionality)
// with Persian text (strong RTL). Without help, the Unicode bidi
// algorithm reorders the whole bar — the "1" digit floats to the
// visual left edge while "8" lands at the right, swapping the navigation
// order the operator just learned. We isolate every tab in an LRI…PDI
// pair (U+2066…U+2069) so each one renders LTR-internal, and the bar
// itself preserves digit-1-first-on-the-left layout regardless of the
// terminal's base direction.
func renderTabBar(theme *Theme, b *Bundle, active TabID, width int) string {
	const (
		lri = "⁦" // Left-to-Right Isolate
		pdi = "⁩" // Pop Directional Isolate
	)
	parts := make([]string, 0, len(AllTabs)*2)
	for i, t := range AllTabs {
		label := b.S(t.titleKey())
		// Prefix with the digit shortcut so the operator can read off
		// "1 Home, 2 Config, …" without consulting help.
		inner := lri + numberPrefix(i+1) + " " + label + pdi
		if t == active {
			parts = append(parts, theme.TabActive.Render(inner))
		} else {
			parts = append(parts, theme.TabInactive.Render(inner))
		}
	}
	// Wrap the whole bar in another LRI…PDI so a terminal whose base
	// direction is RTL (operator's locale, tmux-bidi etc.) still places
	// tab 1 on the visual left and tab 8 on the right.
	bar := lri + strings.Join(parts, theme.TabDivider.Render("│")) + pdi
	if width > 0 {
		// Force the bar to span the full width with a trailing rule so
		// the terminal background colour fills the line evenly.
		barW := lipgloss.Width(bar)
		if barW < width {
			bar += strings.Repeat(" ", width-barW)
		}
	}
	return bar
}

// numberPrefix returns "1".."9" for indices 1-9 and an empty string
// beyond that. Tabs past the ninth are still navigable via arrow keys.
func numberPrefix(i int) string {
	if i < 1 || i > 9 {
		return " "
	}
	return string(rune('0' + i))
}
