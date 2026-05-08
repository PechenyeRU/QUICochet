package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// renderStatusBar produces the bottom row: daemon health on the left,
// hotkey legend on the right. The bar always spans the full terminal
// width so background colours fill edge-to-edge — the OS terminal's
// background-erase behaviour otherwise leaves visual seams between
// styled spans.
func renderStatusBar(theme *Theme, b *Bundle, daemonAlive bool, width int) string {
	left := theme.StatusBarWarn.Render(b.S("status.daemon.dead"))
	if daemonAlive {
		left = theme.StatusBarOK.Render(b.S("status.daemon.alive"))
	}

	keys := []string{
		theme.StatusBarKey.Render(b.S("key.tabs")),
		theme.StatusBarKey.Render(b.S("key.refresh")),
		theme.StatusBarKey.Render(b.S("key.help")),
		theme.StatusBarKey.Render(b.S("key.quit")),
	}
	right := strings.Join(keys, theme.StatusBar.Render("  "))

	leftW := lipgloss.Width(left)
	rightW := lipgloss.Width(right)
	pad := width - leftW - rightW
	if pad < 1 {
		return theme.StatusBar.Render(left + " " + right)
	}
	return theme.StatusBar.Render(left) +
		theme.StatusBar.Render(strings.Repeat(" ", pad)) +
		right
}

func max0(x int) int {
	if x < 0 {
		return 0
	}
	return x
}
