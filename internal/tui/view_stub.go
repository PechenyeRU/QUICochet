package tui

import "charm.land/lipgloss/v2"

// stubView is the placeholder rendered for tabs whose implementation
// is queued for later TUI stages. Showing a known "coming soon" panel
// is more honest than hiding the tab entirely — the operator sees the
// product roadmap baked into the navigation.
func (a *App) stubView(t TabID) string {
	b := a.i18n
	theme := a.theme

	title := theme.Title.Render(b.S(t.titleKey()))
	subtitle := theme.Warn.Render(b.S("stub.title"))
	body := theme.Subtitle.Render(b.S("stub.body"))
	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		"",
		subtitle,
		body,
	)
}
