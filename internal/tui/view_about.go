package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// aboutView shows the build provenance. It is intentionally static so
// it stays useful even when the daemon socket is unreachable.
func (a *App) aboutView() string {
	b := a.i18n
	theme := a.theme
	title := theme.Title.Render(b.S("about.title"))

	rows := [][2]string{
		{b.S("about.version"), a.build.Version},
		{b.S("about.commit"), a.build.Commit},
		{b.S("about.build"), a.build.BuildTime},
		{b.S("about.license"), "MIT"},
		{b.S("about.repo"), "https://github.com/pechenyeru/quiccochet"},
	}
	var lines []string
	for _, r := range rows {
		lines = append(lines, theme.Label.Render(r[0]+": ")+theme.Value.Render(r[1]))
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		"",
		strings.Join(lines, "\n"),
	)
}
