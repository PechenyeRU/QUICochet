package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// homeView renders the landing tab: daemon status, config pointer,
// and a list of jump-to-tab actions. The action list doesn't accept
// input yet — Stage 1 is read-only — but is displayed so the operator
// learns the available navigation up front.
func (a *App) homeView() string {
	b := a.i18n
	theme := a.theme

	daemon := a.daemonStatusBlock()
	cfg := a.configBlock()
	actions := a.actionsBlock()

	header := theme.Title.Render(b.S("app.title")) + "  " + theme.Subtitle.Render(b.S("app.subtitle"))
	body := lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		daemon,
		"",
		cfg,
		"",
		actions,
	)
	return body
}

func (a *App) daemonStatusBlock() string {
	b := a.i18n
	theme := a.theme

	title := theme.PanelTitle.Render(b.S("home.daemon.title"))

	sock := a.ipc.SocketPath()
	var lines []string
	if sock == "" {
		lines = append(lines,
			theme.Label.Render(b.S("home.daemon.socket")+": ")+
				theme.Warn.Render(b.S("home.daemon.unset")))
	} else {
		statusVal := theme.Success.Render(b.S("status.daemon.alive"))
		if a.lastReachErr != nil {
			statusVal = theme.Error.Render(b.S("home.daemon.unreach") + ": " + a.lastReachErr.Error())
		}
		lines = append(lines,
			theme.Label.Render(b.S("home.daemon.socket")+": ")+theme.Value.Render(sock),
			statusVal,
		)
	}
	return theme.Panel.Render(title + "\n" + strings.Join(lines, "\n"))
}

func (a *App) configBlock() string {
	b := a.i18n
	theme := a.theme
	title := theme.PanelTitle.Render(b.S("home.config.title"))
	path := a.configPath
	if path == "" {
		path = "—"
	}
	role := "—"
	if a.lastSnapshot != nil && a.lastSnapshot.Role != "" {
		role = b.S("status.role." + a.lastSnapshot.Role)
		if role == "status.role."+a.lastSnapshot.Role {
			role = a.lastSnapshot.Role
		}
	}
	body := strings.Join([]string{
		theme.Label.Render(b.S("home.config.path")+": ") + theme.Value.Render(path),
		theme.Label.Render(b.S("home.config.role")+": ") + theme.Value.Render(role),
	}, "\n")
	return theme.Panel.Render(title + "\n" + body)
}

func (a *App) actionsBlock() string {
	b := a.i18n
	theme := a.theme
	title := theme.PanelTitle.Render(b.S("home.actions.title"))
	items := []string{
		"  " + theme.Accent.Render("2") + "  " + b.S("home.actions.config"),
		"  " + theme.Accent.Render("3") + "  " + b.S("home.actions.dash"),
		"  " + theme.Accent.Render("5") + "  " + b.S("home.actions.bench"),
		"  " + theme.Accent.Render("7") + "  " + b.S("home.actions.tools"),
	}
	return theme.Panel.Render(title + "\n" + strings.Join(items, "\n"))
}
