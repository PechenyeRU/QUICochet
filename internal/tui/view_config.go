package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// configView dispatches to one of the Config tab's sub-screens based
// on a.cfgCtx.state. The first-time visitor sees the menu; once they
// pick "New" the wizard takes over until they save or abort.
func (a *App) configView() string {
	if a.cfgCtx == nil {
		a.cfgCtx = &configCtx{state: configMenu}
	}
	switch a.cfgCtx.state {
	case configWizard:
		return a.configWizardView()
	case configEdit:
		return a.configEditView()
	case configSaving:
		return a.configSavingView()
	case configSaved:
		return a.configSavedView()
	default:
		return a.configMenuView()
	}
}

// configMenuView lists the Config tab actions. Stage 2.1 ships New;
// Open and Save-current arrive in 2.4 and become hotkey-active there.
func (a *App) configMenuView() string {
	b := a.i18n
	theme := a.theme

	title := theme.Title.Render(b.S("config.menu.title"))
	subtitle := theme.Subtitle.Render(b.S("config.menu.subtitle"))

	items := []struct {
		key     string
		label   string
		desc    string
		enabled bool
	}{
		{"n", b.S("config.menu.new"), b.S("config.menu.new.desc"), true},
		{"o", b.S("config.menu.open"), b.S("config.menu.open.desc"), true},
		{"d", b.S("config.menu.diff"), b.S("config.menu.diff.desc"), false},
	}
	var lines []string
	for _, it := range items {
		key := theme.Accent.Render("[" + it.key + "]")
		lbl := it.label
		if !it.enabled {
			lbl = theme.Muted.Render(lbl + " — " + b.S("stub.title"))
		} else {
			lbl = theme.Value.Render(lbl)
		}
		lines = append(lines, fmt.Sprintf("  %s  %s", key, lbl))
		if it.desc != "" {
			lines = append(lines, "      "+theme.Muted.Render(it.desc))
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		subtitle,
		"",
		strings.Join(lines, "\n"),
	)
}

// configWizardView frames the active huh form with a step indicator.
// The frame is repainted on every keystroke; huh's form does the
// actual field rendering inside.
func (a *App) configWizardView() string {
	w := a.cfgCtx.wizard
	b := a.i18n
	theme := a.theme

	step := fmt.Sprintf("%s %d / %d", b.S("config.wiz.step"), w.step+1, len(w.steps))
	header := theme.Subtitle.Render(step) + "   " + theme.Muted.Render(b.S("config.wiz.esc"))

	return lipgloss.JoinVertical(lipgloss.Left,
		theme.Title.Render(b.S("config.wiz.title")),
		header,
		"",
		w.form.View(),
	)
}

// configEditView frames the editor sub-app with a phase indicator
// (path prompt vs flat field form) and the active form.
func (a *App) configEditView() string {
	e := a.cfgCtx.editor
	b := a.i18n
	theme := a.theme

	var phase string
	if e.step == 0 {
		phase = b.S("config.edit.phase.path")
	} else {
		phase = b.S("config.edit.phase.fields") + " — " + e.path
	}
	header := theme.Subtitle.Render(phase) + "   " + theme.Muted.Render(b.S("config.wiz.esc"))

	return lipgloss.JoinVertical(lipgloss.Left,
		theme.Title.Render(b.S("config.edit.title")),
		header,
		"",
		e.form.View(),
	)
}

// configSavingView is shown for the brief moment between the operator
// confirming the save and the file write completing. In practice it
// flashes by; rendering it ensures the UI never freezes mid-state.
func (a *App) configSavingView() string {
	b := a.i18n
	theme := a.theme
	return lipgloss.JoinVertical(lipgloss.Left,
		theme.Title.Render(b.S("config.saving.title")),
		"",
		theme.Subtitle.Render(b.S("config.saving.body")),
	)
}

// configSavedView reports the outcome of a save. On success, it shows
// the absolute path written and a hint to relaunch the daemon. On
// validation/IO failure, it shows the error and offers to re-enter
// the wizard with the same working cfg preserved.
func (a *App) configSavedView() string {
	b := a.i18n
	theme := a.theme

	if a.cfgCtx.saveErr != nil {
		return lipgloss.JoinVertical(lipgloss.Left,
			theme.Title.Render(b.S("config.saved.fail.title")),
			"",
			theme.Error.Render(a.cfgCtx.saveErr.Error()),
			"",
			theme.Muted.Render(b.S("config.saved.fail.hint")),
		)
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		theme.Title.Render(b.S("config.saved.ok.title")),
		"",
		theme.Success.Render("✓ "+a.cfgCtx.savedPath),
		"",
		theme.Muted.Render(b.S("config.saved.ok.hint")),
	)
}

// configHandleKey routes input within the Config tab. Returns
// (handled, cmd): handled==true tells the App-level dispatcher to
// stop processing this key (i.e. don't apply tab navigation while a
// wizard form is consuming arrow keys). handled==false leaves the
// global dispatcher to do its thing.
func (a *App) configHandleKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if a.cfgCtx == nil {
		a.cfgCtx = &configCtx{state: configMenu}
	}
	switch a.cfgCtx.state {
	case configMenu:
		switch msg.String() {
		case "n":
			w, cmd := newWizard(a.i18n, a.bodyWidth(), a.formHeight())
			a.cfgCtx.wizard = w
			a.cfgCtx.state = configWizard
			return true, cmd
		case "o":
			ed, cmd := newEditor(a.i18n, a.bodyWidth(), a.formHeight())
			a.cfgCtx.editor = ed
			a.cfgCtx.state = configEdit
			return true, cmd
		}
		return false, nil

	case configWizard:
		// Esc bubbles out of the wizard back to the menu. Everything
		// else is forwarded to the active huh.Form, which handles
		// tab/shift-tab/arrows internally.
		if msg.String() == "esc" {
			a.cfgCtx.state = configMenu
			a.cfgCtx.wizard = nil
			return true, nil
		}
		done, cmd := a.cfgCtx.wizard.updateForm(msg, a.i18n)
		if a.cfgCtx.wizard.aborted {
			a.cfgCtx.state = configMenu
			a.cfgCtx.wizard = nil
			return true, cmd
		}
		if done {
			return true, a.beginSave()
		}
		return true, cmd

	case configEdit:
		if msg.String() == "esc" {
			a.cfgCtx.state = configMenu
			a.cfgCtx.editor = nil
			return true, nil
		}
		done, cmd := a.cfgCtx.editor.updateForm(msg, a.i18n)
		if a.cfgCtx.editor.loadErr != nil {
			// Surface load error through the same configSaved screen
			// the save flow uses — same affordance (any key returns
			// to the menu) so the operator's mental model is uniform.
			a.cfgCtx.saveErr = fmt.Errorf("load %s: %w", a.cfgCtx.editor.path, a.cfgCtx.editor.loadErr)
			a.cfgCtx.state = configSaved
			a.cfgCtx.editor = nil
			return true, cmd
		}
		if a.cfgCtx.editor.aborted {
			a.cfgCtx.state = configMenu
			a.cfgCtx.editor = nil
			return true, cmd
		}
		if done {
			return true, a.beginEditorSave()
		}
		return true, cmd

	case configSaved:
		// Any keypress returns to the menu — the operator's seen the
		// outcome and is ready to do something else.
		a.cfgCtx.state = configMenu
		a.cfgCtx.saveErr = nil
		a.cfgCtx.savedPath = ""
		return true, nil
	}
	return false, nil
}

// beginSave fires the file-write off the Bubble Tea loop. The result
// flips configSaving → configSaved with success or error populated.
func (a *App) beginSave() tea.Cmd {
	w := a.cfgCtx.wizard
	cfg := w.cfg
	path := w.savePath
	a.cfgCtx.state = configSaving
	a.cfgCtx.cfg = cfg
	a.cfgCtx.path = path
	return func() tea.Msg {
		err := saveConfig(cfg, path)
		return configSavedMsg{path: path, err: err}
	}
}

// beginEditorSave is the editor's equivalent of beginSave; same Cmd
// shape so the App.Update handler treats the result identically. The
// path is the file the operator originally opened — Edit always
// writes back over the source file.
func (a *App) beginEditorSave() tea.Cmd {
	e := a.cfgCtx.editor
	cfg := e.cfg
	path := e.path
	a.cfgCtx.state = configSaving
	a.cfgCtx.cfg = cfg
	a.cfgCtx.path = path
	return func() tea.Msg {
		err := saveConfig(cfg, path)
		return configSavedMsg{path: path, err: err}
	}
}

// configSavedMsg is the tea.Msg fired once the file write attempt
// completes. The App.Update handler maps it to configSaved state.
type configSavedMsg struct {
	path string
	err  error
}
