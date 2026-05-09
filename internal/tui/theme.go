package tui

import (
	"os"

	"charm.land/lipgloss/v2"
)

// Theme bundles the lipgloss styles the views compose with. Keeping
// them on a single struct lets the App pass one value down instead of
// scattering style globals across files, and makes a future
// dark/light/no-color switch a one-line change.
type Theme struct {
	NoColor bool

	// Borders and panels.
	Panel      lipgloss.Style
	PanelTitle lipgloss.Style
	PanelMuted lipgloss.Style

	// Tab bar.
	TabActive   lipgloss.Style
	TabInactive lipgloss.Style
	TabDivider  lipgloss.Style

	// Status bar.
	StatusBar     lipgloss.Style
	StatusBarOK   lipgloss.Style
	StatusBarWarn lipgloss.Style
	StatusBarKey  lipgloss.Style
	StatusBarItem lipgloss.Style

	// Generic content.
	Title    lipgloss.Style
	Subtitle lipgloss.Style
	Label    lipgloss.Style
	Value    lipgloss.Style
	Accent   lipgloss.Style
	Success  lipgloss.Style
	Warn     lipgloss.Style
	Error    lipgloss.Style
	Muted    lipgloss.Style
}

// NewTheme builds the default theme. When NO_COLOR is set in the
// environment (https://no-color.org) every style collapses to plain
// text; this respects the user's accessibility preference and lets
// vhs tapes record clean output on demand.
func NewTheme() *Theme {
	noColor := os.Getenv("NO_COLOR") != ""
	t := &Theme{NoColor: noColor}
	if noColor {
		// Plain styles still need defined zero values so callers don't
		// crash on a nil receiver in lipgloss.
		t.fillNoColor()
		return t
	}
	t.fillColor()
	return t
}

func (t *Theme) fillColor() {
	border := lipgloss.RoundedBorder()
	t.Panel = lipgloss.NewStyle().
		Border(border).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 1)
	t.PanelTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("63")).
		Bold(true)
	t.PanelMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	// Active tab: bold + bright foreground. Deliberately NO Background
	// and NO Padding — the Padding(0,1)+Background combo paints the
	// padding cells with the bg colour and Bubble Tea v2's diff
	// renderer leaves ghost-highlight cells at tab boundaries when
	// the active tab moves. The leading/trailing space inside each
	// tab is added in renderTabBar's inner string instead of via
	// lipgloss.Padding.
	t.TabActive = lipgloss.NewStyle().
		Foreground(lipgloss.Color("63")).
		Bold(true)
	t.TabInactive = lipgloss.NewStyle().
		Foreground(lipgloss.Color("245"))
	t.TabDivider = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	t.StatusBar = lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Foreground(lipgloss.Color("250"))
	t.StatusBarOK = lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Foreground(lipgloss.Color("42")).Bold(true)
	t.StatusBarWarn = lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Foreground(lipgloss.Color("214")).Bold(true)
	t.StatusBarKey = lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Foreground(lipgloss.Color("63")).Bold(true)
	t.StatusBarItem = lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Foreground(lipgloss.Color("250"))

	t.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	t.Subtitle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	t.Label = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	t.Value = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	t.Accent = lipgloss.NewStyle().Foreground(lipgloss.Color("63")).Bold(true)
	t.Success = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	t.Warn = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	t.Error = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	t.Muted = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
}

func (t *Theme) fillNoColor() {
	plain := lipgloss.NewStyle()
	t.Panel = plain.Border(lipgloss.NormalBorder()).Padding(0, 1)
	t.PanelTitle = plain.Bold(true)
	t.PanelMuted = plain
	t.TabActive = plain.Bold(true)
	t.TabInactive = plain
	t.TabDivider = plain
	t.StatusBar = plain
	t.StatusBarOK = plain.Bold(true)
	t.StatusBarWarn = plain.Bold(true)
	t.StatusBarKey = plain.Bold(true)
	t.StatusBarItem = plain
	t.Title = plain.Bold(true)
	t.Subtitle = plain
	t.Label = plain
	t.Value = plain
	t.Accent = plain.Bold(true)
	t.Success = plain.Bold(true)
	t.Warn = plain.Bold(true)
	t.Error = plain.Bold(true)
	t.Muted = plain
}
