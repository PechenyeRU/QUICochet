package tui

import (
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/tui/ipc"
)

// BuildInfo carries the version metadata stamped into the binary by
// the build system. It is rendered verbatim on the About tab.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

// App is the Bubble Tea root model. It owns global state (theme,
// translation bundle, daemon IPC client, build info) and dispatches
// keyboard input + render duties to the active tab.
//
// Tabs are kept inside a single struct rather than per-tab models
// because Stage 1 tabs are stateless beyond what the App already
// tracks (lastSnapshot, lastReachErr); the Config tab introduces
// per-tab state via cfgCtx, and later stages may follow that pattern.
type App struct {
	width, height int

	theme *Theme
	i18n  *Bundle
	ipc   *ipc.Client
	build BuildInfo

	configPath string
	current    TabID

	// Cached daemon state, refreshed by tickPoll when Dashboard or Home
	// is active. nil means "never queried".
	lastSnapshot *admin.Snapshot
	lastReachErr error
	lastPollAt   time.Time

	// Per-tab state. cfgCtx is allocated lazily on the first visit so
	// a session that never touches the Config tab keeps zero working
	// state attached to it.
	cfgCtx *configCtx
}

// Options bundles the parameters Run accepts. Keeping them on a struct
// avoids a long positional argument list as future tabs add knobs.
type Options struct {
	SocketPath string
	ConfigPath string
	Build      BuildInfo
}

// Run constructs the App, ties Bubble Tea to it, and drives the event
// loop until the user quits or the terminal disconnects. The TUI runs
// in altscreen and exits cleanly on SIGINT/SIGTERM.
func Run(opts Options) error {
	bundle, err := NewBundle()
	if err != nil {
		return err
	}
	app := &App{
		theme:      NewTheme(),
		i18n:       bundle,
		ipc:        ipc.New(opts.SocketPath),
		build:      opts.Build,
		configPath: opts.ConfigPath,
		current:    TabHome,
	}
	p := tea.NewProgram(app)
	_, err = p.Run()
	return err
}

// Init kicks off the first poll so the home view shows a fresh
// daemon-status badge instead of "unknown" until the first user
// keystroke.
func (a *App) Init() tea.Cmd {
	return tea.Batch(
		a.pollNow(),
		tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }),
	)
}

// tickMsg is the recurring wake-up for the dashboard poll loop.
type tickMsg time.Time

// pollResultMsg carries the outcome of a single admin.sock query.
// Either Err or Snap is populated, not both.
type pollResultMsg struct {
	Snap *admin.Snapshot
	Err  error
	At   time.Time
}

// pollNow returns a Cmd that runs one Stats query and emits a
// pollResultMsg. Network and filesystem work happens off the Bubble
// Tea loop so the UI never stalls on a slow socket.
func (a *App) pollNow() tea.Cmd {
	client := a.ipc
	return func() tea.Msg {
		now := time.Now()
		if err := client.Reachable(); err != nil {
			return pollResultMsg{Err: err, At: now}
		}
		snap, err := client.Stats()
		if err != nil {
			return pollResultMsg{Err: err, At: now}
		}
		return pollResultMsg{Snap: &snap, At: now}
	}
}

// Update applies one Bubble Tea message. Global keys are handled here;
// anything not recognised is currently ignored, but Stage 2 will route
// unhandled messages to the active tab's own Update.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = m.Width
		a.height = m.Height
		return a, nil

	case tickMsg:
		// Re-arm the ticker first so a slow poll never delays the next
		// scheduled wake-up. The poll cmd runs concurrently.
		next := tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
		// Only poll when a tab actually shows live data. Saving cycles
		// on Home is fine — the home page caches the last snapshot.
		if a.current == TabHome || a.current == TabDashboard {
			return a, tea.Batch(next, a.pollNow())
		}
		return a, next

	case pollResultMsg:
		a.lastSnapshot = m.Snap
		a.lastReachErr = m.Err
		a.lastPollAt = m.At
		return a, nil

	case configSavedMsg:
		if a.cfgCtx != nil {
			a.cfgCtx.state = configSaved
			a.cfgCtx.savedPath = m.path
			a.cfgCtx.saveErr = m.err
		}
		return a, nil

	case tea.KeyPressMsg:
		return a.handleKey(m)
	}
	// Forward non-key messages (e.g. WindowSizeMsg) to the Config tab's
	// huh form when active so it can adapt its layout. Other tabs are
	// stateless w.r.t. these messages.
	if a.current == TabConfig && a.cfgCtx != nil && a.cfgCtx.state == configWizard && a.cfgCtx.wizard != nil {
		_, cmd := a.cfgCtx.wizard.updateForm(msg, a.i18n)
		return a, cmd
	}
	return a, nil
}

// handleKey resolves global hotkeys into model mutations or commands.
// The Config tab is given first dibs when active so its huh form can
// own keys like Tab / arrows; only when it declines to handle a key
// does the global router get its turn.
func (a *App) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// q and ctrl+c always quit, even mid-wizard, so a stuck UI is
	// recoverable without searching for the abort sequence.
	if s := msg.String(); s == "ctrl+c" {
		return a, tea.Quit
	}

	if a.current == TabConfig {
		if handled, cmd := a.configHandleKey(msg); handled {
			return a, cmd
		}
	}

	switch msg.String() {
	case "q":
		return a, tea.Quit
	case "r":
		return a, a.pollNow()
	case "tab", "right", "l+shift":
		a.current = AllTabs[(indexOf(a.current)+1)%len(AllTabs)]
		return a, a.pollNow()
	case "shift+tab", "left":
		i := indexOf(a.current) - 1
		if i < 0 {
			i = len(AllTabs) - 1
		}
		a.current = AllTabs[i]
		return a, a.pollNow()
	}
	// Digit shortcuts 1..9 jump directly to the matching tab.
	if r := msg.String(); len(r) == 1 && r[0] >= '1' && r[0] <= '9' {
		idx := int(r[0] - '1')
		if idx >= 0 && idx < len(AllTabs) {
			a.current = AllTabs[idx]
			return a, a.pollNow()
		}
	}
	return a, nil
}

// View renders the chrome (tab bar, body, status bar) and dispatches
// the body to the active tab's renderer.
func (a *App) View() tea.View {
	tabBar := renderTabBar(a.theme, a.i18n, a.current, a.width)
	body := a.renderBody()
	bodyHeight := max(a.height-2, 1) // tab bar + status bar
	bodyBox := lipgloss.NewStyle().
		Width(a.width).
		Height(bodyHeight).
		Padding(0, 1).
		Render(body)
	statusBar := renderStatusBar(a.theme, a.i18n, a.daemonAlive(), a.width)
	out := strings.Join([]string{tabBar, bodyBox, statusBar}, "\n")
	v := tea.NewView(out)
	v.AltScreen = true
	return v
}

func (a *App) daemonAlive() bool {
	return a.lastReachErr == nil && a.lastSnapshot != nil
}

func (a *App) renderBody() string {
	switch a.current {
	case TabHome:
		return a.homeView()
	case TabConfig:
		return a.configView()
	case TabDashboard:
		return a.dashboardView()
	case TabAbout:
		return a.aboutView()
	default:
		return a.stubView(a.current)
	}
}
