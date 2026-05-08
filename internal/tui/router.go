package tui

// TabID enumerates the top-level tabs the TUI exposes. The ordering
// is meaningful: it controls both keyboard digit shortcuts (1..N) and
// left-to-right placement in the tab bar. Adding a new tab anywhere
// other than the end shifts the digit shortcut for every later tab,
// so prefer to append.
type TabID int

const (
	TabHome TabID = iota
	TabConfig
	TabDashboard
	TabSpoof
	TabBench
	TabLogs
	TabTools
	TabAbout
)

// AllTabs is the iteration order used by the tab bar and by the
// digit-key router. It is the canonical source of truth for "which
// tabs exist and in what order"; do not iterate the const block by
// hand elsewhere.
var AllTabs = []TabID{
	TabHome,
	TabConfig,
	TabDashboard,
	TabSpoof,
	TabBench,
	TabLogs,
	TabTools,
	TabAbout,
}

// titleKey returns the i18n key whose value is the tab's display
// label. Centralised so the bundle stays the single source of truth
// for user-facing strings.
func (t TabID) titleKey() string {
	switch t {
	case TabHome:
		return "tab.home"
	case TabConfig:
		return "tab.config"
	case TabDashboard:
		return "tab.dashboard"
	case TabSpoof:
		return "tab.spoof"
	case TabBench:
		return "tab.bench"
	case TabLogs:
		return "tab.logs"
	case TabTools:
		return "tab.tools"
	case TabAbout:
		return "tab.about"
	}
	return ""
}

// indexOf returns the zero-based position of t in AllTabs, or -1 if
// it isn't registered.
func indexOf(t TabID) int {
	for i, x := range AllTabs {
		if x == t {
			return i
		}
	}
	return -1
}
