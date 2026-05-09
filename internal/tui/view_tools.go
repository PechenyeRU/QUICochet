package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// toolsCtx is the per-session state for the Tools tab. Allocated
// lazily on first visit so a session that only watches Dashboard
// keeps zero working state attached.
type toolsCtx struct {
	// generated holds the result of the last keygen action so the
	// keypair stays on screen across redraws. nil = not generated.
	generated *crypto.KeyPair

	// pprofStatus is the most recent pprof state observed via the
	// admin socket. Updated on every (k)eygen / (p)profile action
	// so a stale state from a previous tab visit doesn't mislead
	// the operator. Empty Address with Running=false is the
	// "steady, never started" view.
	pprofStatus  admin.PprofStatus
	pprofErr     error
	pprofChecked bool
}

// toolsView lays out the Tools tab. Two panels: keygen on the left
// with a hotkey hint and the most recent generated keypair, pprof
// on the right showing the live state read from admin.sock and the
// hotkey to toggle it.
func (a *App) toolsView() string {
	b := a.i18n
	theme := a.theme

	if a.toolsCtxRef() == nil {
		a.toolsCtxNew()
	}
	tc := a.toolsCtxRef()

	half := a.toolsPanelWidth()
	left := a.toolsKeygenBlock(tc, half)
	right := a.toolsPprofBlock(tc, half)
	side := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)

	hint := theme.Muted.Render(b.S("tools.hint"))
	return lipgloss.JoinVertical(lipgloss.Left,
		theme.Title.Render(b.S("tools.title")),
		"",
		side,
		"",
		hint,
	)
}

// toolsPanelWidth budgets half of the body width per panel, minus
// the two-cell gap between them. lipgloss handles content wrapping
// inside the panel as long as the width is set; without it a long
// error string (e.g. "connection refused" with the full socket
// path) overflows the panel border and bleeds onto the next row.
func (a *App) toolsPanelWidth() int {
	w := a.bodyWidth()
	if w <= 0 {
		return 0
	}
	half := (w - 2) / 2
	if half < 20 {
		return 20
	}
	return half
}

// toolsKeygenBlock renders the X25519 keypair generator panel. The
// public key is fully shown (it's the side the operator hands to
// the peer); the private key is rendered too so the operator can
// copy-paste it into a config without re-running keygen on the CLI.
// Both are base64. The panel is sized to width so long keys wrap
// inside the border instead of bleeding past it.
func (a *App) toolsKeygenBlock(tc *toolsCtx, width int) string {
	b := a.i18n
	theme := a.theme

	title := theme.PanelTitle.Render(b.S("tools.keygen.title"))
	body := theme.Muted.Render(b.S("tools.keygen.idle"))
	if tc.generated != nil {
		body = strings.Join([]string{
			theme.Label.Render(b.S("tools.keygen.public") + ":"),
			theme.Value.Render(tc.generated.PublicKeyBase64()),
			"",
			theme.Label.Render(b.S("tools.keygen.private") + ":"),
			theme.Value.Render(tc.generated.PrivateKeyBase64()),
			"",
			theme.Muted.Render(b.S("tools.keygen.peer.hint")),
		}, "\n")
	}
	style := theme.Panel
	if width > 0 {
		style = style.Width(width)
	}
	return style.Render(title + "\n\n" + body)
}

// toolsPprofBlock renders the on-demand pprof toggle panel. State
// is read from the admin socket the first time the operator opens
// the Tools tab and refreshed on every (p) keypress. Errors from
// the admin socket render in the warn colour so the operator
// notices the daemon needs to be restarted with admin enabled.
// The panel is sized to width so a long socket-path error wraps
// inside the border instead of bleeding past it.
func (a *App) toolsPprofBlock(tc *toolsCtx, width int) string {
	b := a.i18n
	theme := a.theme

	title := theme.PanelTitle.Render(b.S("tools.pprof.title"))
	var body string
	switch {
	case tc.pprofErr != nil:
		body = theme.Warn.Render(b.S("tools.pprof.err") + ": " + tc.pprofErr.Error())
	case !tc.pprofChecked:
		body = theme.Muted.Render(b.S("tools.pprof.unchecked"))
	case tc.pprofStatus.Running:
		body = strings.Join([]string{
			theme.Success.Render("● " + b.S("tools.pprof.running")),
			theme.Label.Render(b.S("tools.pprof.address")+": ") + theme.Value.Render(tc.pprofStatus.Address),
			"",
			theme.Muted.Render(b.S("tools.pprof.url") + ": http://" + tc.pprofStatus.Address + "/debug/pprof/"),
		}, "\n")
	default:
		body = theme.Muted.Render("○ " + b.S("tools.pprof.stopped"))
	}
	style := theme.Panel
	if width > 0 {
		style = style.Width(width)
	}
	return style.Render(title + "\n\n" + body)
}

// toolsHandleKey is the Tools-tab specific key router. Returns
// (handled, cmd): handled==true short-circuits the App-level
// dispatcher so digit keys (1..8) stay reserved for tab nav even
// when the operator is on the Tools tab. The actions are
// idempotent — pressing 'k' twice produces a different key the
// second time, pressing 'p' toggles whatever the daemon currently
// reports.
func (a *App) toolsHandleKey(s string) (bool, error) {
	if a.toolsCtxRef() == nil {
		a.toolsCtxNew()
	}
	tc := a.toolsCtxRef()
	switch s {
	case "k":
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			return true, fmt.Errorf("keygen: %w", err)
		}
		tc.generated = kp
		return true, nil
	case "p":
		tc.pprofChecked = true
		// Toggle: stop if currently running, otherwise start with an
		// empty address (daemon picks a port).
		var st admin.PprofStatus
		var err error
		if tc.pprofStatus.Running {
			st, err = a.ipc.PprofStop()
		} else {
			st, err = a.ipc.PprofStart("")
		}
		tc.pprofStatus = st
		tc.pprofErr = err
		return true, err
	case "P":
		// Plain-status refresh, no toggle. Useful when the daemon was
		// started with pprof already on (admin restart preserved
		// state) and the TUI's cached value is stale.
		tc.pprofChecked = true
		st, err := a.ipc.PprofStatus()
		tc.pprofStatus = st
		tc.pprofErr = err
		return true, err
	}
	return false, nil
}

// toolsCtxRef / toolsCtxNew sit on App rather than directly on the
// struct so the field allocation pattern matches configCtx and a
// future relocation to a sub-app file doesn't churn callers.
func (a *App) toolsCtxRef() *toolsCtx { return a.toolsState }
func (a *App) toolsCtxNew()           { a.toolsState = &toolsCtx{} }
