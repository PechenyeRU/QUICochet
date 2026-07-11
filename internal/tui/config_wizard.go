package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// customFormKeyMap extends huh's defaults with bindings that work
// uniformly across every field type:
//
//   - back nav: shift+tab (huh default) AND ctrl+b. ctrl+b is the
//     critical addition — shift+tab works everywhere already, but
//     ctrl+b gives the operator a single-keystroke back option that
//     doesn't conflict with input cursor editing the way ← would.
//
//   - confirm/select: space joins enter as a synonym on Select and
//     Confirm. Input fields are unaffected (space inserts a literal
//     space in the textbox, as it should).
//
// arrow keys are deliberately NOT remapped: ← / → on Input fields
// move the text cursor and rebinding them in only one direction
// produced the "arrow keys are unusable whenever there's a text
// field" experience cappy reported. ↑/↓ continue to scroll
// select options (huh default).
func customFormKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()

	// Add ctrl+b to every field type's Prev binding so back-nav has
	// a single keystroke that works on text inputs too.
	km.Input.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))
	km.Text.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))
	km.Select.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))
	km.Confirm.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))
	km.Note.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))
	km.MultiSelect.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))
	km.FilePicker.Prev = key.NewBinding(key.WithKeys("shift+tab", "ctrl+b"), key.WithHelp("shift+tab/ctrl+b", "back"))

	// space confirms a Select / Confirm choice in addition to enter.
	km.Select.Next = key.NewBinding(key.WithKeys("enter", "tab", "space"), key.WithHelp("enter/space", "select"))
	km.Confirm.Next = key.NewBinding(key.WithKeys("enter", "tab", "space"), key.WithHelp("enter/space", "next"))

	return km
}

// seedDefaults pre-fills numeric and string defaults so the form's
// initial render shows the value the daemon would actually use,
// not the Go zero value. The wizard step_advanced and the editor
// flat-form both call this — without it, MTU shows "0" until the
// operator types something even though the runtime would substitute
// 1400.
//
// Mirrors the relevant subset of config.Config.setDefaults; kept as
// a separate helper so the TUI's seeding is intentional rather than
// a side-effect of validation, and so we can test it in isolation.
func seedDefaults(cfg *config.Config) {
	if cfg.Performance.MTU == 0 {
		cfg.Performance.MTU = 1400
	}
	if cfg.Performance.BufferSize == 0 {
		cfg.Performance.BufferSize = 65535
	}
	if cfg.Performance.ReadBuffer == 0 {
		cfg.Performance.ReadBuffer = 32 * 1024 * 1024
	}
	if cfg.Performance.WriteBuffer == 0 {
		cfg.Performance.WriteBuffer = 32 * 1024 * 1024
	}
	if cfg.QUIC.KeepAlivePeriodSec == 0 {
		cfg.QUIC.KeepAlivePeriodSec = 5
	}
	if cfg.QUIC.MaxIdleTimeoutSec == 0 {
		cfg.QUIC.MaxIdleTimeoutSec = 10
	}
	if cfg.QUIC.PoolSize == 0 {
		cfg.QUIC.PoolSize = 8
	}
	if cfg.QUIC.PacketThreshold == 0 {
		cfg.QUIC.PacketThreshold = 128
	}
	if cfg.QUIC.CongestionControl == "" {
		cfg.QUIC.CongestionControl = "auto"
	}
	if cfg.Obfuscation.Mode == "" {
		cfg.Obfuscation.Mode = string(config.ObfuscationStandard)
	}
	if cfg.Obfuscation.ChaffingIntervalMs == 0 {
		cfg.Obfuscation.ChaffingIntervalMs = 50
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = config.LogInfo
	}
	if cfg.Security.BlockPrivateTargets == nil {
		def := true
		cfg.Security.BlockPrivateTargets = &def
	}
}

// configState enumerates the Config tab's sub-views. The Config tab is
// itself a small state machine because the editing flow has more
// states than other tabs (menu → wizard → saved with success/error).
type configState int

const (
	configMenu configState = iota
	configWizard
	configEdit
	configDiff
	configSaving
	configSaved
)

// configCtx is the per-session state for the Config tab. It is
// allocated lazily when the operator first navigates to the tab so a
// wizard run isn't kept alive across daemon-detached sessions where
// the operator never opens the tab.
type configCtx struct {
	state configState

	cfg  *config.Config // working copy; populated by wizard fields
	path string         // target file path entered in step_review

	wizard *wizard
	editor *editor
	differ *differ

	// Set when save fails; rendered in configSaved view so the
	// operator can fix the path or validation errors.
	saveErr error

	// Set after save succeeds, to confirm the absolute path written.
	savedPath string
}

// wizard threads the user through the new-config flow. Each step
// produces a huh.Form bound to fields of cfg; on form completion the
// wizard advances to the next step. The constructor list is short by
// design so each step gets its own dedicated builder function and the
// flow is auditable end-to-end.
type wizard struct {
	cfg *config.Config

	// width / height are the terminal dimensions reported by the
	// most recent tea.WindowSizeMsg. Stored on the wizard so a form
	// rebuilt mid-session (advance to the next step) is sized
	// correctly the first frame, not after a resize.
	width, height int

	step  int
	form  *huh.Form
	steps []stepBuilder

	// savePath is bound by the review step. The TUI keeps it on the
	// wizard rather than on cfg because cfg has no place for "where
	// to write me" — that is metadata about the editing session.
	savePath string

	// confirmSave is bound by the review step; once true and the form
	// reports completed, the Config tab transitions to configSaving.
	confirmSave bool

	// cryptoChoice is bound by step_crypto: "generate" or "paste".
	// Determines which sub-group renders and what consolidate() copies
	// into cfg.Crypto on step exit.
	cryptoChoice string
	// generatedKP is the keypair pre-built by step_crypto when the
	// operator picks "generate". Cached on the wizard so the public
	// key shown in the form remains stable across re-renders.
	generatedKP *crypto.KeyPair

	// inboundChoice is bound by step_inbounds: "socks", "forward",
	// or "skip". Drives which sub-group renders and what consolidate()
	// stitches into cfg.Inbounds on step exit. Skip leaves the slice
	// empty so the daemon starts without a local listener (server
	// mode default; client mode is unusual but valid for chained
	// configs that get inbounds via Open+Edit later).
	inboundChoice string
	inboundListen string
	inboundTarget string

	// showAdvanced is set by the advanced-toggle step. When true,
	// the next step renders the advanced field group; when false,
	// the wizard skips straight to review.
	showAdvanced bool

	// activated when the operator hits Esc during the flow; the Config
	// tab observes the flag and bounces back to the menu.
	aborted bool

	// spoofSrcIP / spoofPeerSpoofIP are scratch strings for the spoof
	// step (client mode only). They hold the first element of the
	// respective plural slices so huh can bind to a *string, and are
	// synced back into cfg.Spoof.SourceIPs / PeerSpoofIPs by
	// consolidate(). The MVP collects a single IP each; multi-IP list
	// editing lands with the iplist component later.
	spoofSrcIP  string
	spoofPeerIP string

	// peer* are scratch strings for the iterative server-mode peers
	// step. Each StateCompleted of step_peers commits the scratch into
	// cfg.Peers and either resets the scratch (addAnotherPeer == true)
	// for the next iteration or advances to the next step. They live
	// on the wizard so a re-render of the same step does not lose
	// half-typed input.
	peerName       string
	peerPub        string
	peerClientReal string
	peerSpoofCsv   string
	addAnotherPeer bool

	// wantReverseForwards is bound by step_reverse_toggle (server mode).
	// When false the iterative step_reverse_forwards is skipped entirely
	// so reverse port forwarding stays opt-in (zero rules is valid).
	wantReverseForwards bool

	// rev* are scratch strings for the iterative server-mode reverse
	// forwards step (ssh -R). Each StateCompleted commits the scratch
	// into cfg.ReverseForwards via commitCurrentReverseForward and either
	// resets for the next iteration (addAnotherReverse == true) or
	// advances. revPeer is chosen from the peers already committed by
	// step_peers, so it is always a known peer name.
	revListen         string
	revTarget         string
	revPeer           string
	addAnotherReverse bool

	// reverseAllowCsv is the client-mode scratch string for
	// reverse_accept.allow. Holds a comma-separated list of
	// "host:port" / bare "host" entries; consolidate() splits it into
	// cfg.ReverseAccept.Allow. Mirrors the peerSpoofCsv pattern.
	reverseAllowCsv string
}

// stepBuilder pairs a builder with an optional skip predicate. When
// shouldRun returns false, advance() loops past the step entirely
// without rendering an empty form. This keeps the pure-data step list
// declarative while letting role-conditional steps (e.g. server config
// is client-only) hide cleanly.
//
// iterative steps may complete multiple times before advancing — used
// by the peers step where the operator types one peer, the form
// reaches StateCompleted, and either (a) the wizard rebuilds the same
// step for the next peer or (b) advances past the step. updateForm
// reads the flag to decide which path to take.
type stepBuilder struct {
	build     func(w *wizard, b *Bundle) *huh.Form
	shouldRun func(w *wizard) bool // nil == always run
	iterative bool

	// commit folds the current iteration's scratch into cfg (iterative
	// steps only). loop reports whether the operator asked to add another
	// item and is evaluated BEFORE commit clears the scratch flags. Both
	// are nil for non-iterative steps.
	commit func(w *wizard)
	loop   func(w *wizard) bool
}

func newWizard(b *Bundle, width, height int) (*wizard, tea.Cmd) {
	cfg := &config.Config{}
	w := &wizard{
		cfg:    cfg,
		width:  width,
		height: height,
		steps: []stepBuilder{
			{build: buildStepMode},
			{build: buildStepTransport},
			{build: buildStepServer, shouldRun: clientOnly},
			{build: buildStepSpoof, shouldRun: clientOnly},
			{
				build: buildStepPeers, shouldRun: serverOnly, iterative: true,
				commit: func(w *wizard) { w.commitCurrentPeer() },
				loop:   func(w *wizard) bool { return w.addAnotherPeer },
			},
			{build: buildStepCrypto},
			{build: buildStepInbounds, shouldRun: clientOnly},
			{build: buildStepReverseToggle, shouldRun: serverOnly},
			{
				build: buildStepReverseForwards, shouldRun: reverseForwardsRequested, iterative: true,
				commit: func(w *wizard) { w.commitCurrentReverseForward() },
				loop:   func(w *wizard) bool { return w.addAnotherReverse },
			},
			{build: buildStepReverseAccept, shouldRun: clientOnly},
			{build: buildStepBasic},
			{build: buildStepTunablesToggle},
			{build: buildStepTunables, shouldRun: tunablesRequested},
			{build: buildStepReview},
		},
	}
	w.form = w.applySize(w.steps[0].build(w, b))
	// huh.Form needs Init() to set initial focus and emit its first
	// render command; without it the first frame is blank and the
	// operator has to press an arrow key to "wake" the form.
	return w, w.form.Init()
}

// applySize sets the wizard's recorded width/height onto a freshly
// built form so the first frame already wraps text at the terminal
// edge instead of huh's much narrower default. Also installs the
// custom keymap so the bindings are uniform across every step.
// Safe to call with zero dimensions — huh's WithWidth/WithHeight
// short-circuit on <=0.
func (w *wizard) applySize(f *huh.Form) *huh.Form {
	f = f.WithKeyMap(customFormKeyMap())
	if w.width > 0 {
		f = f.WithWidth(w.width)
	}
	if w.height > 0 {
		f = f.WithHeight(w.height)
	}
	return f
}

// setSize updates the wizard's recorded dimensions and pushes a
// fresh WindowSizeMsg into the active form so its current frame
// re-wraps. Called from App.Update on tea.WindowSizeMsg.
func (w *wizard) setSize(width, height int) tea.Cmd {
	w.width = width
	w.height = height
	if w.form == nil {
		return nil
	}
	model, c := w.form.Update(tea.WindowSizeMsg{Width: width, Height: height})
	if f, ok := model.(*huh.Form); ok {
		w.form = w.applySize(f)
	}
	return c
}

// clientOnly hides a step in server mode. Used by step_server and
// (later) step_inbounds.
func clientOnly(w *wizard) bool {
	return w.cfg.Mode == config.ModeClient || w.cfg.Mode == ""
}

// serverOnly hides a step in client mode. Used by step_peers — the
// per-peer identity collection only makes sense on the receiving
// (server) side.
func serverOnly(w *wizard) bool {
	return w.cfg.Mode == config.ModeServer
}

// reverseForwardsRequested gates the iterative step_reverse_forwards
// behind the server-mode toggle so reverse port forwarding stays
// opt-in — an operator who leaves the toggle off never sees the rule
// collection step and cfg.ReverseForwards stays empty (which is valid).
func reverseForwardsRequested(w *wizard) bool {
	return w.cfg.Mode == config.ModeServer && w.wantReverseForwards
}

// advance moves to the next step or signals completion. It rebuilds
// the form fresh each time so dynamic content (e.g. the review JSON)
// always reflects the latest cfg, and skips any steps whose shouldRun
// predicate returns false. The returned cmd is the new form's Init —
// huh.Form requires it to emit the first render after construction.
func (w *wizard) advance(b *Bundle) (done bool, cmd tea.Cmd) {
	for {
		w.step++
		if w.step >= len(w.steps) {
			return true, nil
		}
		s := w.steps[w.step]
		if s.shouldRun != nil && !s.shouldRun(w) {
			continue
		}
		// consolidate is the right hook for "fold the previous step's
		// scratch state into cfg" — e.g. crypto's generated keypair.
		// Run it before the next builder so the new step sees a
		// consistent cfg if it needs to render dynamic content.
		w.consolidate()
		w.form = w.applySize(s.build(w, b))
		return false, w.form.Init()
	}
}

// consolidate copies wizard scratch state (crypto choice, inbound
// choice, spoof IPs) into cfg. Called both before each step transition
// and once more on the final advance (so the review preview reflects
// the last edits).
//
// Server-mode peers are NOT folded here — they are committed
// incrementally by commitCurrentPeer() each time step_peers reaches
// StateCompleted, so re-running consolidate is idempotent and never
// duplicates entries.
func (w *wizard) consolidate() {
	if w.cryptoChoice == "generate" && w.generatedKP != nil {
		w.cfg.Crypto.PrivateKey = w.generatedKP.PrivateKeyBase64()
	}
	// Server mode keeps cfg.Crypto.PeerPublicKey empty — each peer's
	// public key lives in cfg.Peers[i].PeerPublicKey. The validator
	// hard-fails if the top-level field is set on a server config, so
	// scrub any value the user might have entered before switching mode.
	if w.cfg.Mode == config.ModeServer {
		w.cfg.Crypto.PeerPublicKey = ""
	}
	w.cfg.Inbounds = w.cfg.Inbounds[:0]
	switch w.inboundChoice {
	case "socks":
		w.cfg.Inbounds = append(w.cfg.Inbounds, config.InboundConfig{
			Type:   config.InboundSocks,
			Listen: w.inboundListen,
		})
	case "forward":
		w.cfg.Inbounds = append(w.cfg.Inbounds, config.InboundConfig{
			Type:   config.InboundForward,
			Listen: w.inboundListen,
			Target: w.inboundTarget,
		})
	}

	// Client-mode spoof: sync scratch strings into the plural slice form.
	// MVP single-IP; multi-IP editing lands with the iplist component.
	if w.cfg.Mode != config.ModeServer {
		if w.spoofSrcIP != "" {
			w.cfg.Spoof.SourceIPs = []string{w.spoofSrcIP}
		}
		if w.spoofPeerIP != "" {
			w.cfg.Spoof.PeerSpoofIPs = []string{w.spoofPeerIP}
		}
	} else {
		// Server-mode never reads cfg.Spoof.* at runtime, but leaving
		// stale client-side values from a mode flip would confuse the
		// review preview. Clear them.
		w.cfg.Spoof = config.SpoofConfig{}
	}

	// Reverse forwards are server-only and committed incrementally (like
	// peers), so consolidate never folds them in — it only scrubs any
	// entries a client<->server mode flip would otherwise leave behind.
	if w.cfg.Mode != config.ModeServer {
		w.cfg.ReverseForwards = nil
	}

	// Reverse accept is client-only. Fold the scratch CSV into Allow when
	// enabled; scrub the whole struct in server mode where the validator
	// rejects it. Splitting "" yields nil, so this stays idempotent.
	if w.cfg.Mode == config.ModeServer {
		w.cfg.ReverseAccept = config.ReverseAcceptConfig{}
	} else if w.cfg.ReverseAccept.Enabled {
		w.cfg.ReverseAccept.Allow = parseReverseAllowCSV(w.reverseAllowCsv)
	} else {
		w.cfg.ReverseAccept.Allow = nil
	}
}

// commitCurrentPeer appends the current peer scratch into cfg.Peers
// and clears the scratch fields so the next iteration starts from a
// blank slate. Called by updateForm when step_peers reaches
// StateCompleted. The huh validators on the form already guarantee
// the fields are well-formed, so this is unconditional append.
func (w *wizard) commitCurrentPeer() {
	w.cfg.Peers = append(w.cfg.Peers, config.PeerConfig{
		Name:          w.peerName,
		PeerPublicKey: w.peerPub,
		ClientRealIP:  w.peerClientReal,
		PeerSpoofIPs:  parseIPv4CSV(w.peerSpoofCsv),
	})
	w.peerName = ""
	w.peerPub = ""
	w.peerClientReal = ""
	w.peerSpoofCsv = ""
	w.addAnotherPeer = false
}

// commitCurrentReverseForward appends the current reverse-forward scratch
// into cfg.ReverseForwards and clears the scratch so the next iteration
// starts blank. Called by updateForm when step_reverse_forwards reaches
// StateCompleted. Target is left as typed (possibly empty) — config
// setDefaults fills the "127.0.0.1:<listen-port>" default at load time,
// matching the daemon's behaviour. The huh validators already guarantee
// the fields are well-formed, so this is an unconditional append.
func (w *wizard) commitCurrentReverseForward() {
	w.cfg.ReverseForwards = append(w.cfg.ReverseForwards, config.ReverseForwardConfig{
		Listen: w.revListen,
		Target: w.revTarget,
		Peer:   w.revPeer,
	})
	w.revListen = ""
	w.revTarget = ""
	w.revPeer = ""
	w.addAnotherReverse = false
}

// tunablesRequested gates step_tunables behind the confirm. Basic
// settings are always shown; only the performance tunables (CC,
// pacing, buffers, packet threshold) sit behind the confirm so the
// New flow stays under a minute for an operator who doesn't need
// to override them.
func tunablesRequested(w *wizard) bool { return w.showAdvanced }

// buildStepMode is wizard step 0: choose client or server. The mode
// gates several later steps (e.g. step_server only runs in client
// mode), so it must come first.
func buildStepMode(w *wizard, b *Bundle) *huh.Form {
	f := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[config.Mode]().
				Title(b.S("wiz.mode.title")).
				Description(b.S("wiz.mode.desc")).
				Options(
					huh.NewOption(b.S("wiz.mode.client"), config.ModeClient),
					huh.NewOption(b.S("wiz.mode.server"), config.ModeServer),
				).
				Value(&w.cfg.Mode),
		),
	).WithShowHelp(false).WithShowErrors(true)
	return f
}

// buildStepTransport is wizard step 1: pick a transport type and any
// type-specific sub-field (protocol number for raw, icmp_mode for
// icmp/icmpv6). The conditional sub-field lives in a second group so
// huh keeps it skipped when the type doesn't need it.
func buildStepTransport(w *wizard, b *Bundle) *huh.Form {
	t := &w.cfg.Transport
	protoStr := strconv.Itoa(t.ProtocolNumber)

	groups := []*huh.Group{
		huh.NewGroup(
			huh.NewSelect[config.TransportType]().
				Title(b.S("wiz.transport.title")).
				Description(b.S("wiz.transport.desc")).
				Options(
					huh.NewOption("udp", config.TransportUDP),
					huh.NewOption("icmp", config.TransportICMP),
					huh.NewOption("icmpv6", config.TransportICMPv6),
					huh.NewOption("raw", config.TransportRAW),
					huh.NewOption("syn_udp", config.TransportSynUDP),
				).
				Value(&t.Type),
		),
		huh.NewGroup(
			huh.NewInput().
				Title(b.S("wiz.transport.protocol")).
				Description(b.S("wiz.transport.protocol.desc")).
				Value(&protoStr).
				Validate(func(s string) error {
					if t.Type != config.TransportRAW {
						return nil
					}
					n, err := strconv.Atoi(s)
					if err != nil || n < 1 || n > 255 {
						return fmt.Errorf("must be 1..255")
					}
					t.ProtocolNumber = n
					return nil
				}),
		).WithHideFunc(func() bool { return t.Type != config.TransportRAW }),
		huh.NewGroup(
			huh.NewSelect[config.ICMPMode]().
				Title(b.S("wiz.transport.icmp_mode")).
				Description(b.S("wiz.transport.icmp_mode.desc")).
				Options(
					huh.NewOption("echo", config.ICMPModeEcho),
					huh.NewOption("reply", config.ICMPModeReply),
				).
				Value(&t.ICMPMode),
		).WithHideFunc(func() bool {
			return t.Type != config.TransportICMP && t.Type != config.TransportICMPv6
		}),
	}

	return huh.NewForm(groups...).WithShowHelp(false).WithShowErrors(true)
}

// buildStepServer is wizard step 2 (client only): the remote address
// and port to dial. Validation is light — full address resolution
// happens at daemon start, not here, so the operator can save a config
// targeting a hostname that hasn't propagated DNS yet.
func buildStepServer(w *wizard, b *Bundle) *huh.Form {
	s := &w.cfg.Server
	portStr := strconv.Itoa(s.Port)
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(b.S("wiz.server.address")).
				Description(b.S("wiz.server.address.desc")).
				Value(&s.Address).
				Validate(func(v string) error {
					if v == "" {
						return fmt.Errorf("address required")
					}
					return nil
				}),
			huh.NewInput().
				Title(b.S("wiz.server.port")).
				Description(b.S("wiz.server.port.desc")).
				Value(&portStr).
				Validate(func(v string) error {
					n, err := strconv.Atoi(v)
					if err != nil || n < 1 || n > 65535 {
						return fmt.Errorf("port must be 1..65535")
					}
					s.Port = n
					return nil
				}),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildStepSpoof captures source/peer IPs for client mode. MVP
// single-IP only — multi-IP list builder lands with the iplist
// component in a later sub-stage. The scratch strings are synced into
// cfg.Spoof.SourceIPs / PeerSpoofIPs by consolidate() on step exit.
//
// Server mode does NOT use this step (the steps slice gates it with
// shouldRun: clientOnly); per-peer identities are collected by
// step_peers instead, which writes directly into cfg.Peers[i].
func buildStepSpoof(w *wizard, b *Bundle) *huh.Form {
	// Seed scratch vars from current config so an editor round-trip
	// preserves the existing values.
	if len(w.cfg.Spoof.SourceIPs) > 0 && w.spoofSrcIP == "" {
		w.spoofSrcIP = w.cfg.Spoof.SourceIPs[0]
	}
	if len(w.cfg.Spoof.PeerSpoofIPs) > 0 && w.spoofPeerIP == "" {
		w.spoofPeerIP = w.cfg.Spoof.PeerSpoofIPs[0]
	}

	src := huh.NewInput().
		Title(b.S("wiz.spoof.source")).
		Description(b.S("wiz.spoof.source.desc")).
		Value(&w.spoofSrcIP).
		Validate(validateIPv4Required)

	peer := huh.NewInput().
		Title(b.S("wiz.spoof.peer")).
		Description(b.S("wiz.spoof.peer.desc")).
		Value(&w.spoofPeerIP).
		Validate(validateIPv4Optional)

	return huh.NewForm(huh.NewGroup(src, peer)).
		WithShowHelp(false).
		WithShowErrors(true)
}

// buildStepPeers is the server-mode iterative peer-collection step.
// Each StateCompleted commits the scratch into cfg.Peers (via
// commitCurrentPeer) and either re-runs the same step (when the
// "add another peer?" confirm is true) or advances. The form is
// rebuilt on every iteration so the title shows the current index
// (`Peer #N`) and validators that depend on already-committed peers
// (e.g. unique name) see the latest list.
//
// Validation uses the same building blocks as the rest of the wizard
// — full disjointness/well-formedness of the resulting cfg.Peers is
// re-verified at save time by config.Validate, so this layer only
// ensures the per-field input parses.
func buildStepPeers(w *wizard, b *Bundle) *huh.Form {
	title := fmt.Sprintf(b.S("wiz.peers.intro.title"), len(w.cfg.Peers)+1)
	committed := w.cfg.Peers
	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(title).Description(b.S("wiz.peers.intro.desc")),
			huh.NewInput().
				Title(b.S("wiz.peers.name")).
				Description(b.S("wiz.peers.name.desc")).
				Value(&w.peerName).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("required")
					}
					if strings.ContainsAny(s, " \t\n") {
						return fmt.Errorf("no whitespace in name")
					}
					for _, p := range committed {
						if p.Name == s {
							return fmt.Errorf("duplicate name %q", s)
						}
					}
					return nil
				}),
			huh.NewInput().
				Title(b.S("wiz.peers.peer_pub")).
				Description(b.S("wiz.peers.peer_pub.desc")).
				Value(&w.peerPub).
				Validate(validateB64PubKey),
			huh.NewInput().
				Title(b.S("wiz.peers.client_real")).
				Description(b.S("wiz.peers.client_real.desc")).
				Value(&w.peerClientReal).
				Validate(validateIPv4Required),
			huh.NewInput().
				Title(b.S("wiz.peers.spoof_ips")).
				Description(b.S("wiz.peers.spoof_ips.desc")).
				Value(&w.peerSpoofCsv).
				Validate(validateIPv4CSVRequired),
			huh.NewConfirm().
				Title(b.S("wiz.peers.add_another")).
				Description(b.S("wiz.peers.add_another.desc")).
				Value(&w.addAnotherPeer),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// validateIPv4CSVRequired accepts a non-empty comma-separated list of
// IPv4 addresses. Whitespace around commas is tolerated; empty entries
// (e.g. trailing comma) are skipped silently rather than rejected so a
// quick edit doesn't make the field invalid.
func validateIPv4CSVRequired(s string) error {
	parts := parseIPv4CSV(s)
	if len(parts) == 0 {
		return fmt.Errorf("at least one ipv4 required")
	}
	for _, p := range parts {
		if err := validateIPv4Required(p); err != nil {
			return fmt.Errorf("%q: %w", p, err)
		}
	}
	return nil
}

// parseIPv4CSV splits a comma-separated string into trimmed non-empty
// entries. No validation here — pair with validateIPv4CSVRequired
// when input correctness matters (e.g. on huh form submission). At
// commit time the validators have already run so this is a pure
// destructure.
func parseIPv4CSV(s string) []string {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildStepCrypto offers two paths: generate a fresh keypair (the
// public key is shown immediately so the operator can hand it to the
// peer) or paste an existing private + peer public. The generated
// keypair is cached on the wizard so re-rendering the form during
// validation doesn't churn keys.
//
// Server mode collects only the LOCAL keys (private + corresponding
// public for distribution); the peer public keys live per-peer in
// step_peers, so the "peer pub" inputs are hidden in server mode.
func buildStepCrypto(w *wizard, b *Bundle) *huh.Form {
	if w.cryptoChoice == "" {
		w.cryptoChoice = "generate"
	}
	if w.generatedKP == nil {
		if kp, err := crypto.GenerateKeyPair(); err == nil {
			w.generatedKP = kp
		}
	}
	pubKey := "(keygen failed)"
	if w.generatedKP != nil {
		pubKey = w.generatedKP.PublicKeyBase64()
	}

	isServer := w.cfg.Mode == config.ModeServer

	choice := huh.NewGroup(
		huh.NewSelect[string]().
			Title(b.S("wiz.crypto.title")).
			Description(b.S("wiz.crypto.desc")).
			Options(
				huh.NewOption(b.S("wiz.crypto.generate"), "generate"),
				huh.NewOption(b.S("wiz.crypto.paste"), "paste"),
			).
			Value(&w.cryptoChoice),
	)

	genNote := huh.NewGroup(
		huh.NewNote().
			Title(b.S("wiz.crypto.generated_title")).
			Description(b.S("wiz.crypto.generated_pub") + "\n\n" + pubKey + "\n\n" + b.S("wiz.crypto.share_with_peer")),
	).WithHideFunc(func() bool { return w.cryptoChoice != "generate" })

	genPeerPub := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.crypto.peer_pub")).
			Description(b.S("wiz.crypto.peer_pub.desc")).
			Value(&w.cfg.Crypto.PeerPublicKey).
			Validate(validateB64PubKey),
	).WithHideFunc(func() bool { return w.cryptoChoice != "generate" || isServer })

	pastePriv := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.crypto.private")).
			Description(b.S("wiz.crypto.private.desc")).
			Value(&w.cfg.Crypto.PrivateKey).
			Validate(validateB64PrivKey),
	).WithHideFunc(func() bool { return w.cryptoChoice != "paste" })

	pastePeerPub := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.crypto.peer_pub")).
			Description(b.S("wiz.crypto.peer_pub.desc")).
			Value(&w.cfg.Crypto.PeerPublicKey).
			Validate(validateB64PubKey),
	).WithHideFunc(func() bool { return w.cryptoChoice != "paste" || isServer })

	return huh.NewForm(choice, genNote, genPeerPub, pastePriv, pastePeerPub).
		WithShowHelp(false).
		WithShowErrors(true)
}

// validateIPv4Required parses a non-empty IPv4 string. Used by spoof
// fields the daemon will refuse to start without.
func validateIPv4Required(s string) error {
	if s == "" {
		return fmt.Errorf("required")
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("not an ipv4 address")
	}
	return nil
}

// validateIPv4Optional accepts an empty string or a valid IPv4. The
// peer spoof IP is optional on transports that don't filter source.
func validateIPv4Optional(s string) error {
	if s == "" {
		return nil
	}
	return validateIPv4Required(s)
}

// validateB64PrivKey makes sure the pasted private key parses cleanly.
// crypto.ParsePrivateKey itself derives the public key, so a bad
// encoding fails fast here instead of at daemon start.
func validateB64PrivKey(s string) error {
	if s == "" {
		return fmt.Errorf("required")
	}
	if _, err := crypto.ParsePrivateKey(s); err != nil {
		return err
	}
	return nil
}

// validateB64PubKey rejects empty, malformed, and the all-zero pubkey
// — the latter is the canonical "pasted nothing by accident" case.
func validateB64PubKey(s string) error {
	if s == "" {
		return fmt.Errorf("required")
	}
	if _, err := crypto.ParsePublicKey(s); err != nil {
		return err
	}
	return nil
}

// buildStepInbounds offers an MVP single-inbound choice for client
// mode: a SOCKS5 listener (the common case for outgoing tunnels), a
// forward listener (single TCP target), or skip (no local listener,
// the operator will add one later via Open+Edit). Multi-inbound
// editing belongs in the flat-form sub-mode where the iplist
// component can grow the slice in place.
func buildStepInbounds(w *wizard, b *Bundle) *huh.Form {
	if w.inboundChoice == "" {
		w.inboundChoice = "socks"
		w.inboundListen = "127.0.0.1:1080"
	}

	choice := huh.NewGroup(
		huh.NewSelect[string]().
			Title(b.S("wiz.inbound.title")).
			Description(b.S("wiz.inbound.desc")).
			Options(
				huh.NewOption(b.S("wiz.inbound.socks"), "socks"),
				huh.NewOption(b.S("wiz.inbound.forward"), "forward"),
				huh.NewOption(b.S("wiz.inbound.skip"), "skip"),
			).
			Value(&w.inboundChoice),
	)

	socks := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.inbound.listen")).
			Description(b.S("wiz.inbound.listen.desc")).
			Value(&w.inboundListen).
			Validate(validateListenAddr),
	).WithHideFunc(func() bool { return w.inboundChoice != "socks" })

	forward := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.inbound.listen")).
			Description(b.S("wiz.inbound.listen.desc")).
			Value(&w.inboundListen).
			Validate(validateListenAddr),
		huh.NewInput().
			Title(b.S("wiz.inbound.target")).
			Description(b.S("wiz.inbound.target.desc")).
			Value(&w.inboundTarget).
			Validate(validateListenAddr),
	).WithHideFunc(func() bool { return w.inboundChoice != "forward" })

	return huh.NewForm(choice, socks, forward).WithShowHelp(false).WithShowErrors(true)
}

// buildStepReverseToggle is a server-only confirm gating the iterative
// reverse-forwards step. Reverse port forwarding (ssh -R) is optional, so
// the toggle keeps the New flow short for operators who do not need it;
// only when it is on does buildStepReverseForwards run.
func buildStepReverseToggle(w *wizard, b *Bundle) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(b.S("wiz.reverse.toggle.title")).
				Description(b.S("wiz.reverse.toggle.desc")).
				Value(&w.wantReverseForwards),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildStepReverseForwards is the server-only iterative step that
// collects reverse_forwards rules (ssh -R). Each StateCompleted commits
// the scratch into cfg.ReverseForwards (via commitCurrentReverseForward)
// and either re-runs the same step (add-another == true) or advances.
//
// The peer is chosen from a Select populated with the names already
// committed by step_peers, so the reference is always a known peer name
// and cannot be mistyped. Listen/target parse the same way config.Validate
// checks them: listen via config.NormalizeReverseListen (accepts host:port,
// :port, and bare port; loopback-defaults a hostless bind), target as an
// optional host:port that defaults to 127.0.0.1:<listen-port> when blank.
func buildStepReverseForwards(w *wizard, b *Bundle) *huh.Form {
	// Default the peer selector to the first committed peer so the bound
	// value is never empty when the operator accepts the default option.
	if w.revPeer == "" {
		for _, p := range w.cfg.Peers {
			if p.Name != "" {
				w.revPeer = p.Name
				break
			}
		}
	}

	title := fmt.Sprintf(b.S("wiz.reverse.intro.title"), len(w.cfg.ReverseForwards)+1)
	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(title).Description(b.S("wiz.reverse.intro.desc")),
			huh.NewInput().
				Title(b.S("wiz.reverse.listen")).
				Description(b.S("wiz.reverse.listen.desc")).
				Value(&w.revListen).
				Validate(validateReverseListen),
			huh.NewInput().
				Title(b.S("wiz.reverse.target")).
				Description(b.S("wiz.reverse.target.desc")).
				Value(&w.revTarget).
				Validate(validateReverseTargetOptional),
			huh.NewSelect[string]().
				Title(b.S("wiz.reverse.peer")).
				Description(b.S("wiz.reverse.peer.desc")).
				Options(reversePeerOptions(w.cfg.Peers)...).
				Value(&w.revPeer),
			huh.NewConfirm().
				Title(b.S("wiz.reverse.add_another")).
				Description(b.S("wiz.reverse.add_another.desc")).
				Value(&w.addAnotherReverse),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildStepReverseAccept is the client-only step configuring the
// reverse_accept default-deny policy: an enabled toggle plus a
// comma-separated allow-list of "host:port" / bare "host" entries. The
// allow input is hidden while disabled and required (non-empty, each
// entry well-formed) when enabled — mirroring config.Validate, which
// rejects an enabled-but-empty policy. consolidate() splits the CSV into
// cfg.ReverseAccept.Allow on step exit.
func buildStepReverseAccept(w *wizard, b *Bundle) *huh.Form {
	// Seed the scratch from any existing Allow so an editor-style
	// round-trip preserves the entries.
	if w.reverseAllowCsv == "" && len(w.cfg.ReverseAccept.Allow) > 0 {
		w.reverseAllowCsv = strings.Join(w.cfg.ReverseAccept.Allow, ", ")
	}

	enabled := huh.NewGroup(
		huh.NewConfirm().
			Title(b.S("wiz.reverse_accept.enabled")).
			Description(b.S("wiz.reverse_accept.enabled.desc")).
			Value(&w.cfg.ReverseAccept.Enabled),
	)

	allow := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.reverse_accept.allow")).
			Description(b.S("wiz.reverse_accept.allow.desc")).
			Value(&w.reverseAllowCsv).
			Validate(validateReverseAllowCSVRequired),
	).WithHideFunc(func() bool { return !w.cfg.ReverseAccept.Enabled })

	return huh.NewForm(enabled, allow).WithShowHelp(false).WithShowErrors(true)
}

// reversePeerOptions builds Select options from the committed peers'
// names, skipping empty stubs. Used by the reverse-forwards peer picker
// so the referenced peer is guaranteed to exist.
func reversePeerOptions(peers []config.PeerConfig) []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(peers))
	for _, p := range peers {
		if p.Name != "" {
			opts = append(opts, huh.NewOption(p.Name, p.Name))
		}
	}
	return opts
}

// validateReverseListen accepts host:port, :port, or a bare port and
// reuses config.NormalizeReverseListen so the TUI never diverges from
// the daemon's own parse/normalize rules.
func validateReverseListen(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("required")
	}
	if _, _, err := config.NormalizeReverseListen(s); err != nil {
		return err
	}
	return nil
}

// validateReverseTargetOptional accepts an empty string (the daemon
// defaults it to 127.0.0.1:<listen-port>) or a host:port pair.
func validateReverseTargetOptional(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return fmt.Errorf("expected host:port (got %q)", s)
	}
	return nil
}

// validateReverseAllowCSVRequired accepts a non-empty comma-separated
// allow-list where every entry is a well-formed "host:port" or bare
// "host". Whitespace around commas is tolerated; empty entries are
// skipped. Used only when reverse_accept is enabled.
func validateReverseAllowCSVRequired(s string) error {
	entries := parseReverseAllowCSV(s)
	if len(entries) == 0 {
		return fmt.Errorf("at least one allowed target required")
	}
	for _, e := range entries {
		if err := validateReverseAllowEntry(e); err != nil {
			return err
		}
	}
	return nil
}

// validateReverseAllowEntry mirrors config.validateReverseAllowEntry (the
// config helper is unexported): an entry parses as "host:port" (exact) or
// a bare host (any port). A stray colon that is neither is rejected.
func validateReverseAllowEntry(entry string) error {
	if entry == "" {
		return fmt.Errorf("empty entry")
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		if host == "" {
			return fmt.Errorf("host is empty in %q", entry)
		}
		if port == "" {
			return fmt.Errorf("port is empty in %q", entry)
		}
		return nil
	}
	if net.ParseIP(entry) != nil {
		return nil
	}
	if strings.ContainsRune(entry, ':') {
		return fmt.Errorf("%q is neither a valid host:port nor a bare host", entry)
	}
	return nil
}

// parseReverseAllowCSV splits a comma-separated allow-list into trimmed
// non-empty entries. No validation — pair with
// validateReverseAllowCSVRequired when correctness matters.
func parseReverseAllowCSV(s string) []string {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildStepBasic is shown unconditionally to every operator: it
// covers the operational knobs a real deployment usually touches
// (MTU, obfuscation mode + chaff, log level, security guard, admin
// socket, metrics listener). These aren't tunables — they're the
// "second tier" of common settings that don't fit in the focused
// transport/server/spoof/crypto steps but are still worth seeing
// before the operator decides whether to dig into the perf knobs.
func buildStepBasic(w *wizard, b *Bundle) *huh.Form {
	seedDefaults(w.cfg)
	perf := &w.cfg.Performance
	mtuStr := strconv.Itoa(perf.MTU)
	chaffStr := strconv.Itoa(w.cfg.Obfuscation.ChaffingIntervalMs)

	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(b.S("wiz.basic.section")),
			huh.NewInput().
				Title(b.S("wiz.adv.mtu")).
				Description(b.S("wiz.adv.mtu.desc")).
				Value(&mtuStr).
				Validate(parseIntoIntRange(&perf.MTU, 1231, 1500)),
			huh.NewSelect[string]().
				Title(b.S("wiz.adv.obf.mode")).
				Description(b.S("wiz.adv.obf.mode.desc")).
				Options(
					huh.NewOption("none", string(config.ObfuscationNone)),
					huh.NewOption("standard", string(config.ObfuscationStandard)),
					huh.NewOption("paranoid", string(config.ObfuscationParanoid)),
				).
				Value(&w.cfg.Obfuscation.Mode),
			huh.NewInput().
				Title(b.S("wiz.adv.obf.chaff")).
				Description(b.S("wiz.adv.obf.chaff.desc")).
				Value(&chaffStr).
				Validate(parseIntoIntMin(&w.cfg.Obfuscation.ChaffingIntervalMs, 0)),
			huh.NewSelect[config.LogLevel]().
				Title(b.S("wiz.adv.log.level")).
				Description(b.S("wiz.adv.log.level.desc")).
				Options(
					huh.NewOption("debug", config.LogDebug),
					huh.NewOption("info", config.LogInfo),
					huh.NewOption("warn", config.LogWarn),
					huh.NewOption("error", config.LogError),
				).
				Value(&w.cfg.Logging.Level),
			huh.NewConfirm().
				Title(b.S("wiz.adv.security.block_private")).
				Description(b.S("wiz.adv.security.block_private.desc")).
				Value(w.cfg.Security.BlockPrivateTargets),
			huh.NewInput().
				Title(b.S("wiz.adv.admin.socket")).
				Description(b.S("wiz.adv.admin.socket.desc")).
				Value(&w.cfg.Admin.Socket).
				Validate(func(s string) error {
					w.cfg.Admin.Enabled = s != ""
					return nil
				}),
			huh.NewInput().
				Title(b.S("wiz.adv.metrics.listen")).
				Description(b.S("wiz.adv.metrics.listen.desc")).
				Value(&w.cfg.Metrics.Listen).
				Validate(func(s string) error {
					if s == "" {
						w.cfg.Metrics.Enabled = false
						return nil
					}
					if err := validateListenAddr(s); err != nil {
						return err
					}
					w.cfg.Metrics.Enabled = true
					return nil
				}),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildStepTunablesToggle is a single confirm gating the tunables
// step. The basic step has already been shown by this point, so the
// confirm is specifically about the performance knobs (CC, pacing,
// buffers, etc.) and not about advanced settings in general.
func buildStepTunablesToggle(w *wizard, b *Bundle) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(b.S("wiz.tunables.toggle.title")).
				Description(b.S("wiz.tunables.toggle.desc")).
				Value(&w.showAdvanced),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildStepTunables is the performance-tunables step, gated by the
// preceding confirm. All knobs live in a single huh.Group; when the
// terminal is too short to show every field, huh scrolls within
// the group as the operator advances focus past the visible window.
func buildStepTunables(w *wizard, b *Bundle) *huh.Form {
	seedDefaults(w.cfg)
	perf := &w.cfg.Performance
	q := &w.cfg.QUIC

	pacingStr := strconv.Itoa(perf.PacingRateMbps)
	jitterStr := strconv.Itoa(perf.JitterBufferMs)
	rbufStr := strconv.Itoa(perf.ReadBuffer)
	wbufStr := strconv.Itoa(perf.WriteBuffer)
	poolStr := strconv.Itoa(q.PoolSize)
	keepAliveStr := strconv.Itoa(q.KeepAlivePeriodSec)
	idleStr := strconv.Itoa(q.MaxIdleTimeoutSec)
	pktThStr := strconv.Itoa(q.PacketThreshold)

	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title(b.S("wiz.tunables.section")).
				Description(b.S("wiz.tunables.intro.desc")),
			huh.NewSelect[string]().
				Title(b.S("wiz.adv.cc")).
				Description(b.S("wiz.adv.cc.desc")).
				Options(
					huh.NewOption("auto (try BBRv1, fallback CUBIC)", "auto"),
					huh.NewOption("cubic (RFC 9438)", "cubic"),
					huh.NewOption("bbrv1 (force, panic on fail)", "bbrv1"),
				).
				Value(&q.CongestionControl),
			huh.NewInput().
				Title(b.S("wiz.adv.pacing")).
				Description(b.S("wiz.adv.pacing.desc")).
				Value(&pacingStr).
				Validate(parseIntoIntMin(&perf.PacingRateMbps, 0)),
			huh.NewInput().
				Title(b.S("wiz.adv.jitter")).
				Description(b.S("wiz.adv.jitter.desc")).
				Value(&jitterStr).
				Validate(parseIntoIntMin(&perf.JitterBufferMs, -1)),
			huh.NewInput().
				Title(b.S("wiz.adv.rbuf")).
				Description(b.S("wiz.adv.rbuf.desc")).
				Value(&rbufStr).
				Validate(parseIntoIntMin(&perf.ReadBuffer, 0)),
			huh.NewInput().
				Title(b.S("wiz.adv.wbuf")).
				Description(b.S("wiz.adv.wbuf.desc")).
				Value(&wbufStr).
				Validate(parseIntoIntMin(&perf.WriteBuffer, 0)),
			huh.NewInput().
				Title(b.S("wiz.adv.pool")).
				Description(b.S("wiz.adv.pool.desc")).
				Value(&poolStr).
				Validate(parseIntoIntMin(&q.PoolSize, 0)),
			huh.NewInput().
				Title(b.S("wiz.adv.keepalive")).
				Description(b.S("wiz.adv.keepalive.desc")).
				Value(&keepAliveStr).
				Validate(parseIntoIntMin(&q.KeepAlivePeriodSec, 0)),
			huh.NewInput().
				Title(b.S("wiz.adv.idle")).
				Description(b.S("wiz.adv.idle.desc")).
				Value(&idleStr).
				Validate(parseIntoIntMin(&q.MaxIdleTimeoutSec, 0)),
			huh.NewInput().
				Title(b.S("wiz.adv.pkt_threshold")).
				Description(b.S("wiz.adv.pkt_threshold.desc")).
				Value(&pktThStr).
				Validate(parseIntoIntRange(&q.PacketThreshold, 1, 4096)),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// parseIntoIntRange returns a huh validator that parses s as an int,
// rejects values outside [lo, hi], and writes the parsed value to
// dst on success. Centralising the pattern makes the long advanced
// step readable and keeps the error message format consistent.
func parseIntoIntRange(dst *int, lo, hi int) func(string) error {
	return func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("must be %d..%d", lo, hi)
		}
		*dst = n
		return nil
	}
}

// parseIntoIntMin is the open-ended sibling of parseIntoIntRange.
// Used for fields with no upper cap (memory budgets, pool sizes).
func parseIntoIntMin(dst *int, lo int) func(string) error {
	return func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < lo {
			return fmt.Errorf("must be >= %d", lo)
		}
		*dst = n
		return nil
	}
}

// validateListenAddr accepts host:port or :port. The actual bind
// happens in the daemon, this just rejects clearly malformed input.
func validateListenAddr(s string) error {
	if s == "" {
		return fmt.Errorf("required")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("expected host:port (got %q)", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be 1..65535")
	}
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			// allow hostnames; the daemon resolves at start time
			if _, perr := net.LookupHost(host); perr != nil && len(host) > 253 {
				return fmt.Errorf("host too long")
			}
		}
	}
	return nil
}

// buildStepReview is the final wizard step: render a JSON preview,
// prompt for a save path, and confirm before writing.
func buildStepReview(w *wizard, b *Bundle) *huh.Form {
	preview := previewJSON(w.cfg)
	if w.savePath == "" {
		// Default to the example file name matching the chosen role so
		// the operator's first save lands at a recognisable path.
		switch w.cfg.Mode {
		case config.ModeServer:
			w.savePath = "server-config.json"
		default:
			w.savePath = "client-config.json"
		}
	}
	w.confirmSave = false

	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title(b.S("wiz.review.title")).
				Description(preview),
			huh.NewInput().
				Title(b.S("wiz.review.path")).
				Description(b.S("wiz.review.path.desc")).
				Value(&w.savePath).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("path required")
					}
					return nil
				}),
			huh.NewConfirm().
				Title(b.S("wiz.review.confirm")).
				Value(&w.confirmSave),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// previewJSON renders the working cfg as indented JSON. Used by the
// review step's note; truncated nothing — the cfg is always small.
func previewJSON(cfg *config.Config) string {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(data)
}

// saveConfig writes cfg to path, atomically (temp + rename). Validate
// is run first; failures are surfaced as the returned error so the
// operator sees them in the configSaved screen and can re-enter the
// wizard with an Esc → New.
func saveConfig(cfg *config.Config, path string) error {
	// config.Validate does not apply defaults (Load does, via setDefaults),
	// so fill the reverse-forward target default here before validating.
	// Without this, a rule saved with an empty target would fail Validate
	// with "target is required", even though the daemon would default it
	// on load. Mirrors config.setDefaults' reverse-target block.
	applyReverseTargetDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// applyReverseTargetDefaults fills the "127.0.0.1:<listen-port>" target
// default for any reverse-forward rule that omits it, mirroring
// config.setDefaults so the TUI's Validate-only save path stays
// consistent with the daemon's Load path. A malformed listen is left for
// config.Validate to report.
func applyReverseTargetDefaults(cfg *config.Config) {
	for i := range cfg.ReverseForwards {
		if cfg.ReverseForwards[i].Target != "" {
			continue
		}
		norm, _, err := config.NormalizeReverseListen(cfg.ReverseForwards[i].Listen)
		if err != nil {
			continue
		}
		if _, port, err := net.SplitHostPort(norm); err == nil {
			cfg.ReverseForwards[i].Target = net.JoinHostPort("127.0.0.1", port)
		}
	}
}

// updateForm forwards a tea.Msg to the active step's form. If the
// form transitions to StateCompleted, advance() is called; if that
// returns done == true, the wizard's terminal step has completed and
// the caller (the Config tab dispatcher) should move into configSaving.
//
// Iterative steps (currently only step_peers) are handled specially:
// on StateCompleted the scratch is committed and, if the operator
// asked to add another item, the SAME step is rebuilt rather than
// advancing. This keeps the iteration entirely inside one step
// position so the rest of the flow (predicates, abort handling) is
// unaware that a single step can complete N times.
func (w *wizard) updateForm(msg tea.Msg, b *Bundle) (done bool, cmd tea.Cmd) {
	model, c := w.form.Update(msg)
	if f, ok := model.(*huh.Form); ok {
		w.form = f
	}
	cmd = c
	if w.form.State == huh.StateCompleted {
		// On the review step the operator may have hit submit with
		// confirm=false; in that case treat it as a back-navigation
		// to the previous step rather than completing the wizard.
		if w.step == len(w.steps)-1 && !w.confirmSave {
			w.aborted = true
			return false, cmd
		}
		// Iterative step: commit current entry and decide whether to
		// loop or advance. When looping, rebuild the form so the
		// counter/title reflects the new index AND huh resets its
		// internal field state — reusing the completed form leaves
		// the previous values displayed which would surprise the
		// operator. The loop flag is read BEFORE commit clears it.
		if s := w.steps[w.step]; s.iterative {
			again := s.loop != nil && s.loop(w)
			if s.commit != nil {
				s.commit(w)
			}
			if again {
				w.form = w.applySize(s.build(w, b))
				return false, tea.Batch(cmd, w.form.Init())
			}
		}
		var nextCmd tea.Cmd
		done, nextCmd = w.advance(b)
		if nextCmd != nil {
			cmd = tea.Batch(cmd, nextCmd)
		}
	}
	return done, cmd
}
