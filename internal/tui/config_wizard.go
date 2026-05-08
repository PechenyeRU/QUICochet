package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
)

// configState enumerates the Config tab's sub-views. The Config tab is
// itself a small state machine because the editing flow has more
// states than other tabs (menu → wizard → saved with success/error).
type configState int

const (
	configMenu configState = iota
	configWizard
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
}

// stepBuilder pairs a builder with an optional skip predicate. When
// shouldRun returns false, advance() loops past the step entirely
// without rendering an empty form. This keeps the pure-data step list
// declarative while letting role-conditional steps (e.g. server config
// is client-only) hide cleanly.
type stepBuilder struct {
	build     func(w *wizard, b *Bundle) *huh.Form
	shouldRun func(w *wizard) bool // nil == always run
}

func newWizard(b *Bundle) (*wizard, tea.Cmd) {
	cfg := &config.Config{}
	w := &wizard{
		cfg: cfg,
		steps: []stepBuilder{
			{build: buildStepMode},
			{build: buildStepTransport},
			{build: buildStepServer, shouldRun: clientOnly},
			{build: buildStepSpoof},
			{build: buildStepCrypto},
			{build: buildStepInbounds, shouldRun: clientOnly},
			{build: buildStepAdvancedToggle},
			{build: buildStepAdvanced, shouldRun: advancedRequested},
			{build: buildStepReview},
		},
	}
	w.form = w.steps[0].build(w, b)
	// huh.Form needs Init() to set initial focus and emit its first
	// render command; without it the first frame is blank and the
	// operator has to press an arrow key to "wake" the form.
	return w, w.form.Init()
}

// clientOnly hides a step in server mode. Used by step_server and
// (later) step_inbounds.
func clientOnly(w *wizard) bool {
	return w.cfg.Mode == config.ModeClient || w.cfg.Mode == ""
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
		w.form = s.build(w, b)
		return false, w.form.Init()
	}
}

// consolidate copies wizard scratch state (crypto choice, inbound
// choice) into cfg. Called both before each step transition and once
// more on the final advance (so the review preview reflects the last
// edits).
func (w *wizard) consolidate() {
	if w.cryptoChoice == "generate" && w.generatedKP != nil {
		w.cfg.Crypto.PrivateKey = w.generatedKP.PrivateKeyBase64()
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
}

// advancedRequested gates step_advanced behind the toggle. The
// operator sees the advanced fields only when they explicitly opt in,
// so the New flow stays under a minute for the common case.
func advancedRequested(w *wizard) bool { return w.showAdvanced }

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

// buildStepSpoof captures source/peer/(server-side) client-real IPs.
// MVP single-IP only — multi-IP list builder lands with the iplist
// component in a later sub-stage. For now mode-conditional: server mode
// also collects the client-real-IP (where reply traffic is sent).
func buildStepSpoof(w *wizard, b *Bundle) *huh.Form {
	sp := &w.cfg.Spoof

	src := huh.NewInput().
		Title(b.S("wiz.spoof.source")).
		Description(b.S("wiz.spoof.source.desc")).
		Value(&sp.SourceIP).
		Validate(validateIPv4Required)

	peer := huh.NewInput().
		Title(b.S("wiz.spoof.peer")).
		Description(b.S("wiz.spoof.peer.desc")).
		Value(&sp.PeerSpoofIP).
		Validate(validateIPv4Optional)

	clientReal := huh.NewInput().
		Title(b.S("wiz.spoof.client_real")).
		Description(b.S("wiz.spoof.client_real.desc")).
		Value(&sp.ClientRealIP).
		Validate(validateIPv4Required)

	groups := []*huh.Group{
		huh.NewGroup(src, peer),
		huh.NewGroup(clientReal).
			WithHideFunc(func() bool { return w.cfg.Mode != config.ModeServer }),
	}
	return huh.NewForm(groups...).WithShowHelp(false).WithShowErrors(true)
}

// buildStepCrypto offers two paths: generate a fresh keypair (the
// public key is shown immediately so the operator can hand it to the
// peer) or paste an existing private + peer public. The generated
// keypair is cached on the wizard so re-rendering the form during
// validation doesn't churn keys.
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

	gen := huh.NewGroup(
		huh.NewNote().
			Title(b.S("wiz.crypto.generated_title")).
			Description(b.S("wiz.crypto.generated_pub")+"\n\n"+pubKey+"\n\n"+b.S("wiz.crypto.share_with_peer")),
		huh.NewInput().
			Title(b.S("wiz.crypto.peer_pub")).
			Description(b.S("wiz.crypto.peer_pub.desc")).
			Value(&w.cfg.Crypto.PeerPublicKey).
			Validate(validateB64PubKey),
	).WithHideFunc(func() bool { return w.cryptoChoice != "generate" })

	paste := huh.NewGroup(
		huh.NewInput().
			Title(b.S("wiz.crypto.private")).
			Description(b.S("wiz.crypto.private.desc")).
			Value(&w.cfg.Crypto.PrivateKey).
			Validate(validateB64PrivKey),
		huh.NewInput().
			Title(b.S("wiz.crypto.peer_pub")).
			Description(b.S("wiz.crypto.peer_pub.desc")).
			Value(&w.cfg.Crypto.PeerPublicKey).
			Validate(validateB64PubKey),
	).WithHideFunc(func() bool { return w.cryptoChoice != "paste" })

	return huh.NewForm(choice, gen, paste).WithShowHelp(false).WithShowErrors(true)
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

// buildStepAdvancedToggle is a single confirm — keeping the advanced
// fields off the default path lets the operator finish New in under
// a minute. When they say yes, advance() runs buildStepAdvanced;
// when they say no, advance() skips it.
func buildStepAdvancedToggle(w *wizard, b *Bundle) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(b.S("wiz.adv.toggle.title")).
				Description(b.S("wiz.adv.toggle.desc")).
				Value(&w.showAdvanced),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildStepAdvanced exposes the fields a real deployment usually
// touches: MTU, obfuscation mode, security private-target guard,
// admin socket, metrics listener, and log level. Anything more
// niche stays at default and can be edited via the flat-form Edit
// sub-mode (Stage 2.4).
func buildStepAdvanced(w *wizard, b *Bundle) *huh.Form {
	perf := &w.cfg.Performance
	mtuStr := strconv.Itoa(perf.MTU)

	chaffStr := strconv.Itoa(w.cfg.Obfuscation.ChaffingIntervalMs)

	if w.cfg.Logging.Level == "" {
		w.cfg.Logging.Level = config.LogInfo
	}
	if w.cfg.Obfuscation.Mode == "" {
		w.cfg.Obfuscation.Mode = string(config.ObfuscationStandard)
	}
	if w.cfg.Security.BlockPrivateTargets == nil {
		def := true
		w.cfg.Security.BlockPrivateTargets = &def
	}

	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(b.S("wiz.adv.mtu")).
				Description(b.S("wiz.adv.mtu.desc")).
				Value(&mtuStr).
				Validate(func(s string) error {
					n, err := strconv.Atoi(s)
					if err != nil || n < 1231 || n > 1500 {
						return fmt.Errorf("must be 1231..1500")
					}
					perf.MTU = n
					return nil
				}),
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
				Validate(func(s string) error {
					n, err := strconv.Atoi(s)
					if err != nil || n < 0 {
						return fmt.Errorf("must be a non-negative integer")
					}
					w.cfg.Obfuscation.ChaffingIntervalMs = n
					return nil
				}),
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
					if s == "" {
						w.cfg.Admin.Enabled = false
						return nil
					}
					w.cfg.Admin.Enabled = true
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

// updateForm forwards a tea.Msg to the active step's form. If the
// form transitions to StateCompleted, advance() is called; if that
// returns done == true, the wizard's terminal step has completed and
// the caller (the Config tab dispatcher) should move into configSaving.
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
		var nextCmd tea.Cmd
		done, nextCmd = w.advance(b)
		if nextCmd != nil {
			cmd = tea.Batch(cmd, nextCmd)
		}
	}
	return done, cmd
}
