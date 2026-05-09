package tui

import (
	"fmt"
	"strconv"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// editor drives the Config tab's "Open existing" sub-mode. Two
// phases:
//
//	phase 0 (step == 0): path prompt. The operator types the path
//	to an existing JSON config; on submit we load and validate it.
//	A load error is surfaced via loadErr; the dispatcher routes to
//	the configSaved error screen so the operator can see the
//	parser message and try again.
//
//	phase 1 (step == 1): the flat field form. All Config fields
//	the wizard exposes plus an [a] toggle that gates two
//	additional pages (common settings + tunables) — same layout
//	as buildStepAdvanced but always in-place rather than as a
//	separate step. Final group is a confirm-save.
type editor struct {
	cfg  *config.Config
	path string

	// width / height are the terminal dimensions reported by the
	// most recent tea.WindowSizeMsg. Stored on the editor so a form
	// rebuilt mid-session (path prompt → fields) is sized correctly
	// the first frame.
	width, height int

	step int
	form *huh.Form

	showAdvanced bool
	confirmSave  bool

	aborted bool
	loadErr error
}

// newEditor constructs an editor positioned at the path-prompt phase
// and returns its first init cmd. Loading the file is deferred to
// updateForm — it runs only after the operator submits the prompt.
func newEditor(b *Bundle, width, height int) (*editor, tea.Cmd) {
	e := &editor{width: width, height: height}
	e.form = e.applySize(e.buildPathPrompt(b))
	return e, e.form.Init()
}

// applySize and setSize mirror the wizard's helpers: they push the
// recorded terminal dimensions onto a fresh form (so the first
// frame wraps correctly) and propagate a WindowSizeMsg into the
// active form on terminal resize.
func (e *editor) applySize(f *huh.Form) *huh.Form {
	f = f.WithKeyMap(customFormKeyMap())
	if e.width > 0 {
		f = f.WithWidth(e.width)
	}
	if e.height > 0 {
		f = f.WithHeight(e.height)
	}
	return f
}

func (e *editor) setSize(width, height int) tea.Cmd {
	e.width = width
	e.height = height
	if e.form == nil {
		return nil
	}
	model, c := e.form.Update(tea.WindowSizeMsg{Width: width, Height: height})
	if f, ok := model.(*huh.Form); ok {
		e.form = e.applySize(f)
	}
	return c
}

// buildPathPrompt is phase 0: a single input asking for the JSON
// path. No file-existence check at validate time — the load attempt
// in updateForm produces a more useful error message (parse vs
// missing vs permission).
func (e *editor) buildPathPrompt(b *Bundle) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(b.S("config.edit.path.title")).
				Description(b.S("config.edit.path.desc")).
				Value(&e.path).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("required")
					}
					return nil
				}),
		),
	).WithShowHelp(false).WithShowErrors(true)
}

// buildFieldsForm is phase 1: the flat editor. Layout mirrors the
// wizard step ordering (general → transport → server → spoof →
// crypto → inbounds note → advanced toggle → common → tunables →
// confirm) so an operator who has used the New flow finds the same
// fields in the same place. Inbounds editing is read-only here
// (rendered as a Note summarising the current slice); multi-inbound
// list editing belongs in a follow-up that ships an iplist
// component.
func (e *editor) buildFieldsForm(b *Bundle) *huh.Form {
	seedDefaults(e.cfg)
	cfg := e.cfg

	listenPortStr := strconv.Itoa(cfg.ListenPort)
	srvPortStr := strconv.Itoa(cfg.Server.Port)
	protoStr := strconv.Itoa(cfg.Transport.ProtocolNumber)

	mtuStr := strconv.Itoa(cfg.Performance.MTU)
	chaffStr := strconv.Itoa(cfg.Obfuscation.ChaffingIntervalMs)

	pacingStr := strconv.Itoa(cfg.Performance.PacingRateMbps)
	jitterStr := strconv.Itoa(cfg.Performance.JitterBufferMs)
	rbufStr := strconv.Itoa(cfg.Performance.ReadBuffer)
	wbufStr := strconv.Itoa(cfg.Performance.WriteBuffer)
	poolStr := strconv.Itoa(cfg.QUIC.PoolSize)
	keepAliveStr := strconv.Itoa(cfg.QUIC.KeepAlivePeriodSec)
	idleStr := strconv.Itoa(cfg.QUIC.MaxIdleTimeoutSec)
	pktThStr := strconv.Itoa(cfg.QUIC.PacketThreshold)

	general := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.general")),
		huh.NewSelect[config.Mode]().
			Title(b.S("wiz.mode.title")).
			Options(
				huh.NewOption(b.S("wiz.mode.client"), config.ModeClient),
				huh.NewOption(b.S("wiz.mode.server"), config.ModeServer),
			).
			Value(&cfg.Mode),
		huh.NewInput().
			Title(b.S("config.edit.listen_port")).
			Description(b.S("config.edit.listen_port.desc")).
			Value(&listenPortStr).
			Validate(parseIntoIntMin(&cfg.ListenPort, 0)),
	)

	transport := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.transport")),
		huh.NewSelect[config.TransportType]().
			Title(b.S("wiz.transport.title")).
			Options(
				huh.NewOption("udp", config.TransportUDP),
				huh.NewOption("icmp", config.TransportICMP),
				huh.NewOption("icmpv6", config.TransportICMPv6),
				huh.NewOption("raw", config.TransportRAW),
				huh.NewOption("syn_udp", config.TransportSynUDP),
			).
			Value(&cfg.Transport.Type),
		huh.NewInput().
			Title(b.S("wiz.transport.protocol")).
			Description(b.S("wiz.transport.protocol.desc")).
			Value(&protoStr).
			Validate(func(s string) error {
				if cfg.Transport.Type != config.TransportRAW {
					return nil
				}
				return parseIntoIntRange(&cfg.Transport.ProtocolNumber, 1, 255)(s)
			}),
		huh.NewSelect[config.ICMPMode]().
			Title(b.S("wiz.transport.icmp_mode")).
			Description(b.S("wiz.transport.icmp_mode.desc")).
			Options(
				huh.NewOption("echo", config.ICMPModeEcho),
				huh.NewOption("reply", config.ICMPModeReply),
			).
			Value(&cfg.Transport.ICMPMode),
	)

	server := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.server")),
		huh.NewInput().
			Title(b.S("wiz.server.address")).
			Description(b.S("wiz.server.address.desc")).
			Value(&cfg.Server.Address).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("address required")
				}
				return nil
			}),
		huh.NewInput().
			Title(b.S("wiz.server.port")).
			Description(b.S("wiz.server.port.desc")).
			Value(&srvPortStr).
			Validate(parseIntoIntRange(&cfg.Server.Port, 1, 65535)),
	).WithHideFunc(func() bool { return cfg.Mode != config.ModeClient })

	// Scratch strings for the spoof group: bind to these then write
	// back into the plural slices via the Validate closure. Using the
	// first-element convention mirrors the wizard's single-IP MVP.
	var spoofSrcStr, spoofPeerStr, spoofClientRealStr string
	if len(cfg.Spoof.SourceIPs) > 0 {
		spoofSrcStr = cfg.Spoof.SourceIPs[0]
	}
	if len(cfg.Spoof.PeerSpoofIPs) > 0 {
		spoofPeerStr = cfg.Spoof.PeerSpoofIPs[0]
	}
	if len(cfg.Peers) > 0 {
		spoofClientRealStr = cfg.Peers[0].ClientRealIP
	}

	spoof := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.spoof")),
		huh.NewInput().
			Title(b.S("wiz.spoof.source")).
			Description(b.S("wiz.spoof.source.desc")).
			Value(&spoofSrcStr).
			Validate(func(s string) error {
				if err := validateIPv4Required(s); err != nil {
					return err
				}
				cfg.Spoof.SourceIPs = []string{s}
				return nil
			}),
		huh.NewInput().
			Title(b.S("wiz.spoof.peer")).
			Description(b.S("wiz.spoof.peer.desc")).
			Value(&spoofPeerStr).
			Validate(func(s string) error {
				if err := validateIPv4Optional(s); err != nil {
					return err
				}
				if s != "" {
					cfg.Spoof.PeerSpoofIPs = []string{s}
				}
				return nil
			}),
		huh.NewInput().
			Title(b.S("wiz.spoof.client_real")).
			Description(b.S("wiz.spoof.client_real.desc")).
			Value(&spoofClientRealStr).
			Validate(func(s string) error {
				if err := validateIPv4Optional(s); err != nil {
					return err
				}
				if s != "" && len(cfg.Peers) > 0 {
					cfg.Peers[0].ClientRealIP = s
				}
				return nil
			}),
	)

	crypto := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.crypto")),
		huh.NewInput().
			Title(b.S("wiz.crypto.peer_pub")).
			Description(b.S("wiz.crypto.peer_pub.desc")).
			Value(&cfg.Crypto.PeerPublicKey).
			Validate(validateB64PubKey),
	)

	inboundsNote := huh.NewGroup(
		huh.NewNote().
			Title(b.S("config.edit.section.inbounds")).
			Description(summariseInbounds(cfg.Inbounds, b)),
	)

	// Basic always rendered, no toggle. Tunables sit behind the
	// confirm so an operator who only wants to tweak the obvious
	// knobs (admin socket, metrics, log level) doesn't need to
	// page through congestion control + buffer sizing fields.
	basic := huh.NewGroup(
		huh.NewNote().Title(b.S("wiz.basic.section")),
		huh.NewInput().
			Title(b.S("wiz.adv.mtu")).
			Description(b.S("wiz.adv.mtu.desc")).
			Value(&mtuStr).
			Validate(parseIntoIntRange(&cfg.Performance.MTU, 1231, 1500)),
		huh.NewSelect[string]().
			Title(b.S("wiz.adv.obf.mode")).
			Description(b.S("wiz.adv.obf.mode.desc")).
			Options(
				huh.NewOption("none", string(config.ObfuscationNone)),
				huh.NewOption("standard", string(config.ObfuscationStandard)),
				huh.NewOption("paranoid", string(config.ObfuscationParanoid)),
			).
			Value(&cfg.Obfuscation.Mode),
		huh.NewInput().
			Title(b.S("wiz.adv.obf.chaff")).
			Description(b.S("wiz.adv.obf.chaff.desc")).
			Value(&chaffStr).
			Validate(parseIntoIntMin(&cfg.Obfuscation.ChaffingIntervalMs, 0)),
		huh.NewSelect[config.LogLevel]().
			Title(b.S("wiz.adv.log.level")).
			Description(b.S("wiz.adv.log.level.desc")).
			Options(
				huh.NewOption("debug", config.LogDebug),
				huh.NewOption("info", config.LogInfo),
				huh.NewOption("warn", config.LogWarn),
				huh.NewOption("error", config.LogError),
			).
			Value(&cfg.Logging.Level),
		huh.NewConfirm().
			Title(b.S("wiz.adv.security.block_private")).
			Description(b.S("wiz.adv.security.block_private.desc")).
			Value(cfg.Security.BlockPrivateTargets),
		huh.NewInput().
			Title(b.S("wiz.adv.admin.socket")).
			Description(b.S("wiz.adv.admin.socket.desc")).
			Value(&cfg.Admin.Socket).
			Validate(func(s string) error {
				cfg.Admin.Enabled = s != ""
				return nil
			}),
		huh.NewInput().
			Title(b.S("wiz.adv.metrics.listen")).
			Description(b.S("wiz.adv.metrics.listen.desc")).
			Value(&cfg.Metrics.Listen).
			Validate(func(s string) error {
				if s == "" {
					cfg.Metrics.Enabled = false
					return nil
				}
				if err := validateListenAddr(s); err != nil {
					return err
				}
				cfg.Metrics.Enabled = true
				return nil
			}),
	)

	tunablesToggle := huh.NewGroup(
		huh.NewConfirm().
			Title(b.S("wiz.tunables.toggle.title")).
			Description(b.S("wiz.tunables.toggle.desc")).
			Value(&e.showAdvanced),
	)

	tunables := huh.NewGroup(
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
			Value(&cfg.QUIC.CongestionControl),
		huh.NewInput().
			Title(b.S("wiz.adv.pacing")).
			Description(b.S("wiz.adv.pacing.desc")).
			Value(&pacingStr).
			Validate(parseIntoIntMin(&cfg.Performance.PacingRateMbps, 0)),
		huh.NewInput().
			Title(b.S("wiz.adv.jitter")).
			Description(b.S("wiz.adv.jitter.desc")).
			Value(&jitterStr).
			Validate(parseIntoIntMin(&cfg.Performance.JitterBufferMs, -1)),
		huh.NewInput().
			Title(b.S("wiz.adv.rbuf")).
			Description(b.S("wiz.adv.rbuf.desc")).
			Value(&rbufStr).
			Validate(parseIntoIntMin(&cfg.Performance.ReadBuffer, 0)),
		huh.NewInput().
			Title(b.S("wiz.adv.wbuf")).
			Description(b.S("wiz.adv.wbuf.desc")).
			Value(&wbufStr).
			Validate(parseIntoIntMin(&cfg.Performance.WriteBuffer, 0)),
		huh.NewInput().
			Title(b.S("wiz.adv.pool")).
			Description(b.S("wiz.adv.pool.desc")).
			Value(&poolStr).
			Validate(parseIntoIntMin(&cfg.QUIC.PoolSize, 0)),
		huh.NewInput().
			Title(b.S("wiz.adv.keepalive")).
			Description(b.S("wiz.adv.keepalive.desc")).
			Value(&keepAliveStr).
			Validate(parseIntoIntMin(&cfg.QUIC.KeepAlivePeriodSec, 0)),
		huh.NewInput().
			Title(b.S("wiz.adv.idle")).
			Description(b.S("wiz.adv.idle.desc")).
			Value(&idleStr).
			Validate(parseIntoIntMin(&cfg.QUIC.MaxIdleTimeoutSec, 0)),
		huh.NewInput().
			Title(b.S("wiz.adv.pkt_threshold")).
			Description(b.S("wiz.adv.pkt_threshold.desc")).
			Value(&pktThStr).
			Validate(parseIntoIntRange(&cfg.QUIC.PacketThreshold, 1, 4096)),
	).WithHideFunc(func() bool { return !e.showAdvanced })

	confirm := huh.NewGroup(
		huh.NewConfirm().
			Title(b.S("config.edit.confirm.title")).
			Description(b.S("config.edit.confirm.desc") + " " + e.path).
			Value(&e.confirmSave),
	)

	return huh.NewForm(general, transport, server, spoof, crypto, inboundsNote, basic, tunablesToggle, tunables, confirm).
		WithShowHelp(false).
		WithShowErrors(true)
}

// summariseInbounds renders the current inbounds slice as a short
// human-readable line so the operator can see what the loaded file
// has without scrolling through a JSON dump. Empty slice produces
// the "(none)" hint.
func summariseInbounds(in []config.InboundConfig, b *Bundle) string {
	if len(in) == 0 {
		return b.S("config.edit.inbounds.none")
	}
	out := ""
	for i, ib := range in {
		if i > 0 {
			out += "\n"
		}
		switch ib.Type {
		case config.InboundForward:
			out += fmt.Sprintf("• forward %s → %s", ib.Listen, ib.Target)
		default:
			out += fmt.Sprintf("• %s %s", ib.Type, ib.Listen)
		}
	}
	return out
}

// updateForm is the editor's tea.Update equivalent. Phase 0 ends
// when the path prompt completes — we attempt the load synchronously
// (config files are tiny) and either surface loadErr or transition
// to phase 1. Phase 1 ends on confirm-save = true; if the operator
// submits with confirm=false, the run is aborted (back to menu).
func (e *editor) updateForm(msg tea.Msg, b *Bundle) (done bool, cmd tea.Cmd) {
	model, c := e.form.Update(msg)
	if f, ok := model.(*huh.Form); ok {
		e.form = f
	}
	if e.form.State != huh.StateCompleted {
		return false, c
	}
	switch e.step {
	case 0:
		cfg, err := config.Load(e.path)
		if err != nil {
			e.loadErr = err
			return true, c
		}
		e.cfg = cfg
		e.step = 1
		e.form = e.applySize(e.buildFieldsForm(b))
		init := e.form.Init()
		if init != nil {
			c = tea.Batch(c, init)
		}
		return false, c
	case 1:
		if !e.confirmSave {
			e.aborted = true
			return false, c
		}
		return true, c
	}
	return false, c
}
