package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// maxEditorPeers caps how many server-side peers the flat-form editor
// supports in one session. Picked so the form fits on a typical
// terminal even when every slot is unfolded; operators with more peers
// should hand-edit the JSON. Validation is in config.Validate, so an
// over-large file loaded via Open shows the actual existing peers
// only up to this cap (the rest stay in cfg.Peers untouched).
const maxEditorPeers = 16

// maxEditorReverse caps how many server-side reverse_forwards rules the
// flat-form editor shows in one session. Same rationale as
// maxEditorPeers; operators with more rules hand-edit the JSON.
const maxEditorReverse = 16

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

	// peerCount is the number of server-side peer slots the operator
	// wants visible in the form. Initialized from len(cfg.Peers) on
	// load; finalize() truncates cfg.Peers to this value before save.
	// Increasing it past the original count exposes empty slots that
	// must be filled before the save validates.
	peerCount int

	// peerSpoofCsv[i] is a per-slot scratch string for the
	// comma-separated PeerSpoofIPs of peer i. Bound to the huh input
	// so multi-IP entries survive re-renders; finalize() splits each
	// non-empty entry into PeerSpoofIPs at save time.
	peerSpoofCsv [maxEditorPeers]string

	// revCount is the number of server-side reverse_forwards slots the
	// operator wants visible. Initialized from len(cfg.ReverseForwards)
	// on load; finalize() truncates the slice to this value before save.
	revCount int

	// reverseAllowCsv is the client-side scratch string for the
	// comma-separated reverse_accept.allow list. finalize() splits it
	// into cfg.ReverseAccept.Allow when the policy is enabled.
	reverseAllowCsv string

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

	// Scratch strings for the client-mode spoof group: bind to these
	// then write back into the plural slices via the Validate closure.
	// Using the first-element convention mirrors the wizard's single-IP
	// MVP. Server mode hides this group entirely — the per-peer
	// identity lives in cfg.Peers[i] and is edited via the Peers section
	// below.
	var spoofSrcStr, spoofPeerStr string
	if len(cfg.Spoof.SourceIPs) > 0 {
		spoofSrcStr = cfg.Spoof.SourceIPs[0]
	}
	if len(cfg.Spoof.PeerSpoofIPs) > 0 {
		spoofPeerStr = cfg.Spoof.PeerSpoofIPs[0]
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
	).WithHideFunc(func() bool { return cfg.Mode == config.ModeServer })

	// Peers section is server-only at render time, but the slots are
	// pre-grown unconditionally so peerSlotGroups below can safely
	// bind to cfg.Peers[i].* even when client mode hides every group.
	// finalize() scrubs the stubs back out for client mode before save.
	if cfg.Mode == config.ModeServer {
		if e.peerCount == 0 {
			e.peerCount = len(cfg.Peers)
		}
		if e.peerCount > maxEditorPeers {
			e.peerCount = maxEditorPeers
		}
	}
	for len(cfg.Peers) < maxEditorPeers {
		cfg.Peers = append(cfg.Peers, config.PeerConfig{})
	}
	if cfg.Mode == config.ModeServer {
		// Seed the per-slot CSV scratch from any existing PeerSpoofIPs.
		// Only seed slots we haven't touched yet (empty scratch) so a
		// re-render mid-edit doesn't clobber half-typed input.
		for i := 0; i < maxEditorPeers; i++ {
			if e.peerSpoofCsv[i] == "" {
				e.peerSpoofCsv[i] = strings.Join(cfg.Peers[i].PeerSpoofIPs, ", ")
			}
		}
	}

	peerCountStr := strconv.Itoa(e.peerCount)
	peerCountGroup := huh.NewGroup(
		huh.NewNote().
			Title(b.S("config.edit.section.peers")).
			Description(b.S("config.edit.section.peers.desc")),
		huh.NewInput().
			Title(b.S("config.edit.peers.count")).
			Description(b.S("config.edit.peers.count.desc")).
			Value(&peerCountStr).
			Validate(parseIntoIntRange(&e.peerCount, 0, maxEditorPeers)),
	).WithHideFunc(func() bool { return cfg.Mode != config.ModeServer })

	peerSlotGroups := make([]*huh.Group, maxEditorPeers)
	for i := 0; i < maxEditorPeers; i++ {
		idx := i
		peerSlotGroups[i] = huh.NewGroup(
			huh.NewNote().Title(fmt.Sprintf(b.S("config.edit.peers.peer_n"), idx+1)),
			huh.NewInput().
				Title(b.S("wiz.peers.name")).
				Description(b.S("wiz.peers.name.desc")).
				Value(&cfg.Peers[idx].Name).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("required")
					}
					if strings.ContainsAny(s, " \t\n") {
						return fmt.Errorf("no whitespace in name")
					}
					return nil
				}),
			huh.NewInput().
				Title(b.S("wiz.peers.peer_pub")).
				Description(b.S("wiz.peers.peer_pub.desc")).
				Value(&cfg.Peers[idx].PeerPublicKey).
				Validate(validateB64PubKey),
			huh.NewInput().
				Title(b.S("wiz.peers.client_real")).
				Description(b.S("wiz.peers.client_real.desc")).
				Value(&cfg.Peers[idx].ClientRealIP).
				Validate(validateIPv4Required),
			huh.NewInput().
				Title(b.S("wiz.peers.spoof_ips")).
				Description(b.S("wiz.peers.spoof_ips.desc")).
				Value(&e.peerSpoofCsv[idx]).
				Validate(validateIPv4CSVRequired),
		).WithHideFunc(func() bool {
			return cfg.Mode != config.ModeServer || idx >= e.peerCount
		})
	}

	// Reverse forwards (server only). Mirrors the peers section: a count
	// input gates how many slots render, and each visible slot binds
	// directly into cfg.ReverseForwards[i]. Slots are pre-grown to the
	// cap unconditionally so the bindings are valid even in client mode
	// (where every group is hidden and finalize() scrubs the stubs).
	if cfg.Mode == config.ModeServer {
		if e.revCount == 0 {
			e.revCount = len(cfg.ReverseForwards)
		}
		if e.revCount > maxEditorReverse {
			e.revCount = maxEditorReverse
		}
	}
	for len(cfg.ReverseForwards) < maxEditorReverse {
		cfg.ReverseForwards = append(cfg.ReverseForwards, config.ReverseForwardConfig{})
	}

	revCountStr := strconv.Itoa(e.revCount)
	revCountGroup := huh.NewGroup(
		huh.NewNote().
			Title(b.S("config.edit.section.reverse")).
			Description(b.S("config.edit.section.reverse.desc")),
		huh.NewInput().
			Title(b.S("config.edit.reverse.count")).
			Description(b.S("config.edit.reverse.count.desc")).
			Value(&revCountStr).
			Validate(parseIntoIntRange(&e.revCount, 0, maxEditorReverse)),
	).WithHideFunc(func() bool { return cfg.Mode != config.ModeServer })

	revSlotGroups := make([]*huh.Group, maxEditorReverse)
	for i := 0; i < maxEditorReverse; i++ {
		idx := i
		revSlotGroups[i] = huh.NewGroup(
			huh.NewNote().Title(fmt.Sprintf(b.S("config.edit.reverse.rule_n"), idx+1)),
			huh.NewInput().
				Title(b.S("wiz.reverse.listen")).
				Description(b.S("wiz.reverse.listen.desc")).
				Value(&cfg.ReverseForwards[idx].Listen).
				Validate(validateReverseListen),
			huh.NewInput().
				Title(b.S("wiz.reverse.target")).
				Description(b.S("wiz.reverse.target.desc")).
				Value(&cfg.ReverseForwards[idx].Target).
				Validate(validateReverseTargetOptional),
			// Peer is a free-text input here rather than a Select: the
			// flat editor builds once, so a Select would show stale
			// options if the operator renamed a peer in the same pass.
			// Non-empty is checked inline; the authoritative "peer must
			// reference an entry in peers[]" cross-check is config.Validate
			// on save (mirrors how the editor defers peer disjointness).
			huh.NewInput().
				Title(b.S("wiz.reverse.peer")).
				Description(b.S("wiz.reverse.peer.desc")).
				Value(&cfg.ReverseForwards[idx].Peer).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("required")
					}
					return nil
				}),
		).WithHideFunc(func() bool {
			return cfg.Mode != config.ModeServer || idx >= e.revCount
		})
	}

	// Reverse accept (client only): enabled toggle + comma-separated
	// allow-list. The allow input requires entries only when enabled
	// (config.Validate rejects an enabled-but-empty policy). Seed the
	// scratch from any existing Allow so a round-trip preserves it.
	if e.reverseAllowCsv == "" && len(cfg.ReverseAccept.Allow) > 0 {
		e.reverseAllowCsv = strings.Join(cfg.ReverseAccept.Allow, ", ")
	}
	reverseAccept := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.reverse_accept")),
		huh.NewConfirm().
			Title(b.S("wiz.reverse_accept.enabled")).
			Description(b.S("wiz.reverse_accept.enabled.desc")).
			Value(&cfg.ReverseAccept.Enabled),
		huh.NewInput().
			Title(b.S("wiz.reverse_accept.allow")).
			Description(b.S("wiz.reverse_accept.allow.desc")).
			Value(&e.reverseAllowCsv).
			Validate(func(s string) error {
				if !cfg.ReverseAccept.Enabled {
					return nil
				}
				return validateReverseAllowCSVRequired(s)
			}),
	).WithHideFunc(func() bool { return cfg.Mode == config.ModeServer })

	// Crypto section: hide the peer-public-key input in server mode
	// (lives per-peer in the Peers section above).
	crypto := huh.NewGroup(
		huh.NewNote().Title(b.S("config.edit.section.crypto")),
		huh.NewInput().
			Title(b.S("wiz.crypto.peer_pub")).
			Description(b.S("wiz.crypto.peer_pub.desc")).
			Value(&cfg.Crypto.PeerPublicKey).
			Validate(validateB64PubKey),
	).WithHideFunc(func() bool { return cfg.Mode == config.ModeServer })

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

	groups := []*huh.Group{general, transport, server, spoof, peerCountGroup}
	groups = append(groups, peerSlotGroups...)
	groups = append(groups, revCountGroup)
	groups = append(groups, revSlotGroups...)
	groups = append(groups, crypto, inboundsNote, reverseAccept, basic, tunablesToggle, tunables, confirm)
	return huh.NewForm(groups...).
		WithShowHelp(false).
		WithShowErrors(true)
}

// finalize folds the editor's per-slot scratch state into cfg before
// save. Server mode: truncate cfg.Peers to e.peerCount (so any stub
// slots pre-grown by buildFieldsForm don't leak into the saved file)
// and parse each visible slot's CSV scratch into PeerSpoofIPs.
// Client mode: nothing to fold — the spoof inputs write directly into
// cfg.Spoof via their Validate closures.
//
// The huh CSV validator on the form has already rejected malformed
// input by the time we get here, so the parse cannot fail. We still
// double-check the count matches a non-zero slice length to surface a
// clear error if the operator decremented count to 0 in server mode.
func (e *editor) finalize() error {
	if e.cfg == nil {
		return nil
	}
	if e.cfg.Mode != config.ModeServer {
		// Client-mode safety: if the form pre-grew cfg.Peers /
		// cfg.ReverseForwards stubs (server-only sections), drop them so
		// the saved file does not carry empty entries. reverse_accept is
		// the client-side reverse policy: fold the allow-list scratch when
		// enabled, clear it otherwise.
		e.cfg.Peers = nil
		e.cfg.ReverseForwards = nil
		if e.cfg.ReverseAccept.Enabled {
			e.cfg.ReverseAccept.Allow = parseReverseAllowCSV(e.reverseAllowCsv)
		} else {
			e.cfg.ReverseAccept.Allow = nil
		}
		return nil
	}
	if e.peerCount < 1 {
		return fmt.Errorf("server mode requires at least one peer (count = %d)", e.peerCount)
	}
	if e.peerCount > len(e.cfg.Peers) {
		return fmt.Errorf("internal: peerCount=%d exceeds pre-grown peers slot count %d", e.peerCount, len(e.cfg.Peers))
	}
	for i := 0; i < e.peerCount; i++ {
		e.cfg.Peers[i].PeerSpoofIPs = parseIPv4CSV(e.peerSpoofCsv[i])
	}
	e.cfg.Peers = e.cfg.Peers[:e.peerCount]

	// Truncate reverse forwards to the visible count (mirrors peers), so
	// pre-grown stubs don't leak into the saved file. reverse_accept is
	// client-only; scrub any stub the pre-grow left in server mode.
	if e.revCount > len(e.cfg.ReverseForwards) {
		return fmt.Errorf("internal: revCount=%d exceeds pre-grown reverse slot count %d", e.revCount, len(e.cfg.ReverseForwards))
	}
	e.cfg.ReverseForwards = e.cfg.ReverseForwards[:e.revCount]
	e.cfg.ReverseAccept = config.ReverseAcceptConfig{}
	return nil
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
