package tui

import (
	"testing"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// TestSeedDefaultsFillsZeros checks the helper substitutes the
// sensible runtime defaults for every numeric/string field the
// wizard's advanced step exposes. catches a regression that caused
// the wizard to display "0" for MTU and other tuned defaults.
func TestSeedDefaultsFillsZeros(t *testing.T) {
	cfg := &config.Config{}
	seedDefaults(cfg)

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"MTU", cfg.Performance.MTU, 1400},
		{"BufferSize", cfg.Performance.BufferSize, 65535},
		{"ReadBuffer", cfg.Performance.ReadBuffer, 32 * 1024 * 1024},
		{"WriteBuffer", cfg.Performance.WriteBuffer, 32 * 1024 * 1024},
		{"KeepAlive", cfg.QUIC.KeepAlivePeriodSec, 5},
		{"IdleTimeout", cfg.QUIC.MaxIdleTimeoutSec, 10},
		{"PoolSize", cfg.QUIC.PoolSize, 8},
		{"PacketThreshold", cfg.QUIC.PacketThreshold, 128},
		{"CongestionControl", cfg.QUIC.CongestionControl, "auto"},
		{"ObfMode", cfg.Obfuscation.Mode, "standard"},
		{"ChaffMs", cfg.Obfuscation.ChaffingIntervalMs, 50},
		{"LogLevel", cfg.Logging.Level, config.LogInfo},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
	if cfg.Security.BlockPrivateTargets == nil || !*cfg.Security.BlockPrivateTargets {
		t.Errorf("BlockPrivateTargets should default to true, got %v", cfg.Security.BlockPrivateTargets)
	}
}

// TestSeedDefaultsPreservesExplicit confirms a non-zero value is
// not clobbered. lets an operator drop into the wizard with a
// hand-edited cfg and not have their override silently reset.
func TestSeedDefaultsPreservesExplicit(t *testing.T) {
	cfg := &config.Config{}
	cfg.Performance.MTU = 1280
	cfg.QUIC.PoolSize = 4
	cfg.Obfuscation.Mode = "paranoid"
	seedDefaults(cfg)

	if cfg.Performance.MTU != 1280 {
		t.Errorf("MTU got overwritten: %d", cfg.Performance.MTU)
	}
	if cfg.QUIC.PoolSize != 4 {
		t.Errorf("PoolSize got overwritten: %d", cfg.QUIC.PoolSize)
	}
	if cfg.Obfuscation.Mode != "paranoid" {
		t.Errorf("ObfMode got overwritten: %s", cfg.Obfuscation.Mode)
	}
}

// TestConsolidateInboundSocks confirms that the wizard's inbound
// scratch state (choice + listen) is folded into cfg.Inbounds as a
// single SOCKS entry on consolidate(), and that re-running consolidate
// is idempotent (the slice doesn't keep growing on re-entry).
func TestConsolidateInboundSocks(t *testing.T) {
	w := &wizard{
		cfg:           &config.Config{},
		inboundChoice: "socks",
		inboundListen: "127.0.0.1:1080",
	}
	w.consolidate()
	if len(w.cfg.Inbounds) != 1 {
		t.Fatalf("inbounds len = %d, want 1", len(w.cfg.Inbounds))
	}
	got := w.cfg.Inbounds[0]
	if got.Type != config.InboundSocks {
		t.Errorf("type = %q, want %q", got.Type, config.InboundSocks)
	}
	if got.Listen != "127.0.0.1:1080" {
		t.Errorf("listen = %q, want 127.0.0.1:1080", got.Listen)
	}
	if got.Target != "" {
		t.Errorf("socks should not set target, got %q", got.Target)
	}

	// Idempotent: running consolidate again must not duplicate.
	w.consolidate()
	if len(w.cfg.Inbounds) != 1 {
		t.Errorf("idempotency broken: len = %d after second consolidate", len(w.cfg.Inbounds))
	}
}

// TestConsolidateInboundForward checks the forward branch carries
// both Listen and Target, distinguishing it from the socks case.
func TestConsolidateInboundForward(t *testing.T) {
	w := &wizard{
		cfg:           &config.Config{},
		inboundChoice: "forward",
		inboundListen: "127.0.0.1:8443",
		inboundTarget: "203.0.113.10:443",
	}
	w.consolidate()
	if len(w.cfg.Inbounds) != 1 {
		t.Fatalf("inbounds len = %d, want 1", len(w.cfg.Inbounds))
	}
	got := w.cfg.Inbounds[0]
	if got.Type != config.InboundForward {
		t.Errorf("type = %q, want %q", got.Type, config.InboundForward)
	}
	if got.Target != "203.0.113.10:443" {
		t.Errorf("target = %q, want 203.0.113.10:443", got.Target)
	}
}

// TestConsolidateInboundSkip leaves cfg.Inbounds empty so the
// daemon can be started against no local listener (server mode
// default, or chained client setups that get inbounds applied
// later via Open+Edit).
func TestConsolidateInboundSkip(t *testing.T) {
	w := &wizard{
		cfg:           &config.Config{},
		inboundChoice: "skip",
	}
	w.consolidate()
	if len(w.cfg.Inbounds) != 0 {
		t.Errorf("skip should produce zero inbounds, got %d", len(w.cfg.Inbounds))
	}
}

// TestStepIterationClientFull covers the longest path: client mode,
// tunables toggle on. Asserts the wizard reaches the review step
// after exactly the expected number of transitions and that the
// basic step renders before the toggle (cappy explicitly asked for
// this ordering: basic always shown, tunables behind the confirm).
func TestStepIterationClientFull(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	w, _ := newWizard(b, 0, 0)
	w.cfg.Mode = config.ModeClient
	w.showAdvanced = true

	// Client-mode visible steps. peers / reverse-toggle /
	// reverse-forwards are server-only (skipped here); reverse-accept is
	// client-only (shown, right after inbounds).
	want := []string{
		"mode", "transport", "server", "spoof", "crypto",
		"inbounds", "reverse-accept", "basic", "tunables-toggle", "tunables", "review",
	}
	got := stepNamesForCfg(w)
	if len(got) != len(want) {
		t.Fatalf("step count = %d, want %d (%v)", len(got), len(want), got)
	}
	// Spot-check the critical ordering: basic precedes tunables-toggle.
	basicIdx := indexOfStr(got, "basic")
	toggleIdx := indexOfStr(got, "tunables-toggle")
	if basicIdx < 0 || toggleIdx < 0 || basicIdx > toggleIdx {
		t.Errorf("basic must be before tunables-toggle; basic@%d toggle@%d", basicIdx, toggleIdx)
	}
	// peers must NOT be in the client visible list.
	if indexOfStr(got, "peers") != -1 {
		t.Errorf("peers must be server-only; got it in client-mode list: %v", got)
	}
	// reverse-toggle / reverse-forwards are server-only.
	if indexOfStr(got, "reverse-toggle") != -1 || indexOfStr(got, "reverse-forwards") != -1 {
		t.Errorf("reverse forwards steps must be server-only; got them in client-mode list: %v", got)
	}
	// reverse-accept is client-only and must appear.
	if indexOfStr(got, "reverse-accept") == -1 {
		t.Errorf("reverse-accept must be in client-mode list: %v", got)
	}
}

// TestStepIterationServerSkipsClientOnly: server mode hides server,
// spoof, and inbounds (clientOnly). It runs peers (serverOnly)
// instead. Tunables toggle off — tunables step also hidden. Basic
// still always shown.
func TestStepIterationServerSkipsClientOnly(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	w, _ := newWizard(b, 0, 0)
	w.cfg.Mode = config.ModeServer
	w.showAdvanced = false

	// reverse-toggle is server-only and always shown; reverse-forwards is
	// gated behind the toggle (off here) so it stays hidden. reverse-accept
	// is client-only and skipped.
	want := []string{"mode", "transport", "peers", "crypto", "reverse-toggle", "basic", "tunables-toggle", "review"}
	got := stepNamesForCfg(w)
	if len(got) != len(want) {
		t.Fatalf("server step count = %d, want %d (got %v)", len(got), len(want), got)
	}
	if indexOfStr(got, "spoof") != -1 {
		t.Errorf("spoof must be client-only; got it in server-mode list: %v", got)
	}
	if indexOfStr(got, "peers") == -1 {
		t.Errorf("peers must be in server-mode list: %v", got)
	}
	if indexOfStr(got, "reverse-accept") != -1 {
		t.Errorf("reverse-accept must be client-only; got it in server-mode list: %v", got)
	}
	if indexOfStr(got, "reverse-forwards") != -1 {
		t.Errorf("reverse-forwards must stay hidden when the toggle is off: %v", got)
	}
}

// TestStepIterationServerReverseForwardsShown: with the reverse toggle
// on, the iterative reverse-forwards step becomes visible right after
// the toggle. Verifies reverseForwardsRequested gating.
func TestStepIterationServerReverseForwardsShown(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	w, _ := newWizard(b, 0, 0)
	w.cfg.Mode = config.ModeServer
	w.wantReverseForwards = true

	got := stepNamesForCfg(w)
	ti := indexOfStr(got, "reverse-toggle")
	fi := indexOfStr(got, "reverse-forwards")
	if ti == -1 || fi == -1 {
		t.Fatalf("both reverse steps must be visible when toggle on: %v", got)
	}
	if fi != ti+1 {
		t.Errorf("reverse-forwards must immediately follow reverse-toggle; toggle@%d forwards@%d", ti, fi)
	}
}

// TestCommitPeerAccumulates exercises the iterative peers step: each
// call to commitCurrentPeer must append a new entry into cfg.Peers,
// reset the scratch fields, and clear addAnotherPeer so a re-render
// of the same step starts blank.
func TestCommitPeerAccumulates(t *testing.T) {
	w := &wizard{cfg: &config.Config{Mode: config.ModeServer}}
	w.peerName = "alpha"
	w.peerPub = "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	w.peerClientReal = "203.0.113.10"
	w.peerSpoofCsv = "192.168.10.79, 192.168.10.80"
	w.addAnotherPeer = true
	w.commitCurrentPeer()

	if len(w.cfg.Peers) != 1 {
		t.Fatalf("after first commit, len(Peers) = %d, want 1", len(w.cfg.Peers))
	}
	got := w.cfg.Peers[0]
	if got.Name != "alpha" {
		t.Errorf("peer[0].Name = %q, want alpha", got.Name)
	}
	if len(got.PeerSpoofIPs) != 2 {
		t.Fatalf("peer[0].PeerSpoofIPs = %v, want 2 entries", got.PeerSpoofIPs)
	}
	if got.PeerSpoofIPs[0] != "192.168.10.79" || got.PeerSpoofIPs[1] != "192.168.10.80" {
		t.Errorf("peer[0].PeerSpoofIPs = %v, want [192.168.10.79 192.168.10.80]", got.PeerSpoofIPs)
	}

	// Scratch must be reset, addAnotherPeer flipped back so the next
	// loop iteration starts with the confirm at false.
	if w.peerName != "" || w.peerPub != "" || w.peerClientReal != "" || w.peerSpoofCsv != "" {
		t.Errorf("scratch not reset: name=%q pub=%q real=%q csv=%q",
			w.peerName, w.peerPub, w.peerClientReal, w.peerSpoofCsv)
	}
	if w.addAnotherPeer {
		t.Errorf("addAnotherPeer not reset")
	}

	// Second commit grows to 2, validating idempotency of the loop.
	w.peerName = "bravo"
	w.peerPub = "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	w.peerClientReal = "203.0.113.11"
	w.peerSpoofCsv = "192.168.10.81"
	w.commitCurrentPeer()
	if len(w.cfg.Peers) != 2 {
		t.Fatalf("after second commit, len(Peers) = %d, want 2", len(w.cfg.Peers))
	}
	if w.cfg.Peers[1].Name != "bravo" {
		t.Errorf("peer[1].Name = %q, want bravo", w.cfg.Peers[1].Name)
	}
}

// TestConsolidateServerScrubsClientFields: switching mid-wizard from
// client → server must clear cfg.Spoof.* and cfg.Crypto.PeerPublicKey
// because the validator hard-fails if either is set in server mode.
func TestConsolidateServerScrubsClientFields(t *testing.T) {
	w := &wizard{
		cfg: &config.Config{
			Mode: config.ModeServer,
			Spoof: config.SpoofConfig{
				SourceIPs:    []string{"192.168.10.79"},
				PeerSpoofIPs: []string{"192.168.10.80"},
			},
			Crypto: config.CryptoConfig{
				PeerPublicKey: "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
		},
	}
	w.consolidate()
	if len(w.cfg.Spoof.SourceIPs) != 0 || len(w.cfg.Spoof.PeerSpoofIPs) != 0 {
		t.Errorf("server-mode consolidate must clear spoof: %+v", w.cfg.Spoof)
	}
	if w.cfg.Crypto.PeerPublicKey != "" {
		t.Errorf("server-mode consolidate must clear crypto.peer_public_key: %q", w.cfg.Crypto.PeerPublicKey)
	}
}

// TestCommitReverseForwardAccumulates exercises the iterative
// reverse-forwards step: each commit appends a rule (target preserved as
// typed, including empty for the daemon default), resets the scratch, and
// clears addAnotherReverse.
func TestCommitReverseForwardAccumulates(t *testing.T) {
	w := &wizard{cfg: &config.Config{Mode: config.ModeServer}}
	w.revListen = "0.0.0.0:8443"
	w.revTarget = "127.0.0.1:8443"
	w.revPeer = "laptop"
	w.addAnotherReverse = true
	w.commitCurrentReverseForward()

	if len(w.cfg.ReverseForwards) != 1 {
		t.Fatalf("after first commit, len(ReverseForwards) = %d, want 1", len(w.cfg.ReverseForwards))
	}
	got := w.cfg.ReverseForwards[0]
	if got.Listen != "0.0.0.0:8443" || got.Target != "127.0.0.1:8443" || got.Peer != "laptop" {
		t.Errorf("rule[0] = %+v, want {0.0.0.0:8443 127.0.0.1:8443 laptop}", got)
	}
	if w.revListen != "" || w.revTarget != "" || w.revPeer != "" || w.addAnotherReverse {
		t.Errorf("scratch not reset: listen=%q target=%q peer=%q add=%v",
			w.revListen, w.revTarget, w.revPeer, w.addAnotherReverse)
	}

	// Second rule with empty target: preserved empty (daemon defaults it).
	w.revListen = ":9000"
	w.revPeer = "phone"
	w.commitCurrentReverseForward()
	if len(w.cfg.ReverseForwards) != 2 {
		t.Fatalf("after second commit, len = %d, want 2", len(w.cfg.ReverseForwards))
	}
	if w.cfg.ReverseForwards[1].Target != "" {
		t.Errorf("rule[1].Target = %q, want empty (daemon default)", w.cfg.ReverseForwards[1].Target)
	}
}

// TestConsolidateReverseAcceptClient: an enabled client policy folds the
// scratch CSV into Allow; the operation is idempotent, and disabling
// clears the list.
func TestConsolidateReverseAcceptClient(t *testing.T) {
	w := &wizard{
		cfg:             &config.Config{Mode: config.ModeClient},
		reverseAllowCsv: "127.0.0.1:8443, 10.0.0.5",
	}
	w.cfg.ReverseAccept.Enabled = true
	w.consolidate()
	if got := w.cfg.ReverseAccept.Allow; len(got) != 2 || got[0] != "127.0.0.1:8443" || got[1] != "10.0.0.5" {
		t.Fatalf("Allow = %v, want [127.0.0.1:8443 10.0.0.5]", got)
	}
	// Idempotent.
	w.consolidate()
	if len(w.cfg.ReverseAccept.Allow) != 2 {
		t.Errorf("idempotency broken: Allow len = %d", len(w.cfg.ReverseAccept.Allow))
	}
	// Disabling clears the list.
	w.cfg.ReverseAccept.Enabled = false
	w.consolidate()
	if w.cfg.ReverseAccept.Allow != nil {
		t.Errorf("disabled policy must clear Allow, got %v", w.cfg.ReverseAccept.Allow)
	}
}

// TestConsolidateServerScrubsReverseAccept: reverse_accept is client-only,
// so a server-mode consolidate must clear the whole struct (the validator
// rejects it in server mode). Symmetrically, a client-mode consolidate
// scrubs any server-only reverse_forwards left by a mode flip.
func TestConsolidateServerScrubsReverseAccept(t *testing.T) {
	w := &wizard{cfg: &config.Config{Mode: config.ModeServer}}
	w.cfg.ReverseAccept = config.ReverseAcceptConfig{Enabled: true, Allow: []string{"127.0.0.1:8443"}}
	w.consolidate()
	if w.cfg.ReverseAccept.Enabled || len(w.cfg.ReverseAccept.Allow) != 0 {
		t.Errorf("server-mode consolidate must clear reverse_accept: %+v", w.cfg.ReverseAccept)
	}

	wc := &wizard{cfg: &config.Config{Mode: config.ModeClient}}
	wc.cfg.ReverseForwards = []config.ReverseForwardConfig{{Listen: ":8443", Peer: "x"}}
	wc.consolidate()
	if wc.cfg.ReverseForwards != nil {
		t.Errorf("client-mode consolidate must scrub reverse_forwards, got %v", wc.cfg.ReverseForwards)
	}
}

// stepNamesForCfg walks the wizard's step list applying shouldRun
// against the wizard state, returning a label for each visible step.
// Used by the iteration tests above to assert which steps are
// rendered for a given (mode, showAdvanced) combination without
// driving real huh.Form lifecycles.
func stepNamesForCfg(w *wizard) []string {
	names := []string{
		"mode", "transport", "server", "spoof", "peers", "crypto",
		"inbounds", "reverse-toggle", "reverse-forwards", "reverse-accept",
		"basic", "tunables-toggle", "tunables", "review",
	}
	out := make([]string, 0, len(names))
	for i, s := range w.steps {
		if s.shouldRun != nil && !s.shouldRun(w) {
			continue
		}
		out = append(out, names[i])
	}
	return out
}

func indexOfStr(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}
