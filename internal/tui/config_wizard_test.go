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

	// 11 declared steps; client-mode visible: 9. peers is server-only
	// (skipped here).
	want := []string{
		"mode", "transport", "server", "spoof", "crypto",
		"inbounds", "basic", "tunables-toggle", "tunables", "review",
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

	want := []string{"mode", "transport", "peers", "crypto", "basic", "tunables-toggle", "review"}
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

// stepNamesForCfg walks the wizard's step list applying shouldRun
// against the wizard state, returning a label for each visible step.
// Used by the iteration tests above to assert which steps are
// rendered for a given (mode, showAdvanced) combination without
// driving real huh.Form lifecycles.
func stepNamesForCfg(w *wizard) []string {
	names := []string{
		"mode", "transport", "server", "spoof", "peers", "crypto",
		"inbounds", "basic", "tunables-toggle", "tunables", "review",
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
