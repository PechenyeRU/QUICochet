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

	// 10 declared steps: mode, transport, server, spoof, crypto,
	// inbounds, basic, tunables-toggle, tunables, review.
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
}

// TestStepIterationServerSkipsClientOnly: server mode hides server
// and inbounds (clientOnly). Tunables toggle off — tunables step
// also hidden. Basic still always shown.
func TestStepIterationServerSkipsClientOnly(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	w, _ := newWizard(b, 0, 0)
	w.cfg.Mode = config.ModeServer
	w.showAdvanced = false

	want := []string{"mode", "transport", "spoof", "crypto", "basic", "tunables-toggle", "review"}
	got := stepNamesForCfg(w)
	if len(got) != len(want) {
		t.Fatalf("server step count = %d, want %d (got %v)", len(got), len(want), got)
	}
}

// stepNamesForCfg walks the wizard's step list applying shouldRun
// against the wizard state, returning a label for each visible step.
// Used by the iteration tests above to assert which steps are
// rendered for a given (mode, showAdvanced) combination without
// driving real huh.Form lifecycles.
func stepNamesForCfg(w *wizard) []string {
	names := []string{
		"mode", "transport", "server", "spoof", "crypto",
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
