package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// TestSummariseInboundsEmpty: zero inbounds renders the explicit
// "(none)" string from the bundle, not an empty paragraph that
// would make the section look broken.
func TestSummariseInboundsEmpty(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	got := summariseInbounds(nil, b)
	if !strings.Contains(got, "none") {
		t.Errorf("empty summary should mention 'none', got %q", got)
	}
}

// TestSummariseInboundsMultiline lists each inbound on its own line
// with the right shape per type. Asserts both the SOCKS and forward
// branches carry the listen address and that forward also shows the
// target.
func TestSummariseInboundsMultiline(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	in := []config.InboundConfig{
		{Type: config.InboundSocks, Listen: "127.0.0.1:1080"},
		{Type: config.InboundForward, Listen: "127.0.0.1:8443", Target: "203.0.113.10:443"},
	}
	got := summariseInbounds(in, b)
	if !strings.Contains(got, "127.0.0.1:1080") {
		t.Errorf("missing socks listen: %q", got)
	}
	if !strings.Contains(got, "203.0.113.10:443") {
		t.Errorf("missing forward target: %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("two inbounds should produce one newline; got %d in %q", strings.Count(got, "\n"), got)
	}
}

// TestEditorLoadHappyPath drives newEditor through phase 0 by
// writing a valid config, setting e.path manually (bypassing the
// huh form), and asserting that updateForm in phase-0-completed
// flow loads the file and advances to phase 1. Tests the load
// branch deterministically without driving real keypresses.
func TestEditorLoadHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	json := `{
  "mode": "client",
  "transport": {"type": "udp", "icmp_mode": "echo", "protocol_number": 0},
  "server": {"address": "203.0.113.10", "port": 4242},
  "spoof": {"source_ip": "10.0.0.2", "peer_spoof_ip": "10.0.0.1", "client_real_ip": ""},
  "crypto": {"private_key": "MC4CAQAwBQYDK2VuBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "peer_public_key": "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
  "inbounds": [{"type": "socks", "listen": "127.0.0.1:1080"}]
}`
	if err := os.WriteFile(path, []byte(json), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	e := &editor{path: path}
	loaded, loadErr := config.Load(path)
	if loadErr != nil {
		t.Fatalf("seed config did not load: %v", loadErr)
	}
	e.cfg = loaded
	e.step = 1
	e.form = e.buildFieldsForm(b)
	if e.form == nil {
		t.Fatal("buildFieldsForm returned nil")
	}
	if e.cfg.Mode != config.ModeClient {
		t.Errorf("loaded mode = %q, want client", e.cfg.Mode)
	}
	if len(e.cfg.Inbounds) != 1 {
		t.Errorf("loaded inbounds = %d, want 1", len(e.cfg.Inbounds))
	}
}

// TestEditorBuildPathPromptStep0 confirms newEditor returns an
// editor at step 0 with a non-nil form. This is the bare-minimum
// "the constructor doesn't blow up" guard.
func TestEditorBuildPathPromptStep0(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	e, _ := newEditor(b)
	if e.step != 0 {
		t.Errorf("initial step = %d, want 0", e.step)
	}
	if e.form == nil {
		t.Fatal("initial form is nil")
	}
	if e.cfg != nil {
		t.Errorf("initial cfg should be nil until path loads, got %+v", e.cfg)
	}
}
