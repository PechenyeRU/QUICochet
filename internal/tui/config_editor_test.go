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
  "spoof": {"source_ips": ["10.0.0.2"], "peer_spoof_ips": ["10.0.0.1"]},
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
	e, _ := newEditor(b, 0, 0)
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

// TestEditorFinalizeServerTruncates: after the form pre-grew
// cfg.Peers to maxEditorPeers stubs, finalize() must truncate back
// to peerCount, parse each visible slot's CSV scratch into
// PeerSpoofIPs, and not touch PeerSpoofIPs in slots beyond peerCount
// (those slots will be dropped anyway).
func TestEditorFinalizeServerTruncates(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeServer}
	// Pre-grow as buildFieldsForm would do.
	for i := 0; i < maxEditorPeers; i++ {
		cfg.Peers = append(cfg.Peers, config.PeerConfig{})
	}
	cfg.Peers[0].Name = "alpha"
	cfg.Peers[1].Name = "bravo"

	e := &editor{cfg: cfg, peerCount: 2}
	e.peerSpoofCsv[0] = "192.168.10.79, 192.168.10.80"
	e.peerSpoofCsv[1] = "192.168.10.81"
	// Slot 2..15 left blank — must be discarded by truncate.

	if err := e.finalize(); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("after finalize, len(Peers) = %d, want 2", len(cfg.Peers))
	}
	if got := cfg.Peers[0].PeerSpoofIPs; len(got) != 2 || got[0] != "192.168.10.79" || got[1] != "192.168.10.80" {
		t.Errorf("peer[0].PeerSpoofIPs = %v, want [192.168.10.79 192.168.10.80]", got)
	}
	if got := cfg.Peers[1].PeerSpoofIPs; len(got) != 1 || got[0] != "192.168.10.81" {
		t.Errorf("peer[1].PeerSpoofIPs = %v, want [192.168.10.81]", got)
	}
}

// TestEditorFinalizeServerRejectsZeroCount: finalize must surface a
// clear error if the operator decremented peerCount to 0 in server
// mode — the saved file would otherwise fail validation downstream
// with a less actionable message.
func TestEditorFinalizeServerRejectsZeroCount(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeServer}
	for i := 0; i < maxEditorPeers; i++ {
		cfg.Peers = append(cfg.Peers, config.PeerConfig{})
	}
	e := &editor{cfg: cfg, peerCount: 0}
	if err := e.finalize(); err == nil {
		t.Fatal("expected error for peerCount=0 in server mode, got nil")
	}
}

// TestEditorFinalizeClientDropsStubs: in client mode the form does
// NOT pre-grow cfg.Peers, but if it ever did (mode flipped mid-edit)
// finalize must scrub the stub slice so a saved client config never
// carries an empty peers list.
func TestEditorFinalizeClientDropsStubs(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeClient}
	cfg.Peers = []config.PeerConfig{{}, {}, {}}
	e := &editor{cfg: cfg}
	if err := e.finalize(); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if cfg.Peers != nil {
		t.Errorf("client-mode finalize must nil out Peers; got %+v", cfg.Peers)
	}
}
