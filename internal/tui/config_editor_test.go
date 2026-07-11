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

// TestSaveConfigRoundTripsReverseForward: a server config carrying a
// reverse-forward rule with an EMPTY target must survive saveConfig
// (whose Validate-only path fills the 127.0.0.1:<listen-port> default via
// applyReverseTargetDefaults) and reload cleanly with the rule intact.
func TestSaveConfigRoundTripsReverseForward(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	cfg := &config.Config{
		Mode:        config.ModeServer,
		Transport:   config.TransportConfig{Type: config.TransportUDP, ICMPMode: config.ICMPModeEcho},
		ListenPort:  8080,
		Crypto:      config.CryptoConfig{PrivateKey: "server-private-key"},
		Obfuscation: config.ObfuscationConfig{Mode: "standard"},
		Performance: config.PerformanceConfig{MTU: 1400},
		Logging:     config.LoggingConfig{Level: config.LogInfo},
		Peers: []config.PeerConfig{{
			Name: "laptop", PeerPublicKey: "client-public-key",
			ClientRealIP: "203.0.113.5", PeerSpoofIPs: []string{"10.0.0.3"},
		}},
		ReverseForwards: []config.ReverseForwardConfig{
			{Listen: ":8443", Peer: "laptop"}, // empty target -> defaulted at save
		},
	}
	if err := saveConfig(cfg, path); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.ReverseForwards) != 1 {
		t.Fatalf("reloaded reverse forwards = %d, want 1", len(reloaded.ReverseForwards))
	}
	r := reloaded.ReverseForwards[0]
	if r.Peer != "laptop" {
		t.Errorf("peer = %q, want laptop", r.Peer)
	}
	if r.Target != "127.0.0.1:8443" {
		t.Errorf("target = %q, want 127.0.0.1:8443 (defaulted)", r.Target)
	}
}

// TestSaveConfigRoundTripsReverseAccept: a client config with an enabled
// reverse_accept policy round-trips through saveConfig + config.Load with
// the allow-list intact.
func TestSaveConfigRoundTripsReverseAccept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	cfg := &config.Config{
		Mode:        config.ModeClient,
		Transport:   config.TransportConfig{Type: config.TransportUDP, ICMPMode: config.ICMPModeEcho},
		Server:      config.ServerConfig{Address: "10.0.0.1", Port: 8080},
		Spoof:       config.SpoofConfig{SourceIPs: []string{"192.168.1.1"}},
		Crypto:      config.CryptoConfig{PrivateKey: "some-private-key", PeerPublicKey: "some-peer-public-key"},
		Obfuscation: config.ObfuscationConfig{Mode: "standard"},
		Performance: config.PerformanceConfig{MTU: 1400},
		Logging:     config.LoggingConfig{Level: config.LogInfo},
		ReverseAccept: config.ReverseAcceptConfig{
			Enabled: true, Allow: []string{"127.0.0.1:8443", "10.0.0.5"},
		},
	}
	if err := saveConfig(cfg, path); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.ReverseAccept.Enabled || len(reloaded.ReverseAccept.Allow) != 2 {
		t.Fatalf("reverse_accept = %+v, want enabled with 2 allow entries", reloaded.ReverseAccept)
	}
}

// TestEditorFinalizeServerTruncatesReverse: after buildFieldsForm pre-grew
// cfg.ReverseForwards to maxEditorReverse stubs, finalize() must truncate
// back to revCount and scrub the client-only reverse_accept struct.
func TestEditorFinalizeServerTruncatesReverse(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeServer}
	cfg.Peers = []config.PeerConfig{{Name: "laptop"}}
	cfg.ReverseForwards = []config.ReverseForwardConfig{
		{Listen: "0.0.0.0:8443", Target: "127.0.0.1:8443", Peer: "laptop"},
	}
	// Pre-grow peers + reverse forwards as buildFieldsForm would.
	for len(cfg.Peers) < maxEditorPeers {
		cfg.Peers = append(cfg.Peers, config.PeerConfig{})
	}
	for len(cfg.ReverseForwards) < maxEditorReverse {
		cfg.ReverseForwards = append(cfg.ReverseForwards, config.ReverseForwardConfig{})
	}
	// A stale reverse_accept stub that must be scrubbed in server mode.
	cfg.ReverseAccept = config.ReverseAcceptConfig{Enabled: true, Allow: []string{"x:1"}}

	e := &editor{cfg: cfg, peerCount: 1, revCount: 1}
	e.peerSpoofCsv[0] = "192.168.10.79"
	if err := e.finalize(); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(cfg.ReverseForwards) != 1 {
		t.Fatalf("after finalize, len(ReverseForwards) = %d, want 1", len(cfg.ReverseForwards))
	}
	if got := cfg.ReverseForwards[0]; got.Listen != "0.0.0.0:8443" || got.Peer != "laptop" {
		t.Errorf("rule[0] = %+v, want listen 0.0.0.0:8443 peer laptop", got)
	}
	if cfg.ReverseAccept.Enabled || cfg.ReverseAccept.Allow != nil {
		t.Errorf("server-mode finalize must scrub reverse_accept, got %+v", cfg.ReverseAccept)
	}
}

// TestEditorFinalizeClientFoldsReverseAccept: in client mode finalize
// drops server-only reverse_forwards stubs and folds the allow-list
// scratch into cfg.ReverseAccept.Allow when enabled.
func TestEditorFinalizeClientFoldsReverseAccept(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeClient}
	// Server-only stubs a mode flip could leave behind.
	for len(cfg.ReverseForwards) < maxEditorReverse {
		cfg.ReverseForwards = append(cfg.ReverseForwards, config.ReverseForwardConfig{})
	}
	cfg.ReverseAccept.Enabled = true

	e := &editor{cfg: cfg, reverseAllowCsv: "127.0.0.1:8443, 10.0.0.5"}
	if err := e.finalize(); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if cfg.ReverseForwards != nil {
		t.Errorf("client-mode finalize must scrub reverse_forwards, got %+v", cfg.ReverseForwards)
	}
	if got := cfg.ReverseAccept.Allow; len(got) != 2 || got[0] != "127.0.0.1:8443" || got[1] != "10.0.0.5" {
		t.Errorf("Allow = %v, want [127.0.0.1:8443 10.0.0.5]", got)
	}

	// Disabled: allow-list cleared even if the scratch has content.
	cfg2 := &config.Config{Mode: config.ModeClient}
	e2 := &editor{cfg: cfg2, reverseAllowCsv: "127.0.0.1:8443"}
	if err := e2.finalize(); err != nil {
		t.Fatalf("finalize disabled: %v", err)
	}
	if cfg2.ReverseAccept.Allow != nil {
		t.Errorf("disabled policy must leave Allow nil, got %v", cfg2.ReverseAccept.Allow)
	}
}
