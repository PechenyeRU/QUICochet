package configmigrate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// mustMigrate calls MigrateV1ToV2 and fails the test on error.
func mustMigrate(t *testing.T, input string) (out []byte, changed bool) {
	t.Helper()
	o, c, err := MigrateV1ToV2([]byte(input))
	if err != nil {
		t.Fatalf("MigrateV1ToV2 error: %v", err)
	}
	return o, c
}

// parseAndValidate unmarshals the migrated JSON into config.Config, applies
// setDefaults (via Load path), and runs Validate. Returns the validation error.
// We replicate what config.Load does without touching the disk.
func parseAndValidate(t *testing.T, data []byte) (*config.Config, error) {
	t.Helper()
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal migrated config: %v", err)
	}
	// We can't call setDefaults directly (unexported); call Validate directly.
	// Some validation checks (e.g. MTU floor, log level) need defaults applied
	// first. To avoid that, we pre-populate known-needed defaults.
	applyTestDefaults(&cfg)
	return &cfg, cfg.Validate()
}

// applyTestDefaults sets just enough defaults so Validate does not complain
// about fields we deliberately left at zero in test fixtures.
func applyTestDefaults(c *config.Config) {
	if c.Transport.Type == "" {
		c.Transport.Type = config.TransportUDP
	}
	if c.Transport.ICMPMode == "" {
		if c.Mode == config.ModeServer {
			c.Transport.ICMPMode = config.ICMPModeReply
		} else {
			c.Transport.ICMPMode = config.ICMPModeEcho
		}
	}
	if c.Performance.MTU == 0 {
		c.Performance.MTU = 1400
	}
	if c.Performance.BufferSize == 0 {
		c.Performance.BufferSize = 65535
	}
	if c.Performance.ReadBuffer == 0 {
		c.Performance.ReadBuffer = 32 * 1024 * 1024
	}
	if c.Performance.WriteBuffer == 0 {
		c.Performance.WriteBuffer = 32 * 1024 * 1024
	}
	if c.Obfuscation.Mode == "" {
		c.Obfuscation.Mode = "none"
	}
	if c.QUIC.KeepAlivePeriodSec == 0 {
		c.QUIC.KeepAlivePeriodSec = 5
	}
	if c.QUIC.MaxIdleTimeoutSec == 0 {
		c.QUIC.MaxIdleTimeoutSec = 10
	}
	if c.QUIC.MaxStreamReceiveWindow == 0 {
		c.QUIC.MaxStreamReceiveWindow = 32 * 1024 * 1024
	}
	if c.QUIC.MaxConnectionReceiveWindow == 0 {
		c.QUIC.MaxConnectionReceiveWindow = 128 * 1024 * 1024
	}
	if c.QUIC.PoolSize == 0 {
		c.QUIC.PoolSize = 8
	}
	if c.QUIC.StreamCloseTimeoutSec == 0 {
		c.QUIC.StreamCloseTimeoutSec = 10
	}
	if c.QUIC.MaxIncomingStreams == 0 {
		c.QUIC.MaxIncomingStreams = 100000
	}
	if c.QUIC.MaxIncomingUniStreams == 0 {
		c.QUIC.MaxIncomingUniStreams = 1000
	}
	if c.QUIC.MaxConcurrentSessions == 0 {
		c.QUIC.MaxConcurrentSessions = 1000
	}
	if c.QUIC.UDPRouteIdleSec == 0 {
		c.QUIC.UDPRouteIdleSec = 90
	}
	if c.QUIC.UDPRouteMax == 0 {
		c.QUIC.UDPRouteMax = 50000
	}
	if c.QUIC.PacketThreshold == 0 {
		c.QUIC.PacketThreshold = 128
	}
	if c.QUIC.CongestionControl == "" {
		c.QUIC.CongestionControl = "auto"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = config.LogInfo
	}
	if c.Mode == config.ModeServer && c.ListenPort == 0 {
		c.ListenPort = 8080
	}
	if len(c.Inbounds) == 0 && c.Mode == config.ModeClient {
		c.Inbounds = []config.InboundConfig{{
			Type:   config.InboundSocks,
			Listen: "127.0.0.1:1080",
		}}
	}
}

// ─── test cases ───────────────────────────────────────────────────────────────

func TestMigrateV1ToV2(t *testing.T) {
	t.Run("server v1 all legacy fields", func(t *testing.T) {
		// All legacy fields: crypto.peer_public_key, spoof.client_real_ip,
		// singular spoof fields.
		input := `{
  "mode": "server",
  "transport": {"type": "udp"},
  "listen_port": 8080,
  "spoof": {
    "source_ip": "1.2.3.4",
    "peer_spoof_ip": "5.6.7.8",
    "client_real_ip": "10.0.0.1"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true for v1 server config")
		}

		cfg, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("migrated config fails validation: %v", err)
		}

		// peers[0] must exist.
		if len(cfg.Peers) != 1 {
			t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
		}
		p := cfg.Peers[0]
		if p.Name != "vpn1" {
			t.Errorf("peer name = %q, want %q", p.Name, "vpn1")
		}
		if p.PeerPublicKey != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" {
			t.Errorf("peer_public_key = %q", p.PeerPublicKey)
		}
		if p.ClientRealIP != "10.0.0.1" {
			t.Errorf("client_real_ip = %q, want 10.0.0.1", p.ClientRealIP)
		}
		if len(p.PeerSpoofIPs) != 1 || p.PeerSpoofIPs[0] != "5.6.7.8" {
			t.Errorf("peer_spoof_ips = %v, want [5.6.7.8]", p.PeerSpoofIPs)
		}
		if len(p.SourceIPs) != 1 || p.SourceIPs[0] != "1.2.3.4" {
			t.Errorf("source_ips in peer = %v, want [1.2.3.4]", p.SourceIPs)
		}

		// top-level crypto must NOT have peer_public_key.
		if cfg.Crypto.PeerPublicKey != "" {
			t.Error("crypto.peer_public_key should be empty in server mode after migration")
		}

		// spoof.client_real_ip must be gone.
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(out, &raw)
		var spoofRaw map[string]json.RawMessage
		_ = json.Unmarshal(raw["spoof"], &spoofRaw)
		if _, ok := spoofRaw["client_real_ip"]; ok {
			t.Error("spoof.client_real_ip should be absent after migration")
		}
		if _, ok := spoofRaw["source_ip"]; ok {
			t.Error("spoof.source_ip (singular) should be absent after migration")
		}
	})

	t.Run("server v1 singular and plural both set - merge dedup", func(t *testing.T) {
		// Both source_ip and source_ips set; source_ip should go first, dedup.
		input := `{
  "mode": "server",
  "listen_port": 8080,
  "spoof": {
    "source_ip": "1.2.3.4",
    "source_ips": ["1.2.3.4", "1.2.3.5"],
    "peer_spoof_ip": "5.6.7.8",
    "peer_spoof_ips": ["9.10.11.12"],
    "client_real_ip": "10.0.0.1"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}
		cfg, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}

		// spoof.source_ips: singular "1.2.3.4" first, then deduped rest ["1.2.3.5"]
		if len(cfg.Spoof.SourceIPs) != 2 {
			t.Errorf("spoof.source_ips len = %d, want 2; got %v", len(cfg.Spoof.SourceIPs), cfg.Spoof.SourceIPs)
		}
		if len(cfg.Spoof.SourceIPs) > 0 && cfg.Spoof.SourceIPs[0] != "1.2.3.4" {
			t.Errorf("spoof.source_ips[0] = %q, want 1.2.3.4", cfg.Spoof.SourceIPs[0])
		}

		// spoof.peer_spoof_ips: "5.6.7.8" first, then "9.10.11.12"
		if len(cfg.Spoof.PeerSpoofIPs) != 2 {
			t.Errorf("spoof.peer_spoof_ips len = %d, want 2; got %v", len(cfg.Spoof.PeerSpoofIPs), cfg.Spoof.PeerSpoofIPs)
		}
		if len(cfg.Spoof.PeerSpoofIPs) > 0 && cfg.Spoof.PeerSpoofIPs[0] != "5.6.7.8" {
			t.Errorf("spoof.peer_spoof_ips[0] = %q, want 5.6.7.8", cfg.Spoof.PeerSpoofIPs[0])
		}

		// peer inherits spoof IPs
		if len(cfg.Peers) != 1 {
			t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
		}
	})

	t.Run("client v1 singular spoof fields", func(t *testing.T) {
		input := `{
  "mode": "client",
  "server": {"address": "1.2.3.4", "port": 8080},
  "spoof": {
    "source_ip": "10.0.0.1",
    "peer_spoof_ip": "10.0.0.2"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}
		cfg, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}

		// No peers[] in client mode.
		if len(cfg.Peers) != 0 {
			t.Errorf("client mode should have no peers, got %d", len(cfg.Peers))
		}

		if len(cfg.Spoof.SourceIPs) != 1 || cfg.Spoof.SourceIPs[0] != "10.0.0.1" {
			t.Errorf("spoof.source_ips = %v, want [10.0.0.1]", cfg.Spoof.SourceIPs)
		}
		if len(cfg.Spoof.PeerSpoofIPs) != 1 || cfg.Spoof.PeerSpoofIPs[0] != "10.0.0.2" {
			t.Errorf("spoof.peer_spoof_ips = %v, want [10.0.0.2]", cfg.Spoof.PeerSpoofIPs)
		}

		// Singular fields must be absent.
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(out, &raw)
		var spoofRaw map[string]json.RawMessage
		_ = json.Unmarshal(raw["spoof"], &spoofRaw)
		if _, ok := spoofRaw["source_ip"]; ok {
			t.Error("source_ip (singular) should be absent after migration")
		}
		if _, ok := spoofRaw["peer_spoof_ip"]; ok {
			t.Error("peer_spoof_ip (singular) should be absent after migration")
		}
	})

	t.Run("already v2 - idempotent", func(t *testing.T) {
		input := `{
  "mode": "client",
  "server": {"address": "1.2.3.4", "port": 8080},
  "spoof": {
    "source_ips": ["10.0.0.1"],
    "peer_spoof_ips": ["10.0.0.2"]
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if changed {
			t.Error("expected changed=false for already-v2 config")
		}

		// Output should parse cleanly.
		_, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}

		// Check that the content is equivalent (field values preserved).
		var orig, migrated map[string]any
		_ = json.Unmarshal([]byte(input), &orig)
		_ = json.Unmarshal(out, &migrated)
		origSpoof := orig["spoof"].(map[string]any)
		migrSpoof := migrated["spoof"].(map[string]any)
		origSrcIPs := origSpoof["source_ips"].([]any)
		migrSrcIPs := migrSpoof["source_ips"].([]any)
		if len(origSrcIPs) != len(migrSrcIPs) || origSrcIPs[0] != migrSrcIPs[0] {
			t.Errorf("source_ips changed: %v → %v", origSrcIPs, migrSrcIPs)
		}
	})

	t.Run("server v1 source_ip with empty source_ips array - rename", func(t *testing.T) {
		// source_ips is present but empty; singular source_ip should become source_ips[0].
		input := `{
  "mode": "server",
  "listen_port": 8080,
  "spoof": {
    "source_ip": "1.2.3.4",
    "source_ips": [],
    "client_real_ip": "10.0.0.1",
    "peer_spoof_ip": "5.6.7.8"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}

		var m map[string]any
		_ = json.Unmarshal(out, &m)
		spoof := m["spoof"].(map[string]any)
		sourceIPs, ok := spoof["source_ips"].([]any)
		if !ok || len(sourceIPs) != 1 || sourceIPs[0] != "1.2.3.4" {
			t.Errorf("source_ips = %v, want [1.2.3.4]", spoof["source_ips"])
		}
		if _, ok := spoof["source_ip"]; ok {
			t.Error("source_ip (singular) should be gone")
		}
	})

	t.Run("malformed JSON - error no panic", func(t *testing.T) {
		_, _, err := MigrateV1ToV2([]byte(`{not valid json`))
		if err == nil {
			t.Fatal("expected error for malformed JSON, got nil")
		}
	})

	t.Run("server v1 missing client_real_ip - fails validation", func(t *testing.T) {
		// No client_real_ip or client_real_ipv6 — peers[0] will lack required field.
		input := `{
  "mode": "server",
  "listen_port": 8080,
  "spoof": {
    "source_ip": "1.2.3.4",
    "peer_spoof_ip": "5.6.7.8"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}

		// Validation should fail because peers[0] has no client_real_ip[v6].
		_, err := parseAndValidate(t, out)
		if err == nil {
			t.Fatal("expected validation error for missing client_real_ip, got nil")
		}
		if !strings.Contains(err.Error(), "client_real_ip") {
			t.Errorf("error should mention client_real_ip, got: %v", err)
		}
	})

	t.Run("comment keys preserved verbatim", func(t *testing.T) {
		// JSON with comment-style keys (_,__,___) must survive.
		input := `{
  "_": "this is a comment",
  "__": "another comment",
  "mode": "client",
  "server": {"address": "1.2.3.4", "port": 8080},
  "spoof": {
    "source_ip": "10.0.0.1",
    "peer_spoof_ip": "10.0.0.2"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}

		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("unmarshal output: %v", err)
		}
		if v, ok := m["_"]; !ok || v != "this is a comment" {
			t.Errorf("_ key missing or wrong: %v", m["_"])
		}
		if v, ok := m["__"]; !ok || v != "another comment" {
			t.Errorf("__ key missing or wrong: %v", m["__"])
		}
	})

	t.Run("outbound_proxy and inbounds carried over untouched", func(t *testing.T) {
		input := `{
  "mode": "server",
  "listen_port": 8080,
  "spoof": {
    "source_ip": "1.2.3.4",
    "client_real_ip": "10.0.0.1",
    "peer_spoof_ip": "5.6.7.8"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "outbound_proxy": {
    "enabled": true,
    "type": "socks5",
    "address": "127.0.0.1:2080"
  },
  "quic": {
    "pool_size": 16
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}

		var m map[string]any
		_ = json.Unmarshal(out, &m)

		// outbound_proxy must be present and intact.
		op, ok := m["outbound_proxy"].(map[string]any)
		if !ok {
			t.Fatal("outbound_proxy missing from output")
		}
		if op["address"] != "127.0.0.1:2080" {
			t.Errorf("outbound_proxy.address = %v, want 127.0.0.1:2080", op["address"])
		}

		// quic.pool_size must be preserved.
		quic, ok := m["quic"].(map[string]any)
		if !ok {
			t.Fatal("quic block missing from output")
		}
		// json.Unmarshal into any returns float64 for JSON numbers.
		if ps, ok := quic["pool_size"].(float64); !ok || ps != 16 {
			t.Errorf("quic.pool_size = %v (%T), want 16", quic["pool_size"], quic["pool_size"])
		}
	})

	t.Run("round-trip v2 server config is idempotent", func(t *testing.T) {
		// A proper v2 server config (with peers[], no legacy fields).
		input := `{
  "mode": "server",
  "listen_port": 8080,
  "spoof": {
    "source_ips": ["1.2.3.4"]
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  },
  "peers": [
    {
      "name": "vpn1",
      "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
      "client_real_ip": "10.0.0.1",
      "peer_spoof_ips": ["5.6.7.8"]
    }
  ],
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if changed {
			t.Error("expected changed=false for v2 server config")
		}

		cfg, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}
		if len(cfg.Peers) != 1 || cfg.Peers[0].Name != "vpn1" {
			t.Errorf("peers[0] wrong after idempotent round-trip: %+v", cfg.Peers)
		}
	})

	t.Run("IPv6 fields migrated", func(t *testing.T) {
		input := `{
  "mode": "client",
  "server": {"address": "1.2.3.4", "port": 8080},
  "spoof": {
    "source_ip": "10.0.0.1",
    "source_ipv6": "::1",
    "peer_spoof_ip": "10.0.0.2",
    "peer_spoof_ipv6": "::2"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}

		cfg, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}

		if len(cfg.Spoof.SourceIPv6s) != 1 || cfg.Spoof.SourceIPv6s[0] != "::1" {
			t.Errorf("source_ipv6s = %v, want [::1]", cfg.Spoof.SourceIPv6s)
		}
		if len(cfg.Spoof.PeerSpoofIPv6s) != 1 || cfg.Spoof.PeerSpoofIPv6s[0] != "::2" {
			t.Errorf("peer_spoof_ipv6s = %v, want [::2]", cfg.Spoof.PeerSpoofIPv6s)
		}

		var raw map[string]json.RawMessage
		_ = json.Unmarshal(out, &raw)
		var spoofRaw map[string]json.RawMessage
		_ = json.Unmarshal(raw["spoof"], &spoofRaw)
		for _, badKey := range []string{"source_ipv6", "peer_spoof_ipv6"} {
			if _, ok := spoofRaw[badKey]; ok {
				t.Errorf("singular key %q should be absent", badKey)
			}
		}
	})

	t.Run("server v1 client_real_ipv6 only", func(t *testing.T) {
		input := `{
  "mode": "server",
  "listen_port": 8080,
  "spoof": {
    "source_ip": "1.2.3.4",
    "client_real_ipv6": "::1",
    "peer_spoof_ip": "5.6.7.8"
  },
  "crypto": {
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  },
  "logging": {"level": "info"}
}`
		out, changed := mustMigrate(t, input)
		if !changed {
			t.Fatal("expected changed=true")
		}

		cfg, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}

		if len(cfg.Peers) != 1 {
			t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
		}
		p := cfg.Peers[0]
		if p.ClientRealIPv6 != "::1" {
			t.Errorf("client_real_ipv6 = %q, want ::1", p.ClientRealIPv6)
		}
		if p.ClientRealIP != "" {
			t.Errorf("client_real_ip should be empty, got %q", p.ClientRealIP)
		}
	})
}

// ─── ordered JSON unit tests ──────────────────────────────────────────────────

func TestOrderedMapRoundTrip(t *testing.T) {
	// Field order must be preserved: verify by checking the raw encoded bytes.
	input := `{"z": 1, "a": 2, "m": 3}`
	m, err := parseOrdered([]byte(input))
	if err != nil {
		t.Fatalf("parseOrdered: %v", err)
	}
	if m[0].Key != "z" || m[1].Key != "a" || m[2].Key != "m" {
		t.Errorf("field order not preserved: %v", []string{m[0].Key, m[1].Key, m[2].Key})
	}
}

func TestPrependDedup(t *testing.T) {
	tests := []struct {
		singular string
		existing []string
		want     []string
	}{
		{"a", []string{"b", "c"}, []string{"a", "b", "c"}},
		{"a", []string{"a", "b"}, []string{"a", "b"}}, // dedup: "a" not added twice
		{"", []string{"b", "c"}, []string{"b", "c"}},  // empty singular: unchanged
		{"a", nil, []string{"a"}},
	}
	for _, tt := range tests {
		got := prependDedup(tt.singular, tt.existing)
		if len(got) != len(tt.want) {
			t.Errorf("prependDedup(%q, %v) = %v, want %v", tt.singular, tt.existing, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("prependDedup(%q, %v)[%d] = %q, want %q", tt.singular, tt.existing, i, got[i], tt.want[i])
			}
		}
	}
}

func TestMigrateV1ToV2_MalformedJSON(t *testing.T) {
	cases := []string{
		``,
		`not json`,
		`[1, 2, 3]`,
		`{"unclosed": `,
	}
	for _, c := range cases {
		_, _, err := MigrateV1ToV2([]byte(c))
		if err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}
