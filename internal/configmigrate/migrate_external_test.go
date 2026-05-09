package configmigrate_test

// External test package so we can import internal/config to validate
// migrated output. Lives outside `package configmigrate` to break the
// import cycle: config now imports configmigrate (auto-migrate inside
// Load), so configmigrate's tests can't import config from inside the
// same package.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/configmigrate"
)

// mustMigrate calls MigrateV1ToV2 and fails the test on error.
func mustMigrate(t *testing.T, input string) (out []byte, changed bool) {
	t.Helper()
	o, c, err := configmigrate.MigrateV1ToV2([]byte(input))
	if err != nil {
		t.Fatalf("MigrateV1ToV2 error: %v", err)
	}
	return o, c
}

// parseAndValidate unmarshals the migrated JSON into config.Config,
// applies a minimal set of test defaults (we can't call setDefaults
// from outside the package), and runs Validate. Returns the result so
// the caller can inspect specific fields.
func parseAndValidate(t *testing.T, data []byte) (*config.Config, error) {
	t.Helper()
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal migrated config: %v", err)
	}
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

func TestMigrateV1ToV2(t *testing.T) {
	t.Run("server v1 all legacy fields", func(t *testing.T) {
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

		if cfg.Crypto.PeerPublicKey != "" {
			t.Error("crypto.peer_public_key should be empty in server mode after migration")
		}

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

		if len(cfg.Spoof.SourceIPs) != 2 {
			t.Errorf("spoof.source_ips len = %d, want 2; got %v", len(cfg.Spoof.SourceIPs), cfg.Spoof.SourceIPs)
		}
		if len(cfg.Spoof.SourceIPs) > 0 && cfg.Spoof.SourceIPs[0] != "1.2.3.4" {
			t.Errorf("spoof.source_ips[0] = %q, want 1.2.3.4", cfg.Spoof.SourceIPs[0])
		}

		if len(cfg.Spoof.PeerSpoofIPs) != 2 {
			t.Errorf("spoof.peer_spoof_ips len = %d, want 2; got %v", len(cfg.Spoof.PeerSpoofIPs), cfg.Spoof.PeerSpoofIPs)
		}
		if len(cfg.Spoof.PeerSpoofIPs) > 0 && cfg.Spoof.PeerSpoofIPs[0] != "5.6.7.8" {
			t.Errorf("spoof.peer_spoof_ips[0] = %q, want 5.6.7.8", cfg.Spoof.PeerSpoofIPs[0])
		}

		if len(cfg.Peers) != 1 {
			t.Fatalf("expected 1 peer, got %d", len(cfg.Peers))
		}

		// Regression for QA-C1: applyServerPeer used to coalesce (plural
		// wins, singular dropped) — peers[0] would end up with only the
		// plural entry and the singular peer would be unreachable at
		// runtime. The migrator now merges with dedup.
		p := cfg.Peers[0]
		if len(p.PeerSpoofIPs) != 2 {
			t.Errorf("peers[0].peer_spoof_ips len = %d, want 2; got %v", len(p.PeerSpoofIPs), p.PeerSpoofIPs)
		}
		if len(p.PeerSpoofIPs) > 0 && p.PeerSpoofIPs[0] != "5.6.7.8" {
			t.Errorf("peers[0].peer_spoof_ips[0] = %q, want 5.6.7.8 (singular first)", p.PeerSpoofIPs[0])
		}
		if len(p.SourceIPs) != 2 {
			t.Errorf("peers[0].source_ips len = %d, want 2; got %v", len(p.SourceIPs), p.SourceIPs)
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

		if len(cfg.Peers) != 0 {
			t.Errorf("client mode should have no peers, got %d", len(cfg.Peers))
		}

		if len(cfg.Spoof.SourceIPs) != 1 || cfg.Spoof.SourceIPs[0] != "10.0.0.1" {
			t.Errorf("spoof.source_ips = %v, want [10.0.0.1]", cfg.Spoof.SourceIPs)
		}
		if len(cfg.Spoof.PeerSpoofIPs) != 1 || cfg.Spoof.PeerSpoofIPs[0] != "10.0.0.2" {
			t.Errorf("spoof.peer_spoof_ips = %v, want [10.0.0.2]", cfg.Spoof.PeerSpoofIPs)
		}

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

		_, err := parseAndValidate(t, out)
		if err != nil {
			t.Fatalf("validation: %v", err)
		}

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
		_, _, err := configmigrate.MigrateV1ToV2([]byte(`{not valid json`))
		if err == nil {
			t.Fatal("expected error for malformed JSON, got nil")
		}
	})

	t.Run("server v1 missing client_real_ip - fails validation", func(t *testing.T) {
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

		_, err := parseAndValidate(t, out)
		if err == nil {
			t.Fatal("expected validation error for missing client_real_ip, got nil")
		}
		if !strings.Contains(err.Error(), "client_real_ip") {
			t.Errorf("error should mention client_real_ip, got: %v", err)
		}
	})

	t.Run("comment keys preserved verbatim", func(t *testing.T) {
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

		op, ok := m["outbound_proxy"].(map[string]any)
		if !ok {
			t.Fatal("outbound_proxy missing from output")
		}
		if op["address"] != "127.0.0.1:2080" {
			t.Errorf("outbound_proxy.address = %v, want 127.0.0.1:2080", op["address"])
		}

		quic, ok := m["quic"].(map[string]any)
		if !ok {
			t.Fatal("quic block missing from output")
		}
		if ps, ok := quic["pool_size"].(float64); !ok || ps != 16 {
			t.Errorf("quic.pool_size = %v (%T), want 16", quic["pool_size"], quic["pool_size"])
		}
	})

	t.Run("round-trip v2 server config is idempotent", func(t *testing.T) {
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

func TestMigrateV1ToV2_MalformedJSON(t *testing.T) {
	cases := []string{
		``,
		`not json`,
		`[1, 2, 3]`,
		`{"unclosed": `,
	}
	for _, c := range cases {
		_, _, err := configmigrate.MigrateV1ToV2([]byte(c))
		if err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}

// TestLoadAutoMigratesInPlace exercises the end-to-end path: write a v1
// config to disk, call config.Load, verify the file was rewritten in
// place to v2 form and a .bak of the original was created. This is the
// behaviour an operator hits when upgrading from v1.x → v2.x.
func TestLoadAutoMigratesInPlace(t *testing.T) {
	v1 := `{
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
	dir := t.TempDir()
	path := dir + "/quiccochet.json"
	if err := writeTestFile(path, v1); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Spoof.SourceIPs) != 1 || cfg.Spoof.SourceIPs[0] != "10.0.0.1" {
		t.Errorf("loaded spoof.source_ips = %v, want [10.0.0.1]", cfg.Spoof.SourceIPs)
	}

	on, err := readTestFile(path)
	if err != nil {
		t.Fatalf("read after Load: %v", err)
	}
	if strings.Contains(on, `"source_ip"`) {
		t.Errorf("file still contains singular source_ip after Load auto-migrate:\n%s", on)
	}
	if !strings.Contains(on, `"source_ips"`) {
		t.Errorf("file missing plural source_ips after Load auto-migrate:\n%s", on)
	}

	bak, err := readTestFile(path + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if bak != v1 {
		t.Errorf(".bak should mirror original v1 content, got:\n%s", bak)
	}
}

// TestLoadIdempotentOnV2 verifies that loading a clean v2 config does
// NOT touch the file or create a .bak — Load only writes when migration
// actually changed something.
func TestLoadIdempotentOnV2(t *testing.T) {
	v2 := `{
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
	dir := t.TempDir()
	path := dir + "/quiccochet.json"
	if err := writeTestFile(path, v2); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, err := config.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	on, err := readTestFile(path)
	if err != nil {
		t.Fatalf("read after Load: %v", err)
	}
	if on != v2 {
		t.Errorf("v2 config was rewritten by Load (should be untouched):\nwant: %s\ngot:  %s", v2, on)
	}

	if _, err := readTestFile(path + ".bak"); err == nil {
		t.Error("Load created a .bak for a v2 config that needed no migration")
	}
}
