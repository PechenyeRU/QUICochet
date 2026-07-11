package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validClientConfig returns a minimal valid client config (v2.0.0 schema).
func validClientConfig() Config {
	return Config{
		Mode: ModeClient,
		Transport: TransportConfig{
			Type:     TransportUDP,
			ICMPMode: ICMPModeEcho,
		},
		Server: ServerConfig{
			Address: "10.0.0.1",
			Port:    8080,
		},
		Spoof: SpoofConfig{
			SourceIPs: []string{"192.168.1.1"},
		},
		Crypto: CryptoConfig{
			PrivateKey:    "some-private-key",
			PeerPublicKey: "some-peer-public-key",
		},
		Obfuscation: ObfuscationConfig{
			Mode: "standard",
		},
		Performance: PerformanceConfig{
			MTU: 1400,
		},
		Logging: LoggingConfig{
			Level: LogInfo,
		},
	}
}

// validServerConfig returns a minimal valid server config (v2.0.0 schema with peers[]).
func validServerConfig() Config {
	return Config{
		Mode: ModeServer,
		Transport: TransportConfig{
			Type:     TransportUDP,
			ICMPMode: ICMPModeEcho,
		},
		ListenPort: 8080,
		Spoof: SpoofConfig{
			SourceIPs: []string{"10.0.0.2"},
		},
		Crypto: CryptoConfig{
			PrivateKey: "server-private-key",
		},
		Peers: []PeerConfig{
			{
				Name:          "vpn1",
				PeerPublicKey: "client-public-key",
				ClientRealIP:  "203.0.113.5",
				PeerSpoofIPs:  []string{"10.0.0.3"},
			},
		},
		Obfuscation: ObfuscationConfig{
			Mode: "standard",
		},
		Performance: PerformanceConfig{
			MTU: 1400,
		},
		Logging: LoggingConfig{
			Level: LogInfo,
		},
	}
}

func TestValidateValidConfigs(t *testing.T) {
	t.Run("valid client config", func(t *testing.T) {
		cfg := validClientConfig()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected no error for valid client config, got: %v", err)
		}
	})

	t.Run("valid server config", func(t *testing.T) {
		cfg := validServerConfig()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected no error for valid server config, got: %v", err)
		}
	})
}

func TestValidateInvalidMode(t *testing.T) {
	cfg := validClientConfig()
	cfg.Mode = "foo"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("expected error to contain 'invalid mode', got: %v", err)
	}
}

// Regression for C-15: malformed Inbounds[] entries used to slip past
// Validate and surface as cryptic dial failures at runtime.
func TestValidateInbounds(t *testing.T) {
	t.Run("forward without target", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Inbounds = []InboundConfig{{Type: InboundForward, Listen: ":1080"}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "forward inbound requires target") {
			t.Fatalf("expected forward-target error, got: %v", err)
		}
	})
	t.Run("unknown type", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Inbounds = []InboundConfig{{Type: "http", Listen: ":1080"}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown type") {
			t.Fatalf("expected unknown-type error, got: %v", err)
		}
	})
	t.Run("missing listen", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Inbounds = []InboundConfig{{Type: InboundSocks}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "listen is required") {
			t.Fatalf("expected listen-required error, got: %v", err)
		}
	})
}

func TestValidateInvalidTransport(t *testing.T) {
	cfg := validClientConfig()
	cfg.Transport.Type = "websocket"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid transport type")
	}
	if !strings.Contains(err.Error(), "invalid transport type") {
		t.Fatalf("expected error to contain 'invalid transport type', got: %v", err)
	}
}

func TestValidateRawProtocolNumber(t *testing.T) {
	tests := []struct {
		name      string
		proto     int
		wantError bool
	}{
		{"zero is invalid", 0, true},
		{"one is valid", 1, false},
		{"255 is valid", 255, false},
		{"256 is invalid", 256, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validClientConfig()
			cfg.Transport.Type = TransportRAW
			cfg.Transport.ProtocolNumber = tt.proto
			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("expected no error but got: %v", err)
			}
			if tt.wantError && err != nil && !strings.Contains(err.Error(), "protocol_number") {
				t.Fatalf("expected error about protocol_number, got: %v", err)
			}
		})
	}
}

func TestValidateClientRequiresServer(t *testing.T) {
	cfg := validClientConfig()
	cfg.Server.Address = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when client has no server address")
	}
	if !strings.Contains(err.Error(), "server address is required") {
		t.Fatalf("expected error about server address, got: %v", err)
	}
}

func TestValidateServerRequiresPeers(t *testing.T) {
	t.Run("empty peers rejected", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Peers = nil
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error when server has no peers")
		}
		if !strings.Contains(err.Error(), "peers[]") {
			t.Fatalf("expected error about peers[], got: %v", err)
		}
	})

	t.Run("peer missing client_real_ip rejected", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Peers[0].ClientRealIP = ""
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for peer missing client_real_ip")
		}
		if !strings.Contains(err.Error(), "client_real_ip") {
			t.Fatalf("expected error about client_real_ip, got: %v", err)
		}
	})

	t.Run("peer missing pubkey rejected", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Peers[0].PeerPublicKey = ""
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for peer missing peer_public_key")
		}
		if !strings.Contains(err.Error(), "peer_public_key") {
			t.Fatalf("expected error about peer_public_key, got: %v", err)
		}
	})

	t.Run("peer missing name rejected", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Peers[0].Name = ""
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for peer missing name")
		}
		if !strings.Contains(err.Error(), "name is required") {
			t.Fatalf("expected error about name, got: %v", err)
		}
	})
}

func TestValidateServerPeerDisjointSpoofIPs(t *testing.T) {
	cfg := validServerConfig()
	// Add a second peer with the same peer_spoof_ip as the first.
	cfg.Peers = append(cfg.Peers, PeerConfig{
		Name:          "vpn2",
		PeerPublicKey: "different-key",
		ClientRealIP:  "203.0.113.6",
		PeerSpoofIPs:  []string{"10.0.0.3"}, // collision with vpn1
	})
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate peer_spoof_ip across peers")
	}
	if !strings.Contains(err.Error(), "disjoint") {
		t.Fatalf("expected disjoint error, got: %v", err)
	}
}

// TestValidateServerPeerSpoofIPNormalizedCollision exercises the fact that the
// runtime cipher dispatch (server.go) normalizes wire source IPs via
// netip.Addr.Unmap() before keying the peerCiphers map. Two textually
// different config entries that normalize to the same address would silently
// overwrite each other at runtime; the validator must reject them.
func TestValidateServerPeerSpoofIPNormalizedCollision(t *testing.T) {
	t.Run("v4 vs v4-mapped-v6", func(t *testing.T) {
		cfg := validServerConfig()
		// vpn1 already uses 10.0.0.3. Second peer writes the v4-mapped-v6
		// form, which Unmap normalizes to the same v4 address.
		cfg.Peers = append(cfg.Peers, PeerConfig{
			Name:           "vpn2",
			PeerPublicKey:  "different-key",
			ClientRealIP:   "203.0.113.6",
			PeerSpoofIPv6s: []string{"::ffff:10.0.0.3"},
		})
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error: v4-mapped-v6 collides with the v4 form after Unmap")
		}
		if !strings.Contains(err.Error(), "disjoint") {
			t.Fatalf("expected disjoint error, got: %v", err)
		}
	})

	t.Run("compressed vs expanded ipv6", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Peers[0].PeerSpoofIPs = nil
		cfg.Peers[0].PeerSpoofIPv6s = []string{"2001:db8::1"}
		cfg.Peers = append(cfg.Peers, PeerConfig{
			Name:           "vpn2",
			PeerPublicKey:  "different-key",
			ClientRealIPv6: "2001:db8::dead",
			PeerSpoofIPv6s: []string{"2001:0db8:0000:0000:0000:0000:0000:0001"},
		})
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error: expanded form collides with compressed form")
		}
		if !strings.Contains(err.Error(), "disjoint") {
			t.Fatalf("expected disjoint error, got: %v", err)
		}
	})
}

// TestValidateServerPeerIntraPeerDuplicateSpoofIP verifies that a peer cannot
// list the same spoof IP twice within its own lists. The runtime would just
// re-register the same map entry twice, which is benign, but the config is
// almost certainly a typo and rejecting it surfaces the problem early.
func TestValidateServerPeerIntraPeerDuplicateSpoofIP(t *testing.T) {
	cfg := validServerConfig()
	cfg.Peers[0].PeerSpoofIPs = []string{"10.0.0.3", "10.0.0.3"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate spoof IP within the same peer")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected intra-peer duplicate message, got: %v", err)
	}
}

func TestValidateServerDuplicatePeerName(t *testing.T) {
	cfg := validServerConfig()
	cfg.Peers = append(cfg.Peers, PeerConfig{
		Name:          "vpn1", // duplicate
		PeerPublicKey: "another-key",
		ClientRealIP:  "203.0.113.7",
	})
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate peer name")
	}
	if !strings.Contains(err.Error(), "duplicate peer name") {
		t.Fatalf("expected duplicate name error, got: %v", err)
	}
}

func TestValidateServerDuplicatePubKey(t *testing.T) {
	cfg := validServerConfig()
	cfg.Peers = append(cfg.Peers, PeerConfig{
		Name:          "vpn2",
		PeerPublicKey: "client-public-key", // duplicate
		ClientRealIP:  "203.0.113.7",
	})
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate peer public key")
	}
	if !strings.Contains(err.Error(), "duplicate peer_public_key") {
		t.Fatalf("expected duplicate key error, got: %v", err)
	}
}

// Legacy v1 field detection is now handled by the auto-migrator at the
// top of Load — see configmigrate package + TestLoadAutoMigratesInPlace
// for end-to-end coverage. The bare checkLegacyFields() call inside
// Load remains as a defensive sanity gate against a migrator bug that
// leaves a v1 field behind, but it's not reachable via Load on real v1
// inputs (migrator runs first). No direct test here by design.

func TestValidateInvalidIPs(t *testing.T) {
	t.Run("invalid source_ips entry", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Spoof.SourceIPs = []string{"not.an.ip"}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid source_ips entry")
		}
		if !strings.Contains(err.Error(), "source_ips") {
			t.Fatalf("expected error about source_ips, got: %v", err)
		}
	})

	t.Run("invalid source_ipv6s entry", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Spoof.SourceIPv6s = []string{"not-an-ipv6"}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid source_ipv6s entry")
		}
		if !strings.Contains(err.Error(), "source_ipv6s") {
			t.Fatalf("expected error about source_ipv6s, got: %v", err)
		}
	})

	t.Run("invalid peer_spoof_ips entry", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Spoof.PeerSpoofIPs = []string{"bad-ip"}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid peer_spoof_ips entry")
		}
		if !strings.Contains(err.Error(), "peer_spoof_ips") {
			t.Fatalf("expected error about peer_spoof_ips, got: %v", err)
		}
	})

	t.Run("invalid client_real_ip in server peer", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Peers[0].ClientRealIP = "not-valid"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid client_real_ip")
		}
		if !strings.Contains(err.Error(), "client_real_ip") {
			t.Fatalf("expected error about client_real_ip, got: %v", err)
		}
	})
}

func TestValidateCryptoRequired(t *testing.T) {
	t.Run("missing private_key", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Crypto.PrivateKey = ""
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for missing private_key")
		}
		if !strings.Contains(err.Error(), "private_key") {
			t.Fatalf("expected error about private_key, got: %v", err)
		}
	})

	t.Run("missing peer_public_key in client mode", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Crypto.PeerPublicKey = ""
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for missing peer_public_key")
		}
		if !strings.Contains(err.Error(), "peer_public_key") {
			t.Fatalf("expected error about peer_public_key, got: %v", err)
		}
	})

	t.Run("peer_public_key must not be set in server mode", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Crypto.PeerPublicKey = "some-key"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for peer_public_key in server mode")
		}
		if !strings.Contains(err.Error(), "peers[].peer_public_key") {
			t.Fatalf("expected migration error, got: %v", err)
		}
	})
}

func TestValidateObfuscationMode(t *testing.T) {
	validModes := []string{"none", "standard", "paranoid"}
	for _, mode := range validModes {
		t.Run("valid mode: "+mode, func(t *testing.T) {
			cfg := validClientConfig()
			cfg.Obfuscation.Mode = mode
			if err := cfg.Validate(); err != nil {
				t.Fatalf("expected no error for obfuscation mode %q, got: %v", mode, err)
			}
		})
	}

	t.Run("invalid mode: turbo", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Obfuscation.Mode = "turbo"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid obfuscation mode")
		}
		if !strings.Contains(err.Error(), "invalid obfuscation mode") {
			t.Fatalf("expected error about invalid obfuscation mode, got: %v", err)
		}
	})
}

func TestValidateOutboundProxy(t *testing.T) {
	t.Run("enabled in client mode should error", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.OutboundProxy.Enabled = true
		cfg.OutboundProxy.Type = "socks5"
		cfg.OutboundProxy.Address = "127.0.0.1:2080"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for outbound proxy in client mode")
		}
		if !strings.Contains(err.Error(), "outbound_proxy is only supported in server mode") {
			t.Fatalf("expected error about server-only, got: %v", err)
		}
	})

	t.Run("enabled in server mode with valid config", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.OutboundProxy.Enabled = true
		cfg.OutboundProxy.Type = "socks5"
		cfg.OutboundProxy.Address = "127.0.0.1:2080"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected no error for valid outbound proxy in server mode, got: %v", err)
		}
	})

	t.Run("enabled without address", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.OutboundProxy.Enabled = true
		cfg.OutboundProxy.Type = "socks5"
		cfg.OutboundProxy.Address = ""
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for outbound proxy without address")
		}
		if !strings.Contains(err.Error(), "outbound_proxy.address is required") {
			t.Fatalf("expected error about missing address, got: %v", err)
		}
	})

	t.Run("invalid proxy type", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.OutboundProxy.Enabled = true
		cfg.OutboundProxy.Type = "http"
		cfg.OutboundProxy.Address = "127.0.0.1:8080"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid proxy type")
		}
		if !strings.Contains(err.Error(), "invalid outbound_proxy type") {
			t.Fatalf("expected error about invalid proxy type, got: %v", err)
		}
	})
}

func TestSetDefaults(t *testing.T) {
	cfg := Config{
		Mode: ModeClient,
		Spoof: SpoofConfig{
			SourceIPs: []string{"192.168.1.1"},
		},
		Server: ServerConfig{
			Address: "10.0.0.1",
			Port:    8080,
		},
		Crypto: CryptoConfig{
			PrivateKey:    "key",
			PeerPublicKey: "peer-key",
		},
	}

	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults() returned error: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"Transport.Type", cfg.Transport.Type, TransportUDP},
		{"Transport.ICMPMode", cfg.Transport.ICMPMode, ICMPModeEcho},
		{"Performance.BufferSize", cfg.Performance.BufferSize, 65535},
		{"Performance.MTU", cfg.Performance.MTU, 1400},
		{"Performance.ReadBuffer", cfg.Performance.ReadBuffer, 32 * 1024 * 1024},
		{"Performance.WriteBuffer", cfg.Performance.WriteBuffer, 32 * 1024 * 1024},
		{"Obfuscation.Mode", cfg.Obfuscation.Mode, "none"},
		{"Obfuscation.ChaffingIntervalMs", cfg.Obfuscation.ChaffingIntervalMs, 50},
		{"QUIC.KeepAlivePeriodSec", cfg.QUIC.KeepAlivePeriodSec, 5},
		{"QUIC.MaxIdleTimeoutSec", cfg.QUIC.MaxIdleTimeoutSec, 10},
		{"QUIC.MaxStreamReceiveWindow", cfg.QUIC.MaxStreamReceiveWindow, 32 * 1024 * 1024},
		{"QUIC.MaxConnectionReceiveWindow", cfg.QUIC.MaxConnectionReceiveWindow, 128 * 1024 * 1024},
		{"QUIC.PoolSize", cfg.QUIC.PoolSize, 8},
		{"QUIC.PacketThreshold", cfg.QUIC.PacketThreshold, 128},
		{"QUIC.StreamCloseTimeoutSec", cfg.QUIC.StreamCloseTimeoutSec, 10},
		{"Logging.Level", cfg.Logging.Level, LogInfo},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			// Compare as strings to handle type mismatches between TransportType/string etc.
			gotStr := stringify(c.got)
			wantStr := stringify(c.want)
			if gotStr != wantStr {
				t.Errorf("got %v, want %v", c.got, c.want)
			}
		})
	}

	// Check inbounds backward compat
	t.Run("inbounds backward compat", func(t *testing.T) {
		if len(cfg.Inbounds) != 1 {
			t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
		}
		if cfg.Inbounds[0].Type != InboundSocks {
			t.Errorf("expected inbound type socks, got %s", cfg.Inbounds[0].Type)
		}
		if cfg.Inbounds[0].Listen != "127.0.0.1:1080" {
			t.Errorf("expected inbound listen 127.0.0.1:1080, got %s", cfg.Inbounds[0].Listen)
		}
	})

	// Server mode: listen port default is 8080
	t.Run("server listen port default", func(t *testing.T) {
		srv := Config{Mode: ModeServer}
		_ = srv.setDefaults()
		if srv.ListenPort != 8080 {
			t.Errorf("expected server listen port 8080, got %d", srv.ListenPort)
		}
	})
}

// TestLegacyConfigRoundTrip guards backwards compatibility for the CLIENT
// side: a client JSON config written with the new schema (source_ips array)
// and minor knob variations must still validate and load cleanly.
func TestLegacyConfigRoundTrip(t *testing.T) {
	legacyJSON := `{
		"mode": "client",
		"transport": { "type": "udp" },
		"server": { "address": "10.0.0.1", "port": 8080 },
		"spoof": { "source_ips": ["192.168.1.1"] },
		"crypto": {
			"private_key": "legacy-private-key",
			"peer_public_key": "legacy-peer-key"
		},
		"obfuscation": { "enabled": true, "mode": "standard" },
		"performance": {
			"mtu": 1400,
			"read_buffer": 4194304,
			"write_buffer": 4194304,
			"buffer_size": 65535,
			"workers": 4
		},
		"quic": {
			"keep_alive_period_sec": 5,
			"max_idle_timeout_sec": 10,
			"max_stream_receive_window": 5242880,
			"max_connection_receive_window": 15728640,
			"pool_size": 4,
			"stream_close_timeout_sec": 10,
			"congestion_control": "cubic"
		},
		"logging": { "level": "info" }
	}`

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "legacy.json")
	if err := os.WriteFile(cfgPath, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load legacy config failed: %v — backwards compat broken", err)
	}

	// Verify every explicit legacy value survived setDefaults unchanged.
	if cfg.Performance.ReadBuffer != 4*1024*1024 {
		t.Errorf("legacy read_buffer mutated: got %d want %d", cfg.Performance.ReadBuffer, 4*1024*1024)
	}
	if cfg.Performance.WriteBuffer != 4*1024*1024 {
		t.Errorf("legacy write_buffer mutated: got %d want %d", cfg.Performance.WriteBuffer, 4*1024*1024)
	}
	if cfg.QUIC.MaxStreamReceiveWindow != 5*1024*1024 {
		t.Errorf("legacy max_stream_receive_window mutated: got %d want %d", cfg.QUIC.MaxStreamReceiveWindow, 5*1024*1024)
	}
	if cfg.QUIC.MaxConnectionReceiveWindow != 15*1024*1024 {
		t.Errorf("legacy max_connection_receive_window mutated: got %d want %d", cfg.QUIC.MaxConnectionReceiveWindow, 15*1024*1024)
	}
	if cfg.QUIC.PoolSize != 4 {
		t.Errorf("legacy pool_size mutated: got %d want 4", cfg.QUIC.PoolSize)
	}
	if cfg.QUIC.CongestionControl != "cubic" {
		t.Errorf("legacy congestion_control mutated: got %q want %q", cfg.QUIC.CongestionControl, "cubic")
	}
	// Jitter buffer field didn't exist in legacy configs; must default
	// to 0 (disabled) so legacy behavior is preserved.
	if cfg.Performance.JitterBufferMs != 0 {
		t.Errorf("jitter_buffer_ms on legacy config must default to 0, got %d", cfg.Performance.JitterBufferMs)
	}
}

func stringify(v any) string {
	switch val := v.(type) {
	case TransportType:
		return string(val)
	case ICMPMode:
		return string(val)
	case LogLevel:
		return string(val)
	default:
		return strings.TrimSpace(strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(
					func() string { b, _ := json.Marshal(v); return string(b) }(),
					"\"", ""),
				"\n", ""),
			" ", ""))
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("GetServerAddr", func(t *testing.T) {
		cfg := Config{Server: ServerConfig{Address: "10.0.0.1", Port: 443}}
		if got := cfg.GetServerAddr(); got != "10.0.0.1:443" {
			t.Errorf("GetServerAddr() = %q, want %q", got, "10.0.0.1:443")
		}
	})

	t.Run("GetOutboundProxyAddr disabled", func(t *testing.T) {
		cfg := Config{}
		if got := cfg.GetOutboundProxyAddr(); got != "direct" {
			t.Errorf("GetOutboundProxyAddr() = %q, want %q", got, "direct")
		}
	})

	t.Run("GetOutboundProxyAddr enabled", func(t *testing.T) {
		cfg := Config{
			OutboundProxy: OutboundProxyConfig{
				Enabled: true,
				Type:    "socks5",
				Address: "127.0.0.1:2080",
			},
		}
		want := "socks5://127.0.0.1:2080"
		if got := cfg.GetOutboundProxyAddr(); got != want {
			t.Errorf("GetOutboundProxyAddr() = %q, want %q", got, want)
		}
	})
}

func TestLoadFromJSON(t *testing.T) {
	t.Run("valid JSON loads successfully", func(t *testing.T) {
		cfg := validClientConfig()
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("failed to marshal config: %v", err)
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("failed to write temp config: %v", err)
		}

		loaded, err := Load(path)
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if loaded.Mode != ModeClient {
			t.Errorf("loaded mode = %q, want %q", loaded.Mode, ModeClient)
		}
		if loaded.Server.Address != "10.0.0.1" {
			t.Errorf("loaded server address = %q, want %q", loaded.Server.Address, "10.0.0.1")
		}
	})

	t.Run("invalid JSON fails", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte("{not valid json}"), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "parse config") {
			t.Fatalf("expected parse error, got: %v", err)
		}
	})

	t.Run("valid JSON with invalid config fails", func(t *testing.T) {
		badCfg := Config{
			Mode: "invalid",
		}
		data, _ := json.Marshal(badCfg)

		dir := t.TempDir()
		path := filepath.Join(dir, "invalid.json")
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
		if !strings.Contains(err.Error(), "validate config") {
			t.Fatalf("expected validation error, got: %v", err)
		}
	})

	t.Run("nonexistent file fails", func(t *testing.T) {
		_, err := Load("/nonexistent/path/config.json")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "read config file") {
			t.Fatalf("expected read error, got: %v", err)
		}
	})
}

func TestStatsLogLevel(t *testing.T) {
	t.Run("statistics off defaults to DEBUG", func(t *testing.T) {
		c := &Config{}
		if got := c.StatsLogLevel(); got != slog.LevelDebug {
			t.Fatalf("expected DEBUG, got %v", got)
		}
	})
	t.Run("statistics on promotes to INFO", func(t *testing.T) {
		c := &Config{Logging: LoggingConfig{Statistics: true}}
		if got := c.StatsLogLevel(); got != slog.LevelInfo {
			t.Fatalf("expected INFO, got %v", got)
		}
	})
}

func TestValidateChaffingIntervalFloor(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		intervalMs int
		wantError  bool
	}{
		{"paranoid + interval 1 is invalid", "paranoid", 1, true},
		{"paranoid + interval 4 is invalid", "paranoid", 4, true},
		{"paranoid + interval 0 is valid (default)", "paranoid", 0, false},
		{"paranoid + interval 5 is valid", "paranoid", 5, false},
		{"paranoid + interval 10 is valid", "paranoid", 10, false},
		{"standard + interval 1 is valid (irrelevant mode)", "standard", 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validClientConfig()
			cfg.Obfuscation.Mode = tt.mode
			cfg.Obfuscation.ChaffingIntervalMs = tt.intervalMs
			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("expected no error but got: %v", err)
			}
			if tt.wantError && err != nil && !strings.Contains(err.Error(), "chaffing_interval_ms") {
				t.Fatalf("expected error to mention chaffing_interval_ms, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reverse port forwarding (ssh -R) config layer
// ---------------------------------------------------------------------------

func TestValidateReverseForwards(t *testing.T) {
	t.Run("valid rule", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: "127.0.0.1:8443", Target: "127.0.0.1:8443", Peer: "vpn1"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected no error for valid reverse forward, got: %v", err)
		}
	})

	t.Run("missing peer field", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: "127.0.0.1:8443", Target: "127.0.0.1:8443", Peer: ""},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "peer is required") {
			t.Fatalf("expected peer-required error, got: %v", err)
		}
	})

	t.Run("unknown peer reference", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: "127.0.0.1:8443", Target: "127.0.0.1:8443", Peer: "ghost"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "does not reference any entry in peers[]") {
			t.Fatalf("expected unknown-peer error, got: %v", err)
		}
	})

	t.Run("duplicate listen", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: "127.0.0.1:8443", Target: "127.0.0.1:8443", Peer: "vpn1"},
			{Listen: "127.0.0.1:8443", Target: "127.0.0.1:9000", Peer: "vpn1"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "must be unique") {
			t.Fatalf("expected duplicate-listen error, got: %v", err)
		}
	})

	t.Run("duplicate listen across notations", func(t *testing.T) {
		// ":8443" and "8443" both normalize to 127.0.0.1:8443.
		cfg := validServerConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: ":8443", Target: "127.0.0.1:8443", Peer: "vpn1"},
			{Listen: "8443", Target: "127.0.0.1:9000", Peer: "vpn1"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "must be unique") {
			t.Fatalf("expected duplicate-listen error across notations, got: %v", err)
		}
	})

	t.Run("invalid listen", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: "0.0.0.0", Target: "127.0.0.1:8443", Peer: "vpn1"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "invalid listen") {
			t.Fatalf("expected invalid-listen error, got: %v", err)
		}
	})

	t.Run("only valid in server mode", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.ReverseForwards = []ReverseForwardConfig{
			{Listen: "127.0.0.1:8443", Target: "127.0.0.1:8443", Peer: "vpn1"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "reverse_forwards is only supported in server mode") {
			t.Fatalf("expected server-only gate error, got: %v", err)
		}
	})
}

func TestValidateReverseAccept(t *testing.T) {
	t.Run("valid enabled with allow", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.ReverseAccept = ReverseAcceptConfig{Enabled: true, Allow: []string{"127.0.0.1:8443", "example.com"}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected no error for valid reverse_accept, got: %v", err)
		}
	})

	t.Run("enabled with empty allow", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.ReverseAccept = ReverseAcceptConfig{Enabled: true}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "allow is empty") {
			t.Fatalf("expected empty-allow error, got: %v", err)
		}
	})

	t.Run("only meaningful in client mode", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.ReverseAccept = ReverseAcceptConfig{Enabled: true, Allow: []string{"127.0.0.1:8443"}}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "reverse_accept is only supported in client mode") {
			t.Fatalf("expected client-only gate error, got: %v", err)
		}
	})

	t.Run("bad allow entry", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.ReverseAccept = ReverseAcceptConfig{Enabled: true, Allow: []string{"10.0.0.5:8443:9090"}}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "reverse_accept.allow[0]") {
			t.Fatalf("expected bad-allow-entry error, got: %v", err)
		}
	})

	t.Run("allow entries validated even when disabled", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.ReverseAccept = ReverseAcceptConfig{Enabled: false, Allow: []string{":80"}}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "reverse_accept.allow[0]") {
			t.Fatalf("expected bad-allow-entry error for empty host, got: %v", err)
		}
	})
}

func TestValidateReverseAllowEntry(t *testing.T) {
	tests := []struct {
		entry string
		valid bool
	}{
		{"127.0.0.1:8443", true},      // exact host:port
		{"example.com", true},         // bare hostname
		{"10.0.0.5", true},            // bare IPv4
		{"2001:db8::1", true},         // bare IPv6 (unbracketed)
		{"[2001:db8::1]:8443", true},  // bracketed IPv6 host:port
		{"", false},                   // empty
		{":8443", false},              // empty host
		{"host:", false},              // empty port
		{"10.0.0.5:8443:9090", false}, // too many colons, not an IP
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			err := validateReverseAllowEntry(tt.entry)
			if tt.valid && err != nil {
				t.Fatalf("expected %q valid, got: %v", tt.entry, err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("expected %q invalid, got nil", tt.entry)
			}
		})
	}
}

func TestReverseForwardTargetDefaulting(t *testing.T) {
	cfg := validServerConfig()
	cfg.ReverseForwards = []ReverseForwardConfig{
		{Listen: ":9000", Peer: "vpn1"},                       // no target -> default from port
		{Listen: "0.0.0.0:9001", Peer: "vpn1"},                // no target -> default from port
		{Listen: "8443", Target: "10.0.0.9:80", Peer: "vpn1"}, // explicit target kept
	}
	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults() returned error: %v", err)
	}
	if got := cfg.ReverseForwards[0].Target; got != "127.0.0.1:9000" {
		t.Errorf("rule[0] target = %q, want 127.0.0.1:9000", got)
	}
	if got := cfg.ReverseForwards[1].Target; got != "127.0.0.1:9001" {
		t.Errorf("rule[1] target = %q, want 127.0.0.1:9001", got)
	}
	if got := cfg.ReverseForwards[2].Target; got != "10.0.0.9:80" {
		t.Errorf("rule[2] target = %q (explicit should be preserved), want 10.0.0.9:80", got)
	}
}

func TestNormalizeReverseListen(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantNorm     string
		wantLoopback bool
		wantErr      bool
	}{
		{"bare port defaults loopback", "8443", "127.0.0.1:8443", true, false},
		{"host-less port defaults loopback", ":8443", "127.0.0.1:8443", true, false},
		{"explicit wildcard host kept", "0.0.0.0:8443", "0.0.0.0:8443", false, false},
		{"explicit loopback host kept", "127.0.0.1:8443", "127.0.0.1:8443", false, false},
		{"bracketed ipv6 host kept", "[::1]:8443", "[::1]:8443", false, false},
		{"empty is error", "", "", false, true},
		{"no port is error", "0.0.0.0", "", false, true},
		{"port out of range is error", "99999", "", false, true},
		{"port zero is error", "0", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, loopback, err := NormalizeReverseListen(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got norm=%q", tt.in, norm)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.in, err)
			}
			if norm != tt.wantNorm {
				t.Errorf("norm = %q, want %q", norm, tt.wantNorm)
			}
			if loopback != tt.wantLoopback {
				t.Errorf("defaultedLoopback = %v, want %v", loopback, tt.wantLoopback)
			}
		})
	}
}

func TestResolveAdminSocket(t *testing.T) {
	t.Run("explicit path is returned verbatim", func(t *testing.T) {
		c := &Config{Admin: AdminConfig{Socket: "/tmp/custom.sock"}}
		path, auto := c.ResolveAdminSocket(1234)
		if path != "/tmp/custom.sock" {
			t.Fatalf("expected explicit path, got %q", path)
		}
		if auto {
			t.Fatal("expected auto=false for explicit path")
		}
	})
	t.Run("empty path falls back to pid-based", func(t *testing.T) {
		c := &Config{}
		path, auto := c.ResolveAdminSocket(4321)
		if path != "/run/quiccochet-4321.sock" {
			t.Fatalf("expected pid-based path, got %q", path)
		}
		if !auto {
			t.Fatal("expected auto=true for pid-derived path")
		}
	})
}
