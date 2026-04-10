package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validClientConfig returns a minimal valid client config.
func validClientConfig() Config {
	return Config{
		Mode: ModeClient,
		Transport: TransportConfig{
			Type:     TransportUDP,
			ICMPMode: ICMPModeEcho,
		},
		Listen: ListenConfig{
			Address: "127.0.0.1",
			Port:    1080,
		},
		Server: ServerConfig{
			Address: "10.0.0.1",
			Port:    8080,
		},
		Spoof: SpoofConfig{
			SourceIP: "192.168.1.1",
		},
		Crypto: CryptoConfig{
			PrivateKey:    "some-private-key",
			PeerPublicKey: "some-peer-public-key",
		},
		Obfuscation: ObfuscationConfig{
			Mode: "standard",
		},
		Logging: LoggingConfig{
			Level: LogInfo,
		},
	}
}

// validServerConfig returns a minimal valid server config.
func validServerConfig() Config {
	return Config{
		Mode: ModeServer,
		Transport: TransportConfig{
			Type:     TransportUDP,
			ICMPMode: ICMPModeEcho,
		},
		Listen: ListenConfig{
			Address: "127.0.0.1",
			Port:    8080,
		},
		Spoof: SpoofConfig{
			SourceIP:     "10.0.0.2",
			ClientRealIP: "203.0.113.5",
		},
		Crypto: CryptoConfig{
			PrivateKey:    "server-private-key",
			PeerPublicKey: "client-public-key",
		},
		Obfuscation: ObfuscationConfig{
			Mode: "standard",
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

func TestValidateServerRequiresClientRealIP(t *testing.T) {
	cfg := validServerConfig()
	cfg.Spoof.ClientRealIP = ""
	cfg.Spoof.ClientRealIPv6 = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when server has no client_real_ip")
	}
	if !strings.Contains(err.Error(), "client_real_ip") {
		t.Fatalf("expected error about client_real_ip, got: %v", err)
	}
}

func TestValidateInvalidIPs(t *testing.T) {
	t.Run("invalid source_ip", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Spoof.SourceIP = "not.an.ip"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid source_ip")
		}
		if !strings.Contains(err.Error(), "invalid spoof source_ip") {
			t.Fatalf("expected error about invalid spoof source_ip, got: %v", err)
		}
	})

	t.Run("invalid source_ipv6", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Spoof.SourceIPv6 = "not-an-ipv6"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid source_ipv6")
		}
		if !strings.Contains(err.Error(), "invalid spoof source_ipv6") {
			t.Fatalf("expected error about invalid spoof source_ipv6, got: %v", err)
		}
	})

	t.Run("invalid peer_spoof_ip", func(t *testing.T) {
		cfg := validClientConfig()
		cfg.Spoof.PeerSpoofIP = "bad-ip"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid peer_spoof_ip")
		}
		if !strings.Contains(err.Error(), "invalid spoof peer_spoof_ip") {
			t.Fatalf("expected error about invalid spoof peer_spoof_ip, got: %v", err)
		}
	})

	t.Run("invalid client_real_ip in server mode", func(t *testing.T) {
		cfg := validServerConfig()
		cfg.Spoof.ClientRealIP = "not-valid"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid client_real_ip")
		}
		if !strings.Contains(err.Error(), "invalid client_real_ip") {
			t.Fatalf("expected error about invalid client_real_ip, got: %v", err)
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

	t.Run("missing peer_public_key", func(t *testing.T) {
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
			SourceIP: "192.168.1.1",
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
		got  interface{}
		want interface{}
	}{
		{"Transport.Type", cfg.Transport.Type, TransportUDP},
		{"Transport.ICMPMode", cfg.Transport.ICMPMode, ICMPModeEcho},
		{"Listen.Address", cfg.Listen.Address, "127.0.0.1"},
		{"Listen.Port", cfg.Listen.Port, 1080},
		{"Performance.BufferSize", cfg.Performance.BufferSize, 65535},
		{"Performance.MTU", cfg.Performance.MTU, 1400},
		{"Performance.SessionTimeout", cfg.Performance.SessionTimeout, 600},
		{"Performance.Workers", cfg.Performance.Workers, 4},
		{"Performance.ReadBuffer", cfg.Performance.ReadBuffer, 4 * 1024 * 1024},
		{"Performance.WriteBuffer", cfg.Performance.WriteBuffer, 4 * 1024 * 1024},
		{"Obfuscation.Mode", cfg.Obfuscation.Mode, "standard"},
		{"Obfuscation.ChaffingIntervalMs", cfg.Obfuscation.ChaffingIntervalMs, 50},
		{"QUIC.KeepAlivePeriodSec", cfg.QUIC.KeepAlivePeriodSec, 5},
		{"QUIC.MaxIdleTimeoutSec", cfg.QUIC.MaxIdleTimeoutSec, 10},
		{"QUIC.MaxStreamReceiveWindow", cfg.QUIC.MaxStreamReceiveWindow, 5 * 1024 * 1024},
		{"QUIC.MaxConnectionReceiveWindow", cfg.QUIC.MaxConnectionReceiveWindow, 15 * 1024 * 1024},
		{"QUIC.PoolSize", cfg.QUIC.PoolSize, 4},
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
		if srv.Listen.Port != 8080 {
			t.Errorf("expected server listen port 8080, got %d", srv.Listen.Port)
		}
	})
}

func stringify(v interface{}) string {
	switch val := v.(type) {
	case TransportType:
		return string(val)
	case ICMPMode:
		return string(val)
	case LogLevel:
		return string(val)
	default:
		return strings.TrimSpace(strings.Replace(
			strings.Replace(
				strings.Replace(
					func() string { b, _ := json.Marshal(v); return string(b) }(),
					"\"", "", -1),
				"\n", "", -1),
			" ", "", -1))
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("IsIPv6 with IPv4", func(t *testing.T) {
		cfg := validClientConfig()
		if cfg.IsIPv6() {
			t.Error("expected IsIPv6() to be false for IPv4 source_ip")
		}
	})

	t.Run("IsIPv6 with IPv6 source_ip", func(t *testing.T) {
		cfg := Config{
			Spoof: SpoofConfig{
				SourceIP: "2001:db8::1",
			},
		}
		if !cfg.IsIPv6() {
			t.Error("expected IsIPv6() to be true for IPv6 source_ip")
		}
	})

	t.Run("IsIPv6 with only source_ipv6 set", func(t *testing.T) {
		cfg := Config{
			Spoof: SpoofConfig{
				SourceIPv6: "2001:db8::1",
			},
		}
		if !cfg.IsIPv6() {
			t.Error("expected IsIPv6() to be true when only source_ipv6 is set")
		}
	})

	t.Run("GetSourceIP", func(t *testing.T) {
		cfg := Config{
			Spoof: SpoofConfig{
				SourceIP:   "10.0.0.1",
				SourceIPv6: "2001:db8::1",
			},
		}
		if got := cfg.GetSourceIP(false); got != "10.0.0.1" {
			t.Errorf("GetSourceIP(false) = %q, want %q", got, "10.0.0.1")
		}
		if got := cfg.GetSourceIP(true); got != "2001:db8::1" {
			t.Errorf("GetSourceIP(true) = %q, want %q", got, "2001:db8::1")
		}
	})

	t.Run("GetListenAddr", func(t *testing.T) {
		cfg := Config{Listen: ListenConfig{Address: "0.0.0.0", Port: 9090}}
		if got := cfg.GetListenAddr(); got != "0.0.0.0:9090" {
			t.Errorf("GetListenAddr() = %q, want %q", got, "0.0.0.0:9090")
		}
	})

	t.Run("GetServerAddr", func(t *testing.T) {
		cfg := Config{Server: ServerConfig{Address: "10.0.0.1", Port: 443}}
		if got := cfg.GetServerAddr(); got != "10.0.0.1:443" {
			t.Errorf("GetServerAddr() = %q, want %q", got, "10.0.0.1:443")
		}
	})

	t.Run("GetPeerSpoofIP", func(t *testing.T) {
		cfg := Config{
			Spoof: SpoofConfig{
				PeerSpoofIP:   "172.16.0.1",
				PeerSpoofIPv6: "fd00::1",
			},
		}
		if got := cfg.GetPeerSpoofIP(false); got != "172.16.0.1" {
			t.Errorf("GetPeerSpoofIP(false) = %q, want %q", got, "172.16.0.1")
		}
		if got := cfg.GetPeerSpoofIP(true); got != "fd00::1" {
			t.Errorf("GetPeerSpoofIP(true) = %q, want %q", got, "fd00::1")
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

	t.Run("GetClientRealIP", func(t *testing.T) {
		cfg := Config{
			Spoof: SpoofConfig{
				ClientRealIP:   "203.0.113.5",
				ClientRealIPv6: "2001:db8::5",
			},
		}
		if got := cfg.GetClientRealIP(false); got != "203.0.113.5" {
			t.Errorf("GetClientRealIP(false) = %q, want %q", got, "203.0.113.5")
		}
		if got := cfg.GetClientRealIP(true); got != "2001:db8::5" {
			t.Errorf("GetClientRealIP(true) = %q, want %q", got, "2001:db8::5")
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
