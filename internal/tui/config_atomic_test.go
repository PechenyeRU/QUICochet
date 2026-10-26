package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pechenyeru/quiccochet/internal/config"
)

func TestSaveConfigDoesNotFollowPredictableTempSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Mode:        config.ModeServer,
		Transport:   config.TransportConfig{Type: config.TransportUDP, ICMPMode: config.ICMPModeEcho},
		ListenPort:  8080,
		Crypto:      config.CryptoConfig{PrivateKey: "server-private-key"},
		Obfuscation: config.ObfuscationConfig{Mode: "standard"},
		Performance: config.PerformanceConfig{MTU: 1400},
		Logging:     config.LoggingConfig{Level: config.LogInfo},
		Peers: []config.PeerConfig{{
			Name: "client", PeerPublicKey: "client-public-key",
			ClientRealIP: "203.0.113.5", PeerSpoofIPs: []string{"10.0.0.3"},
		}},
	}
	if err := saveConfig(cfg, path); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "unchanged" {
		t.Fatalf("sentinel changed to %q", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config was not saved: %v", err)
	}
}
