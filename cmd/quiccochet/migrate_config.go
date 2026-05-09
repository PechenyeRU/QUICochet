package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/configmigrate"
	"github.com/spf13/cobra"
)

var (
	migrateIn      string
	migrateOut     string
	migrateInPlace bool
	migrateDryRun  bool
	migrateForce   bool
)

var migrateConfigCmd = &cobra.Command{
	Use:   "migrate-config",
	Short: "Migrate a v1.x config file to v2.x schema",
	Long: `migrate-config rewrites a v1.x QUICochet config file to the v2.0.0+ schema.

Changes applied:
  - spoof.source_ip / source_ipv6 / peer_spoof_ip / peer_spoof_ipv6 (singular)
    are renamed to their plural array form.
  - Server mode: crypto.peer_public_key + spoof.client_real_ip[v6] are
    moved into peers[0] (name "vpn1"). The peer also receives a copy of
    the spoof source and peer-spoof IPs from the legacy spoof block.

All other fields (transport, quic, obfuscation, security, inbounds,
outbound_proxy, logging, metrics, admin) are carried over untouched.

If the input is already v2.0+, the command reports "already v2.0+" and
exits 0 without writing anything (unless --out or --in-place is set, in
which case it writes the canonicalised JSON).

Exit codes:
  0  success (or already-v2 with no write requested)
  1  input error (file missing, parse fail, write fail)
  2  the migrated config fails validation (use --force to override)`,

	// SilenceUsage keeps cobra from printing the full usage on every error.
	SilenceUsage: true,

	RunE: func(cmd *cobra.Command, args []string) error {
		// Flag validation.
		if migrateIn == "" {
			return fmt.Errorf("--in is required")
		}
		if migrateInPlace && migrateOut != "" {
			return fmt.Errorf("--in-place and --out are mutually exclusive")
		}

		// Read input.
		inBytes, err := os.ReadFile(migrateIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read %s: %v\n", migrateIn, err)
			os.Exit(1)
		}

		// Migrate.
		outBytes, changed, err := configmigrate.MigrateV1ToV2(inBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: migration failed: %v\n", err)
			os.Exit(1)
		}

		if !changed {
			fmt.Fprintln(os.Stderr, "info: config is already v2.0+ — no migration needed")
			// If the user explicitly asked for output, write the canonicalised form.
			if !migrateInPlace && migrateOut == "" && !migrateDryRun {
				return nil
			}
		}

		// Validation step (skip with --force).
		if err := validateMigrated(outBytes); err != nil {
			if !migrateForce {
				fmt.Fprintf(os.Stderr, "error: migrated config fails validation (use --force to override):\n  %v\n", err)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "warning: migrated config fails validation (--force): %v\n", err)
		}

		// --dry-run: print diff to stdout, do not write.
		if migrateDryRun {
			fmt.Println(unifiedDiff(string(inBytes), string(outBytes), migrateIn))
			return nil
		}

		// Determine write target.
		switch {
		case migrateInPlace:
			// Write a .bak backup first.
			bakPath := migrateIn + ".bak"
			if err := os.WriteFile(bakPath, inBytes, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "error: write backup %s: %v\n", bakPath, err)
				os.Exit(1)
			}
			if err := os.WriteFile(migrateIn, outBytes, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "error: write %s: %v\n", migrateIn, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "info: backup written to %s\n", bakPath)
			fmt.Fprintf(os.Stderr, "info: migrated config written to %s\n", migrateIn)

		case migrateOut != "":
			if err := os.WriteFile(migrateOut, outBytes, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "error: write %s: %v\n", migrateOut, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "info: migrated config written to %s\n", migrateOut)

		default:
			// Default: write to stdout.
			if _, err := os.Stdout.Write(outBytes); err != nil {
				fmt.Fprintf(os.Stderr, "error: write stdout: %v\n", err)
				os.Exit(1)
			}
		}

		return nil
	},
}

// validateMigrated unmarshals the migrated JSON and runs config.Validate.
// It also applies the same defaults that config.Load would apply, so the
// validator doesn't reject zero-valued optional fields.
func validateMigrated(data []byte) error {
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	// We can't call the unexported setDefaults, so invoke Load via a temp
	// file — but that would be I/O in a validation helper. Instead we use
	// the same approach as the test package: replicate just enough defaults
	// to let Validate run without spurious failures.
	applyValidationDefaults(&cfg)
	return cfg.Validate()
}

// applyValidationDefaults sets the same defaults that config.setDefaults
// would apply, so Validate doesn't reject unset optional fields.
func applyValidationDefaults(c *config.Config) {
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
	if c.Obfuscation.ChaffingIntervalMs == 0 {
		c.Obfuscation.ChaffingIntervalMs = 50
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
	if c.OutboundProxy.Enabled && c.OutboundProxy.Type == "" {
		c.OutboundProxy.Type = "socks5"
	}
}

// unifiedDiff produces a simple line-by-line diff between two strings.
// It is intentionally minimal — not a real unified diff, but sufficient
// for the --dry-run use case where the operator just wants to see what
// changed before committing.
func unifiedDiff(orig, migrated, filename string) string {
	origLines := strings.Split(orig, "\n")
	migrLines := strings.Split(migrated, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s (original)\n", filename)
	fmt.Fprintf(&sb, "+++ %s (migrated)\n", filename)

	// Simple LCS-free diff: emit removed and added lines by comparing the
	// two sets. For a config file this is always small, so O(n²) is fine.
	maxLen := len(origLines)
	if len(migrLines) > maxLen {
		maxLen = len(migrLines)
	}

	i, j := 0, 0
	for i < len(origLines) || j < len(migrLines) {
		origLine := ""
		migrLine := ""
		if i < len(origLines) {
			origLine = origLines[i]
		}
		if j < len(migrLines) {
			migrLine = migrLines[j]
		}

		if origLine == migrLine {
			fmt.Fprintf(&sb, " %s\n", origLine)
			i++
			j++
		} else {
			if i < len(origLines) {
				fmt.Fprintf(&sb, "-%s\n", origLine)
				i++
			}
			if j < len(migrLines) {
				fmt.Fprintf(&sb, "+%s\n", migrLine)
				j++
			}
		}
	}
	_ = maxLen
	return sb.String()
}

func init() {
	migrateConfigCmd.Flags().StringVar(&migrateIn, "in", "", "path to v1 config file (required)")
	migrateConfigCmd.Flags().StringVar(&migrateOut, "out", "", "write migrated config to this path (default: stdout)")
	migrateConfigCmd.Flags().BoolVar(&migrateInPlace, "in-place", false, "rewrite --in file in place (creates a .bak backup); mutually exclusive with --out")
	migrateConfigCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "print migrated config and diff to stdout, do not write")
	migrateConfigCmd.Flags().BoolVar(&migrateForce, "force", false, "skip v2 validation step and write even if validation fails")

	_ = migrateConfigCmd.MarkFlagRequired("in")
	mainCmd.AddCommand(migrateConfigCmd)
}
