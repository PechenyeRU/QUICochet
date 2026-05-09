package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
	"github.com/pechenyeru/quiccochet/internal/tunnel"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"
)

var (
	Version    = "dev"
	Commit     = "unknown"
	BuildTime  = "unknown"
	ConfigFile = "config.json"
	blue       = color.New(color.FgBlue).SprintFunc()
	yellow     = color.New(color.FgYellow).SprintFunc()
	green      = color.New(color.FgGreen).SprintFunc()
)

var mainCmd = &cobra.Command{
	Use:     "quiccochet",
	Version: Version + " (" + Commit + ") built " + BuildTime,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, yellow("Warning: Running without root privileges. Raw sockets may fail."))
			fmt.Fprintln(os.Stderr, "Run with: sudo ./quiccochet -c client-config.json")
			fmt.Fprintln(os.Stderr)
		}

		cfg, err := config.Load(ConfigFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		setupLogger(cfg)

		keyPair, err := crypto.ParsePrivateKey(cfg.Crypto.PrivateKey)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		fmt.Println()
		fmt.Println(green("============ QUICochet " + Version + " (" + Commit + ") ============"))
		fmt.Printf("%-30s %s\n", "Mode:", cfg.Mode)
		fmt.Printf("%-30s %s\n", "Transport:", cfg.Transport.Type)
		fmt.Printf("%-30s %s\n", "Local public key:", keyPair.PublicKeyBase64())
		if cfg.Transport.Type == config.TransportICMP {
			fmt.Printf("%-30s %s\n", "ICMP Mode:", blue(cfg.Transport.ICMPMode))
		}

		switch cfg.Mode {
		case config.ModeClient:
			// Client mode: single peer, derive shared secret from cfg.Crypto.PeerPublicKey.
			peerPubKey, err := crypto.ParsePublicKey(cfg.Crypto.PeerPublicKey)
			if err != nil {
				return fmt.Errorf("parse peer public key: %w", err)
			}
			sharedSecret, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, peerPubKey)
			if err != nil {
				return fmt.Errorf("compute shared secret: %w", err)
			}

			// Derive ICMP echo ID via HKDF so no raw key material leaks into packets.
			idReader := hkdf.New(sha256.New, sharedSecret[:],
				[]byte("quiccochet-v2-session-keys"), []byte("icmp-echo-id"))
			var idBytes [2]byte
			if _, err = io.ReadFull(idReader, idBytes[:]); err != nil {
				return fmt.Errorf("derive icmp echo id: %w", err)
			}
			cfg.Transport.ICMPEchoID = binary.BigEndian.Uint16(idBytes[:])
			if cfg.Transport.ICMPEchoID == 0 {
				cfg.Transport.ICMPEchoID = 1
			}

			sendKey, recvKey, err := crypto.DeriveSessionKeys(sharedSecret, true /* client is initiator */)
			if err != nil {
				return fmt.Errorf("derive session keys: %w", err)
			}
			cipher, err := crypto.NewCipher(sendKey, recvKey)
			if err != nil {
				return fmt.Errorf("create cipher: %w", err)
			}
			// Derive the deterministic TLS certificate + expected peer hash.
			tlsCert, err := crypto.DeriveTLSCertificate(sharedSecret)
			if err != nil {
				return fmt.Errorf("derive tls certificate: %w", err)
			}
			expectedPeerCertHash, err := crypto.DeriveTLSCertHash(sharedSecret)
			if err != nil {
				return fmt.Errorf("derive expected peer cert hash: %w", err)
			}
			return runClient(cfg, cipher, tlsCert, expectedPeerCertHash, sigCh)

		case config.ModeServer:
			// Server mode: per-peer ECDH is done inside NewServer; we only
			// need to pass the server's own key pair. Derive ICMP echo ID
			// from the first peer's shared secret (it is only used to
			// filter own reflected ICMP replies — any consistent value works).
			if len(cfg.Peers) > 0 {
				firstPub, parseErr := crypto.ParsePublicKey(cfg.Peers[0].PeerPublicKey)
				if parseErr == nil {
					ss, ssErr := crypto.ComputeSharedSecret(keyPair.PrivateKey, firstPub)
					if ssErr == nil {
						idReader := hkdf.New(sha256.New, ss[:],
							[]byte("quiccochet-v2-session-keys"), []byte("icmp-echo-id"))
						var idBytes [2]byte
						if _, readErr := io.ReadFull(idReader, idBytes[:]); readErr == nil {
							cfg.Transport.ICMPEchoID = binary.BigEndian.Uint16(idBytes[:])
							if cfg.Transport.ICMPEchoID == 0 {
								cfg.Transport.ICMPEchoID = 1
							}
						}
					}
				}
			}
			return runServer(cfg, keyPair, sigCh)
		}
		return nil
	},
}

// maybeStartAdmin spins up the admin unix socket when admin.enabled is
// set in config. Returns a Stop closure to call on shutdown (nil when
// admin is disabled or fails to bind — a failure is logged but not
// fatal so an operator error on the socket path doesn't prevent the
// tunnel from starting).
func maybeStartAdmin(cfg *config.Config, backend admin.Backend) func() {
	if !cfg.Admin.Enabled {
		return nil
	}
	path, auto := cfg.ResolveAdminSocket(os.Getpid())
	srv := admin.New(path, backend)
	if err := srv.Start(); err != nil {
		slog.Error("failed to start admin socket", "path", path, "error", err)
		return nil
	}
	if auto {
		fmt.Printf("%-30s %s %s\n", "Admin socket:", blue(path), yellow("(auto, pid-based)"))
	} else {
		fmt.Printf("%-30s %s\n", "Admin socket:", blue(path))
	}
	slog.Info("admin socket listening", "component", "admin", "path", path, "auto", auto)
	return srv.Stop
}

// maybeStartMetrics spins up the Prometheus /metrics HTTP exporter
// when metrics.enabled is set in config. Returns a Stop closure to
// call on shutdown (nil when metrics are disabled or fail to bind —
// a failure is logged but not fatal so an operator error on the
// listen address doesn't prevent the tunnel from starting).
func maybeStartMetrics(cfg *config.Config, backend admin.Backend) func() {
	if !cfg.Metrics.Enabled {
		return nil
	}
	srv := admin.NewPrometheusServer()
	st, err := srv.Start(cfg.Metrics.Listen, backend)
	if err != nil {
		slog.Error("failed to start metrics endpoint", "listen", cfg.Metrics.Listen, "error", err)
		return nil
	}
	fmt.Printf("%-30s %s\n", "Metrics endpoint:", blue("http://"+st.Address+"/metrics"))
	slog.Info("metrics endpoint listening", "component", "metrics", "address", st.Address)
	return func() { _ = srv.Stop() }
}

func setupLogger(cfg *config.Config) {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}

	var handler slog.Handler
	if cfg.Logging.File != "" {
		f, err := os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, yellow("Failed to open log file: "+err.Error()))
			handler = slog.NewTextHandler(os.Stderr, opts)
		} else {
			handler = slog.NewJSONHandler(f, opts)
		}
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func main() {
	mainCmd.DisableSuggestions = false
	mainCmd.CompletionOptions.DisableDefaultCmd = true
	mainCmd.SetHelpCommand(&cobra.Command{})

	// Persistent so subcommands (admin, ui, …) see -c the same as
	// the bare daemon invocation. Local Flags() registration left
	// the ui subcommand reporting "unknown shorthand flag: 'c'".
	mainCmd.PersistentFlags().StringVarP(
		&ConfigFile,
		"config",
		"c",
		ConfigFile,
		"config file",
	)

	if err := mainCmd.Execute(); err != nil {
		// Cobra has already printed the error; exit non-zero so callers
		// (systemd, CI, shell scripts) can detect the failure. The prior
		// panic here dumped a useless stack trace for plain command
		// errors like a failed admin dial.
		os.Exit(1)
	}
}

func runClient(cfg *config.Config, cipher *crypto.Cipher, tlsCert *tls.Certificate, expectedPeerCertHash []byte, sigCh chan os.Signal) error {
	fmt.Printf("%-30s %s\n", "Server:", cfg.GetServerAddr())
	if len(cfg.Spoof.SourceIPs) > 0 {
		fmt.Printf("%-30s %s\n", "Spoof source IPs:", strings.Join(cfg.Spoof.SourceIPs, ", "))
	}
	if len(cfg.Spoof.PeerSpoofIPs) > 0 {
		fmt.Printf("%-30s %s\n", "Expected server spoof IPs:", strings.Join(cfg.Spoof.PeerSpoofIPs, ", "))
	}
	fmt.Println()
	for _, inb := range cfg.Inbounds {
		switch inb.Type {
		case config.InboundSocks:
			fmt.Printf("%-30s %s\n", "Inbound [socks]:", inb.Listen)
		case config.InboundForward:
			fmt.Printf("%-30s %s → %s\n", "Inbound [forward]:", inb.Listen, inb.Target)
		}
	}
	fmt.Println()
	slog.Info("starting client mode")

	client, err := tunnel.NewClient(cfg, cipher, tlsCert, expectedPeerCertHash)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	if stop := maybeStartAdmin(cfg, client); stop != nil {
		defer stop()
	}
	if stop := maybeStartMetrics(cfg, client); stop != nil {
		defer stop()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Start()
	}()

	var runErr error
	select {
	case sig := <-sigCh:
		slog.Info("received signal", "signal", sig)
	case err := <-errCh:
		if err != nil {
			slog.Error("client error", "error", err)
			runErr = err
		}
	}

	slog.Info("shutting down client")
	client.Stop()

	sent, received := client.Stats()
	slog.Info("stats", "sent_bytes", sent, "received_bytes", received)
	return runErr
}

// runServer initialises and runs the multi-peer server. Per-peer ECDH
// and TLS cert derivation happen inside this function so main's RunE
// stays mode-agnostic. keyPair is the server's own X25519 key pair.
func runServer(cfg *config.Config, keyPair *crypto.KeyPair, sigCh chan os.Signal) error {
	fmt.Printf("%-30s %d\n", "Listening on port:", cfg.ListenPort)
	fmt.Printf("%-30s %d\n", "Peers:", len(cfg.Peers))
	for _, p := range cfg.Peers {
		line := p.Name
		if p.ClientRealIP != "" {
			line += " (" + p.ClientRealIP + ")"
		} else if p.ClientRealIPv6 != "" {
			line += " (" + p.ClientRealIPv6 + ")"
		}
		if len(p.PeerSpoofIPs) > 0 {
			line += " spoof=" + strings.Join(p.PeerSpoofIPs, ",")
		}
		fmt.Printf("  peer: %s\n", line)
	}
	if cfg.OutboundProxy.Enabled {
		fmt.Printf("%-30s %s\n", "Outbound proxy:", green(cfg.GetOutboundProxyAddr()))
	} else {
		fmt.Printf("%-30s %s\n", "Outbound proxy:", "direct (disabled)")
	}
	fmt.Println()
	slog.Info("starting server mode", "peers", len(cfg.Peers))

	// Derive the set of expected peer cert hashes for the multi-peer
	// TLS client-cert gate. The server presents a per-peer cert via
	// tls.Config.GetCertificate (built inside NewServer from the same
	// per-peer shared secrets), so we don't need to hand the cert here.
	peerHashes := make(map[[32]byte]struct{}, len(cfg.Peers))
	for i, p := range cfg.Peers {
		peerPub, err := crypto.ParsePublicKey(p.PeerPublicKey)
		if err != nil {
			return fmt.Errorf("peers[%d] (%s): parse peer_public_key: %w", i, p.Name, err)
		}
		ss, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, peerPub)
		if err != nil {
			return fmt.Errorf("peers[%d] (%s): compute shared secret: %w", i, p.Name, err)
		}
		hashBytes, err := crypto.DeriveTLSCertHash(ss)
		if err != nil {
			return fmt.Errorf("peers[%d] (%s): derive tls cert hash: %w", i, p.Name, err)
		}
		var h32 [32]byte
		copy(h32[:], hashBytes)
		peerHashes[h32] = struct{}{}
	}

	server, err := tunnel.NewServer(cfg, keyPair, peerHashes)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	if stop := maybeStartAdmin(cfg, server); stop != nil {
		defer stop()
	}
	if stop := maybeStartMetrics(cfg, server); stop != nil {
		defer stop()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	var runErr error
	select {
	case sig := <-sigCh:
		slog.Info("received signal", "signal", sig)
	case err := <-errCh:
		if err != nil {
			slog.Error("server error", "error", err)
			runErr = err
		}
	}

	slog.Info("shutting down server")
	server.Stop()

	sent, received, sessions := server.Stats()
	slog.Info("stats", "sent_bytes", sent, "received_bytes", received, "active_sessions", sessions)
	return runErr
}
