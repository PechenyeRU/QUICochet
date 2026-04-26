package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/crypto"
	"golang.org/x/crypto/hkdf"
	"github.com/pechenyeru/quiccochet/internal/tunnel"
	"github.com/spf13/cobra"
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

		peerPubKey, err := crypto.ParsePublicKey(cfg.Crypto.PeerPublicKey)
		if err != nil {
			return fmt.Errorf("parse peer public key: %w", err)
		}

		sharedSecret, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, peerPubKey)
		if err != nil {
			return fmt.Errorf("compute shared secret: %w", err)
		}

		// Derive ICMP echo ID via HKDF so no raw key material leaks into packets
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

		isInitiator := cfg.Mode == config.ModeClient
		sendKey, recvKey, err := crypto.DeriveSessionKeys(sharedSecret, isInitiator)
		if err != nil {
			return fmt.Errorf("derive session keys: %w", err)
		}

		cipher, err := crypto.NewCipher(sendKey, recvKey)
		if err != nil {
			return fmt.Errorf("create cipher: %w", err)
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
			return runClient(cfg, cipher, sigCh)
		case config.ModeServer:
			return runServer(cfg, cipher, sigCh)
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

func setupLogger(cfg *config.Config) {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}

	var handler slog.Handler
	if cfg.Logging.File != "" {
		f, err := os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

	mainCmd.Flags().StringVarP(
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

func runClient(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) error {
	fmt.Printf("%-30s %s\n", "Server:", cfg.GetServerAddr())
	fmt.Printf("%-30s %s\n", "Spoof source IP:", cfg.Spoof.SourceIP)
	if cfg.Spoof.PeerSpoofIP != "" {
		fmt.Printf("%-30s %s\n", "Expected server spoof IP:", cfg.Spoof.PeerSpoofIP)
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

	client, err := tunnel.NewClient(cfg, cipher)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	if stop := maybeStartAdmin(cfg, client); stop != nil {
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

func runServer(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) error {
	fmt.Printf("%-30s %d\n", "Listening on port:", cfg.ListenPort)
	fmt.Printf("%-30s %s\n", "Spoof source IP:", cfg.Spoof.SourceIP)
	if cfg.Spoof.PeerSpoofIP != "" {
		fmt.Printf("%-30s %s\n", "Expected client spoof IP:", cfg.Spoof.PeerSpoofIP)
	}
	if cfg.OutboundProxy.Enabled {
		fmt.Printf("%-30s %s\n", "Outbound proxy:", green(cfg.GetOutboundProxyAddr()))
	} else {
		fmt.Printf("%-30s %s\n", "Outbound proxy:", "direct (disabled)")
	}

	fmt.Println()
	slog.Info("starting server mode")

	server, err := tunnel.NewServer(cfg, cipher)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	if stop := maybeStartAdmin(cfg, server); stop != nil {
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
