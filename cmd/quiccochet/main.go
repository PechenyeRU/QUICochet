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
	red        = color.New(color.FgRed).SprintFunc()
	yellow     = color.New(color.FgYellow).SprintFunc()
	green      = color.New(color.FgGreen).SprintFunc()
)

var mainCmd = &cobra.Command{
	Use:     "quiccochet",
	Version: Version + " (" + Commit + ") built " + BuildTime,
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, yellow("Warning: Running without root privileges. Raw sockets may fail."))
			fmt.Fprintln(os.Stderr, "Run with: sudo ./quiccochet -c client-config.json")
			fmt.Fprintln(os.Stderr)
		}

		cfg, err := config.Load(ConfigFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, red("Failed to load config"))
			fmt.Fprintln(os.Stderr, red(err))
			return
		}

		setupLogger(cfg)

		keyPair, err := crypto.ParsePrivateKey(cfg.Crypto.PrivateKey)
		if err != nil {
			slog.Error("failed to parse private key", "error", err)
			return
		}

		peerPubKey, err := crypto.ParsePublicKey(cfg.Crypto.PeerPublicKey)
		if err != nil {
			slog.Error("failed to parse peer public key", "error", err)
			return
		}

		sharedSecret, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, peerPubKey)
		if err != nil {
			slog.Error("failed to compute shared secret", "error", err)
			return
		}

		// Derive ICMP echo ID via HKDF so no raw key material leaks into packets
		idReader := hkdf.New(sha256.New, sharedSecret[:],
			[]byte("quiccochet-v2-session-keys"), []byte("icmp-echo-id"))
		var idBytes [2]byte
		if _, err = io.ReadFull(idReader, idBytes[:]); err != nil {
			slog.Error("failed to derive icmp echo id", "error", err)
			return
		}
		cfg.Transport.ICMPEchoID = binary.BigEndian.Uint16(idBytes[:])
		if cfg.Transport.ICMPEchoID == 0 {
			cfg.Transport.ICMPEchoID = 1
		}

		isInitiator := cfg.Mode == config.ModeClient
		sendKey, recvKey, err := crypto.DeriveSessionKeys(sharedSecret, isInitiator)
		if err != nil {
			slog.Error("failed to derive session keys", "error", err)
			return
		}

		cipher, err := crypto.NewCipher(sendKey, recvKey)
		if err != nil {
			slog.Error("failed to create cipher", "error", err)
			return
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
			runClient(cfg, cipher, sigCh)
		case config.ModeServer:
			runServer(cfg, cipher, sigCh)
		}
	},
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
		panic(err)
	}
}

func runClient(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) {
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
		slog.Error("failed to create client", "error", err)
		return
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Start()
	}()

	select {
	case sig := <-sigCh:
		slog.Info("received signal", "signal", sig)
	case err := <-errCh:
		if err != nil {
			slog.Error("client error", "error", err)
		}
	}

	slog.Info("shutting down client")
	client.Stop()

	sent, received := client.Stats()
	slog.Info("stats", "sent_bytes", sent, "received_bytes", received)
}

func runServer(cfg *config.Config, cipher *crypto.Cipher, sigCh chan os.Signal) {
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
		slog.Error("failed to create server", "error", err)
		return
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	select {
	case sig := <-sigCh:
		slog.Info("received signal", "signal", sig)
	case err := <-errCh:
		if err != nil {
			slog.Error("server error", "error", err)
		}
	}

	slog.Info("shutting down server")
	server.Stop()

	sent, received, sessions := server.Stats()
	slog.Info("stats", "sent_bytes", sent, "received_bytes", received, "active_sessions", sessions)
}
