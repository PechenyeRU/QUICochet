package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
)

// Mode represents the operating mode of the tunnel
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// TransportType represents the transport protocol
type TransportType string

const (
	TransportUDP    TransportType = "udp"
	TransportICMP   TransportType = "icmp"
	TransportRAW    TransportType = "raw"
	TransportSynUDP TransportType = "syn_udp"
)

// ICMPMode represents the ICMP packet type to use
type ICMPMode string

const (
	ICMPModeEcho  ICMPMode = "echo"
	ICMPModeReply ICMPMode = "reply"
)

// LogLevel represents logging verbosity
type LogLevel string

const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// InboundType represents the type of inbound listener
type InboundType string

const (
	InboundSocks   InboundType = "socks"
	InboundForward InboundType = "forward"
)

// ObfuscationMode represents the level of traffic obfuscation
type ObfuscationMode string

const (
	ObfuscationNone     ObfuscationMode = "none"
	ObfuscationStandard ObfuscationMode = "standard"
	ObfuscationParanoid ObfuscationMode = "paranoid"
)

// InboundConfig configures a single inbound listener
type InboundConfig struct {
	Type       InboundType `json:"type"`
	Listen     string      `json:"listen"`
	Target string `json:"target,omitempty"` // forward mode: remote target address
}

// Config holds all configuration for the tunnel
type Config struct {
	Mode       Mode            `json:"mode"`
	Transport  TransportConfig `json:"transport"`
	ListenPort int             `json:"listen_port"` // server mode: UDP port to listen on
	Server     ServerConfig    `json:"server"`
	Spoof         SpoofConfig         `json:"spoof"`
	Crypto        CryptoConfig        `json:"crypto"`
	Performance   PerformanceConfig   `json:"performance"`
	Obfuscation   ObfuscationConfig   `json:"obfuscation"`
	QUIC          QUICConfig          `json:"quic"`
	Security      SecurityConfig      `json:"security"`
	OutboundProxy OutboundProxyConfig `json:"outbound_proxy"`
	Logging       LoggingConfig       `json:"logging"`
	Inbounds []InboundConfig `json:"inbounds"`
}

// TransportConfig configures the transport layer
type TransportConfig struct {
	Type           TransportType `json:"type"`
	ICMPMode       ICMPMode      `json:"icmp_mode"`
	ProtocolNumber int           `json:"protocol_number"` // Custom IP protocol number (1-255), used when type is "raw"
	ICMPEchoID     uint16        `json:"-"`               // Derived at runtime from shared secret, not persisted
}

// ServerConfig configures the remote server (client mode only)
type ServerConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// SpoofConfig configures IP spoofing
type SpoofConfig struct {
	SourceIP      string `json:"source_ip"`
	SourceIPv6    string `json:"source_ipv6"`
	PeerSpoofIP   string `json:"peer_spoof_ip"`
	PeerSpoofIPv6 string `json:"peer_spoof_ipv6"`
	// ClientRealIP is the actual IP of the client (server mode only)
	// Server sends packets to this IP
	ClientRealIP   string `json:"client_real_ip"`
	ClientRealIPv6 string `json:"client_real_ipv6"`
}

// CryptoConfig configures encryption keys
type CryptoConfig struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
}

// PerformanceConfig configures performance tuning
type PerformanceConfig struct {
	BufferSize     int `json:"buffer_size"`
	MTU            int `json:"mtu"`
	SessionTimeout int `json:"session_timeout"`
	Workers        int `json:"workers"`
	ReadBuffer     int `json:"read_buffer"`
	WriteBuffer    int `json:"write_buffer"`
	SendRateLimit  int `json:"send_rate_limit"` // packets per second, 0 = unlimited
	SendBandwidth  int `json:"send_bandwidth"`  // bandwidth limit in Mbps, 0 = unlimited (overrides send_rate_limit)
}

// ObfuscationConfig configures Anti-DPI/IA defenses
type ObfuscationConfig struct {
	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"` // "none", "standard", "paranoid"
	ChaffingIntervalMs int    `json:"chaffing_interval_ms"`
}

// QUICConfig configures the QUIC transport layer
type QUICConfig struct {
	KeepAlivePeriodSec         int `json:"keep_alive_period_sec"`
	MaxIdleTimeoutSec          int `json:"max_idle_timeout_sec"`
	MaxStreamReceiveWindow     int `json:"max_stream_receive_window"`     // bytes, 0 = default (5 MB)
	MaxConnectionReceiveWindow int `json:"max_connection_receive_window"` // bytes, 0 = default (15 MB)
	PoolSize                   int `json:"pool_size"`                     // connection pool size (client only), 0 = default (4)
}

// LoggingConfig configures logging
type LoggingConfig struct {
	Level LogLevel `json:"level"`
	File  string   `json:"file"`
}

// SecurityConfig configures security policies for target connections.
type SecurityConfig struct {
	BlockPrivateTargets *bool `json:"block_private_targets,omitempty"` // default true
}

// BlocksPrivateTargets returns whether dialing private/internal IPs is blocked.
func (s *SecurityConfig) BlocksPrivateTargets() bool {
	if s.BlockPrivateTargets == nil {
		return true // safe by default
	}
	return *s.BlockPrivateTargets
}

// OutboundProxyConfig configures an outbound proxy for server-side target connections.
type OutboundProxyConfig struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`     // Proxy type: "socks5"
	Address  string `json:"address"`  // Proxy address (e.g. "127.0.0.1:2080")
	Username string `json:"username"` // Optional authentication username
	Password string `json:"password"` // Optional authentication password
}

// Load reads and parses configuration from a JSON file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// setDefaults applies default values for unset fields
func (c *Config) setDefaults() error {
	// Transport defaults
	if c.Transport.Type == "" {
		c.Transport.Type = TransportUDP
	}
	if c.Transport.ICMPMode == "" {
		c.Transport.ICMPMode = ICMPModeEcho
	}

	// Listen port default (server mode)
	if c.ListenPort == 0 && c.Mode == ModeServer {
		c.ListenPort = 8080
	}

	// Performance defaults
	if c.Performance.BufferSize == 0 {
		c.Performance.BufferSize = 65535
	}
	if c.Performance.MTU == 0 {
		c.Performance.MTU = 1400
	}
	if c.Performance.SessionTimeout == 0 {
		c.Performance.SessionTimeout = 600 // 10 minutes
	}
	if c.Performance.Workers == 0 {
		c.Performance.Workers = 4
	}
	if c.Performance.ReadBuffer == 0 {
		c.Performance.ReadBuffer = 4 * 1024 * 1024
	}
	if c.Performance.WriteBuffer == 0 {
		c.Performance.WriteBuffer = 4 * 1024 * 1024
	}

	// Obfuscation defaults
	if !c.Obfuscation.Enabled {
		c.Obfuscation.Mode = "none"
	} else if c.Obfuscation.Mode == "" {
		c.Obfuscation.Mode = "standard"
	}
	if c.Obfuscation.ChaffingIntervalMs == 0 {
		c.Obfuscation.ChaffingIntervalMs = 50
	}

	// QUIC defaults
	if c.QUIC.KeepAlivePeriodSec == 0 {
		c.QUIC.KeepAlivePeriodSec = 5
	}
	if c.QUIC.MaxIdleTimeoutSec == 0 {
		c.QUIC.MaxIdleTimeoutSec = 10
	}
	if c.QUIC.MaxStreamReceiveWindow == 0 {
		c.QUIC.MaxStreamReceiveWindow = 5 * 1024 * 1024 // 5 MB
	}
	if c.QUIC.MaxConnectionReceiveWindow == 0 {
		c.QUIC.MaxConnectionReceiveWindow = 15 * 1024 * 1024 // 15 MB
	}
	if c.QUIC.PoolSize == 0 {
		c.QUIC.PoolSize = 4 // 4 connections = sweet spot for WAN links
	}

	// Outbound proxy defaults - disabled by default
	if c.OutboundProxy.Enabled {
		if c.OutboundProxy.Type == "" {
			c.OutboundProxy.Type = "socks5"
		}
	}

	// Logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = LogInfo
	}

	// Default inbound: if no inbounds defined in client mode, create a SOCKS5 listener
	if len(c.Inbounds) == 0 && c.Mode == ModeClient {
		c.Inbounds = []InboundConfig{{
			Type:   InboundSocks,
			Listen: "127.0.0.1:1080",
		}}
	}

	return nil
}

// Validate checks that the configuration is valid
func (c *Config) Validate() error {
	var errs []string

	// Mode validation
	if c.Mode != ModeClient && c.Mode != ModeServer {
		errs = append(errs, fmt.Sprintf("invalid mode: %s (must be 'client' or 'server')", c.Mode))
	}

	// Transport validation
	if c.Transport.Type != TransportUDP && c.Transport.Type != TransportICMP && c.Transport.Type != TransportRAW && c.Transport.Type != TransportSynUDP {
		errs = append(errs, fmt.Sprintf("invalid transport type: %s (must be 'udp', 'icmp', 'raw', or 'syn_udp')", c.Transport.Type))
	}
	if c.Transport.Type == TransportICMP {
		if c.Transport.ICMPMode != ICMPModeEcho && c.Transport.ICMPMode != ICMPModeReply {
			errs = append(errs, fmt.Sprintf("invalid icmp_mode: %s", c.Transport.ICMPMode))
		}
	}
	if c.Transport.Type == TransportRAW {
		if c.Transport.ProtocolNumber < 1 || c.Transport.ProtocolNumber > 255 {
			errs = append(errs, fmt.Sprintf("invalid protocol_number: %d (must be 1-255)", c.Transport.ProtocolNumber))
		}
	}

	// Listen port validation (server mode)
	if c.Mode == ModeServer {
		if c.ListenPort < 1 || c.ListenPort > 65535 {
			errs = append(errs, fmt.Sprintf("invalid listen_port: %d", c.ListenPort))
		}
	}

	// Server validation (client mode only)
	if c.Mode == ModeClient {
		if c.Server.Address == "" {
			errs = append(errs, "server address is required in client mode")
		}
		if c.Server.Port < 1 || c.Server.Port > 65535 {
			errs = append(errs, fmt.Sprintf("invalid server port: %d", c.Server.Port))
		}
	}

	// Spoof validation
	if c.Spoof.SourceIP != "" && net.ParseIP(c.Spoof.SourceIP) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof source_ip: %s", c.Spoof.SourceIP))
	}
	if c.Spoof.SourceIPv6 != "" && net.ParseIP(c.Spoof.SourceIPv6) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof source_ipv6: %s", c.Spoof.SourceIPv6))
	}
	if c.Spoof.PeerSpoofIP != "" && net.ParseIP(c.Spoof.PeerSpoofIP) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof peer_spoof_ip: %s", c.Spoof.PeerSpoofIP))
	}
	if c.Spoof.PeerSpoofIPv6 != "" && net.ParseIP(c.Spoof.PeerSpoofIPv6) == nil {
		errs = append(errs, fmt.Sprintf("invalid spoof peer_spoof_ipv6: %s", c.Spoof.PeerSpoofIPv6))
	}

	// At least one spoof IP required
	if c.Spoof.SourceIP == "" && c.Spoof.SourceIPv6 == "" {
		errs = append(errs, "at least one spoof source IP (IPv4 or IPv6) is required")
	}

	// Server mode: client_real_ip is required
	if c.Mode == ModeServer {
		if c.Spoof.ClientRealIP == "" && c.Spoof.ClientRealIPv6 == "" {
			errs = append(errs, "client_real_ip is required in server mode (where to send packets)")
		}
		if c.Spoof.ClientRealIP != "" && net.ParseIP(c.Spoof.ClientRealIP) == nil {
			errs = append(errs, fmt.Sprintf("invalid client_real_ip: %s", c.Spoof.ClientRealIP))
		}
		if c.Spoof.ClientRealIPv6 != "" && net.ParseIP(c.Spoof.ClientRealIPv6) == nil {
			errs = append(errs, fmt.Sprintf("invalid client_real_ipv6: %s", c.Spoof.ClientRealIPv6))
		}
	}

	// Crypto validation
	if c.Crypto.PrivateKey == "" {
		errs = append(errs, "crypto.private_key is required (generate with: ./quiccochet keygen)")
	}
	if c.Crypto.PeerPublicKey == "" {
		errs = append(errs, "crypto.peer_public_key is required")
	}

	// Outbound proxy validation (server mode only)
	if c.OutboundProxy.Enabled {
		if c.Mode != ModeServer {
			errs = append(errs, "outbound_proxy is only supported in server mode")
		}
		if c.OutboundProxy.Type != "socks5" {
			errs = append(errs, fmt.Sprintf("invalid outbound_proxy type: %s (must be 'socks5')", c.OutboundProxy.Type))
		}
		if c.OutboundProxy.Address == "" {
			errs = append(errs, "outbound_proxy.address is required when outbound_proxy is enabled")
		}
	}

	// Obfuscation validation
	validModes := map[string]bool{"none": true, "standard": true, "paranoid": true}
	if !validModes[c.Obfuscation.Mode] {
		errs = append(errs, fmt.Sprintf("invalid obfuscation mode: %s (must be 'none', 'standard', or 'paranoid')", c.Obfuscation.Mode))
	}

	// Logging validation
	validLevels := map[LogLevel]bool{LogDebug: true, LogInfo: true, LogWarn: true, LogError: true}
	if !validLevels[c.Logging.Level] {
		errs = append(errs, fmt.Sprintf("invalid log level: %s", c.Logging.Level))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config errors:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// GetServerAddr returns the formatted server address
func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Address, c.Server.Port)
}

// IsIPv6 returns true if the primary spoof IP is IPv6
func (c *Config) IsIPv6() bool {
	if c.Spoof.SourceIP != "" {
		ip := net.ParseIP(c.Spoof.SourceIP)
		return ip != nil && ip.To4() == nil
	}
	return c.Spoof.SourceIPv6 != ""
}

// GetSourceIP returns the appropriate source IP based on IP version
func (c *Config) GetSourceIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.SourceIPv6
	}
	return c.Spoof.SourceIP
}

// GetPeerSpoofIP returns the appropriate peer spoof IP based on IP version
func (c *Config) GetPeerSpoofIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.PeerSpoofIPv6
	}
	return c.Spoof.PeerSpoofIP
}

// GetOutboundProxyAddr returns the formatted outbound proxy address (e.g. "socks5://127.0.0.1:2080")
func (c *Config) GetOutboundProxyAddr() string {
	if !c.OutboundProxy.Enabled {
		return "direct"
	}
	return fmt.Sprintf("%s://%s", c.OutboundProxy.Type, c.OutboundProxy.Address)
}

// SlogLevel converts the config log level to slog.Level
func (c *Config) SlogLevel() slog.Level {
	switch c.Logging.Level {
	case LogDebug:
		return slog.LevelDebug
	case LogWarn:
		return slog.LevelWarn
	case LogError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// GetClientRealIP returns the appropriate client real IP based on IP version
func (c *Config) GetClientRealIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.ClientRealIPv6
	}
	return c.Spoof.ClientRealIP
}
