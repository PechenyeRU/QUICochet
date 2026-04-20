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
	ListenPort int             `json:"listen_port"` // server: port to listen on. client: fixed receive port (0 = dynamic, set >0 when behind NAT/port forward)
	Server     ServerConfig    `json:"server"`
	Spoof         SpoofConfig         `json:"spoof"`
	Crypto        CryptoConfig        `json:"crypto"`
	Performance   PerformanceConfig   `json:"performance"`
	Obfuscation   ObfuscationConfig   `json:"obfuscation"`
	QUIC          QUICConfig          `json:"quic"`
	Security      SecurityConfig      `json:"security"`
	OutboundProxy OutboundProxyConfig `json:"outbound_proxy"`
	Logging       LoggingConfig       `json:"logging"`
	Admin         AdminConfig         `json:"admin"`
	Inbounds []InboundConfig `json:"inbounds"`
}

// TransportConfig configures the transport layer.
//
// Available types:
//   - "udp"     — raw UDP with spoofed source IP (default, best throughput)
//   - "icmp"    — ICMP Echo with spoofed source IP (bypasses UDP blocks)
//   - "raw"     — custom IP protocol number, requires protocol_number (1-255)
//   - "syn_udp" — asymmetric: client sends TCP SYN, server replies with UDP
type TransportConfig struct {
	Type           TransportType `json:"type"`            // transport protocol (default "udp")
	ICMPMode       ICMPMode      `json:"icmp_mode"`       // "echo" or "reply", only used when type is "icmp"
	ProtocolNumber int           `json:"protocol_number"` // required when type is "raw": custom IP protocol (1-255)
	ICMPEchoID     uint16        `json:"-"`               // derived at runtime from shared secret, not persisted
}

// ServerConfig configures the remote server (client mode only)
type ServerConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// SpoofConfig configures IP spoofing.
//
// Source IPs can be specified as a single value (source_ip) or a list
// (source_ips). When a list is provided, each outgoing packet picks a
// random entry — to middleboxes, traffic appears to come from N
// independent hosts. The singular and plural fields are merged at
// config load time; the singular field is kept for backward compat
// (acts as a one-element list). At least one source IP (v4 or v6) is
// required.
//
// peer_spoof_ips must list every IP the peer might use as source —
// i.e. the peer's full source_ips list. Non-raw transports (udp)
// don't filter by source, but raw/icmp/syn_udp do.
type SpoofConfig struct {
	SourceIP       string   `json:"source_ip"`
	SourceIPv6     string   `json:"source_ipv6"`
	SourceIPs      []string `json:"source_ips"`
	SourceIPv6s    []string `json:"source_ipv6s"`
	PeerSpoofIP    string   `json:"peer_spoof_ip"`
	PeerSpoofIPv6  string   `json:"peer_spoof_ipv6"`
	PeerSpoofIPs   []string `json:"peer_spoof_ips"`
	PeerSpoofIPv6s []string `json:"peer_spoof_ipv6s"`
	ClientRealIP   string   `json:"client_real_ip"`
	ClientRealIPv6 string   `json:"client_real_ipv6"`
}

// CryptoConfig configures encryption keys
type CryptoConfig struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
}

// PerformanceConfig configures performance tuning
type PerformanceConfig struct {
	BufferSize  int `json:"buffer_size"`  // internal pool buffer size in bytes (default 65535)
	// MTU is the on-wire size budget for the obfuscator output, in bytes.
	// The raw transport will send packets of (MTU + IP header) size; quic-go
	// is configured with InitialPacketSize = MTU - 31 (obfuscator overhead).
	// Minimum 1231 (enforced); default 1400; safe maximum for eth ~1460.
	MTU         int `json:"mtu"`
	Workers     int `json:"workers"`      // number of worker goroutines (default 4)
	ReadBuffer  int `json:"read_buffer"`  // SO_RCVBUF socket buffer size in bytes (default 4 MB)
	WriteBuffer int `json:"write_buffer"` // SO_SNDBUF socket buffer size in bytes (default 4 MB)
}

// ObfuscationConfig configures Anti-DPI/IA defenses.
//
// Modes:
//   - "none"     — no obfuscation, minimal overhead
//   - "standard" — encryption + fixed-size padding to hide payload length
//   - "paranoid" — standard + constant bit rate chaffing at chaffing_interval_ms
type ObfuscationConfig struct {
	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"`                // "none", "standard", "paranoid"
	ChaffingIntervalMs int    `json:"chaffing_interval_ms"` // chaff interval in ms, only used in paranoid mode (default 50)
}

// QUICConfig configures the QUIC transport layer.
//
// For high-BDP links (high latency + high bandwidth), increase the receive
// windows. E.g. for 100ms RTT at 1 Gbps: BDP = 12.5 MB, so set
// max_stream_receive_window >= 15 MB and max_connection_receive_window >= 45 MB.
type QUICConfig struct {
	KeepAlivePeriodSec         int `json:"keep_alive_period_sec"`         // seconds between keep-alive pings (default 5)
	MaxIdleTimeoutSec          int `json:"max_idle_timeout_sec"`          // close connection after this many idle seconds (default 10)
	MaxStreamReceiveWindow     int `json:"max_stream_receive_window"`     // per-stream flow control window in bytes (default 5 MB)
	MaxConnectionReceiveWindow int `json:"max_connection_receive_window"` // per-connection flow control window in bytes (default 15 MB)
	PoolSize                   int `json:"pool_size"`                     // QUIC connection pool size, client only (default 4)
	StreamCloseTimeoutSec      int `json:"stream_close_timeout_sec"`      // seconds before force-canceling a closing stream (default 10)

	// MaxIncomingStreams is the maximum number of concurrent bidirectional
	// QUIC streams accepted per connection. quic-go's default is 100,
	// which caps the whole pool at pool_size * 100 streams; with many
	// SOCKS5 clients sharing one tunnel (e.g. xray fan-in) this saturates
	// in seconds and causes "0kbps or 100Mbps" behavior as OpenStreamSync
	// waits 5s for MAX_STREAMS credit and times out.
	//
	// Default is 100000, high enough that a single tunnel can serve
	// thousands of concurrent SOCKS5 clients without ever hitting the
	// cap. quic-go allocates stream state lazily on stream open (not per
	// credit slot), so the memory cost of a large cap is negligible
	// until the streams are actually in use. Must match on client and
	// server or the smaller of the two wins (the peer enforces).
	MaxIncomingStreams int `json:"max_incoming_streams"` // default 100000
	// MaxIncomingUniStreams is the same, for unidirectional streams. We
	// don't currently use uni streams; default 1000 is fine.
	MaxIncomingUniStreams int `json:"max_incoming_uni_streams"` // default 1000

	// EnablePathMTUDiscovery turns on quic-go's PLPMTUD probing. Default
	// false (disabled) because the obfuscator silently drops packets >1472
	// bytes as an anti-fragmentation measure, so PLPMTUD probes above that
	// threshold are black-holed and quic-go cannot converge on a real path
	// MTU. Enable ONLY after raising the obfuscator cap (see
	// obfuscator.go maxPacketSize). If you don't know what that means,
	// leave it off.
	EnablePathMTUDiscovery bool `json:"enable_path_mtu_discovery"` // default false

	// UDPRouteIdleSec is the idle timeout applied to a per-target UDP
	// relay route on the server. Idle is measured bidirectionally: the
	// timer resets every time a datagram flows in either direction.
	// After this many seconds of true silence on a route, the UDP socket
	// is closed and its goroutine exits (both the receive-loop and a
	// background janitor enforce it). Default 90s covers keepalive-heavy
	// protocols. Server-only.
	UDPRouteIdleSec int `json:"udp_route_idle_sec"` // default 90

	// UDPRouteMax is a hard circuit-breaker on the number of concurrent
	// UDP relay routes per QUIC session. When the cap is hit, creating a
	// new route evicts the route with the oldest lastActivity (LRU).
	// This is a safety net against runaway growth from pathological
	// workloads — in normal operation the idle timeout keeps the working
	// set well below this cap. Default 50000 (each route = 1 fd;
	// LimitNOFILE in the systemd unit is 1048576, so 50000 leaves
	// headroom for sockets unrelated to UDP routes). Server-only.
	UDPRouteMax int `json:"udp_route_max"` // default 50000

	// CongestionControl selects the congestion-control algorithm.
	//   "" or "cubic" — quic-go's default NewReno/CUBIC (stable, upstream)
	//   "bbrv1"       — Google BBR v1 via qiulaidongfeng/quic-go fork
	//                   (experimental, may improve throughput on lossy/high-RTT
	//                   paths but unreviewed community implementation)
	CongestionControl string `json:"congestion_control"`
}

// LoggingConfig configures logging.
//
// Statistics, when true, promotes the 30s stats ticker (pool health,
// bytes, UDP routes, open FDs) from DEBUG to INFO so operators can
// watch tunnel health without enabling full debug-level verbosity.
type LoggingConfig struct {
	Level      LogLevel `json:"level"`
	File       string   `json:"file"`
	Statistics bool     `json:"statistics"`
}

// AdminConfig configures the admin Unix socket used for on-demand
// stats dumps and in-link benchmarks. Disabled by default.
//
// Socket is the path to bind. When empty and Enabled=true, the
// runtime picks /run/quiccochet-<pid>.sock and logs the resolved
// path at startup. Explicit paths are preferred when running
// multiple daemons on one host (e.g. client + client-vpn1).
type AdminConfig struct {
	Enabled bool   `json:"enabled"`
	Socket  string `json:"socket"`
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
	// Merge singular spoof fields into their plural lists. The singular
	// field acts as a one-element list for backward compat. If both are
	// set, the singular is prepended (deduped).
	c.Spoof.SourceIPs = mergeIPField(c.Spoof.SourceIP, c.Spoof.SourceIPs)
	c.Spoof.SourceIPv6s = mergeIPField(c.Spoof.SourceIPv6, c.Spoof.SourceIPv6s)
	c.Spoof.PeerSpoofIPs = mergeIPField(c.Spoof.PeerSpoofIP, c.Spoof.PeerSpoofIPs)
	c.Spoof.PeerSpoofIPv6s = mergeIPField(c.Spoof.PeerSpoofIPv6, c.Spoof.PeerSpoofIPv6s)
	// Back-fill the singular field so legacy readers see the first entry.
	if len(c.Spoof.SourceIPs) > 0 {
		c.Spoof.SourceIP = c.Spoof.SourceIPs[0]
	}
	if len(c.Spoof.SourceIPv6s) > 0 {
		c.Spoof.SourceIPv6 = c.Spoof.SourceIPv6s[0]
	}
	if len(c.Spoof.PeerSpoofIPs) > 0 {
		c.Spoof.PeerSpoofIP = c.Spoof.PeerSpoofIPs[0]
	}
	if len(c.Spoof.PeerSpoofIPv6s) > 0 {
		c.Spoof.PeerSpoofIPv6 = c.Spoof.PeerSpoofIPv6s[0]
	}

	// Transport defaults
	if c.Transport.Type == "" {
		c.Transport.Type = TransportUDP
	}
	// ICMP mode default depends on role: client emits Echo Request, server
	// emits Echo Reply. The two peers MUST use opposite modes (see README
	// "ICMP Mode Asymmetry"); defaulting both to "echo" caused the v1.6
	// e2e test to deadlock because both sides filtered for the type they
	// were also emitting.
	if c.Transport.ICMPMode == "" {
		if c.Mode == ModeServer {
			c.Transport.ICMPMode = ICMPModeReply
		} else {
			c.Transport.ICMPMode = ICMPModeEcho
		}
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
	if c.QUIC.StreamCloseTimeoutSec == 0 {
		c.QUIC.StreamCloseTimeoutSec = 10
	}
	if c.QUIC.MaxIncomingStreams == 0 {
		c.QUIC.MaxIncomingStreams = 100000
	}
	if c.QUIC.MaxIncomingUniStreams == 0 {
		c.QUIC.MaxIncomingUniStreams = 1000
	}
	if c.QUIC.UDPRouteIdleSec == 0 {
		c.QUIC.UDPRouteIdleSec = 90
	}
	if c.QUIC.UDPRouteMax == 0 {
		c.QUIC.UDPRouteMax = 50000
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

	// Listen port validation
	if c.Mode == ModeServer {
		if c.ListenPort < 1 || c.ListenPort > 65535 {
			errs = append(errs, fmt.Sprintf("invalid listen_port: %d (required for server)", c.ListenPort))
		}
	}
	if c.Mode == ModeClient && c.ListenPort != 0 {
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

	// Spoof validation — validate singular fields (kept for backward
	// compat / direct Validate() calls) AND every entry in the plural
	// lists. After setDefaults(), the singular is inside the list, but
	// Validate() may be called standalone by tests.
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
	for _, ip := range c.Spoof.SourceIPs {
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("invalid spoof source_ips entry: %s", ip))
		}
	}
	for _, ip := range c.Spoof.SourceIPv6s {
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("invalid spoof source_ipv6s entry: %s", ip))
		}
	}
	for _, ip := range c.Spoof.PeerSpoofIPs {
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("invalid spoof peer_spoof_ips entry: %s", ip))
		}
	}
	for _, ip := range c.Spoof.PeerSpoofIPv6s {
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("invalid spoof peer_spoof_ipv6s entry: %s", ip))
		}
	}

	if len(c.Spoof.SourceIPs) == 0 && len(c.Spoof.SourceIPv6s) == 0 && c.Spoof.SourceIP == "" && c.Spoof.SourceIPv6 == "" {
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

	// Congestion control validation
	validCC := map[string]bool{"": true, "cubic": true, "bbrv1": true}
	if !validCC[c.QUIC.CongestionControl] {
		errs = append(errs, fmt.Sprintf("invalid quic.congestion_control: %q (must be 'cubic' or 'bbrv1')", c.QUIC.CongestionControl))
	}

	if c.QUIC.MaxIncomingStreams < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.max_incoming_streams: %d (must be >= 0)", c.QUIC.MaxIncomingStreams))
	}
	if c.QUIC.MaxIncomingUniStreams < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.max_incoming_uni_streams: %d (must be >= 0)", c.QUIC.MaxIncomingUniStreams))
	}
	// 0 means "use default" (applied in setDefaults); reject only explicit small values.
	if c.QUIC.UDPRouteIdleSec != 0 && c.QUIC.UDPRouteIdleSec < 10 {
		errs = append(errs, fmt.Sprintf("invalid quic.udp_route_idle_sec: %d (minimum 10)", c.QUIC.UDPRouteIdleSec))
	}
	if c.QUIC.UDPRouteMax < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.udp_route_max: %d (must be >= 0)", c.QUIC.UDPRouteMax))
	}

	// MTU floor: quic-go requires InitialPacketSize ≥ 1200 (RFC 9000 §14.1)
	// and the obfuscator adds 31 bytes on top (3 framing + 12 nonce + 16 tag)
	// before writing to the transport. So cfg.MTU must leave room for both:
	// MTU ≥ 1200 + 31 = 1231.
	if c.Performance.MTU < 1231 {
		errs = append(errs, fmt.Sprintf("performance.mtu=%d is below the minimum 1231 (quic-go requires 1200-byte packets + 31 bytes of obfuscator overhead)", c.Performance.MTU))
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

// StatsLogLevel returns the level at which the periodic stats ticker
// should emit. When logging.statistics is true, stats are promoted to
// INFO; otherwise they stay at DEBUG (visible only when log_level=debug).
func (c *Config) StatsLogLevel() slog.Level {
	if c.Logging.Statistics {
		return slog.LevelInfo
	}
	return slog.LevelDebug
}

// ResolveAdminSocket returns the path the admin listener should bind
// to. When admin.socket is explicitly set the value is returned
// verbatim; when empty, the runtime picks /run/quiccochet-<pid>.sock.
// The returned bool is true when the path was derived from the PID
// (callers use this to decide whether to log the chosen path at
// startup so operators can find it).
func (c *Config) ResolveAdminSocket(pid int) (string, bool) {
	if c.Admin.Socket != "" {
		return c.Admin.Socket, false
	}
	return fmt.Sprintf("/run/quiccochet-%d.sock", pid), true
}

// GetClientRealIP returns the appropriate client real IP based on IP version
func (c *Config) GetClientRealIP(ipv6 bool) string {
	if ipv6 {
		return c.Spoof.ClientRealIPv6
	}
	return c.Spoof.ClientRealIP
}

// mergeIPField prepends singular into the plural list if it isn't
// already present. Returns the resulting list (which may be nil if
// both are empty).
func mergeIPField(singular string, plural []string) []string {
	if singular == "" {
		return plural
	}
	for _, s := range plural {
		if s == singular {
			return plural
		}
	}
	return append([]string{singular}, plural...)
}

// ParseIPs converts a slice of IP strings to net.IP values, skipping
// empty strings. Exported so tunnel packages can use it.
func ParseIPs(strs []string) []net.IP {
	if len(strs) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(strs))
	for _, s := range strs {
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
