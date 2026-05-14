package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/pechenyeru/quiccochet/internal/configmigrate"
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
	TransportICMPv6 TransportType = "icmpv6"
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

// InboundAuthConfig optionally enables SOCKS5 username/password
// authentication (RFC 1929) on a socks inbound. When set, clients
// must complete the username/password sub-negotiation; when nil, the
// inbound accepts no-auth (the legacy behaviour). Stored in plaintext
// — the config file already contains the X25519 private key, so it
// is expected to be 0600 anyway.
type InboundAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// InboundConfig configures a single inbound listener
type InboundConfig struct {
	Type   InboundType        `json:"type"`
	Listen string             `json:"listen"`
	Target string             `json:"target,omitempty"` // forward mode: remote target address
	Auth   *InboundAuthConfig `json:"auth,omitempty"`   // socks mode: optional RFC 1929 auth
}

// PeerConfig describes one client peer on the server side.
// Each peer has its own X25519 public key, real IP address(es) to
// deliver reply traffic to, and a set of spoofed wire source IPs
// that identify packets coming from this peer.
//
// Per-peer source_ips / peer_spoof_ips MUST be disjoint across all
// peers — the server uses the wire source IP of each inbound packet
// to select the right cipher for decryption. Validation hard-fails
// if any IP appears in more than one peer's peer_spoof_ips lists.
type PeerConfig struct {
	// Name is a human-readable label used in logs and admin output.
	Name string `json:"name"`

	// PeerPublicKey is the peer's X25519 public key (base64).
	PeerPublicKey string `json:"peer_public_key"`

	// ClientRealIP / ClientRealIPv6 are the real IP addresses that
	// the server uses to send reply traffic back to this peer. At
	// least one of the two must be set.
	ClientRealIP   string `json:"client_real_ip,omitempty"`
	ClientRealIPv6 string `json:"client_real_ipv6,omitempty"`

	// SourceIPs / SourceIPv6s are documentary fields recording the
	// spoofed source IPs THIS peer uses on its egress (i.e. the peer's
	// own source_ips list). The server does NOT consume them at runtime;
	// it builds its transport filter and cipher dispatch exclusively
	// from PeerSpoofIPs / PeerSpoofIPv6s, which are the IPs the server
	// SEES on the wire from this peer. In a correctly-configured
	// deployment the two are identical (peer's egress source IP =
	// what the server observes), so populating SourceIPs here is
	// optional metadata for operators / migration provenance only.
	SourceIPs   []string `json:"source_ips,omitempty"`
	SourceIPv6s []string `json:"source_ipv6s,omitempty"`

	// PeerSpoofIPs / PeerSpoofIPv6s are the spoofed source IPs the
	// server expects to see on the wire from this peer. This is the
	// dispatch key: when an inbound packet arrives with a source IP
	// in PeerSpoofIPs, it is decrypted with this peer's cipher.
	//
	// MUST be disjoint across all PeerConfigs.
	PeerSpoofIPs   []string `json:"peer_spoof_ips,omitempty"`
	PeerSpoofIPv6s []string `json:"peer_spoof_ipv6s,omitempty"`
}

// Config holds all configuration for the tunnel
type Config struct {
	Mode          Mode                `json:"mode"`
	Transport     TransportConfig     `json:"transport"`
	ListenPort    int                 `json:"listen_port"` // server: port to listen on. client: fixed receive port (0 = dynamic, set >0 when behind NAT/port forward)
	Server        ServerConfig        `json:"server"`
	Spoof         SpoofConfig         `json:"spoof"`
	Crypto        CryptoConfig        `json:"crypto"`
	Performance   PerformanceConfig   `json:"performance"`
	Obfuscation   ObfuscationConfig   `json:"obfuscation"`
	QUIC          QUICConfig          `json:"quic"`
	Security      SecurityConfig      `json:"security"`
	OutboundProxy OutboundProxyConfig `json:"outbound_proxy"`
	Logging       LoggingConfig       `json:"logging"`
	Admin         AdminConfig         `json:"admin"`
	Metrics       MetricsConfig       `json:"metrics"`
	Inbounds      []InboundConfig     `json:"inbounds"`

	// Peers is the multi-peer list for server mode (v2.0.0+).
	// Server mode requires this to be non-empty. Client mode leaves
	// it nil and uses Crypto.PeerPublicKey + Spoof.* instead.
	Peers []PeerConfig `json:"peers,omitempty"`
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

// SpoofConfig configures IP spoofing for client mode.
//
// Only source_ips / source_ipv6s (plural form) are accepted.
// peer_spoof_ips / peer_spoof_ipv6s (plural form) are accepted.
// The singular forms (source_ip, peer_spoof_ip, etc.) and the
// top-level client_real_ip / client_real_ipv6 have been removed in
// v2.0.0. The validator produces a clear error listing all removed
// fields with rename hints so operators can migrate.
//
// In server mode this struct is ignored — use peers[].* instead.
type SpoofConfig struct {
	SourceIPs      []string `json:"source_ips"`
	SourceIPv6s    []string `json:"source_ipv6s"`
	PeerSpoofIPs   []string `json:"peer_spoof_ips"`
	PeerSpoofIPv6s []string `json:"peer_spoof_ipv6s"`
}

// legacySpoofProbe is used only inside the JSON unmarshaller to detect
// the presence of removed legacy fields and emit migration errors.
type legacySpoofProbe struct {
	SourceIP       *json.RawMessage `json:"source_ip"`
	SourceIPv6     *json.RawMessage `json:"source_ipv6"`
	PeerSpoofIP    *json.RawMessage `json:"peer_spoof_ip"`
	PeerSpoofIPv6  *json.RawMessage `json:"peer_spoof_ipv6"`
	ClientRealIP   *json.RawMessage `json:"client_real_ip"`
	ClientRealIPv6 *json.RawMessage `json:"client_real_ipv6"`
}

// legacyCryptoProbe detects the presence of removed crypto.peer_public_key
// at the top-level config level in server mode.
type legacyCryptoProbe struct {
	PeerPublicKey *json.RawMessage `json:"peer_public_key"`
}

// CryptoConfig configures encryption keys.
//
// In server mode, PeerPublicKey must be empty — each peer's public
// key lives in peers[].peer_public_key. The validator hard-fails with
// a clear migration message if PeerPublicKey is set in server mode.
//
// In client mode, both PrivateKey and PeerPublicKey are required.
type CryptoConfig struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
}

// PerformanceConfig configures performance tuning
type PerformanceConfig struct {
	BufferSize int `json:"buffer_size"` // internal pool buffer size in bytes (default 65535)
	// MTU is the on-wire size budget for the obfuscator output, in bytes.
	// The raw transport will send packets of (MTU + IP header) size; quic-go
	// is configured with InitialPacketSize = MTU - 31 (obfuscator overhead).
	// Minimum 1231 (enforced); default 1400; safe maximum for eth ~1460.
	MTU int `json:"mtu"`
	// ReadBuffer / WriteBuffer: target SO_RCVBUF / SO_SNDBUF in bytes
	// (default 32 MB). The transport layer applies these via
	// SetSocketBufferSmart, which prefers SO_*BUFFORCE (bypasses
	// net.core.rmem_max / wmem_max when CAP_NET_ADMIN is present — the
	// normal root-run case) and falls back progressively if refused.
	// No sysctl tuning required in the common deployment.
	ReadBuffer  int `json:"read_buffer"`
	WriteBuffer int `json:"write_buffer"`

	// JitterBufferMs is an experimental receive-side smoother: when >0
	// or -1, it holds inbound packets briefly so quic-go's congestion
	// control sees even inter-arrival times. Default 0 (disabled).
	//
	//   0  = disabled (default)
	//   -1 = auto — budget adapts via RFC 3550-style jitter EMA,
	//        clamped to [2ms, 100ms]
	//   >0 = fixed budget in milliseconds
	//
	// Empirically has not shown consistent throughput gains under
	// standard lossy/jittery WAN test cases, so it stays off by
	// default. Enable only if you have benchmarked it on your path.
	JitterBufferMs int `json:"jitter_buffer_ms"`

	// PacingRateMbps sets SO_MAX_PACING_RATE on the UDP send socket.
	// When set, the kernel spreads outgoing packets at up to this rate
	// (in Mbps) — the UDP-equivalent of TCP's natural TSO/GSO pacing.
	// This is THE fix for the most common real-world failure mode:
	// user-space QUIC bursts at Go-scheduler speed, overflows small ISP
	// router queues (typically 1000-10000 packets), the drops make
	// quic-go's CC think there's congestion, cwnd collapses, and we
	// end up at ~10% of link capacity even on quiet paths.
	//
	//   0     = disabled (default; backwards-compatible)
	//   > 0   = rate in Mbps, applied via SO_MAX_PACING_RATE
	//
	// Set this slightly below your actual bottleneck bandwidth (e.g.
	// 900 for a 1 Gbps link) to leave headroom. Requires `fq` qdisc
	// on the output interface — check with `tc qdisc show dev <iface>`
	// and set with `sudo tc qdisc replace dev <iface> root fq`. On
	// kernels without fq the sockopt is silently accepted but inert.
	PacingRateMbps int `json:"pacing_rate_mbps"`
}

// ObfuscationConfig configures Anti-DPI/IA defenses.
//
// Modes:
//   - "none"     — no obfuscation, minimal overhead
//   - "standard" — encryption + fixed-size padding to hide payload length
//   - "paranoid" — standard + constant bit rate chaffing at chaffing_interval_ms
type ObfuscationConfig struct {
	Mode               string `json:"mode"`                 // "none", "standard", "paranoid"; empty defaults to "none"
	ChaffingIntervalMs int    `json:"chaffing_interval_ms"` // chaff interval in ms, only used in paranoid mode (default 50)
}

// QUICConfig configures the QUIC transport layer.
//
// The defaults are sized to saturate modern WAN links end-to-end without
// manual tuning: 32 MB stream windows cover single-stream throughput up
// to ~2.5 Gbps at 100 ms RTT, 128 MB connection windows cover aggregate
// workloads, and hardcoded 2/4 MB initial windows skip the 3-5 RTT
// slow-ramp that previously crippled short-lived streams (HTTP,
// handshakes) on high-RTT paths. Only override these fields if you have
// a specific constraint; the defaults work in the widest set of scenarios.
type QUICConfig struct {
	KeepAlivePeriodSec         int `json:"keep_alive_period_sec"`         // seconds between keep-alive pings (default 5)
	MaxIdleTimeoutSec          int `json:"max_idle_timeout_sec"`          // close connection after this many idle seconds (default 10)
	MaxStreamReceiveWindow     int `json:"max_stream_receive_window"`     // per-stream flow control cap in bytes (default 32 MB)
	MaxConnectionReceiveWindow int `json:"max_connection_receive_window"` // per-connection flow control cap in bytes (default 128 MB)
	PoolSize                   int `json:"pool_size"`                     // QUIC connection pool size, client only (default 8)
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

	// MaxConcurrentSessions caps the number of QUIC sessions the server
	// will accept simultaneously. Beyond this, Accept reads the new
	// session just to call CloseWithError on it, so the underlying UDP
	// flow drains rather than letting the QUIC state machine pile up.
	// Defends against trivial DoS where an attacker opens thousands of
	// sessions to exhaust TLS handshake CPU and FD budget. 0 = unlimited
	// (legacy behaviour). Default 1000 — covers any realistic fan-in,
	// well below kernel FD limits on a stock host. Server-only.
	MaxConcurrentSessions int `json:"max_concurrent_sessions"` // default 1000

	// EnablePathMTUDiscovery turns on quic-go's PLPMTUD probing. Default
	// false (disabled) and effectively a no-op here: the obfuscator pads
	// every packet to a fixed size to hide payload length, so a PLPMTUD
	// probe has no signal — and a probe larger than the target would
	// leak a non-constant packet size, defeating the obfuscation. Do not
	// enable without redesigning the padding strategy.
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
	//   "" or "auto"  — default. try BBRv1, silently fall back to CUBIC
	//                   on any failure (panic or nil factory). BBRv1 is
	//                   hugely better on lossy paths (90× over CUBIC at
	//                   1% loss on our benchmarks) because it models
	//                   bandwidth explicitly instead of halving cwnd on
	//                   every loss. Measured on netem 115 ms RTT:
	//
	//                     loss    cubic    bbrv1    ratio
	//                     0%      896      1140     1.3×
	//                     0.1%     46      1060     23×
	//                     1%        9       833     90×
	//
	//   "cubic"       — quic-go's default NewReno/CUBIC. Upstream-stable
	//                   but suffers badly when the path has any real loss.
	//   "bbrv1"       — force BBRv1 via qiulaidongfeng/quic-go fork.
	//                   Panics if the fork constructor fails — use "auto"
	//                   for a safer rollout.
	CongestionControl string `json:"congestion_control"`

	// PacketThreshold is the maximum packet reorder distance (in packets)
	// before quic-go's fast loss-detection path declares a packet lost.
	//
	// RFC 9002 §6.1.1 sets this to 3. In practice 3 is catastrophic on
	// real WAN paths: µs-level jitter plus user-space send bursts cause
	// persistent spurious-loss cascades that collapse cwnd.
	//
	// Default 128 chosen empirically as the sweet spot between jitter
	// robustness and real-loss recovery speed. Higher thresholds (e.g.
	// 1024) give slightly better throughput on pristine paths but tank
	// performance on lossy ones because real-loss detection falls back
	// to the time threshold (9/8 × RTT ≈ 130 ms per loss). 128 keeps the
	// packet-threshold fast path alive for real loss while tolerating
	// the ~30+ position reorder typical of Go-scheduler burst + jitter.
	//
	// See third_party/quic-go/internal/ackhandler/sent_packet_handler.go
	// for the measurement table. Requires the patched fork; applied
	// process-wide via quic.SetPacketThreshold at startup.
	PacketThreshold int `json:"packet_threshold"` // default 128
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

// MetricsConfig configures the Prometheus /metrics HTTP exporter.
// Disabled by default. Listen is a TCP address (e.g. "127.0.0.1:9200")
// where the daemon binds the metrics endpoint. Each daemon instance on
// a host needs its own port — pick distinct ports across services.
type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
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
//
// Private-target policy is governed by Security.BlockPrivateTargets and
// applies uniformly to direct dials and proxy hops: when the guard is
// on (default) the server resolves the hostname locally and rejects
// RFC 1918 / ULA / link-local destinations even when proxying, so a
// misconfigured or hostile proxy cannot pivot into the server's
// network. Set Security.BlockPrivateTargets=false only when the
// outbound proxy is itself an internal service whose final hops are
// private by design.
type OutboundProxyConfig struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`     // Proxy type: "socks5"
	Address  string `json:"address"`  // Proxy address (e.g. "127.0.0.1:2080")
	Username string `json:"username"` // Optional authentication username
	Password string `json:"password"` // Optional authentication password
}

// rawConfigForLegacyCheck is a minimal struct that captures the raw
// JSON fields we need to inspect for legacy-field detection. It is
// only populated inside Load, never persisted.
type rawConfigForLegacyCheck struct {
	Spoof  legacySpoofProbe  `json:"spoof"`
	Crypto legacyCryptoProbe `json:"crypto"`
	Mode   string            `json:"mode"`
}

// Load reads and parses configuration from a JSON file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Auto-migrate v1.x → v2.x in place. Pure-function migration: if any
	// v1 field is detected, write a .bak of the original and rewrite the
	// file atomically with the migrated bytes before continuing the load.
	// Operators see one slog.Info notice; no manual step, no downtime.
	migrated, changed, err := configmigrate.MigrateV1ToV2(data)
	if err != nil {
		return nil, fmt.Errorf("migrate v1 config: %w", err)
	}
	if changed {
		if err := writeMigratedConfig(path, data, migrated); err != nil {
			return nil, fmt.Errorf("auto-migrate v1 → v2: %w", err)
		}
		slog.Info("config auto-migrated v1.x → v2.0", "component", "config",
			"path", path, "backup", path+".bak")
		data = migrated
	}

	// Sanity gate: any legacy field surviving migration is a migrator bug.
	if err := checkLegacyFields(data); err != nil {
		return nil, err
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

// writeMigratedConfig persists the migrated config to disk, creating a
// .bak of the original first and using a tmp+rename for atomicity. File
// mode is inherited from the original so an operator-managed 0600
// stays 0600. Failure at any step leaves the original config intact;
// the .bak (if created) is left for forensic visibility.
//
// The .bak is preserved if it already exists — the oldest backup is the
// most likely to mirror the true original v1 file. Repeated migration
// runs (which should normally produce changed=false on idempotent v2
// input) must not overwrite a forensic backup from the first migration.
func writeMigratedConfig(path string, original, migrated []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}

	bak := path + ".bak"
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		if err := os.WriteFile(bak, original, mode); err != nil {
			return fmt.Errorf("write backup %s: %w", bak, err)
		}
	} else if err != nil {
		return fmt.Errorf("stat backup %s: %w", bak, err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, migrated, mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write new config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// checkLegacyFields inspects raw JSON bytes for removed v1 fields and
// returns a clear migration error when any are present. One error lists
// all offenders with rename hints.
func checkLegacyFields(data []byte) error {
	var raw rawConfigForLegacyCheck
	// Soft-unmarshal; ignore errors — we only care about presence.
	_ = json.Unmarshal(data, &raw)

	var legacy []string

	if raw.Spoof.SourceIP != nil {
		legacy = append(legacy, "  spoof.source_ip       → use spoof.source_ips (array)")
	}
	if raw.Spoof.SourceIPv6 != nil {
		legacy = append(legacy, "  spoof.source_ipv6     → use spoof.source_ipv6s (array)")
	}
	if raw.Spoof.PeerSpoofIP != nil {
		legacy = append(legacy, "  spoof.peer_spoof_ip   → use spoof.peer_spoof_ips (array)")
	}
	if raw.Spoof.PeerSpoofIPv6 != nil {
		legacy = append(legacy, "  spoof.peer_spoof_ipv6 → use spoof.peer_spoof_ipv6s (array)")
	}
	if raw.Spoof.ClientRealIP != nil || raw.Spoof.ClientRealIPv6 != nil {
		legacy = append(legacy, "  spoof.client_real_ip[v6] → moved to peers[].client_real_ip[v6] (server mode)")
	}
	if raw.Crypto.PeerPublicKey != nil && Mode(raw.Mode) == ModeServer {
		legacy = append(legacy, "  crypto.peer_public_key → moved to peers[].peer_public_key (server mode)")
	}

	if len(legacy) == 0 {
		return nil
	}

	return fmt.Errorf("config uses removed v1 fields (breaking change in v2.0.0):\n%s\n\nMigration guide: https://github.com/pechenyeru/quiccochet#v2-migration",
		strings.Join(legacy, "\n"))
}

// setDefaults applies default values for unset fields
func (c *Config) setDefaults() error {
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
	if c.Performance.ReadBuffer == 0 {
		// 32 MB target; helper at internal/transport applies SO_RCVBUFFORCE
		// (bypasses net.core.rmem_max for CAP_NET_ADMIN) and falls back
		// progressively if the kernel refuses. No sysctl required in the
		// common root-run case.
		c.Performance.ReadBuffer = 32 * 1024 * 1024
	}
	if c.Performance.WriteBuffer == 0 {
		c.Performance.WriteBuffer = 32 * 1024 * 1024
	}

	// Obfuscation defaults: empty Mode means disabled.
	// Validate ensures Mode is one of "", "none", "standard", "paranoid".
	if c.Obfuscation.Mode == "" {
		c.Obfuscation.Mode = "none"
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
		// 32 MB caps single-stream throughput at ~2.5 Gbps at 100 ms RTT
		// and ~850 Mbps at 300 ms — covers every realistic WAN link.
		// quic-go grows lazily up to this cap, so memory cost is paid
		// only by active saturated streams.
		c.QUIC.MaxStreamReceiveWindow = 32 * 1024 * 1024
	}
	if c.QUIC.MaxConnectionReceiveWindow == 0 {
		// 128 MB aggregate cap; even a fully-loaded pool of 8 conns
		// stays well below multi-GB memory on modern servers.
		c.QUIC.MaxConnectionReceiveWindow = 128 * 1024 * 1024
	}
	if c.QUIC.PoolSize == 0 {
		// 8 conns parallelizes across ISP ECMP 5-tuple buckets and
		// halves single-path congestion impact vs the old default of 4.
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
		// See QUICConfig.PacketThreshold godoc — 128 is the empirical
		// sweet spot balancing jitter robustness and real-loss recovery.
		c.QUIC.PacketThreshold = 128
	}
	if c.QUIC.CongestionControl == "" {
		// BBRv1-with-CUBIC-fallback. Measured ~90× better than CUBIC on
		// 1% loss paths; never worse than CUBIC thanks to the recover()
		// fallback in applyCongestionControl.
		c.QUIC.CongestionControl = "auto"
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

	// Metrics defaults
	if c.Metrics.Enabled && c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9200"
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
	if c.Transport.Type != TransportUDP && c.Transport.Type != TransportICMP && c.Transport.Type != TransportICMPv6 && c.Transport.Type != TransportRAW && c.Transport.Type != TransportSynUDP {
		errs = append(errs, fmt.Sprintf("invalid transport type: %s (must be 'udp', 'icmp', 'icmpv6', 'raw', or 'syn_udp')", c.Transport.Type))
	}
	if c.Transport.Type == TransportICMP || c.Transport.Type == TransportICMPv6 {
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

	// Mode-split: server uses peers[], client uses Spoof.* + Crypto.PeerPublicKey
	if c.Mode == ModeServer {
		errs = append(errs, c.validateServerPeers()...)
	} else if c.Mode == ModeClient {
		errs = append(errs, c.validateClientSpoof()...)
	}

	// Crypto validation — private_key is required for all modes.
	// peer_public_key: required in client mode, must be absent in server mode
	// (each peer carries its own key).
	if c.Crypto.PrivateKey == "" {
		errs = append(errs, "crypto.private_key is required (generate with: ./quiccochet keygen)")
	}
	if c.Mode == ModeClient && c.Crypto.PeerPublicKey == "" {
		errs = append(errs, "crypto.peer_public_key is required in client mode")
	}
	if c.Mode == ModeServer && c.Crypto.PeerPublicKey != "" {
		errs = append(errs, "crypto.peer_public_key must not be set in server mode — use peers[].peer_public_key instead")
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
	if c.Obfuscation.Mode == "paranoid" && c.Obfuscation.ChaffingIntervalMs != 0 && c.Obfuscation.ChaffingIntervalMs < 5 {
		errs = append(errs, fmt.Sprintf("invalid obfuscation.chaffing_interval_ms: %d (must be >= 5 when mode=paranoid, or 0 for default 50)", c.Obfuscation.ChaffingIntervalMs))
	}

	// Congestion control validation. "auto" picks BBRv1 with a silent
	// fallback to CUBIC on failure; useful as a default because BBRv1
	// is more robust on lossy/high-RTT paths but comes from a community
	// fork and can't be fully trusted.
	validCC := map[string]bool{"": true, "auto": true, "cubic": true, "bbrv1": true}
	if !validCC[c.QUIC.CongestionControl] {
		errs = append(errs, fmt.Sprintf("invalid quic.congestion_control: %q (must be 'auto', 'cubic' or 'bbrv1')", c.QUIC.CongestionControl))
	}

	if c.QUIC.MaxIncomingStreams < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.max_incoming_streams: %d (must be >= 0)", c.QUIC.MaxIncomingStreams))
	}
	if c.QUIC.MaxIncomingUniStreams < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.max_incoming_uni_streams: %d (must be >= 0)", c.QUIC.MaxIncomingUniStreams))
	}
	if c.QUIC.MaxConcurrentSessions < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.max_concurrent_sessions: %d (must be >= 0, 0=unlimited)", c.QUIC.MaxConcurrentSessions))
	}
	// 0 means "use default" (applied in setDefaults); reject only explicit small values.
	if c.QUIC.UDPRouteIdleSec != 0 && c.QUIC.UDPRouteIdleSec < 10 {
		errs = append(errs, fmt.Sprintf("invalid quic.udp_route_idle_sec: %d (minimum 10)", c.QUIC.UDPRouteIdleSec))
	}
	if c.QUIC.UDPRouteMax < 0 {
		errs = append(errs, fmt.Sprintf("invalid quic.udp_route_max: %d (must be >= 0)", c.QUIC.UDPRouteMax))
	}
	if c.QUIC.PacketThreshold < 0 || c.QUIC.PacketThreshold > 10000 {
		errs = append(errs, fmt.Sprintf("invalid quic.packet_threshold: %d (0=default 128, 1..10000 explicit)", c.QUIC.PacketThreshold))
	}

	// MTU floor: quic-go requires InitialPacketSize ≥ 1200 (RFC 9000 §14.1)
	// and the obfuscator adds 31 bytes on top (3 framing + 12 nonce + 16 tag)
	// before writing to the transport. So cfg.MTU must leave room for both:
	// MTU ≥ 1200 + 31 = 1231.
	if c.Performance.MTU < 1231 {
		errs = append(errs, fmt.Sprintf("performance.mtu=%d is below the minimum 1231 (quic-go requires 1200-byte packets + 31 bytes of obfuscator overhead)", c.Performance.MTU))
	}

	// Jitter buffer: 0=off, -1=auto, >0=fixed ms. Reject other values so
	// a typo doesn't silently get accepted as a disable.
	if c.Performance.JitterBufferMs < -1 || c.Performance.JitterBufferMs > 500 {
		errs = append(errs, fmt.Sprintf("performance.jitter_buffer_ms=%d is invalid (0=off, -1=auto, 1..500=fixed ms)", c.Performance.JitterBufferMs))
	}

	// Logging validation
	validLevels := map[LogLevel]bool{LogDebug: true, LogInfo: true, LogWarn: true, LogError: true}
	if !validLevels[c.Logging.Level] {
		errs = append(errs, fmt.Sprintf("invalid log level: %s", c.Logging.Level))
	}

	// Inbounds validation: catch unknown types and missing forward
	// targets at config-load time instead of letting them surface as
	// downstream dial failures at runtime.
	for i, inb := range c.Inbounds {
		switch inb.Type {
		case InboundSocks:
			// no extra fields required
		case InboundForward:
			if inb.Target == "" {
				errs = append(errs, fmt.Sprintf("inbounds[%d]: forward inbound requires target", i))
			}
		default:
			errs = append(errs, fmt.Sprintf("inbounds[%d]: unknown type %q (must be %q or %q)", i, inb.Type, InboundSocks, InboundForward))
		}
		if inb.Listen == "" {
			errs = append(errs, fmt.Sprintf("inbounds[%d]: listen is required", i))
		}
		if inb.Auth != nil {
			if inb.Type != InboundSocks {
				errs = append(errs, fmt.Sprintf("inbounds[%d]: auth is only supported on socks inbounds", i))
			}
			if inb.Auth.Username == "" || inb.Auth.Password == "" {
				errs = append(errs, fmt.Sprintf("inbounds[%d]: auth.username and auth.password must both be non-empty", i))
			}
			// RFC 1929 caps username and password lengths at 255 each;
			// reject overflow at config-load time so the byte cast in
			// the wire encoder cannot wrap silently.
			if len(inb.Auth.Username) > 255 {
				errs = append(errs, fmt.Sprintf("inbounds[%d]: auth.username exceeds RFC 1929 maximum of 255 bytes", i))
			}
			if len(inb.Auth.Password) > 255 {
				errs = append(errs, fmt.Sprintf("inbounds[%d]: auth.password exceeds RFC 1929 maximum of 255 bytes", i))
			}
		}
	}

	// Metrics validation
	if c.Metrics.Enabled {
		if c.Metrics.Listen == "" {
			errs = append(errs, "metrics.enabled=true but metrics.listen is empty")
		} else if _, _, err := net.SplitHostPort(c.Metrics.Listen); err != nil {
			errs = append(errs, fmt.Sprintf("metrics.listen %q is not host:port: %v", c.Metrics.Listen, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config errors:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// validateServerPeers validates the peers[] list for server mode.
// Returns a slice of error strings to be aggregated into the main
// validator.
func (c *Config) validateServerPeers() []string {
	var errs []string

	if len(c.Peers) == 0 {
		errs = append(errs, "server mode requires at least one entry in peers[]")
		return errs
	}

	// Track uniqueness across all peers.
	namesSeen := make(map[string]struct{})
	pubKeysSeen := make(map[string]struct{})
	// spoofAddrsSeen maps each NORMALIZED wire source address (netip.Addr
	// after Unmap) → peer name for the disjointness check. Normalization is
	// load-bearing: server.go (NewServer) uses the same netip.Addr/Unmap key
	// in its cipher dispatch map, so two textual forms that parse to the
	// same address (e.g. "10.0.0.3" vs "::ffff:10.0.0.3", or two notations
	// of the same IPv6 like "2001:db8::1" vs "2001:0db8::1") would collide
	// in peerCiphers at runtime and silently overwrite each other. A
	// string-keyed check would miss those cases.
	spoofAddrsSeen := make(map[netip.Addr]string) // addr → peer name

	for i, p := range c.Peers {
		prefix := fmt.Sprintf("peers[%d]", i)

		// name required + unique
		if p.Name == "" {
			errs = append(errs, prefix+": name is required")
		} else {
			if _, dup := namesSeen[p.Name]; dup {
				errs = append(errs, fmt.Sprintf("%s: duplicate peer name %q", prefix, p.Name))
			}
			namesSeen[p.Name] = struct{}{}
		}

		// peer_public_key required + unique
		if p.PeerPublicKey == "" {
			errs = append(errs, prefix+": peer_public_key is required")
		} else {
			if _, dup := pubKeysSeen[p.PeerPublicKey]; dup {
				errs = append(errs, fmt.Sprintf("%s: duplicate peer_public_key (each peer needs a unique X25519 key)", prefix))
			}
			pubKeysSeen[p.PeerPublicKey] = struct{}{}
		}

		// client real IP: at least one required
		if p.ClientRealIP == "" && p.ClientRealIPv6 == "" {
			errs = append(errs, prefix+": at least one of client_real_ip or client_real_ipv6 is required")
		}
		if p.ClientRealIP != "" && net.ParseIP(p.ClientRealIP) == nil {
			errs = append(errs, fmt.Sprintf("%s: invalid client_real_ip: %s", prefix, p.ClientRealIP))
		}
		if p.ClientRealIPv6 != "" && net.ParseIP(p.ClientRealIPv6) == nil {
			errs = append(errs, fmt.Sprintf("%s: invalid client_real_ipv6: %s", prefix, p.ClientRealIPv6))
		}

		// per-peer source_ips
		for _, ip := range p.SourceIPs {
			if net.ParseIP(ip) == nil {
				errs = append(errs, fmt.Sprintf("%s: invalid source_ips entry: %s", prefix, ip))
			}
		}
		for _, ip := range p.SourceIPv6s {
			if net.ParseIP(ip) == nil {
				errs = append(errs, fmt.Sprintf("%s: invalid source_ipv6s entry: %s", prefix, ip))
			}
		}

		// per-peer peer_spoof_ips: at least one entry required (the wire
		// source IP is the dispatch key on the server — a peer with zero
		// spoof IPs would never be matched by NewServer's cipher map and
		// every packet from it would be silently dropped).
		if len(p.PeerSpoofIPs) == 0 && len(p.PeerSpoofIPv6s) == 0 {
			errs = append(errs, prefix+": at least one peer_spoof_ips or peer_spoof_ipv6s entry is required (the wire source IP is the cipher dispatch key)")
		}

		// per-peer peer_spoof_ips: validate + disjointness (normalized).
		for _, ipStr := range append(p.PeerSpoofIPs, p.PeerSpoofIPv6s...) {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				errs = append(errs, fmt.Sprintf("%s: invalid peer_spoof_ips/ipv6s entry: %s", prefix, ipStr))
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: invalid peer_spoof_ips/ipv6s entry: %s", prefix, ipStr))
				continue
			}
			addr = addr.Unmap()
			if owner, dup := spoofAddrsSeen[addr]; dup {
				if owner == p.Name {
					errs = append(errs, fmt.Sprintf("%s: peer_spoof_ip %s appears more than once in peer %q's spoof IP lists", prefix, ipStr, p.Name))
				} else {
					errs = append(errs, fmt.Sprintf("%s: peer_spoof_ip %s (normalized %s) is already assigned to peer %q, spoof IPs must be disjoint across peers", prefix, ipStr, addr, owner))
				}
			} else {
				spoofAddrsSeen[addr] = p.Name
			}
		}
	}

	return errs
}

// validateClientSpoof validates the client-mode Spoof config.
// Returns a slice of error strings.
func (c *Config) validateClientSpoof() []string {
	var errs []string

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

	if len(c.Spoof.SourceIPs) == 0 && len(c.Spoof.SourceIPv6s) == 0 {
		errs = append(errs, "at least one spoof source IP (IPv4 or IPv6) is required in spoof.source_ips or spoof.source_ipv6s")
	}

	return errs
}

// GetServerAddr returns the formatted server address
func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Address, c.Server.Port)
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
