# QUICochet

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://golang.org)

**QUICochet** is a high-performance Layer 3/4 tunneling proxy with **bidirectional IP spoofing** and **QUIC transport**, designed to bypass Deep Packet Inspection (DPI) and stateful firewalls in restrictive network environments.

## 🚀 Key Features

- **Mutual IP Spoofing**: Both client and server forge their source IPs, leaving no traceable connection state in middleboxes
- **QUIC Transport**: Built on `quic-go` with native stream multiplexing, encryption, and reliability
- **Anti-DPI/anti-IA Defenses**: Packet padding, size binning, and chaffing to evade traffic analysis
- **Connection Pooling**: Multiple QUIC connections (configurable, default: 4) for high-throughput WAN links
- **UDP Relay**: Full SOCKS5 UDP ASSOCIATE support via QUIC datagrams — no IP leak even with outbound proxy
- **Zero-Allocation Hot Path**: Pooled buffers and optimized cipher operations for maximum throughput
- **Multiple Transports**: UDP, ICMP, RAW (custom IP protocol), SYN+UDP (asymmetric DPI evasion)
- **Resilient Pooling**: Exponential backoff with parallel reconnect, instant recovery from restart
- **Anti-SSRF**: Blocks private/loopback/CGNAT/link-local targets by default, with DNS rebinding protection
- **Replay Protection**: Sliding-window bitmap filter with session-unique nonce prefix
- **Structured Logging**: `log/slog` with JSON output to file, text to stderr, configurable levels
- **~900 Mbps single stream, 1+ Gbps multi-stream** throughput on LAN (see [Benchmarks](#benchmark-results))
- **Pluggable Congestion Control**: stock CUBIC by default, optional BBR v1 (experimental)

## 📋 Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Performance Tuning](#performance-tuning)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

## 🏗️ Architecture

### How It Works

Traditional VPN tunnels establish a stateful connection between fixed endpoints. **QUICochet breaks this model**:

1. **Client** sends packets with spoofed source IP to server's real IP
2. **Server** receives packets and responds to client's real IP (not spoofed)
3. Both endpoints pre-share knowledge of each other's physical IPs and spoofed IPs
4. Intermediate firewalls see **unidirectional UDP flows** with no matching state

```
┌─────────────────┐                     ┌─────────────────┐
│  Client         │                     │  Server         │
│  Real: 10.0.0.1 │ ───Spoofed UDP───▶ │  Real: 10.0.0.2 │
│  Spoof: 1.2.3.4 │ ◀──Spoofed UDP──── │  Spoof: 5.6.7.8 │
│  SOCKS5: :1080  │                     │  Tunnel: :8080  │
└─────────────────┘                     └─────────────────┘
```

### Protocol Stack

```
┌─────────────────────────────────────────┐
│  SOCKS5 (TCP + UDP ASSOCIATE)           │  Application
├─────────────────────────────────────────┤
│  QUIC Streams + Datagrams (TLS 1.3)     │  Transport
├─────────────────────────────────────────┤
│  Obfuscated Packet (Padding + Chaff)    │  Anti-DPI
├─────────────────────────────────────────┤
│  ChaCha20-Poly1305 AEAD                 │  Encryption
├─────────────────────────────────────────┤
│  UDP / ICMP / RAW / SYN+UDP (Spoofed)   │  Network
└─────────────────────────────────────────┘
```

### Why QUIC?

- ✅ **Built-in encryption**: TLS 1.3 by default
- ✅ **Stream multiplexing**: Multiple streams over one connection
- ✅ **Reliability handled by QUIC**: No manual retransmission logic
- ✅ **Replay protection**: Packet numbers prevent replay attacks
- ✅ **Congestion control**: CUBIC by default, optional BBR v1 for high-RTT/lossy paths

## 📦 Installation

### Prerequisites

- Go 1.25+ installed
- Linux (raw sockets require Linux syscalls)
- Root privileges or `CAP_NET_RAW` capability

### Build from Source

```bash
git clone https://github.com/PechenyeRU/quiccochet.git
cd quiccochet
go build -ldflags "-X main.Version=$(git describe --tags --always) -X main.Commit=$(git rev-parse --short HEAD) -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o quiccochet ./cmd/quiccochet/
```

### Generate Keys

```bash
./quiccochet keygen
```

This generates X25519 key pairs for client and server.

## 🚀 Quick Start

### 1. Configure Server

Create `server-config.json`:

```json
{
  "mode": "server",
  "transport": {"type": "udp"},
  "listen_port": 8080,
  "spoof": {
    "source_ip": "10.99.0.10",
    "peer_spoof_ip": "10.99.0.11",
    "client_real_ip": "CLIENT_REAL_IP"
  },
  "crypto": {
    "private_key": "SERVER_PRIVATE_KEY",
    "peer_public_key": "CLIENT_PUBLIC_KEY"
  },
  "performance": {
    "mtu": 1400,
    "read_buffer": 16777216,
    "write_buffer": 16777216
  },
  "security": {
    "block_private_targets": true
  },
  "quic": {
    "keep_alive_period_sec": 5,
    "max_idle_timeout_sec": 10
  },
  "logging": {"level": "info"}
}
```

> See [`server-config.json.example`](server-config.json.example) for the full schema.

### 2. Configure Client

Create `client-config.json`:

```json
{
  "mode": "client",
  "transport": {"type": "udp"},
  "server": {"address": "SERVER_REAL_IP", "port": 8080},
  "spoof": {
    "source_ip": "10.99.0.11",
    "peer_spoof_ip": "10.99.0.10"
  },
  "crypto": {
    "private_key": "CLIENT_PRIVATE_KEY",
    "peer_public_key": "SERVER_PUBLIC_KEY"
  },
  "inbounds": [
    {"type": "socks", "listen": "127.0.0.1:1080"}
  ],
  "performance": {
    "mtu": 1400,
    "read_buffer": 4194304,
    "write_buffer": 4194304
  },
  "quic": {
    "keep_alive_period_sec": 5,
    "max_idle_timeout_sec": 10,
    "pool_size": 4
  },
  "logging": {"level": "info"}
}
```

> See [`client-config.json.example`](client-config.json.example) for the full schema.

### 3. Run

**Server:**
```bash
sudo ./quiccochet -c server-config.json
```

**Client:**
```bash
sudo ./quiccochet -c client-config.json
```

Connect via SOCKS5: `curl --socks5 127.0.0.1:1080 https://example.com`

## ⚙️ Configuration

### Required Fields

| Key | Description |
|-----|-------------|
| `mode` | `"client"` or `"server"` |
| `transport.type` | `"udp"`, `"icmp"`, `"raw"`, or `"syn_udp"` |
| `crypto.private_key`, `crypto.peer_public_key` | X25519 keys from `./quiccochet keygen` |
| `spoof.source_ip` or `spoof.source_ipv6` | Your spoofed source IP (fake, not assigned to any interface) |
| `spoof.peer_spoof_ip` | The spoofed IP you expect from the peer |
| `listen_port` (server only) | Port where the server listens for tunnel traffic |
| `server.address`, `server.port` (client only) | Real IP/port of the server |
| `spoof.client_real_ip` (server only) | Real IP of the client — where the server actually sends return packets |

### Transport Details

| Type | When to use | Extra fields |
|------|-------------|--------------|
| `udp` | Default. Best throughput, least overhead | — |
| `icmp` | Networks that block/deprioritize UDP | `transport.icmp_mode`: `"echo"` (client default) or `"reply"` (server default) — **must be opposite** on the two peers |
| `raw` | Deep stealth with a custom IP protocol | `transport.protocol_number`: **required**, 1–255, unused protocols like `253`/`254` work well |
| `syn_udp` | DPI evasion via asymmetric path | — (client sends TCP SYN, server replies with raw UDP) |

### ICMP Mode Asymmetry

The `icmp` transport uses raw ICMP sockets with IP spoofing. The `icmp_mode` field controls which ICMP message type each peer emits:

| Mode | IPv4 send | IPv4 receive (from peer) | IPv6 send | IPv6 receive |
|------|-----------|--------------------------|-----------|--------------|
| `"echo"` (client default) | type 8 (Echo Request) | type 0 (Echo Reply) | type 128 | type 129 |
| `"reply"` (server default) | type 0 (Echo Reply) | type 8 (Echo Request) | type 129 | type 128 |

**Client and server must use opposite modes** — if both sent Echo Request, each kernel would try to auto-generate a Reply racing us. With asymmetric modes, exactly one side emits Echo Request and the other side sees it.

The peer receiving Echo Request (by default the `"reply"` side, i.e. the server) **must disable the kernel's auto-reply** with `sysctl net.ipv4.icmp_echo_ignore_all=1`; otherwise the kernel's Echo Reply races QUICochet's receive. See [ICMP Transport: Kernel Configuration](#icmp-transport-kernel-configuration) below. The peer receiving Echo Reply doesn't need any kernel tuning — Echo Reply is never auto-answered.

If you swap client/server roles (or both peers happen to use the same mode), the tunnel will appear connected but no traffic will flow because both sides filter out the other's packets by type.

### Client Behind NAT (listen_port)

When the client runs behind a NAT router (e.g., MikroTik, pfSense), the server's response packets need to be port-forwarded to the client machine. By default, the client picks a random ephemeral port — which makes port forwarding impossible.

Set `listen_port` on the client to bind to a fixed port, then configure your router to forward that port:

```json
{
  "mode": "client",
  "listen_port": 8080,
  ...
}
```

**Router rules (MikroTik example):**
```
# Bypass masquerade for spoofed source IP
/ip firewall nat add action=accept chain=srcnat src-address=<SPOOF_IP> out-interface=<WAN> place-before=0

# Forward server responses to the client machine
/ip firewall nat add action=dst-nat chain=dstnat dst-port=8080 in-interface=<WAN> protocol=udp to-addresses=<CLIENT_LAN_IP> to-ports=8080
```

If the client has a direct public IP (no NAT), leave `listen_port` at `0` (dynamic).

### Performance Tuning

| Key | Default | Description |
|-----|---------|-------------|
| `performance.mtu` | `1400` | On-wire payload budget (post-obfuscator, pre-IP). **Minimum `1231`**, safe max `~1460` for eth. Drives `quic.InitialPacketSize` automatically |
| `performance.read_buffer` | `4194304` (4 MB) | `SO_RCVBUF` on the receive socket. Bump for high-BDP links |
| `performance.write_buffer` | `4194304` (4 MB) | `SO_SNDBUF` on the send socket |
| `performance.buffer_size` | `65535` | Internal pool buffer size (hot-path re-use). Rarely needs tuning |
| `performance.workers` | `4` | Reserved for future parallelism work |
| `quic.pool_size` | `4` | QUIC connections in the client pool |
| `quic.keep_alive_period_sec` | `5` | QUIC keepalive interval |
| `quic.max_idle_timeout_sec` | `10` | Drop an idle QUIC connection after this many seconds |
| `quic.max_stream_receive_window` | `5242880` (5 MB) | Per-stream flow-control window |
| `quic.max_connection_receive_window` | `15728640` (15 MB) | Per-connection flow-control window |
| `quic.stream_close_timeout_sec` | `10` | Force-cancel a stream if the second copy direction hasn't drained within this window |
| `quic.congestion_control` | `"cubic"` | `"cubic"` (default) or `"bbrv1"` (**experimental**, see below) |

**Why `pool_size = 4`?**
- Saturates high-BDP (Bandwidth-Delay Product) links
- Parallelizes stream operations across connections
- Reduces head-of-line blocking
- Recommended: 4 for Gigabit links with 50-100ms RTT, 8–12 for very lossy paths

**High-BDP tuning.** For a 200 ms RTT × 1 Gbps link the BDP is ~25 MB, so set `max_stream_receive_window >= 30 MB` and `max_connection_receive_window >= 90 MB`, and bump `read_buffer`/`write_buffer` to `16 MB` on both ends.

### Congestion Control

Two algorithms are selectable via `quic.congestion_control`:

- **`"cubic"`** (default) — `quic-go`'s upstream NewReno/CUBIC sender. Well-tested, stable, fair to other TCP flows.
- **`"bbrv1"`** — **Experimental**. Google BBR v1, wired in through the [`qiulaidongfeng/quic-go`](https://github.com/qiulaidongfeng/quic-go) community fork (see upstream tracking issue [`quic-go#4565`](https://github.com/quic-go/quic-go/issues/4565)). May improve sustained throughput on high-RTT and lossy paths where CUBIC under-utilizes the pipe. Known caveats:
  - The BBR implementation is not upstream and not formally reviewed; treat any build using it as experimental.
  - BBR is more aggressive than CUBIC on contention — prefer it on dedicated links, avoid on shared tenancy where fairness matters.
  - **Enable on both client and server** — mixing CUBIC on one side with BBR on the other creates pathological sharing dynamics.
  - Fall back by setting the value to `"cubic"` and restarting — no rebuild needed.

### UDP Relay Datagram Size

The SOCKS5 UDP ASSOCIATE relay ships each UDP packet inside a single QUIC DATAGRAM frame (RFC 9221), which is bounded by `InitialPacketSize - ~29 bytes` of QUIC overhead. With the default MTU `1400` that ceiling is **~1340 bytes** of UDP payload. Packets above that — e.g. near-MTU DNS responses or games using full 1472-byte payloads — are dropped at send time with a debug log. This is a protocol-level constraint of QUIC datagrams on an eth-MTU path, not a bug.

### Security

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `security.block_private_targets` | `true` | Block dialing private/internal IPs through the tunnel |

When enabled (default), the server blocks connections to:
- **RFC 1918**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Loopback**: `127.0.0.0/8`, `::1`
- **CGNAT (RFC 6598)**: `100.64.0.0/10` (Tailscale, cloud metadata)
- **Link-local**: `169.254.0.0/16`, `fe80::/10`
- **Multicast/Broadcast**: `224.0.0.0/4`, `255.255.255.255`
- **IPv6 ULA**: `fc00::/7`

Domain targets are resolved once and the resolved IP is validated before dialing, preventing DNS rebinding attacks.

### Obfuscation (Anti-DPI)

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `obfuscation.enabled` | false | Enable anti-DPI layer |
| `obfuscation.mode` | `"standard"` | `"none"`, `"standard"`, `"paranoid"` |
| `obfuscation.chaffing_interval_ms` | 50 | Send dummy packets when idle (paranoid mode) |

**Modes:**
- `"none"`: No obfuscation (pure QUIC)
- `"standard"`: Padding + size binning
- `"paranoid"`: All defenses + constant bit rate chaffing (fills idle gaps with dummy packets)

> **Throughput cost**: `standard` and `paranoid` pad every packet to the configured MTU before encryption. A small ACK (~40 B) becomes a full ~1400 B on wire, inflating the physical link usage 2–4× relative to user payload. This is the price of traffic-analysis resistance. On uncensored paths where DPI isn't a concern, set `"mode": "none"` to recover the full throughput headroom.

### Outbound Proxy (server mode only)

The server can forward all tunneled traffic through an upstream SOCKS5 proxy (e.g. a local `sing-box`/`xray` instance). This is useful when the server's IP itself is blocked from reaching the final targets and needs a second hop, or when you want to layer a separate censorship-evasion stack.

| Key | Description |
|-----|-------------|
| `outbound_proxy.enabled` | `true` to route TCP streams and UDP datagrams through the upstream proxy |
| `outbound_proxy.type` | Currently only `"socks5"` |
| `outbound_proxy.address` | `host:port` of the upstream proxy |
| `outbound_proxy.username`, `outbound_proxy.password` | Optional RFC 1929 auth |

When enabled, the server skips its own DNS resolution and lets the proxy do it (preventing DNS leaks of the final target from the server's network). UDP ASSOCIATE is used for datagrams — the relay keeps a per-flow TCP control channel to the upstream proxy with a 2-minute idle timeout to prevent fd accumulation.

## 🛠️ Performance Tuning

### OS-Level Configuration

QUICochet requires kernel tuning for high-throughput UDP and IP spoofing:

```bash
sudo tee /etc/sysctl.d/99-quiccochet.conf > /dev/null << 'EOF'
# IP Spoofing (CRITICAL)
net.ipv4.conf.all.accept_local = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.all.log_martians = 0

# UDP Buffer Tuning (16 MB max, 4 MB default)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 10000

# TCP Buffers (if applicable)
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
EOF

sudo sysctl -p /etc/sysctl.d/99-quiccochet.conf
```

### ICMP Transport: Kernel Configuration

When using `"transport": {"type": "icmp"}`, the kernel's built-in ICMP echo reply must be disabled. Otherwise the kernel responds to incoming ICMP Echo Request packets before QUICochet can process them, causing duplicate replies and breaking the QUIC handshake.

```bash
# Disable kernel ICMP echo reply (required on BOTH client and server)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

To make it permanent, add to your sysctl config:

```bash
echo "net.ipv4.icmp_echo_ignore_all = 1" | sudo tee -a /etc/sysctl.d/99-quiccochet.conf
sudo sysctl -p /etc/sysctl.d/99-quiccochet.conf
```

> **Note:** This disables `ping` on the machine. If you switch back to a non-ICMP transport, re-enable it with `sysctl -w net.ipv4.icmp_echo_ignore_all=0`.

The e2e provisioning scripts (`test/e2e/provision-common.sh`) set this automatically.

### Benchmark Results

> These are **LAN-local** numbers from a controlled environment with ~0.2 ms RTT and no packet loss. They show the implementation has near-line-rate headroom on a clean path. **Real-world throughput over a high-RTT censored WAN with `standard` obfuscation and an upstream SOCKS5 hop will be significantly lower** — typically in the single-digit Mbps range sustained, because of CBR-style padding, RTT-bound QUIC windows, and the upstream proxy latency. Use these figures to reason about upper bounds, not end-user experience.

**Test Environment:**
- 2x KVM VMs (4 vCPU, 4 GB RAM, libvirt private network)
- Ubuntu 24.04, Linux 6.8

**Results (all transports, 10s iperf3, PLPMTUD disabled):**

Single stream (1 connection):
```
Transport    Download     Upload
─────────    ─────────    ──────
UDP          ~945 Mbps    ~910 Mbps
ICMP         ~790 Mbps    ~820 Mbps
RAW          ~925 Mbps    ~930 Mbps
SYN+UDP      ~760 Mbps    ~530 Mbps
```

4 parallel streams (pool_size=4):
```
Transport    Download     Upload
─────────    ─────────    ──────
UDP          ~985 Mbps    ~1.05 Gbps
ICMP         ~915 Mbps    ~950 Mbps
RAW          ~1.11 Gbps   ~1.11 Gbps
SYN+UDP      ~890 Mbps    ~910 Mbps
```

## 🗺️ Roadmap

### ✅ Complete

- ✅ QUIC integration with stream multiplexing
- ✅ ChaCha20-Poly1305 encryption
- ✅ Obfuscation layer (padding + chaffing + CBR mode)
- ✅ Connection pooling with exponential backoff and parallel reconnect
- ✅ 4 transport modes: UDP, ICMP, RAW, SYN+UDP (all verified with IP spoofing)
- ✅ UDP relay via QUIC datagrams with SOCKS5 UDP ASSOCIATE
- ✅ Outbound proxy support (SOCKS5 TCP + UDP, zero IP leak)
- ✅ E2E test environment with Vagrant
- ✅ HKDF key derivation (RFC 5869) replacing XOR-based KDF
- ✅ ICMP transport kernel configuration documentation
- ✅ Anti-SSRF: private target blocking with DNS rebinding prevention
- ✅ Replay protection: sliding-window bitmap with session-unique nonce prefix
- ✅ Structured logging (`log/slog`)
- ✅ Optional BBR v1 congestion control (experimental, via community fork)
- ✅ Idle-timeout cleanup for SOCKS5 UDP ASSOCIATE proxy routes (no fd leak)
- ✅ MTU floor validation (`1231`) to preserve QUIC + obfuscator invariants

### ⏳ Future

- [ ] **Forward Secrecy**: Noise-IK ephemeral handshake for PFS
- [ ] **Adaptive Padding**: Machine-learning-resistant traffic patterns
- [ ] **Full IPv6**: Complete IPv6 transport support
- [ ] **Automated E2E test runner**: `run-tests.sh` with assertions
- [ ] **BBR upstreaming**: track [`quic-go#4565`](https://github.com/quic-go/quic-go/issues/4565) and drop the fork once merged

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'feat: add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Development Setup

```bash
go mod download
go test ./internal/...
go build ./cmd/quiccochet/
```

## 🙏 Acknowledgments

- [quic-go](https://github.com/quic-go/quic-go) - QUIC implementation in Go
- Inspired by the need for resilient communication in restrictive network environments

---

**Maintained by [@PechenyeRU](https://github.com/PechenyeRU)**

This project is HEAVILY inspired by [**Spoof Tunnel**](https://github.com/ParsaKSH/spoof-tunnel) which was the original project. QUICochet represents a different approach with QUIC transport.