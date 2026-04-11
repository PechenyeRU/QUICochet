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
- **~900 Mbps single stream, 1+ Gbps multi-stream** throughput depending on transport mode

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
- ✅ **Congestion control**: Adaptive to network conditions

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
    "buffer_size": 4194304,
    "mtu": 1400
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
    "buffer_size": 4194304,
    "mtu": 1400
  },
  "quic": {
    "keep_alive_period_sec": 5,
    "max_idle_timeout_sec": 10,
    "pool_size": 4
  },
  "logging": {"level": "info"}
}
```

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

| Section | Key | Description |
|---------|-----|-------------|
| `mode` | `mode` | `"client"` or `"server"` |
| `transport.type` | `"udp"`, `"icmp"`, `"raw"`, `"syn_udp"` | Transport protocol |
| `crypto` | `private_key`, `peer_public_key` | X25519 keys from `./quiccochet keygen` |
| `spoof.source_ip` | Spoofed source IP (fake, not assigned to interface) |
| `spoof.peer_spoof_ip` | Expected spoofed IP from peer |

### Performance Tuning

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `performance.buffer_size` | 4 MB | UDP buffer size |
| `performance.mtu` | 1400 | Max transmission unit |
| `quic.pool_size` | 4 | Number of QUIC connections (client only) |
| `quic.keep_alive_period_sec` | 5 | QUIC keepalive interval |
| `quic.max_stream_receive_window` | 5 MB | QUIC stream window |
| `quic.max_connection_receive_window` | 15 MB | QUIC connection window |

**Why `pool_size = 4`?**
- Saturates high-BDP (Bandwidth-Delay Product) links
- Parallelizes stream operations across connections
- Reduces head-of-line blocking
- Recommended: 4 for Gigabit links with 50-100ms RTT

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

### ⏳ Future

- [ ] **Forward Secrecy**: Noise-IK ephemeral handshake for PFS
- [ ] **Adaptive Padding**: Machine-learning-resistant traffic patterns
- [ ] **Full IPv6**: Complete IPv6 transport support
- [ ] **Automated E2E test runner**: `run-tests.sh` with assertions

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