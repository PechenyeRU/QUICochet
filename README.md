# QUICochet

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://golang.org)

**QUICochet** is a high-performance Layer 3/4 tunneling proxy with **bidirectional IP spoofing** and **QUIC transport**, designed to bypass Deep Packet Inspection (DPI) and stateful firewalls in restrictive network environments.

<a id="features"></a>
## 🚀 Key Features

- **Mutual IP Spoofing**: Both client and server forge their source IPs, leaving no traceable connection state in middleboxes
- **QUIC Transport**: Built on `quic-go` with native stream multiplexing, encryption, and reliability
- **Anti-DPI/anti-IA Defenses**: Packet padding, size binning, and chaffing to evade traffic analysis
- **Connection Pooling**: Multiple QUIC connections (configurable, default: 4) for high-throughput WAN links
- **UDP Relay**: Full SOCKS5 UDP ASSOCIATE support via QUIC datagrams — no IP leak even with outbound proxy
- **Multi-Spoof**: Randomize outgoing source IP from a configurable pool — traffic appears to originate from N independent hosts
- **sendmsg + IP_TRANSPARENT**: UDP transport uses kernel-native path with per-packet source IP selection via IP_PKTINFO, eliminating manual header construction and enabling TX checksum offload
- **Zero-Allocation Hot Path**: Pooled buffers and optimized cipher operations for maximum throughput
- **Multiple Transports**: UDP, ICMP, RAW (custom IP protocol), SYN+UDP (asymmetric DPI evasion)
- **Resilient Pooling**: Exponential backoff with parallel reconnect, instant recovery from restart
- **Anti-SSRF**: Blocks private/loopback/CGNAT/link-local targets by default, with DNS rebinding protection
- **Replay Protection**: Sliding-window bitmap filter with session-unique nonce prefix
- **Structured Logging**: `log/slog` with JSON output to file, text to stderr, configurable levels
- **~1.1 Gbps single stream, 2.2+ Gbps multi-stream** throughput on LAN (see [Benchmarks](#benchmark-results))
- **Pluggable Congestion Control**: stock CUBIC by default, optional BBR v1 (experimental)
- **Admin Socket**: optional Unix-domain control plane for on-demand stats and in-link latency/throughput benchmarks over the live tunnel — no restart, no extra config on the server side

<a id="toc"></a>
## 📋 Table of Contents

- [Key Features](#features)
- [Architecture](#architecture)
  - [How It Works](#how-it-works)
  - [Protocol Stack](#protocol-stack)
  - [Why QUIC?](#why-quic)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Build from Source](#build-from-source)
  - [Generate Keys](#generate-keys)
- [Quick Start](#quick-start)
  - [Configure Server](#1-configure-server)
  - [Configure Client](#2-configure-client)
  - [Run](#3-run)
- [Configuration](#configuration)
  - [Required Fields](#required-fields)
  - [Transport Details](#transport-details)
  - [Multi-Spoof](#multi-spoof)
  - [ICMP Mode Asymmetry](#icmp-mode-asymmetry)
  - [Client Behind NAT](#client-behind-nat-listen_port)
  - [Performance Tuning (config knobs)](#performance-tuning)
  - [Congestion Control](#congestion-control)
  - [UDP Relay Datagram Size](#udp-relay-datagram-size)
  - [Scaling for Many Clients](#scaling-for-many-clients)
  - [PMTUD and Obfuscation](#pmtud-and-obfuscation)
  - [Security](#security)
  - [Obfuscation (Anti-DPI)](#obfuscation-anti-dpi)
  - [Admin Socket](#admin-socket)
  - [Outbound Proxy](#outbound-proxy-server-mode-only)
  - [sendmsg + IP_TRANSPARENT](#sendmsg--ip_transparent-udp-transport)
- [Performance Tuning (OS)](#performance-tuning-os)
  - [OS-Level Configuration](#os-level-configuration)
  - [File Descriptor Limit](#file-descriptor-limit)
  - [ICMP Transport: Kernel Configuration](#icmp-transport-kernel-configuration)
  - [Benchmark Results](#benchmark-results)
- [Roadmap](#roadmap)
  - [Complete](#complete)
  - [Future](#future)
- [Contributing](#contributing)
  - [Development Setup](#development-setup)
- [Acknowledgments](#acknowledgments)

> **First time setting this up on a pair of fresh VPS?** Read [**SETUP.md**](SETUP.md) for a copy-paste walkthrough on Ubuntu 24.04 — all sysctls, systemd units, troubleshooting included.

<a id="architecture"></a>
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

<a id="installation"></a>
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

<a id="quick-start"></a>
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

<a id="configuration"></a>
## ⚙️ Configuration

### Required Fields

| Key | Description |
|-----|-------------|
| `mode` | `"client"` or `"server"` |
| `transport.type` | `"udp"`, `"icmp"`, `"raw"`, or `"syn_udp"` |
| `crypto.private_key`, `crypto.peer_public_key` | X25519 keys from `./quiccochet keygen` |
| `spoof.source_ip` or `spoof.source_ips` | Your spoofed source IP(s). Single or list — see [Multi-Spoof](#multi-spoof) |
| `spoof.peer_spoof_ip` or `spoof.peer_spoof_ips` | The spoofed IP(s) you expect from the peer |
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

### Multi-Spoof

By default QUICochet spoofs a single source IP on every outgoing packet. **Multi-spoof** lets you specify a list of source IPs — each packet randomly selects one, making the traffic appear to originate from N independent hosts. This hardens against traffic analysis and per-flow fingerprinting by middleboxes.

```jsonc
// client config
"spoof": {
  "source_ips": ["192.0.2.11", "192.0.2.12", "192.0.2.13"],
  "peer_spoof_ips": ["198.51.100.1", "198.51.100.2"]
}

// server config (mirror)
"spoof": {
  "source_ips": ["198.51.100.1", "198.51.100.2"],
  "peer_spoof_ips": ["192.0.2.11", "192.0.2.12", "192.0.2.13"],
  "client_real_ip": "CLIENT_REAL_IP"
}
```

**Rules:**
- `source_ips` on one side must equal `peer_spoof_ips` on the other — and vice versa.
- The old singular `source_ip` / `peer_spoof_ip` still works and is treated as a one-element list. If both singular and plural are set, they are merged (deduplicated).
- IPv6 equivalents: `source_ipv6s`, `peer_spoof_ipv6s`.
- The `raw`, `icmp`, and `syn_udp` transports filter incoming packets by `peer_spoof_ips` — packets from unknown sources are silently dropped. The `udp` transport does not filter (kernel delivers everything to the bound port).
- All listed IPs must be routable on the wire (i.e. your ISP/upstream does not block spoofed sources for those ranges). Use IP ranges you control or that are not allocated on the path.

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

The defaults below are sized to saturate realistic WAN links end-to-end, including RTTs up to ~300 ms, without any manual tuning. The socket buffer path auto-escalates via `SO_*BUFFORCE` on root-run tunnels (the normal case), so no `sysctl` is required unless you run unprivileged.

| Key | Default | Description |
|-----|---------|-------------|
| `performance.mtu` | `1400` | On-wire payload budget (post-obfuscator, pre-IP). **Minimum `1231`**, safe max `~1460` for eth. Drives `quic.InitialPacketSize` automatically |
| `performance.read_buffer` | `33554432` (32 MB) | `SO_RCVBUF` target. Applied via `SO_RCVBUFFORCE` with graceful fallback — no sysctl needed when running as root |
| `performance.write_buffer` | `33554432` (32 MB) | `SO_SNDBUF` target, same auto-escalation as read_buffer |
| `performance.pacing_rate_mbps` | `0` (off) | `SO_MAX_PACING_RATE` in Mbps. Kernel paces outgoing packets at this rate, preventing burst-induced queue drops on real-world WAN. See [Kernel Pacing](#kernel-pacing-so_max_pacing_rate) — **this is the single most impactful flag for high-RTT production paths** |
| `performance.buffer_size` | `65535` | Internal pool buffer size (hot-path re-use). Rarely needs tuning |
| `quic.pool_size` | `8` | QUIC connections in the client pool; parallelizes across ISP ECMP buckets |
| `quic.keep_alive_period_sec` | `5` | QUIC keepalive interval |
| `quic.max_idle_timeout_sec` | `10` | Drop an idle QUIC connection after this many seconds |
| `quic.max_stream_receive_window` | `33554432` (32 MB) | Per-stream flow-control cap; lets a single stream saturate ~2.5 Gbps at 100 ms RTT |
| `quic.max_connection_receive_window` | `134217728` (128 MB) | Per-connection flow-control cap |
| `quic.stream_close_timeout_sec` | `10` | Force-cancel a stream if the second copy direction hasn't drained within this window |
| `quic.congestion_control` | `"auto"` | `"auto"` (default, BBRv1 with CUBIC fallback), `"cubic"`, or `"bbrv1"`. See [Congestion Control](#congestion-control) — BBR is ~90× better than CUBIC on 1% loss paths |
| `quic.packet_threshold` | `1024` | Packet-reorder threshold for fast loss detection. See [Packet Reorder Threshold](#packet-reorder-threshold). RFC 9002 default is 3; we raise it to 128 to survive Go-scheduler burst + WAN jitter. |
| `quic.max_incoming_streams` | `100000` | Hard cap on concurrent bidirectional QUIC streams **per connection**. See [Scaling for Many Clients](#scaling-for-many-clients) |
| `quic.max_incoming_uni_streams` | `1000` | Same for unidirectional streams (unused today, reserved) |
| `quic.enable_path_mtu_discovery` | `false` | Incompatible with the obfuscator padding strategy. See [PMTUD and obfuscation](#pmtud-and-obfuscation) |
| `quic.udp_route_idle_sec` | `90` | Idle timeout for a per-target UDP relay route on the server (measured bidirectionally) |
| `quic.udp_route_max` | `50000` | Hard circuit-breaker on the number of concurrent UDP relay routes per session. LRU-evicts when hit |

**Initial receive windows (hardcoded, no knob).** QUICochet sets `InitialStreamReceiveWindow = 2 MB` and `InitialConnectionReceiveWindow = 4 MB` on every connection. quic-go's defaults (512 KB each) forced short-lived streams to crawl for 3-5 RTTs of slow-ramp before reaching useful throughput, which was the dominant perf killer on high-RTT paths. These are intentionally not exposed as config fields — they're safe on any modern host and a knob here only invites misconfiguration.

**Unprivileged containers.** If you run without `CAP_NET_ADMIN` (scapped Docker, Kubernetes without `--cap-add=NET_ADMIN`), the buffer helper falls back to portable `SO_RCVBUF`/`SO_SNDBUF`, which the kernel caps at `net.core.rmem_max` / `wmem_max` (typically 208 KB on stock distros). In that case, raise those sysctls on the host to the buffer sizes above to avoid silent throughput collapse.

### Packet Reorder Threshold

Real-world WAN paths reorder packets. Even low µs-level inter-packet jitter combined with the way user-space QUIC senders emit packets in short bursts (Go scheduler wake-ups flush dozens of packets in microseconds) routinely produces 30+ position reorder bursts. RFC 9002 §6.1.1 sets quic-go's packet-threshold loss detector at **3**: after 3 later packets are acknowledged, the older one is declared lost and cwnd halves. Under our measured conditions this fires **continuously and falsely** on a perfectly healthy path — every spurious-loss triggers a cwnd collapse, which is why vanilla QUIC tunnels plateau at 5–10% of link capacity on paths above ~50 ms RTT.

We ship a patched quic-go fork at `third_party/quic-go` that makes this threshold tunable (upstream it's a hardcoded const), and default it to **1024**. Time-threshold loss detection (9/8 × RTT) remains the primary safety net — it's jitter-proof by construction — so real loss is still caught, just ~130 ms later in the worst case.

**Why 128?** We measured on netem 115 ms RTT + 1 ms jitter (4 streams) across several threshold values; 128 is the sweet spot between tolerating jitter-induced reorder and recovering quickly from real loss:

| Threshold | 0% loss | 0.1% loss | 1% loss |
|-----------|---------|-----------|---------|
| 3 (RFC 9002) | 5 Mbps | 5 Mbps | 4 Mbps |
| 32 | 253 | 50 | 6 |
| **128** | 875 | **67** | **9** |
| 256 | 1221 | 44 | 8 |
| 1024 | 1098 | 39 | 8 |

Higher thresholds give marginally better throughput on pristine paths but degrade on lossy ones: with threshold too high, real loss is detected only via the time threshold (9/8 × RTT ≈ 130 ms), and each loss costs a full RTT of stalled cwnd. 128 keeps packet-count detection alive for genuine loss while still ignoring the ~30+ position reorder that Go-scheduler bursts + jitter produce.

Tuning:

- `128` (default) — recommended for any real-world deployment.
- Lower values (3–32) — closer to RFC default, very fragile to jitter; only if your path is truly pristine.
- Higher values (256–1024) — if your path has effectively zero loss, a bit more peak throughput; if loss happens, performance tanks.

### Kernel Pacing (`SO_MAX_PACING_RATE`)

On real-world WAN paths the biggest single enemy of user-space QUIC tunnels is **burst-induced queue drop**. quic-go transmits packets at Go-scheduler speed (hundreds of Mbps in a millisecond), which overflows any realistic ISP-grade router queue (1000–10000 packets). The drops fool the congestion controller into thinking the path is congested, cwnd collapses, and throughput plateaus at a tiny fraction of the actual link capacity. TCP doesn't suffer this because the kernel naturally paces via GSO/TSO.

`performance.pacing_rate_mbps` wires up the same kernel facility for our UDP socket: `SO_MAX_PACING_RATE`. Set it to slightly below your known bottleneck bandwidth (e.g. `900` for a 1 Gbps link, `45` for a 50 Mbps residential link) and the kernel will spread packet bursts evenly over time, preserving cwnd and letting the CC converge on the real bandwidth.

**Activating pacing takes TWO things — both required**:

1. Set `performance.pacing_rate_mbps` in the config on **both** client and server.
2. Ensure the output interface uses the `fq` qdisc. Check:
   ```bash
   tc qdisc show dev <iface>    # look for "fq" in the output
   ```
   If it says `fq_codel`, `pfifo_fast`, `noqueue`, or anything other than `fq`, the sockopt is silently ignored. Install `fq` with:
   ```bash
   sudo tc qdisc replace dev <iface> root fq
   ```
   To make this persist across reboots, either add a systemd unit or set `net.core.default_qdisc = fq` in `/etc/sysctl.conf` (takes effect for newly-brought-up interfaces).

The startup log line `pacing rate applied bytes_per_sec=... mbps=...` confirms the sockopt was accepted. Whether it actually paces depends on the qdisc — watch the log at info level.

Leave this at `0` on loopback-only benchmarks or truly unlimited paths, where pacing only adds artificial delay.

### Congestion Control

Three modes are selectable via `quic.congestion_control`:

- **`"auto"`** (default) — attempt BBRv1, silently fall back to CUBIC if the factory panics or returns nil. Check logs for `algo=auto (bbrv1 with cubic fallback)` at boot.
- **`"cubic"`** — force `quic-go`'s upstream NewReno/CUBIC. Stable and fair to other TCP flows but loss-sensitive: cwnd halves on every loss, so any real packet loss on the path tanks throughput (measured: 9 Mbps at 1% loss).
- **`"bbrv1"`** — force BBRv1 via the [`qiulaidongfeng/quic-go`](https://github.com/qiulaidongfeng/quic-go) community fork (see upstream tracking issue [`quic-go#4565`](https://github.com/quic-go/quic-go/issues/4565)). Panics if the fork constructor fails — use `"auto"` for a safer rollout.

**Why BBR is the default**: measured on netem 115 ms RTT + 1 ms jitter, 4 streams:

| Loss | CUBIC | BBRv1 | ratio |
|------|-------|-------|-------|
| 0% | 896 Mbps | 1.14 Gbps | 1.3× |
| 0.1% | 46 Mbps | 1.06 Gbps | **23×** |
| 1% | 9 Mbps | 833 Mbps | **90×** |

BBR models bandwidth explicitly instead of reacting to loss, so its throughput stays nearly path-capacity even when the link has real loss. CUBIC halves cwnd per loss event and on any lossy path collapses to a fraction of capacity. On clean paths BBR is slightly better too (1.3×) thanks to better window recovery.

Caveats:
- BBR is more aggressive than CUBIC on contention — on shared-tenancy links with competing TCP, BBR may take more than its fair share. Prefer `"cubic"` if fairness matters more than throughput.
- `"auto"` is chosen so BBR breakage (experimental fork) degrades gracefully to CUBIC rather than crashing.
- The BBR/CUBIC choice is **local** to each endpoint — client and server can run different CCs.

### UDP Relay Datagram Size

The SOCKS5 UDP ASSOCIATE relay ships each UDP packet inside a single QUIC DATAGRAM frame (RFC 9221), which is bounded by `InitialPacketSize - ~29 bytes` of QUIC overhead. With the default MTU `1400` that ceiling is **~1340 bytes** of UDP payload. Packets above that — e.g. near-MTU DNS responses or games using full 1472-byte payloads — are dropped at send time with a debug log. This is a protocol-level constraint of QUIC datagrams on an eth-MTU path, not a bug.

If your uplink supports a larger frame, raise `performance.mtu` (everything downstream — `InitialPacketSize`, the obfuscator padding target, the transport write size — is derived from this single value; there is no secondary cap to touch). For a 1500-byte eth MTU, `1472` is the safe ceiling (1500 − 20 IP − 8 UDP).

### Scaling for Many Clients

QUICochet is designed to front-end a fan-in proxy (e.g. an `xray` or `sing-box` SOCKS5 server) serving hundreds or thousands of concurrent end-users through a single tunnel. Two previous hard limits have been lifted for this case:

**1. QUIC stream cap.** quic-go's upstream default for `MaxIncomingStreams` is `100` per connection. With `pool_size = 4` that's 400 concurrent streams *globally* — saturated in seconds under fan-in load, after which every new `OpenStreamSync` blocks on `MAX_STREAMS` credit and times out at 5 s. The visible symptom is "0 kbps or 100 Mbps": downloads stall until an old stream closes, then burst until the cap is re-hit.

QUICochet defaults `quic.max_incoming_streams` to **100000** per connection. quic-go allocates stream state lazily on stream open (not per credit slot), so the memory cost of a large cap is negligible until the streams are actually live. For a pool of 4 that gives a 400000 concurrent-stream ceiling, which is effectively unbounded for any realistic fan-in workload.

The knob **must match on client and server** — the smaller of the two wins, since `MAX_STREAMS` is a peer-advertised transport parameter.

**2. UDP relay route lifecycle.** Each target of a SOCKS5 UDP ASSOCIATE flow becomes a per-target route on the server: one `net.UDPConn`, one goroutine, one fd. Browsers open 20–50 such routes per tab per minute (DNS + QUIC + WebRTC). A naive 5-minute fixed read deadline on the receive loop leaked fds and produced periodic cleanup stalls.

The current design enforces **bidirectional idle tracking**: every datagram in either direction (client→target send and target→client receive) touches a per-route `lastActivity` atomic. The receive loop wakes on a short tick (≈ `udp_route_idle_sec / 3`), checks real idle age against `udp_route_idle_sec`, and only closes on true silence. A background janitor (one goroutine per session, 30 s tick) sweeps the map as a safety net for routes stuck in the kernel. A hard LRU circuit breaker at `udp_route_max` routes per session catches runaway growth.

Defaults:

| Knob | Default | Rationale |
|---|---|---|
| `quic.max_incoming_streams` | 100000 | ~unbounded for realistic fan-in, still cheap in memory |
| `quic.udp_route_idle_sec` | 90 s | Long enough for keepalive-heavy protocols (QUIC, WebRTC) |
| `quic.udp_route_max` | 50000 | Each route = 1 fd; `LimitNOFILE` in the systemd unit is 1048576 |

The periodic stats line exposes live counters for capacity monitoring:

```
server stats  active_sessions=12 bytes_sent=... bytes_received=... open_fds=...
              udp_routes=273 udp_evictions=0 udp_idle_closed=1842
```

- `udp_routes` — current live routes across all sessions
- `udp_evictions` — lifetime LRU evictions (non-zero means you're hitting `udp_route_max` and should raise it)
- `udp_idle_closed` — lifetime idle-triggered closes (expected to grow steadily under normal churn)

Set `logging.statistics: true` to promote this line from DEBUG to INFO (so you don't need `log_level=debug` just to watch it). The same snapshot is available on demand via the [Admin Socket](#admin-socket).

**OS-level knobs.** For sustained fan-in loads also raise `net.core.somaxconn` and `LimitNOFILE` (already set to 1048576 in the systemd unit — see [ops docs](SETUP.md)). For ≥ 500 concurrent users, `pool_size: 12–16` on the client is recommended to parallelize `AcceptStream` across more quic-go dispatch loops.

### PMTUD and obfuscation

`quic.enable_path_mtu_discovery` is **off by default** and is architecturally incompatible with the obfuscator for any mode other than `"none"`. The obfuscator pads every outgoing packet to exactly `performance.mtu` bytes regardless of the QUIC packet's logical size — that is the core of the traffic-analysis resistance. PLPMTUD works by *varying* probe sizes and observing which arrive; with fixed-size padding it has no signal, and a probe larger than the target would leak a non-constant packet size, defeating the obfuscation. Set `performance.mtu` manually to match your physical path instead.

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

### Admin Socket

The admin socket is an opt-in Unix-domain control plane for a running daemon. When enabled, a sibling CLI (`quiccochet admin`) can fetch live stats and run in-link benchmarks without touching the config or restarting anything.

| Key | Default | Description |
|-----|---------|-------------|
| `admin.enabled` | `false` | Bind a Unix-domain socket for the admin CLI |
| `admin.socket` | `""` (auto) | Socket path. Empty → `/run/quiccochet-<pid>.sock`, logged at startup |
| `logging.statistics` | `false` | Promote the periodic stats ticker from DEBUG to INFO |

```jsonc
"logging": { "level": "info", "statistics": true },
"admin":   { "enabled": true, "socket": "/run/quiccochet-client.sock" }
```

The socket is created with mode `0600` and unlinked on clean shutdown. If the path is already bound by another live daemon, startup fails cleanly rather than silently unlinking.

**Commands.** All subcommands take `-s/--socket` (overrides the config) and `-H/--human` (compact one-line format, default is raw JSON):

```bash
# Live snapshot — pool health, bytes, UDP routes, fds, uptime
quiccochet admin stats -c client-config.json -H
# ▶ pool 4/4  sent 73 B  recv 0 B  udp_assocs 0  fds 11  up 26s

# In-link latency bench (ping over a dedicated QUIC stream)
quiccochet admin bench latency 2s -c client-config.json -H
# ▶ latency  samples 21683  p50 87.8µs  p90 110.7µs  p99 167.3µs  mean 92.1µs  min 56.9µs  max 1.7ms

# In-link throughput bench — fans out over N parallel streams.
# Omit N and the daemon uses quic.pool_size (the sweet spot).
quiccochet admin bench throughput 3s -c client-config.json -H
# ▶ throughput  906.82 MiB in 3.00s  rate 302.26 MiB/s (2.54 Gbps)  × 4 streams

# Override the fan-out explicitly (e.g. 8 parallel streams)
quiccochet admin bench throughput 3s 8 -c client-config.json -H
# ▶ throughput  899.84 MiB in 3.00s  rate 299.92 MiB/s (2.52 Gbps)  × 8 streams
```

The bench runs on dedicated QUIC streams on the existing pool, so it measures the real tunnel (not the SOCKS5 proxy path) and doesn't require any extra config on the peer — bench is driven entirely from the client side. `bench` is rejected on a server-side socket (server is passive with respect to bench requests).

**On-demand pprof.** The admin socket can also toggle a `net/http/pprof` endpoint on the live daemon for leak / CPU investigations, without redeploying:

```bash
# Turn it on (default 127.0.0.1:6060 loopback)
quiccochet admin pprof start -c client-config.json -H
# ▶ pprof  running at 127.0.0.1:6060
#     go tool pprof http://127.0.0.1:6060/debug/pprof/heap

# Capture heap at different times, diff them
go tool pprof -base heap.t0 http://127.0.0.1:6060/debug/pprof/heap

# Turn it off when done — zero overhead again
quiccochet admin pprof stop -c client-config.json -H
```

Go's built-in heap sampler runs regardless (`MemProfileRate` = 512 KiB), so a profile taken right after `start` covers the process' full lifetime. The HTTP listener only exists between `start` and `stop`; default binding is loopback-only because the admin socket already gates access to `0600` root.

**Why parallel matters.** A single QUIC stream is capped by `max_stream_receive_window` (5 MB default); on a high-BDP link that saturates well below the physical bandwidth. Throughput bench therefore defaults to fanning out across `quic.pool_size` concurrent streams — each one round-robins onto a different QUIC connection in the pool, so the per-connection window is not the bottleneck either. Oversubscribing beyond `pool_size` is wasted work once the physical pipe is full. Latency bench stays single-stream by design, so its numbers reflect RTT and not cross-stream contention.

### Outbound Proxy (server mode only)

The server can forward all tunneled traffic through an upstream SOCKS5 proxy (e.g. a local `sing-box`/`xray` instance). This is useful when the server's IP itself is blocked from reaching the final targets and needs a second hop, or when you want to layer a separate censorship-evasion stack.

| Key | Description |
|-----|-------------|
| `outbound_proxy.enabled` | `true` to route TCP streams and UDP datagrams through the upstream proxy |
| `outbound_proxy.type` | Currently only `"socks5"` |
| `outbound_proxy.address` | `host:port` of the upstream proxy |
| `outbound_proxy.username`, `outbound_proxy.password` | Optional RFC 1929 auth |

When enabled, the server skips its own DNS resolution and lets the proxy do it (preventing DNS leaks of the final target from the server's network). UDP ASSOCIATE is used for datagrams — the relay keeps a per-flow TCP control channel to the upstream proxy with a 2-minute idle timeout to prevent fd accumulation.

### sendmsg + IP_TRANSPARENT (UDP transport)

When using the `udp` transport, QUICochet automatically probes for `IP_TRANSPARENT` support on the receive socket. If available (Linux kernel ≥ 2.6.28, CAP_NET_RAW — both already required), the send path switches from raw sockets with manual IP/UDP header construction to `sendmsg(2)` with `IP_PKTINFO` cmsg for per-packet source IP selection. This gives:

- **No manual headers**: the kernel builds IP + UDP headers, freeing ~300 ns/pkt of CPU
- **TX checksum offload**: the kernel delegates IP/UDP checksum to the NIC if supported, further reducing CPU in the hot path
- **Multi-spoof integration**: the randomly selected source IP is set via `ipi_spec_dst` in the cmsg — no per-IP checksum recomputation
- **Cleaner socket model**: a single `SOCK_DGRAM` fd handles both send and receive (the separate `SOCK_RAW` + `IP_HDRINCL` fd is closed)

If the probe fails (e.g. missing capability or very old kernel), the transport silently falls back to the raw socket path with full backward compatibility. The mode is logged at startup:

```
INFO  udp transport: sendmsg mode enabled  component=transport
```

The `raw`, `icmp`, and `syn_udp` transports are unaffected — they need `IP_HDRINCL` for protocol-level tricks that `SOCK_DGRAM` cannot express.

<a id="performance-tuning-os"></a>
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

### File Descriptor Limit

The SOCKS5 outbound proxy path opens one TCP control connection to the upstream proxy for every unique UDP flow (one per SOCKS5 UDP ASSOCIATE route). Under a DNS/UDP-heavy burst from a busy client, the server can hold thousands of such fds at once before the 2-minute idle timeout drains them. In a production run we measured a peak of **~21 000 open fds** during a few-second burst — well above the typical systemd default of `65535` on some distros, and uncomfortably close to ephemeral-port exhaustion.

Set `LimitNOFILE=1048576` on both systemd units (`quiccochet-server.service` and `quiccochet-client.service`):

```ini
[Service]
...
LimitNOFILE=1048576
```

The e2e provisioning scripts (`test/e2e/provision-{server,client}.sh`) and `deploy.sh` already apply this. Verify on a running instance with:

```bash
cat /proc/$(pgrep -f quiccochet)/limits | grep 'Max open files'
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
- 2x KVM VMs (4 vCPU AMD EPYC-Genoa, 4 GB RAM, libvirt private network, ~0.2 ms RTT)
- Ubuntu 24.04, Linux 6.8
- Obfuscation: `standard` (padding to MTU, ChaCha20-Poly1305 AEAD)
- `sendmsg` + `IP_TRANSPARENT` active on UDP, ICMP, RAW (auto-probed at startup)

**Results (all transports, 15s iperf3):**

Single stream (1 connection):
```
Transport    Download       Upload
─────────    ──────────     ──────────
UDP          1082 Mbps      1097 Mbps
RAW          1094 Mbps      1099 Mbps
ICMP          893 Mbps       876 Mbps
SYN+UDP       936 Mbps       668 Mbps
```

4 parallel streams (pool_size=4):
```
Transport    Download       Upload
─────────    ──────────     ──────────
UDP          2179 Mbps      2237 Mbps
SYN+UDP      2001 Mbps      1349 Mbps
RAW          1151 Mbps      1207 Mbps
ICMP         1012 Mbps      1031 Mbps
```

> **Where is the ceiling?** Single-stream throughput plateaus at ~1.1 Gbps — this is the ChaCha20-Poly1305 AEAD cost in the obfuscation layer. Multi-stream scales past 2 Gbps because QUIC parallelizes encryption across goroutines. ICMP is ~20% slower due to kernel ICMP path overhead. SYN+UDP upload is asymmetric by design (client sends TCP SYN, see [Transport Details](#transport-details)).

<a id="roadmap"></a>
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
- ✅ Multi-spoof: random source IP selection from a configurable list
- ✅ `sendmsg` + `IP_TRANSPARENT` for UDP, ICMP, RAW (auto-probed, kernel builds IP headers)
- ✅ Fan-in scale: `MaxIncomingStreams` default 100k, bidirectional UDP route idle tracking, LRU eviction
- ✅ Admin Unix socket: on-demand stats and in-link latency/throughput bench over a dedicated QUIC stream (`quiccochet admin stats | bench …`)
- ✅ Multi-stream throughput bench: parallel QUIC streams spread across the pool, defaulting to `quic.pool_size` to saturate high-BDP links

### ⏳ Future

- [ ] **Forward Secrecy**: Noise-IK ephemeral handshake for PFS
- [ ] **Adaptive Padding**: Machine-learning-resistant traffic patterns
- [ ] **Full IPv6**: Complete IPv6 transport support
- [ ] **Automated E2E test runner**: `run-tests.sh` with assertions
- [ ] **BBR upstreaming**: track [`quic-go#4565`](https://github.com/quic-go/quic-go/issues/4565) and drop the fork once merged

<a id="contributing"></a>
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

<a id="acknowledgments"></a>
## 🙏 Acknowledgments

- [quic-go](https://github.com/quic-go/quic-go) - QUIC implementation in Go
- Inspired by the need for resilient communication in restrictive network environments

---

**Maintained by [@PechenyeRU](https://github.com/PechenyeRU)**

This project is HEAVILY inspired by [**Spoof Tunnel**](https://github.com/ParsaKSH/spoof-tunnel) which was the original project. QUICochet represents a different approach with QUIC transport.