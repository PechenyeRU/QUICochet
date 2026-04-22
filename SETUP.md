# QUICochet — End-to-End Setup Tutorial

A concrete, copy-paste walkthrough for bringing up a QUICochet tunnel between two **Ubuntu 24.04** VPS instances. Uses the default `udp` transport (best throughput, simplest). For other transports, adjust the config as described in the [README](README.md#transport-details).

## Topology assumption

```
  ┌─────────────────────┐            ┌─────────────────────┐
  │  CLIENT VPS         │            │  SERVER VPS         │
  │  real IP: 10.0.0.1  │───internet │  real IP: 10.0.0.2  │
  │  spoofs 192.0.2.11  │            │  spoofs 192.0.2.10  │
  │  SOCKS5 :1080 local │            │  listens :8080 QUIC │
  └─────────────────────┘            └─────────────────────┘
```

Replace the placeholders:

| Placeholder | Meaning |
|---|---|
| `CLIENT_REAL_IP` | public IPv4 of the client VPS (`10.0.0.1` above) |
| `SERVER_REAL_IP` | public IPv4 of the server VPS (`10.0.0.2` above) |
| `CLIENT_SPOOF_IP` | fake IP the client forges as source — use `192.0.2.11` (RFC 5737 TEST-NET-1, safe) |
| `SERVER_SPOOF_IP` | fake IP the server forges as source — use `192.0.2.10` |

The spoofed IPs must be **routable-looking but unassigned**. TEST-NET-1, TEST-NET-2, TEST-NET-3 ranges from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are ideal for examples — they won't collide with real hosts.

---

## Step 0 — Prerequisites (both VPS)

```bash
sudo apt update
sudo apt install -y curl jq build-essential
```

Confirm kernel ≥ 4.18 (for QUIC features) and 64-bit:

```bash
uname -r  # should be >=6.x on Ubuntu 24.04
uname -m  # should be x86_64 or aarch64
```

## Step 1 — Download the binary (both VPS)

Pick the latest release and the right arch:

```bash
# amd64
curl -sLo /tmp/quiccochet https://github.com/PechenyeRU/QUICochet/releases/latest/download/quiccochet-linux-amd64

# arm64
# curl -sLo /tmp/quiccochet https://github.com/PechenyeRU/QUICochet/releases/latest/download/quiccochet-linux-arm64

# verify checksum
curl -sLo /tmp/checksums.txt https://github.com/PechenyeRU/QUICochet/releases/latest/download/checksums.txt
( cd /tmp && grep "quiccochet-linux-amd64" checksums.txt | sha256sum -c - )

sudo install -m 755 /tmp/quiccochet /usr/local/bin/quiccochet
quiccochet --help  # smoke test
```

*Alternative: build from source with `go build -o quiccochet ./cmd/quiccochet/` if you have Go 1.25+ installed.*

## Step 2 — Generate crypto keys (any VPS, once)

On **either** VPS (you'll move the output around):

```bash
quiccochet keygen
```

Output looks like:

```
Private key: AAAABBBB...   (32 bytes base64)
Public key:  CCCCDDDD...
```

Run it **twice** — once for the server, once for the client. You end up with four values:

- `SERVER_PRIVATE_KEY`, `SERVER_PUBLIC_KEY`
- `CLIENT_PRIVATE_KEY`, `CLIENT_PUBLIC_KEY`

The server needs its own private key + the client's public key, and vice versa. Keep the two private keys secret; share only the public keys.

## Step 3 — Kernel tuning (both VPS)

Only three sysctls are strictly required — the ones that let the kernel accept and forward our spoofed-source packets. Everything buffer-related is handled automatically at runtime via `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` (works because quiccochet already runs with `CAP_NET_ADMIN` for raw sockets).

```bash
sudo tee /etc/sysctl.d/99-quiccochet.conf > /dev/null << 'EOF'
# IP spoofing — CRITICAL: without these the kernel drops our forged packets.
net.ipv4.conf.all.accept_local = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.log_martians = 0
EOF

sudo sysctl -p /etc/sysctl.d/99-quiccochet.conf
```

**Optional — enable kernel pacing** if you plan to set `performance.pacing_rate_mbps` in the config (smooths our outbound bursts on links where router queues are shallow; see [README → Kernel Pacing](README.md#kernel-pacing-so_max_pacing_rate)). Run this once per VPS, persistent until reboot:

```bash
IFACE=$(ip route show default | awk '{print $5}' | head -1)
sudo tc qdisc replace dev "$IFACE" root fq
```

To make the `fq` qdisc permanent across reboots:

```bash
sudo tee -a /etc/sysctl.d/99-quiccochet.conf > /dev/null << 'EOF'
net.core.default_qdisc = fq
EOF
sudo sysctl -p /etc/sysctl.d/99-quiccochet.conf
```

## Step 4 — Server config (on the SERVER VPS only)

```bash
sudo mkdir -p /etc/quiccochet
sudo tee /etc/quiccochet/config.json > /dev/null << 'EOF'
{
  "mode": "server",
  "transport": { "type": "udp" },
  "listen_port": 8080,
  "spoof": {
    "source_ip": "SERVER_SPOOF_IP",
    "peer_spoof_ip": "CLIENT_SPOOF_IP",
    "client_real_ip": "CLIENT_REAL_IP"
  },
  "crypto": {
    "private_key": "SERVER_PRIVATE_KEY",
    "peer_public_key": "CLIENT_PUBLIC_KEY"
  },
  "obfuscation": {
    "enabled": true,
    "mode": "standard"
  },
  "security": {
    "block_private_targets": true
  },
  "logging": {
    "level": "info",
    "file": "/var/log/quiccochet-server.log"
  }
}
EOF

# fill in placeholders
sudo sed -i "s/SERVER_SPOOF_IP/192.0.2.10/; s/CLIENT_SPOOF_IP/192.0.2.11/; s/CLIENT_REAL_IP/<paste here>/" /etc/quiccochet/config.json
sudo sed -i "s|SERVER_PRIVATE_KEY|<paste here>|; s|CLIENT_PUBLIC_KEY|<paste here>|" /etc/quiccochet/config.json

sudo touch /var/log/quiccochet-server.log
sudo chmod 640 /etc/quiccochet/config.json
```

> **Note on what's NOT in this config.** Buffer sizes, receive windows, pool size, congestion control, packet reorder threshold, stream caps, UDP relay idle/max — all defaulted to production-ready values that auto-escalate (e.g. `SO_RCVBUFFORCE` grabs 32 MB of socket buffer without a sysctl; the patched quic-go fork uses `packet_threshold=128` to survive jitter-induced reorder). Only override if you have a measured reason. See [README → Configuration](README.md#configuration) for the full knob list.

## Step 5 — Client config (on the CLIENT VPS only)

```bash
sudo mkdir -p /etc/quiccochet
sudo tee /etc/quiccochet/config.json > /dev/null << 'EOF'
{
  "mode": "client",
  "transport": { "type": "udp" },
  "server": {
    "address": "SERVER_REAL_IP",
    "port": 8080
  },
  "spoof": {
    "source_ip": "CLIENT_SPOOF_IP",
    "peer_spoof_ip": "SERVER_SPOOF_IP"
  },
  "crypto": {
    "private_key": "CLIENT_PRIVATE_KEY",
    "peer_public_key": "SERVER_PUBLIC_KEY"
  },
  "inbounds": [
    { "type": "socks", "listen": "127.0.0.1:1080" }
  ],
  "obfuscation": {
    "enabled": true,
    "mode": "standard"
  },
  "logging": {
    "level": "info",
    "file": "/var/log/quiccochet-client.log"
  }
}
EOF

sudo sed -i "s/SERVER_REAL_IP/<paste here>/; s/SERVER_SPOOF_IP/192.0.2.10/; s/CLIENT_SPOOF_IP/192.0.2.11/" /etc/quiccochet/config.json
sudo sed -i "s|CLIENT_PRIVATE_KEY|<paste here>|; s|SERVER_PUBLIC_KEY|<paste here>|" /etc/quiccochet/config.json

sudo touch /var/log/quiccochet-client.log
sudo chmod 640 /etc/quiccochet/config.json
```

## Step 6 — systemd unit (server VPS)

```bash
sudo tee /etc/systemd/system/quiccochet-server.service > /dev/null << 'EOF'
[Unit]
Description=QUICochet Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now quiccochet-server
sudo systemctl status quiccochet-server
```

## Step 7 — systemd unit (client VPS)

```bash
sudo tee /etc/systemd/system/quiccochet-client.service > /dev/null << 'EOF'
[Unit]
Description=QUICochet Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now quiccochet-client
sudo systemctl status quiccochet-client
```

## Step 8 — Verify the tunnel

**On the server:** check the log for `new session` events once the client connects.

```bash
sudo tail -f /var/log/quiccochet-server.log
```

Expected within a few seconds of starting the client:

```json
{"time":"...","level":"INFO","msg":"starting server mode"}
{"time":"...","level":"INFO","msg":"server listening","port":8080}
{"time":"...","level":"INFO","msg":"new session","component":"quic","remote":{"IP":"192.0.2.11",...}}
```

**On the client:** verify the SOCKS5 inbound is up.

```bash
ss -tlnp | grep :1080
# tcp  LISTEN  0  ...  127.0.0.1:1080  ...  users:(("quiccochet",...))

sudo tail /var/log/quiccochet-client.log
```

Expected:

```json
{"time":"...","level":"INFO","msg":"socket buffer applied","component":"transport","direction":"recv","requested":33554432,"got":33554432,"path":"force"}
{"time":"...","level":"INFO","msg":"quic effective config","component":"client","initial_stream_window_mb":2,"max_stream_window_mb":32,"max_conn_window_mb":128,"packet_threshold":128,...}
{"time":"...","level":"INFO","msg":"pool established","component":"quic","connections":8}
{"time":"...","level":"INFO","msg":"inbound started","component":"socks5","listen":"127.0.0.1:1080"}
```

The `path=force` on the socket buffer line confirms `SO_RCVBUFFORCE` was honored (you're running with `CAP_NET_ADMIN`). `quic effective config` shows the defaults actually applied — a handy grep for "did my override take?".

## Step 9 — Smoke test via SOCKS5 (client VPS)

```bash
# TCP test — your public IP should resolve to the SERVER VPS's egress
curl --socks5 127.0.0.1:1080 https://ifconfig.me
# should print SERVER_REAL_IP (or whatever egress the server uses)

# DNS-over-UDP test via SOCKS5 UDP ASSOCIATE
curl --socks5 127.0.0.1:1080 https://cloudflare.com -v
```

If `curl` returns the server's IP and websites load through it, the tunnel is working. Rest easy.

---

## Troubleshooting

### `dial failed: context deadline exceeded` on the client

The client can reach the server's QUIC listen port, but the handshake doesn't complete. Checklist:

- Both VPS have the `rp_filter = 0` and `accept_local = 1` sysctls applied (Step 3). Without these the kernel silently drops spoofed packets.
- The spoofed IPs on both sides match exactly what the peer expects (`peer_spoof_ip` on the client = `source_ip` on the server, and vice versa).
- The server's `client_real_ip` is the actual public IPv4 of the client, not the spoofed one.
- A middlebox between the two VPS isn't doing egress filtering that drops packets with "foreign" source IPs (BCP 38). Many budget hosting providers enforce this — you'll see the client's outbound packets never arrive. Test by running `tcpdump -i any -n udp port 8080` on both ends.

### `socks5 proxy not listening on 127.0.0.1:1080`

The client never reached `pool established`. Check `/var/log/quiccochet-client.log` for dial failures. Most common cause is the previous bullet.

### `bind: address already in use` after a restart

Linux's TIME_WAIT on the raw socket side. Safe to ignore on a fresh start, but if it persists, `sudo systemctl restart quiccochet-{client,server}` on both sides.

### Low throughput on a high-RTT path

The tunnel collapses well below link capacity on real WAN paths? The defaults already include the biggest fixes (packet reorder threshold 128, initial receive windows 2/4 MB, 32 MB socket buffers via BUFFORCE), but two opt-ins can help further on especially hostile paths:

1. **Kernel pacing** — set `performance.pacing_rate_mbps` in the config to ~90% of your link bandwidth and ensure `fq` qdisc is active on the egress interface (Step 3's optional block). Smooths Go-scheduler bursts that overflow shallow ISP router queues.
2. **BBRv1 congestion control** — set `"congestion_control": "auto"` in the `quic` block. Tries BBRv1, silently falls back to CUBIC if the fork misbehaves. Helps on lossy paths where CUBIC over-reacts.

On obfuscation-enabled deployments (`mode: "standard"` or `"paranoid"`), the padding inflates wire bytes 2–4× relative to user payload — expected. Switch to `mode: "none"` if the path is already hidden upstream (e.g. via a dedicated VPN leg) and you only need the spoofing — that path is ~20% faster because the per-packet encrypt + memcpy is skipped entirely.

### File descriptor exhaustion under DNS-heavy load

Verify `LimitNOFILE` is actually applied:

```bash
cat /proc/$(pgrep -f quiccochet)/limits | grep 'Max open files'
# should read: 1048576  1048576
```

If it reads `65535`, your systemd unit wasn't reloaded — `sudo systemctl daemon-reload && sudo systemctl restart quiccochet-{server,client}`.

### I need more logs

Set `"logging": {"level": "debug"}` in the config and restart. The debug output shows per-stream and per-datagram events — useful for diagnosing hangs, leaks, or client misbehavior. Turn it back to `info` for production; debug logs are verbose (~25 MB/h under moderate load).

---

## Next steps

- Read [README → Configuration](README.md#configuration) for the full schema and advanced fields (outbound proxy, obfuscation modes, ICMP/RAW transports).
- Use `test/e2e/bench.sh` to measure end-to-end throughput once the tunnel is up.
- If you want to front the tunnel with `sing-box` or `xray` as an upstream, enable the `outbound_proxy` block in the server config.
