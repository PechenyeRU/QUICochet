#!/usr/bin/env bash
# Client VM provisioning.
set -euo pipefail

KEYS_DIR=/vagrant/keys
CONF_DIR=/etc/quiccochet
mkdir -p "$CONF_DIR"

# Wait for keys
for i in $(seq 1 30); do
  [ -f "$KEYS_DIR/client.key" ] && [ -f "$KEYS_DIR/server.pub" ] && break
  sleep 1
done

# ── ensure SSH key has correct permissions for client ──
if [ -f "$KEYS_DIR/server_vagrant_key" ]; then
  chmod 600 "$KEYS_DIR/server_vagrant_key"
  chown vagrant:vagrant "$KEYS_DIR/server_vagrant_key" 2>/dev/null || true
fi

CLIENT_PRIV=$(cat "$KEYS_DIR/client.key")
SERVER_PUB=$(cat "$KEYS_DIR/server.pub")
# v2.0.0 multi-peer: peerB runs side-by-side with peerA on this VM,
# distinct keypair, distinct wire spoof IP, distinct SOCKS port.
CLIENT_B_PRIV=""
[ -f "$KEYS_DIR/clientB.key" ] && CLIENT_B_PRIV=$(cat "$KEYS_DIR/clientB.key")

# Three config variants written so switch-stack.sh can flip the active
# stack with a symlink swap. v4 is symlinked by default; v6 dials the
# server's v6 address; dual configures both spoof families on the
# transport (the client side picks one server to dial — v4 here).
write_config() {
  local stack="$1" path="$2" server_addr="$3" spoof_block="$4"
  cat > "$path" << EOF
{
  "mode": "client",
  "transport": { "type": "udp" },
  "server": { "address": "${server_addr}", "port": 8080 },
  "spoof": ${spoof_block},
  "crypto": {
    "private_key": "${CLIENT_PRIV}",
    "peer_public_key": "${SERVER_PUB}"
  },
  "inbounds": [
    { "type": "socks", "listen": "127.0.0.1:1080" }
  ],
  "performance": {
    "buffer_size": 65535,
    "mtu": 1400
  },
  "obfuscation": {
    "mode": "none"
  },
  "quic": {
    "keep_alive_period_sec": 10,
    "max_idle_timeout_sec": 30
  },
  "logging": { "level": "info", "file": "/var/log/quiccochet-client.log", "statistics": true },
  "admin": { "enabled": true, "socket": "/run/quiccochet-client-${stack}.sock" }
}
EOF
}

write_config v4 "$CONF_DIR/config-v4.json" "${SERVER_IP}" "$(cat <<JSON
  {
    "source_ip": "${CLIENT_SPOOF_IP}",
    "peer_spoof_ip": "${SERVER_SPOOF_IP}"
  }
JSON
)"

write_config v6 "$CONF_DIR/config-v6.json" "${SERVER_IPV6}" "$(cat <<JSON
  {
    "source_ipv6": "${CLIENT_SPOOF_IPV6}",
    "peer_spoof_ipv6": "${SERVER_SPOOF_IPV6}"
  }
JSON
)"

write_config dual "$CONF_DIR/config-dual.json" "${SERVER_IP}" "$(cat <<JSON
  {
    "source_ip": "${CLIENT_SPOOF_IP}",
    "peer_spoof_ip": "${SERVER_SPOOF_IP}",
    "source_ipv6": "${CLIENT_SPOOF_IPV6}",
    "peer_spoof_ipv6": "${SERVER_SPOOF_IPV6}"
  }
JSON
)"

# v2.0.0 multi-peer mode: two side-by-side client binaries, each with
# its own keypair/spoof source/SOCKS port. The two configs share the
# same server but advertise distinct peer identities so the server's
# multi-cipher dispatch routes them independently.
if [ -n "$CLIENT_B_PRIV" ]; then
  cat > "$CONF_DIR/config-multi-A.json" << EOF
{
  "mode": "client",
  "transport": { "type": "udp" },
  "server": { "address": "${SERVER_IP}", "port": 8080 },
  "spoof": {
    "source_ips": ["${CLIENT_SPOOF_IP}"],
    "peer_spoof_ips": ["${SERVER_SPOOF_IP}"]
  },
  "crypto": {
    "private_key": "${CLIENT_PRIV}",
    "peer_public_key": "${SERVER_PUB}"
  },
  "inbounds": [
    { "type": "socks", "listen": "127.0.0.1:1080" }
  ],
  "performance": { "buffer_size": 65535, "mtu": 1400 },
  "obfuscation": { "mode": "none" },
  "quic": { "keep_alive_period_sec": 10, "max_idle_timeout_sec": 30 },
  "logging": { "level": "info", "file": "/var/log/quiccochet-client-multi-A.log", "statistics": true },
  "admin": { "enabled": true, "socket": "/run/quiccochet-client-multi-A.sock" }
}
EOF
  cat > "$CONF_DIR/config-multi-B.json" << EOF
{
  "mode": "client",
  "transport": { "type": "udp" },
  "server": { "address": "${SERVER_IP}", "port": 8080 },
  "spoof": {
    "source_ips": ["${CLIENT_SPOOF_IP_B}"],
    "peer_spoof_ips": ["${SERVER_SPOOF_IP}"]
  },
  "crypto": {
    "private_key": "${CLIENT_B_PRIV}",
    "peer_public_key": "${SERVER_PUB}"
  },
  "inbounds": [
    { "type": "socks", "listen": "127.0.0.1:1081" }
  ],
  "performance": { "buffer_size": 65535, "mtu": 1400 },
  "obfuscation": { "mode": "none" },
  "quic": { "keep_alive_period_sec": 10, "max_idle_timeout_sec": 30 },
  "logging": { "level": "info", "file": "/var/log/quiccochet-client-multi-B.log", "statistics": true },
  "admin": { "enabled": true, "socket": "/run/quiccochet-client-multi-B.sock" }
}
EOF
fi

ln -sf "$CONF_DIR/config-v4.json" "$CONF_DIR/config.json"

# proxychains config (for routing iperf3 through SOCKS5)
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF

# systemd: quiccochet client (single-peer, default)
cat > /etc/systemd/system/quiccochet-client.service << 'EOF'
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

# v2.0.0 multi-peer mode: two side-by-side client units pointing at the
# multi-A / multi-B configs. Disabled by default — switch-stack.sh
# multi flips them on (and stops the single-peer unit).
cat > /etc/systemd/system/quiccochet-client-multi-A.service << 'EOF'
[Unit]
Description=QUICochet Client (multi-peer A)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config-multi-A.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/quiccochet-client-multi-B.service << 'EOF'
[Unit]
Description=QUICochet Client (multi-peer B)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config-multi-B.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# The multi-* configs in /etc/quiccochet/ point at the multi-A/B unit
# files, so do NOT touch them at provisioning time — switch-stack.sh
# does the start/stop/symlink dance when you flip the active mode.
systemctl daemon-reload
systemctl enable --now quiccochet-client

sleep 2
echo "=== client provisioning done ==="
systemctl is-active quiccochet-client && echo "QUICochet client: running" || echo "QUICochet client: FAILED"
