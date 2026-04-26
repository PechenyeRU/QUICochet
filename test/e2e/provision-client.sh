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
    "enabled": false
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

# systemd: quiccochet client
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

systemctl daemon-reload
systemctl enable --now quiccochet-client

sleep 2
echo "=== client provisioning done ==="
systemctl is-active quiccochet-client && echo "QUICochet client: running" || echo "QUICochet client: FAILED"
