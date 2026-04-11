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

# Client config v2.0 (QUIC + Anti-IA)
cat > "$CONF_DIR/config.json" << EOF
{
  "mode": "client",
  "transport": { "type": "udp" },
  "server": { "address": "${SERVER_IP}", "port": 8080 },
  "spoof": {
    "source_ip": "${CLIENT_SPOOF_IP}",
    "peer_spoof_ip": "${SERVER_SPOOF_IP}"
  },
  "crypto": {
    "private_key": "${CLIENT_PRIV}",
    "peer_public_key": "${SERVER_PUB}"
  },
  "inbounds": [
    { "type": "socks", "listen": "127.0.0.1:1080" }
  ],
  "performance": {
    "buffer_size": 4194304,
    "mtu": 1400,
    "session_timeout": 600
  },
  "obfuscation": {
    "enabled": false
  },
  "quic": {
    "keep_alive_period_sec": 10,
    "max_idle_timeout_sec": 30
  },
  "logging": { "level": "info", "file": "/var/log/quiccochet-client.log" }
}
EOF

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
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now quiccochet-client

sleep 2
echo "=== client provisioning done ==="
systemctl is-active quiccochet-client && echo "QUICochet client: running" || echo "QUICochet client: FAILED"
