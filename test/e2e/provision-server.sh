#!/usr/bin/env bash
# Server VM provisioning.
set -euo pipefail

KEYS_DIR=/vagrant/keys
CONF_DIR=/etc/quiccochet
mkdir -p "$CONF_DIR"

# Wait for keys
for i in $(seq 1 30); do
  [ -f "$KEYS_DIR/server.key" ] && [ -f "$KEYS_DIR/client.pub" ] && break
  sleep 1
done

# ── configure SSH authorized_keys for vagrant user ──
# Allow client VM to SSH into server without password
if [ -f "$KEYS_DIR/server_vagrant_key" ]; then
  SERVER_PUB_KEY=$(ssh-keygen -y -f "$KEYS_DIR/server_vagrant_key" 2>/dev/null || true)
  if [ -n "$SERVER_PUB_KEY" ]; then
    mkdir -p /home/vagrant/.ssh
    chmod 700 /home/vagrant/.ssh
    echo "$SERVER_PUB_KEY" >> /home/vagrant/.ssh/authorized_keys
    chmod 600 /home/vagrant/.ssh/authorized_keys
    chown -R vagrant:vagrant /home/vagrant/.ssh
    echo "SSH key added to authorized_keys"
  fi
fi

SERVER_PRIV=$(cat "$KEYS_DIR/server.key")
CLIENT_PUB=$(cat "$KEYS_DIR/client.pub")

# Server config v2.0 (QUIC + Anti-IA)
cat > "$CONF_DIR/config.json" << EOF
{
  "mode": "server",
  "transport": { "type": "udp" },
  "listen": { "address": "0.0.0.0", "port": 8080 },
  "spoof": {
    "source_ip": "${SERVER_SPOOF_IP}",
    "peer_spoof_ip": "${CLIENT_SPOOF_IP}",
    "client_real_ip": "${CLIENT_IP}"
  },
  "crypto": {
    "private_key": "${SERVER_PRIV}",
    "peer_public_key": "${CLIENT_PUB}"
  },
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
  "logging": { "level": "info", "file": "/var/log/quiccochet-server.log" }
}
EOF

# systemd: iperf3 server (benchmark target)
cat > /etc/systemd/system/iperf3-server.service << 'EOF'
[Unit]
Description=iperf3 Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/iperf3 -s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# systemd: quiccochet server
cat > /etc/systemd/system/quiccochet-server.service << 'EOF'
[Unit]
Description=QUICochet Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now iperf3-server
systemctl enable --now quiccochet-server

sleep 2
echo "=== server provisioning done ==="
systemctl is-active quiccochet-server && echo "QUICochet server: running" || echo "QUICochet server: FAILED"
systemctl is-active iperf3-server && echo "iperf3-server: running" || echo "iperf3-server: FAILED"
