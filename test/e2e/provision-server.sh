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
# v2.0.0 multi-peer mode reads peerB's public key when present. Older
# checkouts without setup-keys.sh updates leave the file absent — we
# fall back to skipping the multi config in that case.
CLIENT_PUB_B=""
[ -f "$KEYS_DIR/clientB.pub" ] && CLIENT_PUB_B=$(cat "$KEYS_DIR/clientB.pub")

# Three config variants are written so switch-stack.sh can flip the
# active config with a symlink swap; v4 is the default symlinked one
# to preserve backwards-compat with existing harness invocations.
write_config() {
  local stack="$1" path="$2" spoof_block="$3"
  cat > "$path" << EOF
{
  "mode": "server",
  "transport": { "type": "udp" },
  "listen_port": 8080,
  "spoof": ${spoof_block},
  "crypto": {
    "private_key": "${SERVER_PRIV}",
    "peer_public_key": "${CLIENT_PUB}"
  },
  "performance": {
    "buffer_size": 65535,
    "mtu": 1400
  },
  "security": {
    "block_private_targets": false
  },
  "obfuscation": {
    "mode": "none"
  },
  "quic": {
    "keep_alive_period_sec": 10,
    "max_idle_timeout_sec": 30
  },
  "logging": { "level": "info", "file": "/var/log/quiccochet-server.log", "statistics": true },
  "admin": { "enabled": true, "socket": "/run/quiccochet-server-${stack}.sock" }
}
EOF
}

write_config v4 "$CONF_DIR/config-v4.json" "$(cat <<JSON
  {
    "source_ip": "${SERVER_SPOOF_IP}",
    "peer_spoof_ip": "${CLIENT_SPOOF_IP}",
    "client_real_ip": "${CLIENT_IP}"
  }
JSON
)"

write_config v6 "$CONF_DIR/config-v6.json" "$(cat <<JSON
  {
    "source_ipv6": "${SERVER_SPOOF_IPV6}",
    "peer_spoof_ipv6": "${CLIENT_SPOOF_IPV6}",
    "client_real_ipv6": "${CLIENT_IPV6}"
  }
JSON
)"

write_config dual "$CONF_DIR/config-dual.json" "$(cat <<JSON
  {
    "source_ip": "${SERVER_SPOOF_IP}",
    "peer_spoof_ip": "${CLIENT_SPOOF_IP}",
    "client_real_ip": "${CLIENT_IP}",
    "source_ipv6": "${SERVER_SPOOF_IPV6}",
    "peer_spoof_ipv6": "${CLIENT_SPOOF_IPV6}",
    "client_real_ipv6": "${CLIENT_IPV6}"
  }
JSON
)"

# v2.0.0 multi-peer config — same v4 LAN, server has two distinct
# peers. peer_spoof_ips are disjoint per peer (10.99.0.11 vs 10.99.0.12)
# so the server's source-IP cipher dispatch can route each client's
# packets to its own AEAD without ambiguity. Both peers' real IP is the
# same (the client VM); the QUIC sessions are distinguished by the
# (cert hash, learned ephemeral port) tuple, so collocation is fine.
if [ -n "$CLIENT_PUB_B" ]; then
  cat > "$CONF_DIR/config-multi.json" << EOF
{
  "mode": "server",
  "transport": { "type": "udp" },
  "listen_port": 8080,
  "spoof": {
    "source_ips": ["${SERVER_SPOOF_IP}"]
  },
  "crypto": {
    "private_key": "${SERVER_PRIV}"
  },
  "peers": [
    {
      "name": "peerA",
      "peer_public_key": "${CLIENT_PUB}",
      "client_real_ip": "${CLIENT_IP}",
      "peer_spoof_ips": ["${CLIENT_SPOOF_IP}"]
    },
    {
      "name": "peerB",
      "peer_public_key": "${CLIENT_PUB_B}",
      "client_real_ip": "${CLIENT_IP}",
      "peer_spoof_ips": ["${CLIENT_SPOOF_IP_B}"]
    }
  ],
  "performance": { "buffer_size": 65535, "mtu": 1400 },
  "security": { "block_private_targets": false },
  "obfuscation": { "mode": "none" },
  "quic": { "keep_alive_period_sec": 10, "max_idle_timeout_sec": 30 },
  "logging": { "level": "info", "file": "/var/log/quiccochet-server.log", "statistics": true },
  "admin": { "enabled": true, "socket": "/run/quiccochet-server-multi.sock" }
}
EOF
fi

# Active config defaults to v4 (matches legacy harness behaviour).
# switch-stack.sh flips the symlink to multi for the 2-peer test.
ln -sf "$CONF_DIR/config-v4.json" "$CONF_DIR/config.json"

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
TimeoutStopSec=5
LimitNOFILE=1048576

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
