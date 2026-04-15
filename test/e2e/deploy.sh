#!/usr/bin/env bash
# Deploy updated code to both VMs: rsync, rebuild, restart.
#
# Usage (from repo root or test/e2e):
#   ./test/e2e/deploy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== rsync source to VMs ==="
vagrant rsync server
vagrant rsync client

BUILD_CMD='cd /opt/quiccochet && VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev") && COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown") && BUILD_TIME=$(date -u "+%Y-%m-%dT%H:%M:%SZ") && LDFLAGS="-X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" && sudo /usr/local/go/bin/go build -ldflags "${LDFLAGS}" -o /usr/local/bin/quiccochet ./cmd/quiccochet/'

# Systemd unit template (shared by both server and client)
UNIT_BODY='Restart=on-failure
RestartSec=2
TimeoutStopSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target'

echo ""
echo "=== rebuild + restart on server ==="
vagrant ssh server -c "${BUILD_CMD} && sudo bash -c 'cat > /etc/systemd/system/quiccochet-server.service <<EOF
[Unit]
Description=QUICochet Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config.json
${UNIT_BODY}
EOF
' && sudo systemctl daemon-reload && sudo systemctl restart quiccochet-server && sleep 1 && echo \"quiccochet-server: \$(sudo systemctl is-active quiccochet-server)\" && quiccochet --version 2>&1 | head -1"

echo ""
echo "=== rebuild + restart on client ==="
vagrant ssh client -c "${BUILD_CMD} && sudo bash -c 'cat > /etc/systemd/system/quiccochet-client.service <<EOF
[Unit]
Description=QUICochet Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quiccochet -c /etc/quiccochet/config.json
${UNIT_BODY}
EOF
' && sudo systemctl daemon-reload && sudo systemctl restart quiccochet-client && sleep 2 && echo \"quiccochet-client: \$(sudo systemctl is-active quiccochet-client)\" && quiccochet --version 2>&1 | head -1 && ss -tlnp | grep -q ':1080' && echo 'SOCKS5: up' || echo 'SOCKS5: DOWN'"

echo ""
echo "=== deploy complete ==="
