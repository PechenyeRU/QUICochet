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

echo ""
echo "=== rebuild + restart on server ==="
vagrant ssh server -c "
  cd /opt/quiccochet &&
  sudo /usr/local/go/bin/go build -o /usr/local/bin/quiccochet ./cmd/quiccochet/ &&
  sudo systemctl restart quiccochet-server &&
  sleep 1 &&
  echo 'quiccochet-server:' \$(sudo systemctl is-active quiccochet-server)
"

echo ""
echo "=== rebuild + restart on client ==="
vagrant ssh client -c "
  cd /opt/quiccochet &&
  sudo /usr/local/go/bin/go build -o /usr/local/bin/quiccochet ./cmd/quiccochet/ &&
  sudo systemctl restart quiccochet-client &&
  sleep 2 &&
  echo 'quiccochet-client:' \$(sudo systemctl is-active quiccochet-client) &&
  ss -tlnp | grep -q ':1080' && echo 'SOCKS5: up' || echo 'SOCKS5: DOWN'
"

echo ""
echo "=== deploy complete ==="
