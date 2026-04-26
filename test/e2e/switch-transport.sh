#!/usr/bin/env bash
# Switch transport type on both VMs and restart services.
#
# Usage:
#   ./switch-transport.sh udp|icmp|raw|syn_udp
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TRANSPORT="${1:-}"
if [[ -z "$TRANSPORT" ]]; then
  echo "usage: $0 <udp|icmp|raw|syn_udp>"
  exit 1
fi

case "$TRANSPORT" in
  udp|icmp|raw|syn_udp) ;;
  *)
    echo "error: unknown transport '$TRANSPORT' (must be udp, icmp, raw, or syn_udp)"
    exit 1
    ;;
esac

echo "=== switching transport to: $TRANSPORT ==="

for VM in server client; do
  echo ""
  echo "--- $VM ---"
  vagrant ssh "$VM" -c "
    sudo python3 -c \"
import json, glob, os
# config.json is a symlink to one of config-{v4,v6,dual}.json. Apply
# the transport change to ALL three siblings so a later switch-stack
# does not silently revert the transport choice.
for path in glob.glob('/etc/quiccochet/config-*.json'):
    with open(path) as f:
        cfg = json.load(f)
    cfg['transport']['type'] = '$TRANSPORT'
    if '$TRANSPORT' == 'raw':
        cfg['transport']['protocol_number'] = 200
    elif 'protocol_number' in cfg.get('transport', {}):
        del cfg['transport']['protocol_number']
    with open(path, 'w') as f:
        json.dump(cfg, f, indent=2)
print('transport set to: $TRANSPORT in all sibling configs')
\"
    sudo systemctl restart quiccochet-${VM#*-} 2>/dev/null || sudo systemctl restart quiccochet-$VM
    sleep 1
    echo \"service: \$(sudo systemctl is-active quiccochet-$VM 2>/dev/null || echo 'checking...')\"
  "
done

# Extra wait for client SOCKS5
sleep 2
echo ""
vagrant ssh client -c "
  ss -tlnp | grep -q ':1080' && echo 'SOCKS5: up' || echo 'SOCKS5: DOWN'
  grep '\"type\"' /etc/quiccochet/config.json
"

echo ""
echo "=== done. run bench with: vagrant ssh client -c 'sudo bash /vagrant/bench.sh' ==="
