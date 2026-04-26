#!/usr/bin/env bash
# Swap the active QUICochet IP stack on both VMs (v4, v6, or dual).
# Mirrors switch-transport.sh: provisioning writes config-{v4,v6,dual}.json
# and config.json is a symlink to one of them; this script flips the
# symlink and restarts the service.
set -euo pipefail

STACK="${1:-}"
case "$STACK" in
  v4|v6|dual) ;;
  *)
    echo "Usage: $0 <v4|v6|dual>"
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

for vm in server client; do
  echo "─── $vm: switching to $STACK ───"
  vagrant ssh "$vm" -c "
    set -e
    sudo ln -sfn /etc/quiccochet/config-$STACK.json /etc/quiccochet/config.json
    sudo systemctl restart quiccochet-$vm
    sleep 1
    sudo systemctl is-active quiccochet-$vm | sed 's/^/  status: /'
    sudo journalctl -u quiccochet-$vm -n 5 --no-pager | sed 's/^/  /'
  "
done

echo
echo "Active stack on both VMs: $STACK"
echo "Verify with:  vagrant ssh client -c 'sudo bash /vagrant/bench.sh'"
