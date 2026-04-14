#!/usr/bin/env bash
# Apply network impairments using tc (traffic control) on both VMs.
#
# Usage:
#   ./impair.sh <profile>
#   ./impair.sh clear
#
# Profiles:
#   wan       - Typical WAN:     50ms RTT, 1% loss, 100 Mbps
#   far       - Far WAN:         150ms RTT, 1% loss, 200 Mbps (BBR sweet spot)
#   harsh     - Harsh network:   200ms RTT, 5% loss, 50 Mbps
#   lossy     - High loss only:  10ms RTT, 10% loss, no bw limit
#   slow      - Slow link:       20ms RTT, 0.5% loss, 10 Mbps
#   satellite - Satellite link:  600ms RTT, 2% loss, 20 Mbps
#   clear     - Remove all impairments
#
# Impairments are applied on eth1 (the private network interface)
# on BOTH VMs so the effect is symmetric.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="${1:-}"
if [[ -z "$PROFILE" ]]; then
  echo "usage: $0 <wan|harsh|lossy|slow|satellite|clear>"
  exit 1
fi

# tc commands for each profile.
# delay is one-way (applied on both sides, so RTT = 2x).
# loss is per-interface.
case "$PROFILE" in
  wan)
    DELAY="25ms"    # 25ms each side = 50ms RTT
    JITTER="5ms"
    LOSS="1%"
    RATE="100mbit"
    ;;
  far)
    DELAY="75ms"    # 75ms each side = 150ms RTT
    JITTER="10ms"
    LOSS="1%"
    RATE="200mbit"
    ;;
  harsh)
    DELAY="100ms"
    JITTER="20ms"
    LOSS="5%"
    RATE="50mbit"
    ;;
  lossy)
    DELAY="5ms"
    JITTER="2ms"
    LOSS="10%"
    RATE=""         # no bandwidth limit
    ;;
  slow)
    DELAY="10ms"
    JITTER="3ms"
    LOSS="0.5%"
    RATE="10mbit"
    ;;
  satellite)
    DELAY="300ms"
    JITTER="30ms"
    LOSS="2%"
    RATE="20mbit"
    ;;
  clear)
    echo "=== clearing all impairments ==="
    for VM in server client; do
      vagrant ssh "$VM" -c "sudo tc qdisc del dev eth1 root 2>/dev/null; echo 'cleared on $VM'" 2>&1 | grep -v WARNING
    done
    echo "done"
    exit 0
    ;;
  *)
    echo "error: unknown profile '$PROFILE'"
    echo "available: wan, harsh, lossy, slow, satellite, clear"
    exit 1
    ;;
esac

echo "=== applying profile: $PROFILE ==="
echo "  delay:  $DELAY (+/- $JITTER) per side"
echo "  loss:   $LOSS"
echo "  rate:   ${RATE:-unlimited}"
echo ""

for VM in server client; do
  echo "--- $VM ---"
  vagrant ssh "$VM" -c "
    # clear existing rules
    sudo tc qdisc del dev eth1 root 2>/dev/null || true

    if [ -n '$RATE' ]; then
      # with rate limit: use htb + netem
      # netem limit must be large enough for the bandwidth-delay product
      # otherwise netem silently drops packets when its internal queue fills
      sudo tc qdisc add dev eth1 root handle 1: htb default 10
      sudo tc class add dev eth1 parent 1: classid 1:10 htb rate $RATE ceil $RATE
      sudo tc qdisc add dev eth1 parent 1:10 handle 10: netem delay $DELAY $JITTER loss $LOSS limit 50000
    else
      # no rate limit: just netem
      sudo tc qdisc add dev eth1 root netem delay $DELAY $JITTER loss $LOSS limit 50000
    fi

    echo 'applied:'
    sudo tc qdisc show dev eth1
  " 2>&1 | grep -v WARNING
  echo ""
done

echo "=== profile '$PROFILE' active ==="
echo "run benchmark: vagrant ssh client -c 'sudo bash /vagrant/bench.sh'"
echo "clear with:    $0 clear"
