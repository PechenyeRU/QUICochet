#!/usr/bin/env bash
# Benchmark script — run from the CLIENT VM.
#
# Usage:
#   sudo bash /vagrant/bench.sh              # TCP mode, single stream (default)
#   sudo bash /vagrant/bench.sh tcp 4        # TCP mode, 4 parallel streams
#   sudo bash /vagrant/bench.sh udp          # UDP mode (fair comparison under impairment)
#   sudo bash /vagrant/bench.sh udp 50M      # UDP mode with 50 Mbps target
set -euo pipefail

SERVER_IP="192.168.56.10"
SERVER_SSH_KEY="/vagrant/keys/server_vagrant_key"
IPERF_PORT=5201
DURATION="${DURATION:-10}"
MODE="${1:-tcp}"
PARALLEL="${2:-1}"
UDP_BW="${3:-100M}"

echo "============================================"
echo " QUICochet Benchmark"
echo "============================================"
echo ""

# show current config
TRANSPORT=$(python3 -c "import json; print(json.load(open('/etc/quiccochet/config.json'))['transport']['type'])" 2>/dev/null || echo "unknown")
BW_LIMIT=$(python3 -c "import json; c=json.load(open('/etc/quiccochet/config.json')); print(c.get('performance',{}).get('send_bandwidth', 0))" 2>/dev/null || echo "?")
echo "transport:      $TRANSPORT"
echo "send_bandwidth: ${BW_LIMIT} Mbps (0 = unlimited)"
echo "iperf3 mode:    $MODE"
echo "parallel:       $PARALLEL stream(s)"
if [[ "$MODE" == "udp" ]]; then
  echo "udp target bw:  $UDP_BW"
fi
echo ""

# ── check prerequisites ──
if ! ss -tlnp | grep -q ':1080'; then
  echo "ERROR: SOCKS5 proxy not listening on :1080"
  exit 1
fi

echo "SOCKS5 proxy: OK"
echo "duration: ${DURATION}s per test"
echo ""

# iperf3 flags per mode
IPERF_FLAGS="-t $DURATION -P $PARALLEL -J"
if [[ "$MODE" == "udp" ]]; then
  IPERF_FLAGS="-u -b $UDP_BW $IPERF_FLAGS"
fi

run_iperf() {
  local label="$1"
  local jq_path="$2"
  shift 2
  local json
  if ! json=$("$@" 2>/dev/null); then
    echo "  $label: FAILED (iperf3 error)"
    return 1
  fi
  local val
  val=$(echo "$json" | jq -r "$jq_path" 2>/dev/null)
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    echo "  $label: FAILED (no data in json)"
    return 1
  fi
  local mbps lost_pct
  mbps=$(echo "$val" | awk '{printf "%.2f", $1 / 1e6}')
  # show loss % for UDP mode
  if [[ "$MODE" == "udp" ]]; then
    lost_pct=$(echo "$json" | jq -r '.end.sum.lost_percent // .end.sum_sent.lost_percent // empty' 2>/dev/null || true)
    if [[ -n "$lost_pct" ]]; then
      echo "  $label: $mbps Mbps (loss: ${lost_pct}%)"
      return 0
    fi
  fi
  echo "  $label: $mbps Mbps"
  return 0
}

ssh_server() {
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      -i "$SERVER_SSH_KEY" vagrant@"$SERVER_IP" "$@" 2>/dev/null
}

wait_iperf_ready() {
  # Kill local iperf3/proxychains processes.
  pkill -f 'iperf3.*5201' 2>/dev/null || true
  pkill -f proxychains 2>/dev/null || true

  # Restart iperf3 on the server via systemd — clean, atomic, no race.
  # systemctl waits for the old process to exit before starting the new one.
  ssh_server "sudo systemctl restart iperf3-server" || true

  # Wait until the service is active (up to 10s).
  for i in $(seq 1 10); do
    if ssh_server "systemctl is-active --quiet iperf3-server"; then
      return 0
    fi
    sleep 1
  done
  echo "  (warning: iperf3-server did not restart cleanly)"
}

# ── 1) baseline: direct iperf3 (no tunnel) ──
echo "=== 1/3 Baseline: direct (no tunnel) ==="
if [[ "$MODE" == "udp" ]]; then
  run_iperf "bitrate" ".end.sum.bits_per_second" \
    iperf3 -c "$SERVER_IP" -p "$IPERF_PORT" $IPERF_FLAGS || true
else
  run_iperf "sent" ".end.sum_sent.bits_per_second" \
    iperf3 -c "$SERVER_IP" -p "$IPERF_PORT" $IPERF_FLAGS || true
fi
echo ""

wait_iperf_ready

# ── 2) download through tunnel (server -> client, iperf3 -R) ──
echo "=== 2/3 Download via tunnel (server -> client) ==="
if [[ "$MODE" == "udp" ]]; then
  run_iperf "bitrate" ".end.sum.bits_per_second" \
    proxychains4 -q iperf3 -c "$SERVER_IP" -p "$IPERF_PORT" $IPERF_FLAGS -R || true
else
  run_iperf "received" ".end.sum_received.bits_per_second" \
    proxychains4 -q iperf3 -c "$SERVER_IP" -p "$IPERF_PORT" $IPERF_FLAGS -R || true
fi
echo ""

wait_iperf_ready

# ── 3) upload through tunnel (client -> server) ──
echo "=== 3/3 Upload via tunnel (client -> server) ==="
if [[ "$MODE" == "udp" ]]; then
  run_iperf "bitrate" ".end.sum.bits_per_second" \
    proxychains4 -q iperf3 -c "$SERVER_IP" -p "$IPERF_PORT" $IPERF_FLAGS || true
else
  run_iperf "sent" ".end.sum_sent.bits_per_second" \
    proxychains4 -q iperf3 -c "$SERVER_IP" -p "$IPERF_PORT" $IPERF_FLAGS || true
fi
echo ""

echo "============================================"
echo " Done"
echo "============================================"
