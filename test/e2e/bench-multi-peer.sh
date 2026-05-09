#!/usr/bin/env bash
# Multi-peer benchmark for the v2.0.0 break.
#
# Designed to run from the HOST (uses vagrant ssh). Switches the
# server VM to its config-multi.json (peers[peerA, peerB]), starts
# two side-by-side client binaries on the client VM (each with its
# own keypair / wire spoof IP / SOCKS port), and runs iperf3 through
# each SOCKS5 endpoint to verify both peers tunnel independently.
#
# Topology:
#   server VM 192.168.56.10  →  spoof 10.99.0.10        :8080  (peers[peerA, peerB])
#   client VM 192.168.56.11  →  binary A  spoof 10.99.0.11  socks 127.0.0.1:1080
#                            →  binary B  spoof 10.99.0.12  socks 127.0.0.1:1081
#
# UDP transport, no impairment. Verifies multi-cipher source-IP
# dispatch under real network packet flow on a real LAN.
#
# Usage: bash test/e2e/bench-multi-peer.sh [duration_sec]
#
# Restores single-peer mode on exit (trap).

set -euo pipefail

DURATION="${1:-10}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

vssh() { vagrant ssh "$1" -c "$2" ; }

restore() {
    set +e
    echo ""
    echo "=== restore single-peer mode ==="
    vssh client "sudo systemctl stop  quiccochet-client-multi-A quiccochet-client-multi-B 2>/dev/null
                  sudo systemctl start quiccochet-client" 2>/dev/null
    vssh server "sudo ln -sf /etc/quiccochet/config-v4.json /etc/quiccochet/config.json
                  sudo systemctl restart quiccochet-server" 2>/dev/null
}
trap restore EXIT

echo "============================================"
echo " QUICochet multi-peer e2e bench (v2.0.0)"
echo "============================================"
echo ""

echo "=== switch server to multi-peer config ==="
vssh server "test -f /etc/quiccochet/config-multi.json || { echo 'config-multi.json missing — re-run vagrant provision'; exit 1; }
              sudo ln -sf /etc/quiccochet/config-multi.json /etc/quiccochet/config.json
              sudo systemctl restart quiccochet-server
              sleep 1
              sudo systemctl is-active quiccochet-server | sed 's/^/  server: /'"

echo ""
echo "=== start client A + client B on client VM ==="
vssh client "sudo systemctl stop  quiccochet-client
              sudo systemctl start quiccochet-client-multi-A
              sudo systemctl start quiccochet-client-multi-B
              sleep 2
              sudo systemctl is-active quiccochet-client-multi-A | sed 's/^/  peerA: /'
              sudo systemctl is-active quiccochet-client-multi-B | sed 's/^/  peerB: /'"

echo ""
echo "=== verify SOCKS5 listeners ==="
vssh client "ss -tlnp 2>/dev/null | grep -E ':108[01]' | sed 's/^/  /' || { echo '  no SOCKS5 listening on 1080/1081'; exit 1; }"

echo ""
echo "=== iperf3 server up? ==="
vssh server "sudo systemctl is-active iperf3-server | sed 's/^/  iperf3-server: /'"

echo ""
echo "=== bench peerA via 127.0.0.1:1080 (TCP, ${DURATION}s) ==="
A_OUT=$(vssh client "proxychains4 -q -f <(printf 'strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5 127.0.0.1 1080\n') iperf3 -c 192.168.56.10 -t ${DURATION} -J 2>/dev/null" || echo '{}')
A_BPS=$(echo "$A_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('end',{}).get('sum_received',{}).get('bits_per_second',0))" 2>/dev/null || echo 0)
A_MBPS=$(awk -v b="$A_BPS" 'BEGIN{printf "%.1f", b/1e6}')
echo "  peerA throughput: ${A_MBPS} Mbps"

echo ""
echo "=== bench peerB via 127.0.0.1:1081 (TCP, ${DURATION}s) ==="
B_OUT=$(vssh client "proxychains4 -q -f <(printf 'strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5 127.0.0.1 1081\n') iperf3 -c 192.168.56.10 -t ${DURATION} -J 2>/dev/null" || echo '{}')
B_BPS=$(echo "$B_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('end',{}).get('sum_received',{}).get('bits_per_second',0))" 2>/dev/null || echo 0)
B_MBPS=$(awk -v b="$B_BPS" 'BEGIN{printf "%.1f", b/1e6}')
echo "  peerB throughput: ${B_MBPS} Mbps"

echo ""
echo "=== server admin stats (per-peer view) ==="
vssh server "sudo /usr/local/bin/quiccochet admin stats -c /etc/quiccochet/config.json 2>&1 | head -40 | sed 's/^/  /' || true"

echo ""
echo "============================================"
echo " RESULT"
echo "============================================"
ok=true
if [ "$(awk -v b="$A_BPS" 'BEGIN{print (b > 0) ? 1 : 0}')" -eq 0 ]; then
    echo "  peerA: FAIL (no throughput recorded)"
    ok=false
else
    echo "  peerA: PASS  ${A_MBPS} Mbps"
fi
if [ "$(awk -v b="$B_BPS" 'BEGIN{print (b > 0) ? 1 : 0}')" -eq 0 ]; then
    echo "  peerB: FAIL (no throughput recorded)"
    ok=false
else
    echo "  peerB: PASS  ${B_MBPS} Mbps"
fi
echo ""
if $ok; then
    echo "OK — both peers tunnelled iperf3 traffic through one server."
    exit 0
else
    echo "FAIL — at least one peer didn't tunnel. Inspect logs:"
    echo "  vagrant ssh server -c 'sudo tail -50 /var/log/quiccochet-server.log'"
    echo "  vagrant ssh client -c 'sudo tail -50 /var/log/quiccochet-client-multi-A.log /var/log/quiccochet-client-multi-B.log'"
    exit 1
fi
