#!/usr/bin/env bash
# Common provisioning for both server and client VMs.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── packages ──
apt-get update -qq
apt-get install -y -qq iperf3 curl jq proxychains4 openssh-client > /dev/null 2>&1

# ── install Go ──
GO_VERSION="1.25.0"
if ! command -v go &>/dev/null; then
  echo "installing go ${GO_VERSION}..."
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz
fi
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh

# ── build quiccochet ──
cd /opt/quiccochet
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS="-X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"
go build -ldflags "${LDFLAGS}" -o /usr/local/bin/quiccochet ./cmd/quiccochet/
echo "QUICochet built: $(quiccochet --version 2>&1 | head -1)"

# ── verify keys (generated on host by setup-keys.sh, synced via rsync) ──
KEYS_DIR=/vagrant/keys
if [ ! -f "$KEYS_DIR/server.key" ] || [ ! -f "$KEYS_DIR/client.key" ]; then
  echo "ERROR: keys not found in $KEYS_DIR"
  echo "Run ./setup-keys.sh on the host first!"
  exit 1
fi
echo "keys OK: $(ls $KEYS_DIR/*.key | wc -l) keypairs"

# ── disable kernel ICMP echo reply (needed if using ICMP transport) ──
sysctl -w net.ipv4.icmp_echo_ignore_all=1 > /dev/null 2>&1 || true

# ── network tuning: socket buffers and queues ──
# Default Ubuntu values (212 KB rmem/wmem) are far too small for high-
# throughput UDP tunneling. With 100 Mbps and 50ms RTT the bandwidth-delay
# product alone is ~625 KB; bursts at 1+ Gbps need much more.
# Network tuning for QUICochet
cat > /etc/sysctl.d/99-quiccochet.conf << 'EOF'
# Large socket buffers for UDP tunnel traffic (4 MB for high throughput)
net.core.rmem_max     = 16777216
net.core.wmem_max     = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 10000
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.udp_mem  = 102400 873800 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.core.optmem_max   = 65536

# CRITICAL: Allow bidirectional IP spoofing
# Disable reverse path filtering (allow packets from non-local IPs)
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.eth1.rp_filter = 0
net.ipv4.conf.eth0.rp_filter = 0

# Accept packets with non-local source IP
net.ipv4.conf.all.accept_local = 1
net.ipv4.conf.eth1.accept_local = 1
net.ipv4.conf.eth0.accept_local = 1

# Allow source routing (may be needed for some spoofed packets)
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.eth1.accept_source_route = 1

# Disable martian logging (spoofed IPs would be logged as martians)
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.eth1.log_martians = 0

# Disable iptables on raw sockets (allow raw socket operations)
net.ipv4.conf.all.secure_redirects = 0

# IPv6: disable router-advertisement-driven autoconf and accept
# our static ULA. With autoconf=on the kernel could decide to
# replace fd99::xx with a SLAAC-derived address.
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.eth1.disable_ipv6 = 0
net.ipv6.conf.eth1.accept_ra = 0
net.ipv6.conf.eth1.autoconf = 0
EOF
sysctl -p /etc/sysctl.d/99-quiccochet.conf > /dev/null 2>&1

# ── add the v6 ULA address on top of the v4 private LAN (eth1) ──
# Vagrant-libvirt 0.12.2 cannot assign v6 directly via Vagrant
# `private_network, ip:` (it tries to compute the netmask as v4
# and crashes). Layer the ULA onto the existing v4 NIC instead;
# both families end up on the same L2 segment.
if [ -n "${VM_IPV6:-}" ]; then
  ip -6 addr replace "${VM_IPV6}/64" dev eth1
  # Persist across reboots via a tiny systemd one-shot.
  cat > /etc/systemd/system/quiccochet-v6-addr.service << EOF
[Unit]
Description=QUICochet test e2e: persistent v6 ULA on eth1
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip -6 addr replace ${VM_IPV6}/64 dev eth1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now quiccochet-v6-addr.service > /dev/null 2>&1 || true
  echo "v6 ULA configured: $(ip -6 addr show dev eth1 | grep inet6 | head -2)"
fi

echo "=== common provisioning done ==="
