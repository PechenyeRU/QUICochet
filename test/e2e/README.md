# End-to-End Tests

Vagrant-based e2e benchmark environment for QUICochet.
Two libvirt/KVM VMs on a private network with **real IP spoofing**.

## Network Layout

```
+--------------------------+         +--------------------------+
|  client                  |         |  server                  |
|  real v4: 192.168.56.11  | <-----> |  real v4: 192.168.56.10  |
|  real v6: fd99::11       |   LAN   |  real v6: fd99::10       |
|  spoof v4: 10.99.0.11    |         |  spoof v4: 10.99.0.10    |
|  spoof v6: fd99::11:1    |         |  spoof v6: fd99::10:1    |
|  SOCKS5: 127.0.0.1:1080  |         |  iperf3: :5201           |
|                          |         |  tunnel: :8080           |
+--------------------------+         +--------------------------+
```

Tunnel packets use fake source IPs that are not assigned to any
interface, exercising the raw socket spoofing path. Both v4 (`10.99.0.x`)
and v6 (`fd99::x:1`) spoof addresses are pre-provisioned; flip between
stacks at runtime with `./switch-stack.sh v4|v6|dual`.

## Requirements

- [Vagrant](https://www.vagrantup.com/) >= 2.4
- [libvirt](https://libvirt.org/) + KVM
- `vagrant-libvirt` plugin: `vagrant plugin install vagrant-libvirt`
- Go (on the host, for key generation)

## Quick Start

```bash
cd test/e2e

# 1. generate crypto keypairs (once)
./setup-keys.sh

# 2. create and provision the VMs
vagrant up

# 3. run the benchmark (default transport: udp)
vagrant ssh client -c "sudo bash /vagrant/bench.sh"
```

## Deploying Code Changes

After editing source code, push it to the VMs without recreating them:

```bash
./deploy.sh
```

This rsyncs the source, rebuilds the binary on both VMs, and restarts
the tunnel services. Then re-run the benchmark to measure the impact.

## Switching Transport Types

The tunnel supports four transport types: `udp`, `icmp`, `raw`, `syn_udp`.
To switch transport on both VMs and restart:

```bash
# switch to ICMP transport
./switch-transport.sh icmp

# run benchmark
vagrant ssh client -c "sudo bash /vagrant/bench.sh"

# switch back to UDP
./switch-transport.sh udp
```

The script updates `/etc/quiccochet/config.json` on both VMs and
restarts the tunnel services. The bench script prints the current
transport type at the top of its output.

## Switching IP Stack (v4 / v6 / dual)

Provisioning writes three sibling configs (`config-v4.json`,
`config-v6.json`, `config-dual.json`) and symlinks `config.json` to
the v4 one. To flip the active stack on both VMs:

```bash
# v4 only (legacy default)
./switch-stack.sh v4

# v6 single-stack — server bound on [::]:8080, spoof IPs in fd99::/64
./switch-stack.sh v6

# dual-stack — single recv socket on [::] with V6ONLY=0, both
# v4-mapped and native v6 traffic land on the same loop, send picks
# the family by destination
./switch-stack.sh dual
```

The bench script logs which stack is active at the top of its output,
so a v4 vs v6 vs dual run can be compared directly.

**Note**: only the `udp` transport supports dual-stack on a single
recv socket today; `icmp`, `raw`, and `syn_udp` are single-stack
(IPv4 OR IPv6, configured via which `source_ip` / `source_ipv6` is
set). For those transports the `switch-stack.sh dual` config still
loads but only one family is active per transport.

## Network Impairment Testing

Simulate real-world network conditions (delay, packet loss, bandwidth limit)
using `tc` (traffic control):

```bash
# apply a preset profile
./impair.sh wan        # 50ms RTT, 1% loss, 100 Mbps
./impair.sh harsh      # 200ms RTT, 5% loss, 50 Mbps
./impair.sh lossy      # 10ms RTT, 10% loss, no bw limit
./impair.sh slow       # 20ms RTT, 0.5% loss, 10 Mbps
./impair.sh satellite  # 600ms RTT, 2% loss, 20 Mbps

# run benchmark under impairment
vagrant ssh client -c "sudo bash /vagrant/bench.sh"

# remove all impairments
./impair.sh clear
```

Impairments are applied symmetrically on both VMs (eth1 interface).

## Scripts

| File | Purpose |
|------|---------|
| `setup-keys.sh` | Generate X25519 keypairs in `./keys/` |
| `deploy.sh` | Rsync + rebuild + restart on both VMs |
| `switch-transport.sh` | Switch transport type (udp/icmp/raw/syn_udp) on both VMs |
| `switch-stack.sh` | Switch IP stack (v4 / v6 / dual) on both VMs by symlinking the matching `config-*.json` |
| `impair.sh` | Apply/clear network impairments (delay, loss, bandwidth) |
| `bench.sh` | Run iperf3 benchmark (direct + tunnel download + tunnel upload) |
| `provision-common.sh` | Install Go, build binary, verify keys |
| `provision-server.sh` | Generate server configs (v4 / v6 / dual), start quiccochet-server + iperf3 |
| `provision-client.sh` | Generate client configs (v4 / v6 / dual), start quiccochet-client |

## Configuration

The Vagrantfile defines all IPs at the top. To change them, edit:

```ruby
SERVER_IP         = "192.168.56.10"
CLIENT_IP         = "192.168.56.11"
SERVER_SPOOF_IP   = "10.99.0.10"
CLIENT_SPOOF_IP   = "10.99.0.11"
SERVER_IPV6       = "fd99::10"
CLIENT_IPV6       = "fd99::11"
SERVER_SPOOF_IPV6 = "fd99::10:1"
CLIENT_SPOOF_IPV6 = "fd99::11:1"
```

Tunnel configs are generated by the provision scripts as three
sibling files in `/etc/quiccochet/` (`config-v4.json`, `config-v6.json`,
`config-dual.json`); the active one is selected by the symlink
`/etc/quiccochet/config.json`. `switch-stack.sh` flips the symlink and
restarts the service.

## Troubleshooting

```bash
# check service status
vagrant ssh server -c "sudo systemctl status quiccochet-server"
vagrant ssh client -c "sudo systemctl status quiccochet-client"

# check logs
vagrant ssh server -c "sudo tail -30 /var/log/quiccochet-server.log"
vagrant ssh client -c "sudo tail -30 /var/log/quiccochet-client.log"

# verify spoofing with tcpdump
vagrant ssh server -c "sudo tcpdump -i eth1 -n 'udp port 8080' -c 10"

# full teardown
vagrant destroy -f
rm -rf keys/
```
