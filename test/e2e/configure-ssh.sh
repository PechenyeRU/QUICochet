#!/usr/bin/env bash
# Configure SSH keys for passwordless SSH between VMs.
# Run this from the test/e2e directory on the host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
SERVER_IP="192.168.56.10"

# Check if SSH key exists
if [ ! -f "$KEYS_DIR/server_vagrant_key" ]; then
  echo "ERROR: SSH key not found at $KEYS_DIR/server_vagrant_key"
  echo "Run ./setup-keys.sh first"
  exit 1
fi

# Get the public key
SERVER_PUB_KEY=$(ssh-keygen -y -f "$KEYS_DIR/server_vagrant_key" 2>/dev/null)

if [ -z "$SERVER_PUB_KEY" ]; then
  echo "ERROR: Could not generate public key from private key"
  exit 1
fi

echo "=== configuring SSH key on server VM ==="

# Add public key to server's authorized_keys
vagrant ssh server -c "
  mkdir -p /home/vagrant/.ssh
  chmod 700 /home/vagrant/.ssh
  echo '$SERVER_PUB_KEY' >> /home/vagrant/.ssh/authorized_keys
  chmod 600 /home/vagrant/.ssh/authorized_keys
  chown -R vagrant:vagrant /home/vagrant/.ssh
  echo 'SSH key added to authorized_keys'
" 2>&1 | grep -v "^Connection\|^Disconnected"

# Set correct permissions on client
echo "=== setting SSH key permissions on client VM ==="
vagrant ssh client -c "
  chmod 600 /vagrant/keys/server_vagrant_key
  chown vagrant:vagrant /vagrant/keys/server_vagrant_key 2>/dev/null || true
  echo 'SSH key permissions set'
" 2>&1 | grep -v "^Connection\|^Disconnected"

echo ""
echo "=== done ==="
echo "you can now run: vagrant ssh client -c \"sudo bash /vagrant/bench.sh\""