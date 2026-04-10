#!/usr/bin/env bash
# Generate keypairs on the HOST before vagrant up.
# Keys are placed in ./keys/ which gets rsynced into both VMs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
PROJECT_ROOT="$SCRIPT_DIR/../.."

mkdir -p "$KEYS_DIR"

if [ -f "$KEYS_DIR/server.key" ] && [ -f "$KEYS_DIR/client.key" ]; then
  echo "keys already exist in $KEYS_DIR, skipping"
  exit 0
fi

echo "generating keypairs..."

cat > /tmp/quiccochet-keygen.go << 'GOEOF'
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: keygen <dir> <name>\n")
		os.Exit(1)
	}
	dir, name := os.Args[1], os.Args[2]

	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		fmt.Fprintf(os.Stderr, "rand: %v\n", err)
		os.Exit(1)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)

	os.WriteFile(dir+"/"+name+".key", []byte(base64.StdEncoding.EncodeToString(priv[:])), 0600)
	os.WriteFile(dir+"/"+name+".pub", []byte(base64.StdEncoding.EncodeToString(pub[:])), 0644)
	fmt.Printf("generated: %s/%s.{key,pub}\n", dir, name)
}
GOEOF

cd "$PROJECT_ROOT"
go run /tmp/quiccochet-keygen.go "$KEYS_DIR" server
go run /tmp/quiccochet-keygen.go "$KEYS_DIR" client
rm -f /tmp/quiccochet-keygen.go

echo "done. keys in $KEYS_DIR:"
ls -la "$KEYS_DIR"
