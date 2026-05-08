#!/usr/bin/env bash
# run-eval.sh — build the TUI, spin up the fake-admin fixture, run vhs
# against every tape file, and drop the resulting GIFs/PNGs into a
# scratch directory the operator (or a CI artifact uploader) can grab.
#
# Run with:
#   make tui-eval
# or directly:
#   test/tui/run-eval.sh
set -euo pipefail

OUT=${TUI_EVAL_OUT:-/tmp/quiccochet-tui-eval}
SOCK=${TUI_EVAL_SOCK:-/tmp/quiccochet-fake.sock}
BIN=${TUI_EVAL_BIN:-/tmp/quiccochet-tui-bin}

if ! command -v vhs >/dev/null 2>&1; then
  cat >&2 <<EOF
error: vhs not installed.

Install with:
  go install github.com/charmbracelet/vhs@latest

vhs also needs ffmpeg + ttyd in PATH. On Fedora:
  sudo dnf install ffmpeg ttyd
EOF
  exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/*.gif "$OUT"/*.png || true

echo "==> building TUI binary -> $BIN"
go build -o "$BIN" ./cmd/quiccochet/

echo "==> launching fake-admin on $SOCK"
# vhs tape recordings need deterministic output frame-to-frame, so
# the harness pins the fixture to the static (frozen-snapshot) mode.
# Interactive smoke tests get the live (sine-wave bandwidth) mode by
# launching fake-admin directly without --mode=static.
go run ./test/tui/fixtures/fake-admin.go --socket "$SOCK" --mode=static &
FAKE_PID=$!
trap 'kill -TERM $FAKE_PID 2>/dev/null || true; wait $FAKE_PID 2>/dev/null || true; rm -f "$SOCK"' EXIT
sleep 0.5

# vhs invocations require the tape file's relative path so its
# `Output` directives resolve to predictable cwd-anchored paths.
cd "$(dirname "$0")"

for tape in tapes/*.tape; do
  echo "==> vhs $tape"
  vhs "$tape"
done

echo
echo "Output written to $OUT:"
ls -1 "$OUT"
