# TUI evaluation harness

Records the QUICochet TUI against a deterministic fixture so the
output is reproducible across machines. The recordings (GIF + PNG)
land in `/tmp/quiccochet-tui-eval/` for visual review.

## Quick start

```bash
make tui-eval
```

Then open the GIFs in `/tmp/quiccochet-tui-eval/`:

- `home.gif` — Home tab with daemon-alive badge and quick actions
- `dashboard.gif` — Live stats with spoof-IP health digest
- `wizard.gif` — Config wizard (mode → transport → server → spoof → crypto)
- Plus a `*.png` snapshot of each one for static inspection

## Prerequisites

- Go 1.25+
- [`vhs`](https://github.com/charmbracelet/vhs):
  ```bash
  go install github.com/charmbracelet/vhs@latest
  ```
- `ffmpeg` and `ttyd` in `PATH` (vhs uses them as recording backends).
  Fedora: `sudo dnf install ffmpeg ttyd`.

## How it works

`run-eval.sh`:

1. Builds the TUI binary at `/tmp/quiccochet-tui-bin`.
2. Launches `fixtures/fake-admin.go`, a stdlib-only Unix-socket server
   that answers `stats\n` with a canned `admin.Snapshot` (8/8 pool,
   3 spoof IPs with one quarantined, ~3h uptime). This lets us record
   "live data" GIFs without a real QUIC tunnel.
3. Runs `vhs` against every `.tape` file in `tapes/`. Each tape drives
   the binary through a scripted scenario (keypresses + sleeps) and
   emits both the GIF (motion) and a PNG (final frame).
4. Cleans up the fake-admin socket on exit.

## Adding a new scenario

Drop a `.tape` file into `tapes/`. The vhs DSL is documented at
https://github.com/charmbracelet/vhs#configuration. Keep a fixed
`Width` / `Height` / `FontSize` across tapes so reviewers don't have
to re-zoom every recording.

## Troubleshooting

- **`vhs: command not found`** — install vhs (see prerequisites). The
  script checks for it up-front and prints an install hint.
- **Stale `/tmp/quiccochet-fake.sock`** — `run-eval.sh` removes it on
  exit; if it crashed mid-run, delete the file by hand and rerun.
