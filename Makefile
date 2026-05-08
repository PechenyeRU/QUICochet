# QUICochet — top-level Makefile.
# Keep targets thin: real logic lives in scripts so CI and ad-hoc
# shell invocations stay equivalent.

.PHONY: build test vet tui-eval

build:
	go build -o quiccochet ./cmd/quiccochet/

test:
	go test ./internal/... -count=1

vet:
	go vet ./...

# tui-eval records GIFs/PNGs of the admin TUI against a deterministic
# fake-admin fixture. Output lands in /tmp/quiccochet-tui-eval/.
# See test/tui/README.md for prerequisites (vhs + ffmpeg + ttyd).
tui-eval:
	test/tui/run-eval.sh
