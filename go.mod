module github.com/pechenyeru/quiccochet

go 1.25.0

require (
	github.com/fatih/color v1.19.0
	github.com/quic-go/quic-go v0.59.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.50.0
	golang.org/x/net v0.53.0
	golang.org/x/sys v0.43.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
)

// Local patched fork of qiulaidongfeng/quic-go with packetThreshold raised
// from 3 to 32 to tolerate jitter-induced reorder on real WAN paths.
// Original upstream commit: v0.0.0-20260307044114-6af2880cfb81
// The patch is in third_party/quic-go — inspect with git diff against upstream.
replace github.com/quic-go/quic-go => ./third_party/quic-go
