module github.com/pechenyeru/quiccochet

go 1.25.8

require (
	github.com/fatih/color v1.19.0
	github.com/quic-go/quic-go v0.59.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.50.0
	golang.org/x/net v0.53.0
	golang.org/x/sys v0.43.0
)

require (
	charm.land/bubbles/v2 v2.1.0 // indirect
	charm.land/bubbletea/v2 v2.0.6 // indirect
	charm.land/huh/v2 v2.0.3 // indirect
	charm.land/lipgloss/v2 v2.0.3 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/catppuccin/go v0.2.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260416155717-489999b90468 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/exp/ordered v0.1.0 // indirect
	github.com/charmbracelet/x/exp/strings v0.0.0-20240722160745-212f7b056ed0 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/sync v0.20.0 // indirect
)

// Local patched fork of qiulaidongfeng/quic-go with packetThreshold raised
// from 3 to 32 to tolerate jitter-induced reorder on real WAN paths.
// Original upstream commit: v0.0.0-20260307044114-6af2880cfb81
// The patch is in third_party/quic-go — inspect with git diff against upstream.
replace github.com/quic-go/quic-go => ./third_party/quic-go
