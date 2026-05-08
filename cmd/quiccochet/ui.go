package main

import (
	"github.com/spf13/cobra"

	"github.com/pechenyeru/quiccochet/internal/tui"
)

var uiSocket string

// uiCmd launches the interactive admin TUI. It's intentionally
// non-root: the daemon does the privileged work, the TUI only reads
// admin.sock and the config JSON. Operators can run it from a regular
// shell while the daemon runs under systemd.
var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the interactive admin TUI",
	Long: `Open the QUICochet admin TUI: a tabbed terminal dashboard
for inspecting daemon status, browsing live stats, and (in later
stages) editing configuration files.

The TUI talks to a running daemon through its admin Unix socket.
Either pass --socket explicitly, or point -c at the same config file
the daemon was started with — the TUI reads admin.socket from there.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := tui.Options{
			SocketPath: uiSocket,
			ConfigPath: ConfigFile,
			Build: tui.BuildInfo{
				Version:   Version,
				Commit:    Commit,
				BuildTime: BuildTime,
			},
		}
		if opts.SocketPath == "" && ConfigFile != "" {
			opts.SocketPath = readAdminSocketFromConfig(ConfigFile)
		}
		return tui.Run(opts)
	},
}

func init() {
	uiCmd.Flags().StringVarP(&uiSocket, "socket", "s", "", "admin socket path (overrides config)")
	uiCmd.SilenceUsage = true
	mainCmd.AddCommand(uiCmd)
}
