package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pechenyeru/quiccochet/internal/admin"
	"github.com/spf13/cobra"
)

var (
	adminSocketPath string
	adminHuman      bool
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Interact with a running quiccochet daemon via unix socket",
}

var adminStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Dump current tunnel statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		sock, err := resolveAdminSocket()
		if err != nil {
			return err
		}
		resp, err := sendAdminCmd(sock, "stats", 10*time.Second)
		if err != nil {
			return err
		}
		return renderStats(resp)
	},
}

var adminBenchCmd = &cobra.Command{
	Use:   "bench <latency|throughput> [duration]",
	Short: "Run an in-link benchmark over the live tunnel",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sock, err := resolveAdminSocket()
		if err != nil {
			return err
		}
		dur := 5 * time.Second
		if len(args) >= 2 {
			d, err := time.ParseDuration(args[1])
			if err != nil || d <= 0 {
				return fmt.Errorf("invalid duration %q: %v", args[1], err)
			}
			dur = d
		}
		cmdLine := fmt.Sprintf("bench %s %s", args[0], dur)
		resp, err := sendAdminCmd(sock, cmdLine, dur+30*time.Second)
		if err != nil {
			return err
		}
		return renderBench(resp)
	},
}

func init() {
	adminCmd.PersistentFlags().StringVarP(&adminSocketPath, "socket", "s", "", "admin socket path (overrides config)")
	adminCmd.PersistentFlags().BoolVarP(&adminHuman, "human", "H", false, "human-readable output instead of JSON")
	// Cobra doesn't propagate SilenceUsage from parent to subcommands,
	// so set it on each leaf. Errors remain visible via cobra's "Error:"
	// prefix; we only drop the noisy usage block on failures.
	for _, c := range []*cobra.Command{adminCmd, adminStatsCmd, adminBenchCmd} {
		c.SilenceUsage = true
	}
	adminCmd.AddCommand(adminStatsCmd, adminBenchCmd)
	mainCmd.AddCommand(adminCmd)
}

// resolveAdminSocket returns the socket path to dial. Precedence:
// explicit -s/--socket, then admin.socket from -c config file (via a
// shallow JSON decode that skips full validation), else error.
func resolveAdminSocket() (string, error) {
	if adminSocketPath != "" {
		return adminSocketPath, nil
	}
	if ConfigFile != "" {
		if sock := readAdminSocketFromConfig(ConfigFile); sock != "" {
			return sock, nil
		}
	}
	return "", fmt.Errorf("admin socket path not set: pass --socket/-s or set admin.socket in the config file")
}

func readAdminSocketFromConfig(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var partial struct {
		Admin struct {
			Socket string `json:"socket"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(data, &partial); err != nil {
		return ""
	}
	return partial.Admin.Socket
}

func sendAdminCmd(path, cmd string, readTimeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial admin socket %q: %w", path, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	if _, err := fmt.Fprintln(conn, cmd); err != nil {
		return "", fmt.Errorf("write command: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func renderStats(resp string) error {
	if !adminHuman {
		fmt.Println(resp)
		return nil
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp), &errResp); err == nil && errResp.Error != "" {
		// Let cobra's "Error:" prefix handle the surface text; returning
		// the error is enough to get a non-zero exit.
		return fmt.Errorf("%s", errResp.Error)
	}
	var snap admin.Snapshot
	if err := json.Unmarshal([]byte(resp), &snap); err != nil {
		fmt.Println(resp)
		return nil
	}
	var parts []string
	switch snap.Role {
	case "client":
		parts = []string{
			fmt.Sprintf("pool %d/%d", snap.PoolAlive, snap.PoolTotal),
			fmt.Sprintf("sent %s", humanBytes(snap.BytesSent)),
			fmt.Sprintf("recv %s", humanBytes(snap.BytesReceived)),
			fmt.Sprintf("udp_assocs %d", snap.UDPAssocs),
			fmt.Sprintf("fds %d", snap.OpenFDs),
			fmt.Sprintf("up %s", humanUptime(snap.UptimeSec)),
		}
	case "server":
		parts = []string{
			fmt.Sprintf("sessions %d", snap.ActiveSessions),
			fmt.Sprintf("sent %s", humanBytes(snap.BytesSent)),
			fmt.Sprintf("recv %s", humanBytes(snap.BytesReceived)),
			fmt.Sprintf("udp_routes %d", snap.UDPRoutes),
			fmt.Sprintf("fds %d", snap.OpenFDs),
			fmt.Sprintf("up %s", humanUptime(snap.UptimeSec)),
		}
	default:
		fmt.Println(resp)
		return nil
	}
	fmt.Printf("%s %s\n", green("▶"), strings.Join(parts, "  "))
	return nil
}

func renderBench(resp string) error {
	if !adminHuman {
		fmt.Println(resp)
		return nil
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp), &errResp); err == nil && errResp.Error != "" {
		return fmt.Errorf("%s", errResp.Error)
	}
	var res admin.BenchResult
	if err := json.Unmarshal([]byte(resp), &res); err != nil {
		fmt.Println(resp)
		return nil
	}
	switch res.Mode {
	case "latency":
		fmt.Printf("%s latency  samples %d  p50 %s  p90 %s  p99 %s  mean %s  min %s  max %s\n",
			green("▶"),
			res.Samples,
			humanDur(res.P50Ns), humanDur(res.P90Ns), humanDur(res.P99Ns),
			humanDur(res.MeanNs), humanDur(res.MinNs), humanDur(res.MaxNs))
	case "throughput":
		fmt.Printf("%s throughput  %s in %.2fs  rate %s/s\n",
			green("▶"),
			humanBytes(res.Bytes), res.DurationSec,
			humanBytes(uint64(res.BytesPerSec)))
	default:
		fmt.Println(resp)
	}
	return nil
}

func humanDur(ns int64) string {
	d := time.Duration(ns)
	switch {
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", ns)
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.2fs", float64(d)/float64(time.Second))
	}
}

func humanUptime(sec float64) string {
	d := time.Duration(sec * float64(time.Second))
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", sec)
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", sec/60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1fh", sec/3600)
	default:
		return fmt.Sprintf("%.1fd", sec/86400)
	}
}
