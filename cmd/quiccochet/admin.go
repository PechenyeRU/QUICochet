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
	Use:   "bench <latency|throughput> [duration] [parallel]",
	Short: "Run an in-link benchmark over the live tunnel",
	Long: `Run latency or throughput benchmark over a dedicated QUIC stream on the live tunnel.

parallel is only used for throughput; it fans out over N concurrent
streams so the benchmark can saturate the pool. When omitted, the
daemon uses its own quic.pool_size as the default.`,
	Args: cobra.RangeArgs(1, 3),
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
		if len(args) >= 3 {
			var n int
			if _, err := fmt.Sscanf(args[2], "%d", &n); err != nil || n < 1 {
				return fmt.Errorf("invalid parallel %q: must be a positive integer", args[2])
			}
			cmdLine = fmt.Sprintf("%s %d", cmdLine, n)
		}
		resp, err := sendAdminCmd(sock, cmdLine, dur+30*time.Second)
		if err != nil {
			return err
		}
		return renderBench(resp)
	},
}

var adminPprofCmd = &cobra.Command{
	Use:   "pprof <start|stop|status> [addr]",
	Short: "Toggle the pprof HTTP endpoint on the live daemon",
	Long: `Start or stop an on-demand pprof HTTP endpoint on the running daemon.

When stopped, there is zero runtime overhead — Go's built-in heap
sampler is always active, so a profile captured right after start
reflects the process' full lifetime.

Default addr is 127.0.0.1:6060 (loopback only). After start you can
capture profiles with, e.g.:
  go tool pprof http://127.0.0.1:6060/debug/pprof/heap`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sock, err := resolveAdminSocket()
		if err != nil {
			return err
		}
		cmdLine := "pprof " + strings.Join(args, " ")
		resp, err := sendAdminCmd(sock, cmdLine, 10*time.Second)
		if err != nil {
			return err
		}
		return renderPprof(resp)
	},
}

func init() {
	adminCmd.PersistentFlags().StringVarP(&adminSocketPath, "socket", "s", "", "admin socket path (overrides config)")
	adminCmd.PersistentFlags().BoolVarP(&adminHuman, "human", "H", false, "human-readable output instead of JSON")
	// Cobra doesn't propagate SilenceUsage from parent to subcommands,
	// so set it on each leaf. Errors remain visible via cobra's "Error:"
	// prefix; we only drop the noisy usage block on failures.
	for _, c := range []*cobra.Command{adminCmd, adminStatsCmd, adminBenchCmd, adminPprofCmd} {
		c.SilenceUsage = true
	}
	adminCmd.AddCommand(adminStatsCmd, adminBenchCmd, adminPprofCmd)
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
		streams := res.Streams
		if streams <= 0 {
			streams = 1
		}
		fmt.Printf("%s throughput  %s in %.2fs  rate %s/s (%s)  × %d streams\n",
			green("▶"),
			humanBytes(res.Bytes), res.DurationSec,
			humanBytes(uint64(res.BytesPerSec)),
			humanBits(res.BytesPerSec*8),
			streams)
	default:
		fmt.Println(resp)
	}
	return nil
}

func renderPprof(resp string) error {
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
	var st admin.PprofStatus
	if err := json.Unmarshal([]byte(resp), &st); err != nil {
		fmt.Println(resp)
		return nil
	}
	if st.Running {
		fmt.Printf("%s pprof  running at %s\n", green("▶"), st.Address)
		fmt.Printf("    go tool pprof http://%s/debug/pprof/heap\n", st.Address)
	} else {
		fmt.Printf("%s pprof  not running\n", green("▶"))
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
