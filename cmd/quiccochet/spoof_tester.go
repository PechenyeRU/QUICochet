package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pechenyeru/quiccochet/internal/spooftester"
	"github.com/spf13/cobra"
)

var (
	stListPath   string
	stProto      string
	stDst        string
	stPort       uint16
	stPerIP      int
	stRate       int
	stRunID      uint16
	stOutputFmt  string
	stListenPort uint16
	stDuration   time.Duration
	stMinPackets int
	stAllowLarge bool
)

var spoofTesterCmd = &cobra.Command{
	Use:   "spoof-tester",
	Short: "Probe which spoof source IPs actually leave the local network",
	Long: `Test which candidate source IPs are spoofable from this vantage
point and arrive at a remote receiver. Run on the local machine in
'sender' mode and on the remote box in 'receiver' mode using the same
--proto and --run-id (any non-zero uint16).

Pipe receiver's --output json into a file and use the resulting list as
spoof.source_ips in your client config.`,
}

var spoofTesterSenderCmd = &cobra.Command{
	Use:   "sender",
	Short: "Send probes from each candidate source IP",
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("spoof-tester sender requires root (CAP_NET_RAW)")
		}
		proto, err := spooftester.ParseProto(stProto)
		if err != nil {
			return err
		}
		dst, err := netip.ParseAddr(stDst)
		if err != nil {
			return fmt.Errorf("--dst: %w", err)
		}
		ips, err := spooftester.ParseIPListWithOpts(stListPath, spooftester.ParseOpts{AllowLarge: stAllowLarge})
		if err != nil {
			return fmt.Errorf("--src-list: %w", err)
		}
		runID := stRunID
		if runID == 0 {
			r, rerr := spooftester.NewRunID()
			if rerr != nil {
				return fmt.Errorf("generate run-id: %w", rerr)
			}
			runID = r
		}
		intervalMs := 0
		if stRate > 0 {
			intervalMs = max(1, 1000/stRate)
		}

		fmt.Printf("spoof-tester sender\n")
		fmt.Printf("  proto       %s\n", proto)
		fmt.Printf("  dst         %s:%d\n", dst, stPort)
		fmt.Printf("  candidates  %d (from %s)\n", len(ips), stListPath)
		fmt.Printf("  per-ip      %d\n", stPerIP)
		fmt.Printf("  rate        %d pps (gap %d ms)\n", stRate, intervalMs)
		fmt.Printf("  run-id      0x%04x  ← share with receiver via --run-id\n", runID)
		fmt.Println()

		s, _, err := spooftester.NewSender(spooftester.SenderConfig{
			Proto:      proto,
			SrcList:    ips,
			Dst:        dst,
			DstPort:    stPort,
			PerIP:      stPerIP,
			IntervalMs: intervalMs,
			RunID:      runID,
		})
		if err != nil {
			return err
		}
		defer s.Close()

		start := time.Now()
		err = s.Run(func(sent, total uint64) {
			fmt.Fprintf(os.Stderr, "\r  progress    %d / %d (%.0f%%)", sent, total, float64(sent)*100/float64(total))
		})
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Printf("done in %s\n", time.Since(start).Round(time.Millisecond))
		return nil
	},
}

var spoofTesterReceiverCmd = &cobra.Command{
	Use:   "receiver",
	Short: "Listen for probes and report which src IPs arrived",
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("spoof-tester receiver requires root (CAP_NET_RAW)")
		}
		proto, err := spooftester.ParseProto(stProto)
		if err != nil {
			return err
		}
		var expected []netip.Addr
		if stListPath != "" {
			expected, err = spooftester.ParseIPListWithOpts(stListPath, spooftester.ParseOpts{AllowLarge: stAllowLarge})
			if err != nil {
				return fmt.Errorf("--src-list: %w", err)
			}
		}
		switch stOutputFmt {
		case "text", "json":
		default:
			return fmt.Errorf("--output: want text|json, got %q", stOutputFmt)
		}

		fmt.Fprintf(os.Stderr, "spoof-tester receiver\n")
		fmt.Fprintf(os.Stderr, "  proto       %s\n", proto)
		if proto == spooftester.ProtoTCP || proto == spooftester.ProtoUDP {
			fmt.Fprintf(os.Stderr, "  listen      :%d\n", stListenPort)
		}
		fmt.Fprintf(os.Stderr, "  expected    %d src IPs\n", len(expected))
		if stDuration > 0 {
			fmt.Fprintf(os.Stderr, "  duration    %s\n", stDuration)
		} else {
			fmt.Fprintf(os.Stderr, "  duration    indefinite (Ctrl+C to stop and print results)\n")
		}
		fmt.Fprintf(os.Stderr, "  min-pkts    %d (per src to count as pass)\n", stMinPackets)
		fmt.Fprintf(os.Stderr, "  run-id      0x%04x (0 = accept any)\n", stRunID)
		fmt.Fprintln(os.Stderr)

		r, err := spooftester.NewReceiver(spooftester.ReceiverConfig{
			Proto:      proto,
			ListenPort: stListenPort,
			Expected:   expected,
			RunID:      stRunID,
			Duration:   stDuration,
			MinPackets: stMinPackets,
		})
		if err != nil {
			return err
		}
		defer r.Close()

		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		if err := r.Run(ctx); err != nil {
			return err
		}
		res := r.Summary()
		return printResult(res, stOutputFmt)
	},
}

func printResult(res spooftester.Result, format string) error {
	switch format {
	case "json":
		passList := make([]string, 0, len(res.Pass))
		for _, ip := range res.Pass {
			passList = append(passList, ip.String())
		}
		out := map[string]any{
			"proto":      string(res.Proto),
			"run_id":     fmt.Sprintf("0x%04x", res.RunID),
			"pass":       passList,
			"fail":       toStringSlice(res.Fail),
			"unknown":    toStringSlice(res.Unknown),
			"per_src":    toPerSrcSlice(res.PerSrc),
			"packets":    res.Packets,
			"dropped":    res.Dropped,
			"duration_s": int(res.Duration.Seconds()),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	default:
		printTextResult(res)
		return nil
	}
}

func printTextResult(res spooftester.Result) {
	fmt.Printf("\n=== spoof-tester results ===\n")
	fmt.Printf("proto: %s   run-id: 0x%04x   duration: %s\n", res.Proto, res.RunID, res.Duration)
	fmt.Printf("packets seen: %d   matching-magic dropped: %d\n\n", res.Packets, res.Dropped)

	if len(res.PerSrc) == 0 {
		fmt.Println("(no spoof-tester packets observed)")
		return
	}
	fmt.Printf("%-40s  %-8s  %s\n", "src ip", "count", "first → last")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range res.PerSrc {
		fmt.Printf("%-40s  %-8d  %s → %s\n",
			e.IP.String(), e.Count,
			e.First.Format("15:04:05.000"),
			e.Last.Format("15:04:05.000"))
	}

	if len(res.Pass)+len(res.Fail) > 0 {
		fmt.Printf("\nPass (count >= %d): %d\n", 1, len(res.Pass))
		for _, ip := range res.Pass {
			fmt.Printf("  ✓ %s\n", ip)
		}
		fmt.Printf("Fail (expected, missing or below threshold): %d\n", len(res.Fail))
		for _, ip := range res.Fail {
			fmt.Printf("  ✗ %s\n", ip)
		}
	}
	if len(res.Unknown) > 0 {
		fmt.Printf("Unknown (received, not in --src-list): %d\n", len(res.Unknown))
		for _, ip := range res.Unknown {
			fmt.Printf("  ? %s\n", ip)
		}
	}
}

func toStringSlice(in []netip.Addr) []string {
	out := make([]string, len(in))
	for i, ip := range in {
		out[i] = ip.String()
	}
	return out
}

func toPerSrcSlice(in []spooftester.PerSrc) []map[string]any {
	out := make([]map[string]any, len(in))
	for i, e := range in {
		out[i] = map[string]any{
			"ip":    e.IP.String(),
			"count": e.Count,
			"first": e.First.UTC().Format(time.RFC3339Nano),
			"last":  e.Last.UTC().Format(time.RFC3339Nano),
		}
	}
	return out
}

func init() {
	// shared
	for _, c := range []*cobra.Command{spoofTesterSenderCmd, spoofTesterReceiverCmd} {
		c.Flags().StringVar(&stProto, "proto", "tcp", "tcp|udp|icmp|icmpv6")
		c.Flags().Uint16Var(&stRunID, "run-id", 0, "shared run-id (uint16); sender generates a fresh one if 0")
		c.Flags().BoolVar(&stAllowLarge, "allow-large-list", false,
			"bypass the 65k-entry safety cap on CIDR/range expansion (e.g. /0); a warning is printed and memory use is on you")
	}
	// sender flags
	spoofTesterSenderCmd.Flags().StringVar(&stListPath, "src-list", "", "path to candidate IP list (single, CIDR, range)")
	spoofTesterSenderCmd.Flags().StringVar(&stDst, "dst", "", "destination IP")
	spoofTesterSenderCmd.Flags().Uint16Var(&stPort, "dst-port", 443, "destination port (TCP/UDP)")
	spoofTesterSenderCmd.Flags().IntVar(&stPerIP, "per-ip", 5, "packets per source IP")
	spoofTesterSenderCmd.Flags().IntVar(&stRate, "rate", 50, "send rate, packets per second (default 50 = 20 ms gap)")
	_ = spoofTesterSenderCmd.MarkFlagRequired("src-list")
	_ = spoofTesterSenderCmd.MarkFlagRequired("dst")

	// receiver flags
	spoofTesterReceiverCmd.Flags().StringVar(&stListPath, "src-list", "", "expected candidate IP list (used to compute pass/fail)")
	spoofTesterReceiverCmd.Flags().Uint16Var(&stListenPort, "listen-port", 443, "L4 dst port to filter (TCP/UDP)")
	spoofTesterReceiverCmd.Flags().DurationVar(&stDuration, "duration", 0,
		"how long to listen; 0 (default) = listen until Ctrl+C and print results on exit")
	spoofTesterReceiverCmd.Flags().IntVar(&stMinPackets, "min-packets", 1, "packets a src IP needs to qualify as pass")
	spoofTesterReceiverCmd.Flags().StringVar(&stOutputFmt, "output", "text", "text|json (json is paste-able as spoof.source_ips)")

	spoofTesterCmd.AddCommand(spoofTesterSenderCmd)
	spoofTesterCmd.AddCommand(spoofTesterReceiverCmd)
	mainCmd.AddCommand(spoofTesterCmd)
}
