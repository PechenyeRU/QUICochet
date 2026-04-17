package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "In-app benchmarking tools (throughput, latency)",
}

var benchServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run a TCP sink that streams random bytes on accept",
	RunE: func(cmd *cobra.Command, args []string) error {
		listen, _ := cmd.Flags().GetString("listen")
		return runBenchServe(listen)
	},
}

var benchClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Throughput / latency test through a SOCKS5 proxy",
	RunE: func(cmd *cobra.Command, args []string) error {
		socks, _ := cmd.Flags().GetString("socks5")
		target, _ := cmd.Flags().GetString("target")
		parallel, _ := cmd.Flags().GetInt("parallel")
		duration, _ := cmd.Flags().GetDuration("duration")
		mode, _ := cmd.Flags().GetString("mode")
		sample, _ := cmd.Flags().GetDuration("sample")
		return runBenchClient(socks, target, parallel, duration, mode, sample)
	},
}

func init() {
	benchServeCmd.Flags().String("listen", ":9001", "address to listen on (e.g. 0.0.0.0:9001)")

	benchClientCmd.Flags().String("socks5", "127.0.0.1:1080", "SOCKS5 proxy (host:port)")
	benchClientCmd.Flags().String("target", "", "bench server target host:port (required)")
	benchClientCmd.Flags().Int("parallel", 1, "parallel streams")
	benchClientCmd.Flags().Duration("duration", 15*time.Second, "test duration")
	benchClientCmd.Flags().String("mode", "download", "download | latency")
	benchClientCmd.Flags().Duration("sample", 1*time.Second, "per-sample interval for rate reporting")
	_ = benchClientCmd.MarkFlagRequired("target")

	benchCmd.AddCommand(benchServeCmd, benchClientCmd)
	mainCmd.AddCommand(benchCmd)
}

// ──────────── server ────────────

func runBenchServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	fmt.Printf("bench sink listening on %s\n", l.Addr())

	for {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go serveBenchConn(c)
	}
}

// Protocol (super simple, line-based on first line):
//   DOWNLOAD\n         → server streams random bytes forever
//   PING <n>\n         → server reads n bytes then writes them back (RTT test)
// Anything else → close.
func serveBenchConn(c net.Conn) {
	defer c.Close()
	_ = c.(*net.TCPConn).SetNoDelay(true)

	buf := make([]byte, 256)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	n, err := readLine(c, buf)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	cmd := string(buf[:n])

	switch {
	case cmd == "DOWNLOAD":
		serveDownload(c)
	case len(cmd) > 5 && cmd[:5] == "PING ":
		servePing(c, cmd[5:])
	}
}

func serveDownload(c net.Conn) {
	blk := make([]byte, 64*1024)
	_, _ = rand.Read(blk)
	for {
		if _, err := c.Write(blk); err != nil {
			return
		}
	}
}

func servePing(c net.Conn, nStr string) {
	var n int
	if _, err := fmt.Sscanf(nStr, "%d", &n); err != nil || n <= 0 || n > 1<<20 {
		return
	}
	buf := make([]byte, n)
	for {
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}

func readLine(c net.Conn, buf []byte) (int, error) {
	for i := 0; i < len(buf); i++ {
		if _, err := io.ReadFull(c, buf[i:i+1]); err != nil {
			return i, err
		}
		if buf[i] == '\n' {
			return i, nil
		}
	}
	return len(buf), errors.New("line too long")
}

// ──────────── client ────────────

func runBenchClient(socks, target string, parallel int, dur time.Duration, mode string, sample time.Duration) error {
	if parallel < 1 {
		parallel = 1
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	fmt.Printf("bench: socks5=%s target=%s:%s mode=%s parallel=%d duration=%s\n",
		socks, host, port, mode, parallel, dur)

	switch mode {
	case "download":
		return benchDownload(socks, target, parallel, dur, sample)
	case "latency":
		return benchLatency(socks, target, parallel, dur)
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

func benchDownload(socks, target string, parallel int, dur, sample time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	perStream := make([]uint64, parallel)
	var totalBytes atomic.Uint64
	var wg sync.WaitGroup

	start := time.Now()

	// Sampler: prints aggregate rate every `sample`.
	sampCtx, sampCancel := context.WithCancel(context.Background())
	defer sampCancel()
	go func() {
		t := time.NewTicker(sample)
		defer t.Stop()
		var last uint64
		lastT := start
		for {
			select {
			case <-sampCtx.Done():
				return
			case now := <-t.C:
				cur := totalBytes.Load()
				delta := cur - last
				dt := now.Sub(lastT).Seconds()
				last = cur
				lastT = now
				fmt.Fprintf(os.Stderr, "  [t+%4.1fs] %s\n",
					now.Sub(start).Seconds(),
					humanBits(float64(delta)/dt*8))
			}
		}
	}()

	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := socks5Dial(ctx, socks, target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[stream %d] dial err: %v\n", idx, err)
				return
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("DOWNLOAD\n")); err != nil {
				return
			}
			buf := make([]byte, 64*1024)
			for {
				if ctx.Err() != nil {
					return
				}
				n, err := conn.Read(buf)
				if n > 0 {
					totalBytes.Add(uint64(n))
					atomic.AddUint64(&perStream[idx], uint64(n))
				}
				if err != nil {
					return
				}
			}
		}(i)
	}
	wg.Wait()
	sampCancel()
	elapsed := time.Since(start)

	fmt.Println("──────── results ────────")
	fmt.Printf("duration : %s\n", elapsed.Round(100*time.Millisecond))
	fmt.Printf("total    : %s @ %s\n", humanBytes(totalBytes.Load()), humanBits(float64(totalBytes.Load())/elapsed.Seconds()*8))

	// per-stream
	fmt.Println("per-stream rates:")
	rates := make([]float64, parallel)
	for i, b := range perStream {
		r := float64(b) / elapsed.Seconds() * 8 / 1e6 // Mbps
		rates[i] = r
		fmt.Printf("  s%-2d %8.2f Mbps (%s)\n", i, r, humanBytes(b))
	}
	sort.Float64s(rates)
	if parallel >= 2 {
		fmt.Printf("min/med/max Mbps: %.2f / %.2f / %.2f  (spread %.2fx)\n",
			rates[0], rates[len(rates)/2], rates[len(rates)-1], rates[len(rates)-1]/maxFloat(rates[0], 0.001))
	}
	return nil
}

func benchLatency(socks, target string, parallel int, dur time.Duration) error {
	if parallel != 1 {
		fmt.Fprintln(os.Stderr, "latency mode forces parallel=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	conn, err := socks5Dial(ctx, socks, target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.(*net.TCPConn).SetNoDelay(true)

	const payload = 64
	if _, err := fmt.Fprintf(conn, "PING %d\n", payload); err != nil {
		return err
	}

	buf := make([]byte, payload)
	out := make([]byte, payload)
	_, _ = rand.Read(out)

	var rtts []time.Duration
	for ctx.Err() == nil {
		// encode sample index so each ping is unique
		binary.BigEndian.PutUint64(out[:8], uint64(len(rtts)))
		t0 := time.Now()
		if _, err := conn.Write(out); err != nil {
			break
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			break
		}
		rtt := time.Since(t0)
		rtts = append(rtts, rtt)
		time.Sleep(10 * time.Millisecond)
	}

	if len(rtts) == 0 {
		return errors.New("no samples collected")
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	p := func(q float64) time.Duration { return rtts[int(float64(len(rtts)-1)*q)] }
	fmt.Println("──────── latency ────────")
	fmt.Printf("samples : %d\n", len(rtts))
	fmt.Printf("min     : %s\n", rtts[0])
	fmt.Printf("p50     : %s\n", p(0.50))
	fmt.Printf("p90     : %s\n", p(0.90))
	fmt.Printf("p99     : %s\n", p(0.99))
	fmt.Printf("max     : %s\n", rtts[len(rtts)-1])
	fmt.Printf("mean    : %s\n", sum/time.Duration(len(rtts)))
	return nil
}

// ──────────── SOCKS5 CONNECT (RFC 1928, no auth) ────────────

func socks5Dial(ctx context.Context, socksAddr, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	// hello: no-auth
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		c.Close()
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 method reject: %v", rep)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, err
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		c.Close()
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, errors.New("hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect rejected rep=%d", head[1])
	}
	// drain BND.ADDR + BND.PORT
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		oneB := make([]byte, 1)
		if _, err := io.ReadFull(c, oneB); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(oneB[0])
	default:
		c.Close()
		return nil, fmt.Errorf("socks5 bad ATYP %d", head[3])
	}
	drain := make([]byte, skip+2)
	if _, err := io.ReadFull(c, drain); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ──────────── helpers ────────────

func humanBytes(n uint64) string {
	const (
		K = 1024
		M = K * K
		G = M * K
	)
	switch {
	case n >= G:
		return fmt.Sprintf("%.2f GiB", float64(n)/G)
	case n >= M:
		return fmt.Sprintf("%.2f MiB", float64(n)/M)
	case n >= K:
		return fmt.Sprintf("%.2f KiB", float64(n)/K)
	}
	return fmt.Sprintf("%d B", n)
}

// humanBits formats a bits-per-second value; pass the value already in bits/sec.
func humanBits(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	}
	return fmt.Sprintf("%.0f bps", bps)
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
