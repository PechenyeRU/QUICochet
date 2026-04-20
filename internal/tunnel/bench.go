package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// errPeerNoBench is surfaced when the remote daemon closes the bench
// stream without producing any payload — the most likely cause is a
// pre-1.9.0 server that reads the leading 0x00 as a zero-length SOCKS
// target and drops the stream.
var errPeerNoBench = errors.New("peer closed bench stream before any response — ensure the remote daemon is running v1.9.0 or later")

// Bench stream protocol.
//
// A QUIC stream carrying a bench session opens with a leading zero
// byte that shadows the target-address-length byte the server normally
// expects for SOCKS-like streams (target length 0 is never valid for
// real traffic, so the marker is unambiguous). The next byte selects
// the sub-protocol.
//
//   stream: [0x00][mode]
//     mode = 0x01 (latency)  — client sends 16-byte pings; server echoes
//     mode = 0x02 (tput)     — server streams random bytes until cancel
//
// Latency payload is 8 bytes of client-local sequence + 8 bytes of
// client-local nanotime; the server treats it as opaque and echoes.
// The client measures RTT on its own clock, so clock skew with the
// peer never enters the number.
const (
	benchMarker         byte = 0x00
	benchModeLatency    byte = 0x01
	benchModeThroughput byte = 0x02

	benchLatencyPayloadSize = 16
	benchThroughputChunk    = 64 * 1024
)

// handleBenchStream drives the server side of a bench session after
// the marker byte has been consumed by the caller. It reads the mode
// byte and runs the matching per-mode loop until the stream ends.
func handleBenchStream(stream *quic.Stream) {
	var mode [1]byte
	if _, err := io.ReadFull(stream, mode[:]); err != nil {
		return
	}
	switch mode[0] {
	case benchModeLatency:
		benchLatencyServer(stream)
	case benchModeThroughput:
		benchThroughputServer(stream)
	}
}

func benchLatencyServer(stream *quic.Stream) {
	buf := make([]byte, benchLatencyPayloadSize)
	for {
		if _, err := io.ReadFull(stream, buf); err != nil {
			return
		}
		if _, err := stream.Write(buf); err != nil {
			return
		}
	}
}

func benchThroughputServer(stream *quic.Stream) {
	buf := make([]byte, benchThroughputChunk)
	if _, err := rand.Read(buf); err != nil {
		return
	}
	for {
		if _, err := stream.Write(buf); err != nil {
			return
		}
	}
}

// RunBench drives an in-link benchmark for duration. Valid modes:
// "latency" (always single-stream) and "throughput" (fans out over
// parallel streams; 0 means default to quic.pool_size). Default
// duration is 5s when duration <= 0.
func (c *Client) RunBench(ctx context.Context, mode string, duration time.Duration, parallel int) (admin.BenchResult, error) {
	if duration <= 0 {
		duration = 5 * time.Second
	}

	switch mode {
	case "latency":
		stream, err := c.openBenchStream(ctx, benchModeLatency)
		if err != nil {
			return admin.BenchResult{}, err
		}
		defer stream.Close()
		return benchLatencyClient(stream, duration)
	case "throughput":
		if parallel <= 0 {
			parallel = c.config.QUIC.PoolSize
			if parallel < 1 {
				parallel = 1
			}
		}
		return c.runThroughputParallel(ctx, duration, parallel)
	default:
		return admin.BenchResult{}, fmt.Errorf("unknown bench mode: %s", mode)
	}
}

// openBenchStream opens a QUIC stream from the pool and writes the
// bench header (marker + mode byte). Successive calls hit round-robin
// pool slots via getOrDialConn so N opens distribute across the pool.
func (c *Client) openBenchStream(ctx context.Context, modeByte byte) (*quic.Stream, error) {
	session, err := c.getOrDialConn()
	if err != nil {
		return nil, fmt.Errorf("no quic connection available: %w", err)
	}
	openCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	stream, err := session.OpenStreamSync(openCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("open bench stream: %w", err)
	}
	if _, err := stream.Write([]byte{benchMarker, modeByte}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write bench header: %w", err)
	}
	return stream, nil
}

// runThroughputParallel fans out N throughput bench streams and sums
// their byte counts. Each worker opens its own stream; pool round-
// robin in getOrDialConn spreads streams across distinct QUIC
// connections so the per-connection flow-control window is not the
// bottleneck. First non-peer-rejection error from any worker wins.
func (c *Client) runThroughputParallel(ctx context.Context, duration time.Duration, parallel int) (admin.BenchResult, error) {
	type workerResult struct {
		bytes   uint64
		elapsed float64
		err     error
	}
	results := make([]workerResult, parallel)

	var wg sync.WaitGroup
	var peerRejected atomic.Bool
	wg.Add(parallel)
	start := time.Now()
	for i := 0; i < parallel; i++ {
		go func(idx int) {
			defer wg.Done()
			stream, err := c.openBenchStream(ctx, benchModeThroughput)
			if err != nil {
				results[idx] = workerResult{err: err}
				return
			}
			defer stream.Close()
			res, err := benchThroughputClient(stream, duration)
			if errors.Is(err, errPeerNoBench) {
				peerRejected.Store(true)
			}
			results[idx] = workerResult{bytes: res.Bytes, elapsed: res.DurationSec, err: err}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	if peerRejected.Load() {
		return admin.BenchResult{}, errPeerNoBench
	}

	var totalBytes uint64
	var activeStreams int
	var firstErr error
	for _, r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		totalBytes += r.bytes
		activeStreams++
	}
	// If no worker produced bytes, surface the first failure. Otherwise
	// accept partial success — a single failed stream shouldn't void the
	// aggregate when the other N-1 gave useful numbers.
	if activeStreams == 0 && firstErr != nil {
		return admin.BenchResult{}, firstErr
	}

	bps := 0.0
	if elapsed > 0 {
		bps = float64(totalBytes) / elapsed
	}
	return admin.BenchResult{
		Mode:        "throughput",
		DurationSec: elapsed,
		Bytes:       totalBytes,
		BytesPerSec: bps,
		Streams:     activeStreams,
	}, nil
}

func benchLatencyClient(stream *quic.Stream, duration time.Duration) (admin.BenchResult, error) {
	deadline := time.Now().Add(duration)
	buf := make([]byte, benchLatencyPayloadSize)
	echo := make([]byte, benchLatencyPayloadSize)
	samples := make([]time.Duration, 0, 1024)
	var seq uint64
	start := time.Now()
	for time.Now().Before(deadline) {
		seq++
		binary.BigEndian.PutUint64(buf[0:8], seq)
		t0 := time.Now()
		binary.BigEndian.PutUint64(buf[8:16], uint64(t0.UnixNano()))
		if _, err := stream.Write(buf); err != nil {
			return admin.BenchResult{}, fmt.Errorf("lat write: %w", err)
		}
		if _, err := io.ReadFull(stream, echo); err != nil {
			if errors.Is(err, io.EOF) && len(samples) == 0 {
				return admin.BenchResult{}, errPeerNoBench
			}
			return admin.BenchResult{}, fmt.Errorf("lat read: %w", err)
		}
		samples = append(samples, time.Since(t0))
	}
	if len(samples) == 0 {
		return admin.BenchResult{}, fmt.Errorf("no samples collected (duration too short?)")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	pct := func(p float64) time.Duration {
		idx := int(float64(len(samples)-1) * p)
		return samples[idx]
	}
	return admin.BenchResult{
		Mode:        "latency",
		DurationSec: time.Since(start).Seconds(),
		Samples:     len(samples),
		MinNs:       samples[0].Nanoseconds(),
		MaxNs:       samples[len(samples)-1].Nanoseconds(),
		MeanNs:      (sum / time.Duration(len(samples))).Nanoseconds(),
		P50Ns:       pct(0.50).Nanoseconds(),
		P90Ns:       pct(0.90).Nanoseconds(),
		P99Ns:       pct(0.99).Nanoseconds(),
	}, nil
}

func benchThroughputClient(stream *quic.Stream, duration time.Duration) (admin.BenchResult, error) {
	deadline := time.Now().Add(duration)
	// SetReadDeadline lets us stop on the bench clock even if the
	// server is buffered ahead of us; on deadline we break and cancel.
	_ = stream.SetReadDeadline(deadline)
	buf := make([]byte, benchThroughputChunk)
	var total uint64
	start := time.Now()
	for time.Now().Before(deadline) {
		n, err := stream.Read(buf)
		total += uint64(n)
		if err != nil {
			if time.Now().After(deadline) {
				break
			}
			stream.CancelRead(0)
			if errors.Is(err, io.EOF) && total == 0 {
				return admin.BenchResult{}, errPeerNoBench
			}
			return admin.BenchResult{}, fmt.Errorf("tput read: %w", err)
		}
	}
	elapsed := time.Since(start).Seconds()
	stream.CancelRead(0)

	bps := 0.0
	if elapsed > 0 {
		bps = float64(total) / elapsed
	}
	return admin.BenchResult{
		Mode:        "throughput",
		DurationSec: elapsed,
		Bytes:       total,
		BytesPerSec: bps,
	}, nil
}
