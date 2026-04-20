package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
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

// RunBench opens a QUIC stream on the client's pool, drives the
// requested bench mode for duration, and returns the measurements.
// Valid modes: "latency", "throughput". Default duration is 5s when
// duration <= 0.
func (c *Client) RunBench(ctx context.Context, mode string, duration time.Duration) (admin.BenchResult, error) {
	if duration <= 0 {
		duration = 5 * time.Second
	}

	var modeByte byte
	switch mode {
	case "latency":
		modeByte = benchModeLatency
	case "throughput":
		modeByte = benchModeThroughput
	default:
		return admin.BenchResult{}, fmt.Errorf("unknown bench mode: %s", mode)
	}

	session, err := c.getOrDialConn()
	if err != nil {
		return admin.BenchResult{}, fmt.Errorf("no quic connection available: %w", err)
	}

	openCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	stream, err := session.OpenStreamSync(openCtx)
	cancel()
	if err != nil {
		return admin.BenchResult{}, fmt.Errorf("open bench stream: %w", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte{benchMarker, modeByte}); err != nil {
		return admin.BenchResult{}, fmt.Errorf("write bench header: %w", err)
	}

	switch mode {
	case "latency":
		return benchLatencyClient(stream, duration)
	case "throughput":
		return benchThroughputClient(stream, duration)
	}
	return admin.BenchResult{}, nil
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
