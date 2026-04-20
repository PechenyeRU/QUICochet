package tunnel

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// acceptAndRunBenchServer runs the server side of a single bench
// session on top of the loopback testTunnel harness. It mirrors what
// Server.handleStream does in production (read marker, dispatch) but
// is stripped down to the pieces needed for a unit test.
func acceptAndRunBenchServer(t *testing.T, tt *testTunnel) {
	t.Helper()
	stream, err := tt.serverSess.AcceptStream(context.Background())
	if err != nil {
		t.Errorf("server accept stream: %v", err)
		return
	}
	defer stream.Close()
	header := make([]byte, 1)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}
	if header[0] != benchMarker {
		t.Errorf("expected bench marker 0x00, got 0x%02x", header[0])
		return
	}
	handleBenchStream(stream)
}

func openBenchStream(t *testing.T, tt *testTunnel, mode byte) *quic.Stream {
	t.Helper()
	stream, err := tt.clientQUIC.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Write([]byte{benchMarker, mode}); err != nil {
		t.Fatalf("write bench header: %v", err)
	}
	return stream
}

func TestBenchLatencyOverQUIC(t *testing.T) {
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		acceptAndRunBenchServer(t, tt)
	}()

	stream := openBenchStream(t, tt, benchModeLatency)
	res, err := benchLatencyClient(stream, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("latency bench: %v", err)
	}
	_ = stream.Close()
	<-done

	if res.Mode != "latency" {
		t.Fatalf("expected mode=latency, got %q", res.Mode)
	}
	if res.Samples == 0 {
		t.Fatal("expected at least one sample")
	}
	if res.MinNs <= 0 {
		t.Fatalf("min_ns must be positive, got %d", res.MinNs)
	}
	if res.MaxNs < res.MinNs {
		t.Fatalf("max_ns must be >= min_ns, got min=%d max=%d", res.MinNs, res.MaxNs)
	}
	if res.P99Ns < res.P50Ns {
		t.Fatalf("p99 must be >= p50, got p50=%d p99=%d", res.P50Ns, res.P99Ns)
	}
}

func TestBenchThroughputOverQUIC(t *testing.T) {
	tt := setupTestTunnel(t)
	defer tt.cleanup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		acceptAndRunBenchServer(t, tt)
	}()

	stream := openBenchStream(t, tt, benchModeThroughput)
	res, err := benchThroughputClient(stream, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("throughput bench: %v", err)
	}
	_ = stream.Close()
	<-done

	if res.Mode != "throughput" {
		t.Fatalf("expected mode=throughput, got %q", res.Mode)
	}
	if res.Bytes == 0 {
		t.Fatal("expected to receive some bytes")
	}
	if res.BytesPerSec <= 0 {
		t.Fatalf("expected positive bytes_per_sec, got %f", res.BytesPerSec)
	}
}
