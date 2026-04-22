package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"
)

// fakePacketConn emits canned packets when ReadFrom is called, each
// separated by a configurable delay to simulate network pacing / jitter.
// WriteTo is a no-op sink. It satisfies net.PacketConn well enough for
// the jitter buffer's ReadFrom path.
type fakePacketConn struct {
	mu       sync.Mutex
	packets  [][]byte
	delays   []time.Duration // delay to wait BEFORE emitting packets[i]
	idx      int
	closed   bool
	addr     net.Addr
	onClosed chan struct{}
}

func newFakePacketConn(packets [][]byte, delays []time.Duration) *fakePacketConn {
	return &fakePacketConn{
		packets:  packets,
		delays:   delays,
		addr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
		onClosed: make(chan struct{}),
	}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	if f.idx >= len(f.packets) {
		f.mu.Unlock()
		// Block until close so the drain goroutine doesn't spin.
		<-f.onClosed
		return 0, nil, net.ErrClosed
	}
	d := f.delays[f.idx]
	pkt := f.packets[f.idx]
	f.idx++
	f.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
	n := copy(p, pkt)
	return n, f.addr, nil
}

func (f *fakePacketConn) WriteTo(p []byte, a net.Addr) (int, error) { return len(p), nil }
func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.onClosed)
	return nil
}
func (f *fakePacketConn) LocalAddr() net.Addr                { return f.addr }
func (f *fakePacketConn) SetDeadline(time.Time) error        { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error    { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error   { return nil }

func TestJitterBufferFixedBudgetDelaysDelivery(t *testing.T) {
	// One packet, no inner delay — the buffer should hold it ~20ms.
	inner := newFakePacketConn(
		[][]byte{[]byte("hello")},
		[]time.Duration{0},
	)
	jb := newJitterBuffer(inner, 20*time.Millisecond, false)
	defer jb.Close()

	start := time.Now()
	buf := make([]byte, 64)
	n, _, err := jb.ReadFrom(buf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
	// Allow scheduler slop; the key check is that we were held at
	// least close to the budget.
	if elapsed < 15*time.Millisecond {
		t.Fatalf("delivery too fast: %v (expected >= ~20ms)", elapsed)
	}
	if elapsed > 80*time.Millisecond {
		t.Fatalf("delivery too slow: %v", elapsed)
	}
}

func TestJitterBufferPreservesOrder(t *testing.T) {
	// Four packets arriving at unequal intervals. The buffer must
	// deliver them in the order they arrived, regardless of the
	// (identical) fixed budget that smooths their release.
	pkts := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	inner := newFakePacketConn(pkts, []time.Duration{0, 5 * time.Millisecond, 1 * time.Millisecond, 15 * time.Millisecond})
	jb := newJitterBuffer(inner, 10*time.Millisecond, false)
	defer jb.Close()

	buf := make([]byte, 64)
	for _, want := range pkts {
		n, _, err := jb.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if string(buf[:n]) != string(want) {
			t.Fatalf("out-of-order: got %q, want %q", buf[:n], want)
		}
	}
}

func TestJitterBufferAutoTuneConverges(t *testing.T) {
	// Feed 300 packets with a ~10ms jitter pattern. The auto-tune EMA
	// should settle to a budget that is non-trivially above the floor
	// and well below the ceiling — we just check bounds, not exact
	// value (EMA + scheduler make pinpoint assertions flaky).
	const N = 300
	pkts := make([][]byte, N)
	delays := make([]time.Duration, N)
	for i := range pkts {
		pkts[i] = []byte{byte(i)}
		// alternate 5ms / 15ms to create 10ms of swing
		if i%2 == 0 {
			delays[i] = 5 * time.Millisecond
		} else {
			delays[i] = 15 * time.Millisecond
		}
	}
	inner := newFakePacketConn(pkts, delays)
	jb := newJitterBuffer(inner, 0, true)
	defer jb.Close()

	// Drain all packets so updateAuto runs enough times to make
	// several jbAutoTuneEvery recalculations.
	buf := make([]byte, 16)
	for i := 0; i < N; i++ {
		if _, _, err := jb.ReadFrom(buf); err != nil {
			t.Fatalf("ReadFrom[%d]: %v", i, err)
		}
	}

	budget := time.Duration(jb.budgetNs.Load())
	if budget < jbMinBudget || budget > jbMaxBudget {
		t.Fatalf("auto-tuned budget %v out of clamp range [%v, %v]", budget, jbMinBudget, jbMaxBudget)
	}
	// The exact EMA target isn't important; with a 10ms swing we
	// expect the budget to be a few ms at least, not stuck at the
	// floor from uninitialized state.
	if budget < 3*time.Millisecond {
		t.Fatalf("auto-tuned budget %v suspiciously close to floor; EMA didn't engage", budget)
	}
}

func TestJitterBufferCloseUnblocksReader(t *testing.T) {
	// No packets — ReadFrom should block on the queue, Close must
	// unblock it cleanly with net.ErrClosed.
	inner := newFakePacketConn(nil, nil)
	jb := newJitterBuffer(inner, 10*time.Millisecond, false)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, _, err := jb.ReadFrom(buf)
		done <- err
	}()

	// Give ReadFrom a moment to settle on the blocking recv.
	time.Sleep(20 * time.Millisecond)
	_ = jb.Close()

	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}
