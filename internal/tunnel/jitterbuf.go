package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Jitter buffer design
// --------------------
// A receive-side shim that wraps a net.PacketConn. Every arriving
// packet gets a timestamp and is released to the QUIC reader at
// (arrival + budget). The WriteTo path is a passthrough. The effect
// is that inter-arrival spikes on the wire get absorbed into a
// fixed extra latency, so quic-go's congestion control sees a
// smooth stream instead of interpreting reorder/late-arrival as loss.
//
// Two modes:
//
//   * fixed   — caller supplies a constant budget (e.g. 15ms). Simple
//               and predictable; ideal when you already know your
//               path's p99 jitter.
//   * auto    — budget adapts via an RFC 3550-style exponential
//               estimator. Every incoming packet updates a jitter EMA
//               (seeded with the first inter-arrival); the operating
//               budget is recomputed as 3× that estimate every 100
//               packets, clamped to [jbMinBudget, jbMaxBudget].
//
// `budget = 3σ` covers ~99.7% of Gaussian jitter with minimum cost —
// larger values waste latency, smaller values leak spikes through.

const (
	jbChannelDepth = 4096
	jbReadBuf      = 2048

	// Auto-tune clamp range: 2ms is a sanity floor (below that, the
	// buffer is a no-op under typical OS scheduler granularity); 100ms
	// caps how much latency we'd ever add, matching the "accept higher
	// ping for throughput" trade-off the user opted into.
	jbMinBudget = 2 * time.Millisecond
	jbMaxBudget = 100 * time.Millisecond

	// How often (in packets) the auto-tune EMA translates into a new
	// operating budget. 100 packets ≈ a few tens of ms at WAN PPS.
	jbAutoTuneEvery = 100

	// EMA weights: jitter tracks tail-spike deviations (slower), mean
	// tracks central inter-arrival (faster) so a sudden pacing change
	// doesn't poison the jitter estimator.
	jbEmaJitterDiv = 16
	jbEmaMeanDiv   = 8
)

// jitterPacket is an arrived-but-not-yet-released datagram.
type jitterPacket struct {
	buf       []byte
	size      int
	addr      net.Addr
	releaseAt time.Time
}

// jitterBufferConn wraps a PacketConn with a receive-side smoother.
// Safe for concurrent ReadFrom/WriteTo; the internal drain loop is
// single-goroutine, so auto-tune state needs no locking.
type jitterBufferConn struct {
	net.PacketConn

	auto  bool
	queue chan jitterPacket
	pool  sync.Pool

	// Current budget in nanoseconds; read atomically by the drain
	// goroutine on every packet, updated either once at init (fixed
	// mode) or every jbAutoTuneEvery packets (auto mode).
	budgetNs atomic.Int64

	// Drain-goroutine-private auto-tune state. Off-goroutine code must
	// not touch these.
	emaInterArrival time.Duration
	emaJitter       time.Duration
	lastArrival     time.Time
	pktCount        int

	closeOnce sync.Once
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// newJitterBuffer wraps inner. A fixedBudget > 0 enables fixed mode;
// auto=true enables auto-tune mode (fixedBudget is ignored). Exactly
// one of the two must be requested by the caller; the wiring code
// filters out the "disabled" case before calling this.
func newJitterBuffer(inner net.PacketConn, fixedBudget time.Duration, auto bool) *jitterBufferConn {
	j := &jitterBufferConn{
		PacketConn: inner,
		auto:       auto,
		queue:      make(chan jitterPacket, jbChannelDepth),
		stopCh:     make(chan struct{}),
		pool: sync.Pool{New: func() any {
			b := make([]byte, jbReadBuf)
			return &b
		}},
	}
	if auto {
		// Seed a conservative starting budget so early packets aren't
		// delivered instantly (which would make the EMA thrash).
		j.budgetNs.Store(int64(5 * time.Millisecond))
	} else {
		j.budgetNs.Store(int64(fixedBudget))
	}
	j.wg.Add(1)
	go j.drainLoop()
	return j
}

// ReadFrom delivers packets in FIFO order, sleeping as needed to
// honor each packet's releaseAt timestamp. A Close during sleep
// aborts with net.ErrClosed.
func (j *jitterBufferConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-j.queue:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if wait := time.Until(pkt.releaseAt); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-j.stopCh:
				t.Stop()
				j.returnBuf(pkt.buf)
				return 0, nil, net.ErrClosed
			}
		}
		n := copy(p, pkt.buf[:pkt.size])
		addr := pkt.addr
		j.returnBuf(pkt.buf)
		return n, addr, nil
	case <-j.stopCh:
		return 0, nil, net.ErrClosed
	}
}

// SyscallConn delegates to the inner PacketConn so quic-go can set
// socket options (SO_RCVBUF/SO_SNDBUF, UDP_GSO, IP_PKTINFO) on the
// real UDP socket — the wrapper must be transparent here or quic-go
// refuses to bind with "underlying conn does not support SyscallConn".
func (j *jitterBufferConn) SyscallConn() (syscall.RawConn, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if sc, ok := j.PacketConn.(syscallConner); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("inner packet conn does not support SyscallConn")
}

// SetReadBuffer / SetWriteBuffer: quic-go and our own tuning path
// call these to raise SO_RCVBUF/SO_SNDBUF. Delegate when the inner
// conn supports them, otherwise silently succeed so the wrapper
// doesn't break startup on conn types that don't expose the hook.
func (j *jitterBufferConn) SetReadBuffer(bytes int) error {
	type setter interface{ SetReadBuffer(int) error }
	if s, ok := j.PacketConn.(setter); ok {
		return s.SetReadBuffer(bytes)
	}
	return nil
}
func (j *jitterBufferConn) SetWriteBuffer(bytes int) error {
	type setter interface{ SetWriteBuffer(int) error }
	if s, ok := j.PacketConn.(setter); ok {
		return s.SetWriteBuffer(bytes)
	}
	return nil
}

// Close stops the drain goroutine and closes the inner PacketConn.
// Idempotent.
func (j *jitterBufferConn) Close() error {
	j.closeOnce.Do(func() { close(j.stopCh) })
	err := j.PacketConn.Close()
	j.wg.Wait()
	return err
}

func (j *jitterBufferConn) returnBuf(b []byte) {
	bp := b[:cap(b)]
	j.pool.Put(&bp)
}

// drainLoop runs in its own goroutine: reads from the underlying
// PacketConn as fast as it can, updates auto-tune state, and pushes
// each packet into the queue with its release deadline.
func (j *jitterBufferConn) drainLoop() {
	defer j.wg.Done()
	for {
		bufPtr := j.pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < jbReadBuf {
			buf = make([]byte, jbReadBuf)
		} else {
			buf = buf[:jbReadBuf]
		}
		n, addr, err := j.PacketConn.ReadFrom(buf)
		if err != nil {
			j.pool.Put(bufPtr)
			select {
			case <-j.stopCh:
				return
			default:
			}
			// Inner conn is probably closed; exit.
			return
		}

		now := time.Now()
		if j.auto {
			j.updateAuto(now)
		}
		budget := time.Duration(j.budgetNs.Load())

		pkt := jitterPacket{
			buf:       buf,
			size:      n,
			addr:      addr,
			releaseAt: now.Add(budget),
		}
		select {
		case j.queue <- pkt:
		case <-j.stopCh:
			j.pool.Put(bufPtr)
			return
		}
	}
}

// updateAuto runs on every arriving packet, maintains jitter and
// mean-inter-arrival EMAs, and every jbAutoTuneEvery packets rolls
// the result into the live budget.
func (j *jitterBufferConn) updateAuto(arrival time.Time) {
	if j.lastArrival.IsZero() {
		j.lastArrival = arrival
		return
	}
	inter := arrival.Sub(j.lastArrival)
	j.lastArrival = arrival

	if j.emaInterArrival == 0 {
		j.emaInterArrival = inter
		return
	}

	var d time.Duration
	if inter > j.emaInterArrival {
		d = inter - j.emaInterArrival
	} else {
		d = j.emaInterArrival - inter
	}
	j.emaJitter += (d - j.emaJitter) / jbEmaJitterDiv
	j.emaInterArrival += (inter - j.emaInterArrival) / jbEmaMeanDiv

	j.pktCount++
	if j.pktCount%jbAutoTuneEvery != 0 {
		return
	}
	budget := 3 * j.emaJitter
	if budget < jbMinBudget {
		budget = jbMinBudget
	}
	if budget > jbMaxBudget {
		budget = jbMaxBudget
	}
	j.budgetNs.Store(int64(budget))
}

// maybeWrapJitterBuffer is the single call site wired into Client
// and Server startup. It returns the input verbatim when the feature
// is disabled (ms == 0), wraps in fixed mode for ms > 0, or wraps in
// auto mode when ms == -1. Any start is logged at INFO.
func maybeWrapJitterBuffer(inner net.PacketConn, ms int, role string) net.PacketConn {
	switch {
	case ms == 0:
		return inner
	case ms == -1:
		slog.Info("jitter buffer enabled", "component", "tunnel", "role", role, "mode", "auto")
		return newJitterBuffer(inner, 0, true)
	default:
		budget := time.Duration(ms) * time.Millisecond
		slog.Info("jitter buffer enabled", "component", "tunnel", "role", role, "mode", "fixed", "budget_ms", ms)
		return newJitterBuffer(inner, budget, false)
	}
}
