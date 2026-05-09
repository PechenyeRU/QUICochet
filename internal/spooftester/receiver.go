package spooftester

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ReceiverConfig drives a single tester receiver run.
type ReceiverConfig struct {
	Proto      Proto
	ListenPort uint16        // L4 dst port to filter on (TCP/UDP). Ignored for ICMP*.
	Expected   []netip.Addr  // src list the operator expects (gives us a denominator for pass/fail).
	RunID      uint16        // optional filter: 0 = accept any
	Duration   time.Duration // hard timeout for the listening window
	MinPackets int           // a src-IP needs at least N packets to be considered "pass"
}

// PerSrc captures what the receiver saw from a single source IP.
type PerSrc struct {
	IP    netip.Addr
	Count int
	First time.Time
	Last  time.Time
}

// Receiver listens on a raw socket (TCP/ICMP/ICMPv6) or a UDP socket
// and tallies which spoof src IPs actually arrive on the wire.
type Receiver struct {
	cfg     ReceiverConfig
	fd      int          // raw socket fd (-1 if using net.UDPConn)
	udp     *net.UDPConn // for ProtoUDP
	mu      sync.Mutex
	tally   map[netip.Addr]*PerSrc
	pkts    atomic.Uint64
	dropped atomic.Uint64
}

// NewReceiver opens the underlying socket. Requires root for raw modes.
func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if cfg.Duration <= 0 {
		cfg.Duration = 30 * time.Second
	}
	if cfg.MinPackets <= 0 {
		cfg.MinPackets = 1
	}

	r := &Receiver{cfg: cfg, fd: -1, tally: make(map[netip.Addr]*PerSrc)}

	switch cfg.Proto {
	case ProtoTCP:
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		if err != nil {
			return nil, fmt.Errorf("open raw TCP socket: %w (need CAP_NET_RAW)", err)
		}
		r.fd = fd
	case ProtoICMP:
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			return nil, fmt.Errorf("open raw ICMP socket: %w", err)
		}
		r.fd = fd
	case ProtoICMPv6:
		// proto-58-over-IPv4: the kernel hands us proto-58 frames over
		// AF_INET when we listen on IPPROTO_ICMPV6 from an AF_INET
		// socket. Linux specifically supports this.
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipProtoICMPv6)
		if err != nil {
			return nil, fmt.Errorf("open raw ICMPv6-over-v4 socket: %w", err)
		}
		r.fd = fd
	case ProtoUDP:
		laddr := &net.UDPAddr{IP: net.IPv4zero, Port: int(cfg.ListenPort)}
		c, err := net.ListenUDP("udp4", laddr)
		if err != nil {
			return nil, fmt.Errorf("listen UDP %d: %w", cfg.ListenPort, err)
		}
		r.udp = c
	default:
		return nil, fmt.Errorf("unsupported proto %q", cfg.Proto)
	}
	return r, nil
}

// Close releases the socket.
func (r *Receiver) Close() {
	if r.fd >= 0 {
		syscall.Close(r.fd)
		r.fd = -1
	}
	if r.udp != nil {
		r.udp.Close()
		r.udp = nil
	}
}

// Run blocks until either Duration elapses or ctx is cancelled, then
// returns the accumulated stats.
func (r *Receiver) Run(ctx context.Context) error {
	deadline := time.Now().Add(r.cfg.Duration)

	switch r.cfg.Proto {
	case ProtoTCP:
		return r.runRawV4(ctx, deadline, r.consumeTCP)
	case ProtoICMP:
		return r.runRawV4(ctx, deadline, r.consumeICMPv4)
	case ProtoICMPv6:
		return r.runRawV4(ctx, deadline, r.consumeICMPv6OverV4)
	case ProtoUDP:
		return r.runUDP(ctx, deadline)
	}
	return errors.New("unreachable")
}

func (r *Receiver) runRawV4(ctx context.Context, deadline time.Time, consume func([]byte)) error {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil
		}
		// Set a short read deadline by setsockopt SO_RCVTIMEO
		tv := syscall.Timeval{Sec: 0, Usec: 250_000}
		_ = syscall.SetsockoptTimeval(r.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, _, err := syscall.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		if n <= 0 {
			continue
		}
		consume(buf[:n])
	}
}

func (r *Receiver) runUDP(ctx context.Context, deadline time.Time) error {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil
		}
		_ = r.udp.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n < payloadHeaderSize {
			r.dropped.Add(1)
			continue
		}
		rid, _, perr := ParsePayload(buf[:n])
		if perr != nil {
			r.dropped.Add(1)
			continue
		}
		if r.cfg.RunID != 0 && rid != r.cfg.RunID {
			r.dropped.Add(1)
			continue
		}
		r.record(addr.Addr().Unmap())
	}
}

func (r *Receiver) consumeTCP(buf []byte) {
	r.pkts.Add(1)
	src, rid, _, ok := ParseInboundTCPv4(buf, r.cfg.ListenPort)
	if !ok {
		r.dropped.Add(1)
		return
	}
	if r.cfg.RunID != 0 && rid != r.cfg.RunID {
		r.dropped.Add(1)
		return
	}
	r.record(netip.AddrFrom4(src))
}

func (r *Receiver) consumeICMPv4(buf []byte) {
	r.pkts.Add(1)
	src, rid, _, ok := ParseInboundICMPv4(buf, ipProtoICMPv4, icmpEchoRequestV4)
	if !ok {
		r.dropped.Add(1)
		return
	}
	if r.cfg.RunID != 0 && rid != r.cfg.RunID {
		r.dropped.Add(1)
		return
	}
	r.record(netip.AddrFrom4(src))
}

func (r *Receiver) consumeICMPv6OverV4(buf []byte) {
	r.pkts.Add(1)
	src, rid, _, ok := ParseInboundICMPv4(buf, ipProtoICMPv6, icmpEchoRequestV6)
	if !ok {
		r.dropped.Add(1)
		return
	}
	if r.cfg.RunID != 0 && rid != r.cfg.RunID {
		r.dropped.Add(1)
		return
	}
	r.record(netip.AddrFrom4(src))
}

func (r *Receiver) record(src netip.Addr) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.tally[src]
	if !ok {
		e = &PerSrc{IP: src, First: now}
		r.tally[src] = e
	}
	e.Count++
	e.Last = now
}

// Result reports the post-run summary.
type Result struct {
	Proto    Proto
	RunID    uint16
	Duration time.Duration
	Pass     []netip.Addr // sorted, count >= MinPackets
	Fail     []netip.Addr // expected but absent (or below threshold)
	Unknown  []netip.Addr // received but not in Expected
	PerSrc   []PerSrc
	Packets  uint64 // total raw packets seen by the socket
	Dropped  uint64 // dropped due to magic/runID mismatch
}

// Summary builds a Result snapshot — call after Run returns.
func (r *Receiver) Summary() Result {
	r.mu.Lock()
	defer r.mu.Unlock()

	expectedSet := make(map[netip.Addr]struct{}, len(r.cfg.Expected))
	for _, ip := range r.cfg.Expected {
		expectedSet[ip.Unmap()] = struct{}{}
	}

	res := Result{
		Proto:    r.cfg.Proto,
		RunID:    r.cfg.RunID,
		Duration: r.cfg.Duration,
		Packets:  r.pkts.Load(),
		Dropped:  r.dropped.Load(),
	}
	res.PerSrc = make([]PerSrc, 0, len(r.tally))
	seenSet := make(map[netip.Addr]int, len(r.tally))
	for _, e := range r.tally {
		res.PerSrc = append(res.PerSrc, *e)
		seenSet[e.IP] = e.Count
	}
	sort.Slice(res.PerSrc, func(i, j int) bool { return res.PerSrc[i].IP.Less(res.PerSrc[j].IP) })

	// pass = expected AND count >= threshold
	for _, ip := range r.cfg.Expected {
		ip = ip.Unmap()
		if seenSet[ip] >= r.cfg.MinPackets {
			res.Pass = append(res.Pass, ip)
		} else {
			res.Fail = append(res.Fail, ip)
		}
	}
	for _, e := range res.PerSrc {
		if _, ok := expectedSet[e.IP]; !ok {
			res.Unknown = append(res.Unknown, e.IP)
		}
	}
	sort.Slice(res.Pass, func(i, j int) bool { return res.Pass[i].Less(res.Pass[j]) })
	sort.Slice(res.Fail, func(i, j int) bool { return res.Fail[i].Less(res.Fail[j]) })
	sort.Slice(res.Unknown, func(i, j int) bool { return res.Unknown[i].Less(res.Unknown[j]) })
	return res
}
