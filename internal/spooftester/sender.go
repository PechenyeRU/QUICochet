package spooftester

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// SenderConfig drives a single spoof-tester sender run.
type SenderConfig struct {
	// Proto: tcp | udp | icmp | icmpv6.
	Proto Proto
	// SrcList: candidate spoof source IPs (already expanded; see ParseIPList).
	SrcList []netip.Addr
	// Dst: receiver address. Must be IPv4 unless the operator chose to
	// run an all-v6 trial separately (mixed-family runs are rejected).
	Dst netip.Addr
	// DstPort: destination L4 port (TCP/UDP). Ignored for ICMP/ICMPv6.
	DstPort uint16
	// PerIP: how many packets to send per src candidate.
	PerIP int
	// IntervalMs: spacing between consecutive sends, milliseconds.
	// Default ~20 ms (50 pps) keeps middleboxes from rate-dropping us.
	IntervalMs int
	// RunID: shared with the receiver via --run-id, identifies one run.
	RunID uint16
}

// SenderStats tracks live progress, useful for cobra UI.
type SenderStats struct {
	Sent atomic.Uint64
	Errs atomic.Uint64
}

// Sender drives an individual sender pass. Single-shot; build a fresh
// instance per run.
type Sender struct {
	cfg   SenderConfig
	stats *SenderStats
	fd    int
	fd6   int
}

// NewSender opens the underlying raw socket(s) — requires CAP_NET_RAW.
func NewSender(cfg SenderConfig) (*Sender, *SenderStats, error) {
	if cfg.PerIP <= 0 {
		cfg.PerIP = 5
	}
	if cfg.IntervalMs <= 0 {
		cfg.IntervalMs = 20
	}
	if len(cfg.SrcList) == 0 {
		return nil, nil, errors.New("empty src list")
	}
	if !cfg.Dst.IsValid() {
		return nil, nil, errors.New("invalid dst")
	}

	s := &Sender{cfg: cfg, stats: &SenderStats{}, fd: -1, fd6: -1}

	if cfg.Dst.Is4() {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, nil, fmt.Errorf("open raw v4 socket: %w (need CAP_NET_RAW or root)", err)
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			return nil, nil, fmt.Errorf("IP_HDRINCL: %w", err)
		}
		s.fd = fd
	} else {
		// For real IPv6 destinations we'd open AF_INET6/IPPROTO_RAW.
		// Out of scope for stage 1 — first deployment is IPv4-only.
		return nil, nil, errors.New("IPv6 destinations not yet supported in spoof-tester (TODO)")
	}

	// Validate src family matches dst.
	for _, src := range cfg.SrcList {
		if src.Is4() != cfg.Dst.Is4() {
			s.Close()
			return nil, nil, fmt.Errorf("src %s and dst %s family mismatch", src, cfg.Dst)
		}
	}

	return s, s.stats, nil
}

// Close releases the raw socket(s).
func (s *Sender) Close() {
	if s.fd >= 0 {
		syscall.Close(s.fd)
		s.fd = -1
	}
	if s.fd6 >= 0 {
		syscall.Close(s.fd6)
		s.fd6 = -1
	}
}

// Run iterates over (src, packet#) and shoots them out at the configured
// rate. Returns when the work is done (no async loop).
func (s *Sender) Run(progress func(sent, total uint64)) error {
	total := uint64(len(s.cfg.SrcList)) * uint64(s.cfg.PerIP)
	gap := time.Duration(s.cfg.IntervalMs) * time.Millisecond

	dst4 := s.cfg.Dst.As4()

	var lastTick time.Time
	for ipIdx, srcAddr := range s.cfg.SrcList {
		src4 := srcAddr.As4()
		for seq := 0; seq < s.cfg.PerIP; seq++ {
			ipID := uint16(uint64(ipIdx)*16 + uint64(seq) + 1)
			pkt, err := s.buildPacket(src4, dst4, uint32(seq), ipID)
			if err != nil {
				s.stats.Errs.Add(1)
				continue
			}
			sa := &syscall.SockaddrInet4{Port: 0, Addr: dst4}
			if err := syscall.Sendto(s.fd, pkt, 0, sa); err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				s.stats.Errs.Add(1)
			} else {
				s.stats.Sent.Add(1)
			}
			if progress != nil && time.Since(lastTick) > 200*time.Millisecond {
				progress(s.stats.Sent.Load(), total)
				lastTick = time.Now()
			}
			if gap > 0 {
				time.Sleep(gap)
			}
		}
	}
	if progress != nil {
		progress(s.stats.Sent.Load(), total)
	}
	return nil
}

// buildPacket dispatches to the right packet builder for the configured
// proto.
func (s *Sender) buildPacket(src, dst [4]byte, seq uint32, ipID uint16) ([]byte, error) {
	switch s.cfg.Proto {
	case ProtoTCP:
		return BuildTCPSYNv4(src, dst, s.cfg.DstPort, s.cfg.RunID, seq, ipID), nil
	case ProtoUDP:
		// Source port = runID (so receiver can filter by it); fixed
		// per run for clarity. dstPort comes from the operator.
		return BuildUDPv4(src, dst, s.cfg.RunID, s.cfg.DstPort, s.cfg.RunID, seq, ipID), nil
	case ProtoICMP:
		return BuildICMPv4Echo(src, dst, s.cfg.RunID, seq, ipID), nil
	case ProtoICMPv6:
		return BuildICMPv6OverIPv4Echo(src, dst, s.cfg.RunID, seq, ipID), nil
	default:
		return nil, fmt.Errorf("unsupported proto %q", s.cfg.Proto)
	}
}
