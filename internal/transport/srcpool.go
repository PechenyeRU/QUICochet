package transport

import (
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SrcPool tracks the per-family pool of spoof source IPs together with
// their runtime health. Each Send picks an entry via a DCID-based hash
// (preserving per-flow stickiness), but skips entries currently in
// cooldown. On suspected failure the client calls MarkConnDead which
// heuristically blames the IP whose last successful send is the most
// stale among the still-active set, and quarantines it for an
// exponentially-growing backoff window.
//
// The tracking is all best-effort and lock-free on the hot path; only
// MarkConnDead and the resurrect tick take a small lock since they
// reason about the whole set at once.
//
// V4 and V6 pools are independent. Use NewSrcPoolFromConfig to build
// one matching pool per family, or NewSrcSet to test in isolation.
type SrcPool struct {
	v4 *SrcSet
	v6 *SrcSetV6
}

// SrcSet is the IPv4 specialisation; SrcSetV6 mirrors it for IPv6 to
// avoid generics on the hot path. Both share the same field semantics.
type SrcSet struct {
	ips           [][4]byte
	deathStreak   []atomic.Uint32  // consecutive blames before quarantine
	cooldownUntil []atomic.Int64   // unix nanoseconds; <= now → healthy
	cooldownLevel []atomic.Uint32  // backoff exponent (0..maxLevel)
	lastSentNanos []atomic.Int64   // most recent send timestamp through this IP
	sentCount     []atomic.Uint64  // total sends recorded (observability)
	mu            sync.Mutex       // guards MarkConnDead + Resurrect coherence
	cfg           SrcPoolConfig
}

// SrcSetV6 is the IPv6 mirror. Functionally identical except entries
// are 16 bytes — kept as separate struct to keep the [4]byte hot path
// allocation-free.
type SrcSetV6 struct {
	ips           [][16]byte
	deathStreak   []atomic.Uint32
	cooldownUntil []atomic.Int64
	cooldownLevel []atomic.Uint32
	lastSentNanos []atomic.Int64
	sentCount     []atomic.Uint64
	mu            sync.Mutex
	cfg           SrcPoolConfig
}

// SrcPoolConfig holds the tunables. Zero values use the defaults below.
type SrcPoolConfig struct {
	// DeathThreshold is the number of consecutive MarkConnDead blames
	// against a single IP before it is moved into cooldown. Default 2.
	// Set to 1 for aggressive quarantine, higher for noise-tolerant.
	DeathThreshold uint32

	// InitialCooldown is the first cooldown duration applied when an IP
	// crosses DeathThreshold. Default 30s.
	InitialCooldown time.Duration

	// MaxCooldown caps the exponential growth of repeated quarantines.
	// Default 5min.
	MaxCooldown time.Duration

	// StaleSendThreshold is the lookback window used by MarkConnDead to
	// pick a blame target. An IP whose most recent send is older than
	// this window (relative to the median active IP) is considered the
	// likely owner of the dead connection. Default 10s.
	StaleSendThreshold time.Duration
}

func (c *SrcPoolConfig) applyDefaults() {
	if c.DeathThreshold == 0 {
		c.DeathThreshold = 2
	}
	if c.InitialCooldown == 0 {
		c.InitialCooldown = 30 * time.Second
	}
	if c.MaxCooldown == 0 {
		c.MaxCooldown = 5 * time.Minute
	}
	if c.StaleSendThreshold == 0 {
		c.StaleSendThreshold = 10 * time.Second
	}
}

// NewSrcPool builds a pool from per-family slices. Either side may be
// empty (single-stack). Returned pool is safe for concurrent use by
// the transport hot path and the client maintainer.
func NewSrcPool(v4 [][4]byte, v6 [][16]byte, cfg SrcPoolConfig) *SrcPool {
	cfg.applyDefaults()
	p := &SrcPool{}
	if len(v4) > 0 {
		p.v4 = newSrcSet(v4, cfg)
	}
	if len(v6) > 0 {
		p.v6 = newSrcSetV6(v6, cfg)
	}
	return p
}

// NewSrcPoolFromConfig is a convenience that wraps the legacy
// parseSourceLists output into a SrcPool. Callers that already have
// their own [4]byte/[16]byte slices should call NewSrcPool directly.
func NewSrcPoolFromConfig(cfg *Config, poolCfg SrcPoolConfig) *SrcPool {
	v4, v6 := parseSourceLists(cfg)
	return NewSrcPool(v4, v6, poolCfg)
}

func newSrcSet(ips [][4]byte, cfg SrcPoolConfig) *SrcSet {
	s := &SrcSet{
		ips:           ips,
		deathStreak:   make([]atomic.Uint32, len(ips)),
		cooldownUntil: make([]atomic.Int64, len(ips)),
		cooldownLevel: make([]atomic.Uint32, len(ips)),
		lastSentNanos: make([]atomic.Int64, len(ips)),
		sentCount:     make([]atomic.Uint64, len(ips)),
		cfg:           cfg,
	}
	return s
}

func newSrcSetV6(ips [][16]byte, cfg SrcPoolConfig) *SrcSetV6 {
	return &SrcSetV6{
		ips:           ips,
		deathStreak:   make([]atomic.Uint32, len(ips)),
		cooldownUntil: make([]atomic.Int64, len(ips)),
		cooldownLevel: make([]atomic.Uint32, len(ips)),
		lastSentNanos: make([]atomic.Int64, len(ips)),
		sentCount:     make([]atomic.Uint64, len(ips)),
		cfg:           cfg,
	}
}

// V4 returns the IPv4 SrcSet, or nil if the pool has no v4 entries.
func (p *SrcPool) V4() *SrcSet { return p.v4 }

// V6 returns the IPv6 SrcSet, or nil if the pool has no v6 entries.
func (p *SrcPool) V6() *SrcSetV6 { return p.v6 }

// PickV4 selects an IPv4 source for an outgoing QUIC packet, skipping
// any entry currently in cooldown. Returns nil if the pool has no v4
// entries; falls back to the FNV-indexed (possibly quarantined) entry
// only when every entry is in cooldown — failing closed there would
// mean dropping all egress, which is worse than sending from a known
// suspect IP.
//
// Callers MUST treat the returned pointer as read-only. The returned
// idx is the slice position used for RecordSendV4.
func (p *SrcPool) PickV4(payload []byte) (ip *[4]byte, idx int) {
	if p.v4 == nil || len(p.v4.ips) == 0 {
		return nil, -1
	}
	return p.v4.pick(payload)
}

// PickV6 mirrors PickV4 for IPv6.
func (p *SrcPool) PickV6(payload []byte) (ip *[16]byte, idx int) {
	if p.v6 == nil || len(p.v6.ips) == 0 {
		return nil, -1
	}
	return p.v6.pick(payload)
}

// RecordSendV4 marks idx as having just sent a packet. Hot-path safe.
func (p *SrcPool) RecordSendV4(idx int) {
	if p.v4 == nil || idx < 0 || idx >= len(p.v4.ips) {
		return
	}
	p.v4.sentCount[idx].Add(1)
	p.v4.lastSentNanos[idx].Store(time.Now().UnixNano())
}

// RecordSendV6 mirrors RecordSendV4 for IPv6.
func (p *SrcPool) RecordSendV6(idx int) {
	if p.v6 == nil || idx < 0 || idx >= len(p.v6.ips) {
		return
	}
	p.v6.sentCount[idx].Add(1)
	p.v6.lastSentNanos[idx].Store(time.Now().UnixNano())
}

// MarkConnDeadV4 informs the pool that one of the QUIC connections
// pinned to a v4 source IP has died. The pool heuristically blames the
// IP whose most recent send is the oldest among non-quarantined
// entries — that is, the connection that has stopped sending while
// others continue.
//
// If the heuristic produces no clear blame target (e.g. only one
// active entry remains, or all timestamps are equally fresh) the call
// is a no-op so we never quarantine the wrong IP. The min-healthy
// guard prevents quarantining the last remaining active IP.
func (p *SrcPool) MarkConnDeadV4() (ip [4]byte, marked bool) {
	if p.v4 == nil {
		return ip, false
	}
	return p.v4.markConnDead()
}

// MarkConnDeadV6 mirrors MarkConnDeadV4 for IPv6.
func (p *SrcPool) MarkConnDeadV6() (ip [16]byte, marked bool) {
	if p.v6 == nil {
		return ip, false
	}
	return p.v6.markConnDead()
}

// Resurrect clears expired cooldowns across both families and resets
// their death streak. Intended to be called periodically (e.g. every
// 5s) from a single goroutine in the client.
func (p *SrcPool) Resurrect() (resurrected int) {
	now := time.Now().UnixNano()
	if p.v4 != nil {
		resurrected += p.v4.resurrect(now)
	}
	if p.v6 != nil {
		resurrected += p.v6.resurrect(now)
	}
	return
}

// ForceResurrectAll force-clears every active cooldown across both
// families regardless of expiry. Returns the count of entries
// actually flipped from cooldown back to healthy. Used by the
// `srcpool resurrect` admin command without an IP argument so an
// operator can kick a quarantined pool back to life immediately
// after a transient firewall blip without waiting for the cooldown
// to expire on its own.
func (p *SrcPool) ForceResurrectAll() int {
	resurrected := 0
	if p.v4 != nil {
		resurrected += p.v4.forceResurrect()
	}
	if p.v6 != nil {
		resurrected += p.v6.forceResurrect()
	}
	return resurrected
}

// ForceResurrectIP parses ipStr and force-clears the matching
// pool entry's cooldown. Returns (true, nil) when the entry was
// found AND was on cooldown; (false, nil) when the IP exists but
// was already healthy; (false, error) when the IP doesn't parse
// or isn't in the pool. v4 and v6 share one code path via the
// canonical 4-or-16-byte representation.
func (p *SrcPool) ForceResurrectIP(ipStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("not an IP address: %q", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		if p.v4 == nil {
			return false, fmt.Errorf("ipv4 pool is empty")
		}
		var key [4]byte
		copy(key[:], v4)
		return p.v4.forceResurrectOne(key), nil
	}
	if p.v6 == nil {
		return false, fmt.Errorf("ipv6 pool is empty")
	}
	var key [16]byte
	copy(key[:], ip.To16())
	return p.v6.forceResurrectOne(key), nil
}

// SrcStatus is the per-IP snapshot returned by Snapshot for
// observability (Prometheus gauges, admin endpoints).
type SrcStatus struct {
	IP            string
	Healthy       bool
	CooldownUntil time.Time
	DeathStreak   uint32
	CooldownLevel uint32
	LastSentAgo   time.Duration
	SentCount     uint64
}

// Snapshot returns a stable snapshot of all entries (v4 then v6) in
// pool order. Safe to call from any goroutine.
func (p *SrcPool) Snapshot() []SrcStatus {
	out := make([]SrcStatus, 0, p.size())
	now := time.Now()
	if p.v4 != nil {
		for i, ip := range p.v4.ips {
			out = append(out, p.v4.statusAt(i, ip[:], now))
		}
	}
	if p.v6 != nil {
		for i, ip := range p.v6.ips {
			out = append(out, p.v6.statusAt(i, ip[:], now))
		}
	}
	return out
}

func (p *SrcPool) size() int {
	n := 0
	if p.v4 != nil {
		n += len(p.v4.ips)
	}
	if p.v6 != nil {
		n += len(p.v6.ips)
	}
	return n
}

// IPsV4 exposes the underlying v4 slice; callers must not mutate.
func (p *SrcPool) IPsV4() [][4]byte {
	if p.v4 == nil {
		return nil
	}
	return p.v4.ips
}

// IPsV6 exposes the underlying v6 slice; callers must not mutate.
func (p *SrcPool) IPsV6() [][16]byte {
	if p.v6 == nil {
		return nil
	}
	return p.v6.ips
}

// pick walks the IPs starting at the FNV-indexed entry, returning the
// first non-quarantined one. Falls back to the FNV index when every
// entry is in cooldown (failing closed would drop all egress).
func (s *SrcSet) pick(payload []byte) (*[4]byte, int) {
	if len(s.ips) == 1 {
		return &s.ips[0], 0
	}
	now := time.Now().UnixNano()
	var start uint64
	if len(payload) >= 9 {
		start = fnv1aIndex(payload, uint64(len(s.ips)))
	} else {
		start = uint64(mrand.IntN(len(s.ips)))
	}
	n := uint64(len(s.ips))
	for off := range n {
		idx := (start + off) % n
		if s.cooldownUntil[idx].Load() <= now {
			return &s.ips[idx], int(idx)
		}
	}
	// All in cooldown — return the FNV-indexed entry anyway. The
	// resurrect tick will eventually clear cooldowns; in the meantime
	// dropping every packet would be strictly worse.
	return &s.ips[start], int(start)
}

func (s *SrcSet) markConnDead() (out [4]byte, marked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixNano()
	stale := s.cfg.StaleSendThreshold.Nanoseconds()

	// Active IPs are those not currently in cooldown. We need at least
	// 2 active entries to safely quarantine one (otherwise the last
	// active IP would be killed and we'd have nothing left).
	active := make([]lastSentCand, 0, len(s.ips))
	for i := range s.ips {
		if s.cooldownUntil[i].Load() > now {
			continue
		}
		active = append(active, lastSentCand{idx: i, lastSent: s.lastSentNanos[i].Load()})
	}
	if len(active) < 2 {
		// min-healthy guard: refuse to kill the last active IP, even
		// if its sends are stale. Better limping than dead.
		return out, false
	}

	// Sort by lastSent ascending; the first entry is the most stale,
	// the median entry is our reference for "is the staleness gap
	// significant?". Bound is small (typical 1..8) so insertion sort
	// is allocation-free.
	sortByLastSent(active)
	oldest := active[0]
	median := active[len(active)/2].lastSent

	if median-oldest.lastSent < stale {
		// No clear stale outlier — abstain.
		return out, false
	}

	idx := oldest.idx
	streak := s.deathStreak[idx].Add(1)
	if streak < s.cfg.DeathThreshold {
		// First strike — record and bail; let the next dead-conn tick
		// confirm the verdict.
		return out, false
	}

	// Quarantine. Cooldown duration = InitialCooldown * 2^level, capped.
	level := s.cooldownLevel[idx].Add(1)
	dur := s.cfg.InitialCooldown
	for i := uint32(1); i < level && dur < s.cfg.MaxCooldown; i++ {
		dur *= 2
	}
	if dur > s.cfg.MaxCooldown {
		dur = s.cfg.MaxCooldown
	}
	until := time.Now().Add(dur).UnixNano()
	s.cooldownUntil[idx].Store(until)
	s.deathStreak[idx].Store(0)

	out = s.ips[idx]
	slog.Warn("spoof src ip quarantined",
		"component", "transport",
		"family", "v4",
		"ip", net4String(out),
		"cooldown", dur.Round(time.Second),
		"level", level)
	return out, true
}

func (s *SrcSet) resurrect(now int64) int {
	resurrected := 0
	for i := range s.ips {
		until := s.cooldownUntil[i].Load()
		if until == 0 || until > now {
			continue
		}
		// Only flip if the until value hasn't changed in the meantime
		// (another goroutine could have re-quarantined).
		if s.cooldownUntil[i].CompareAndSwap(until, 0) {
			resurrected++
			slog.Info("spoof src ip resurrected",
				"component", "transport",
				"family", "v4",
				"ip", net4String(s.ips[i]))
		}
	}
	return resurrected
}

// forceResurrect ignores the cooldown timestamp and clears every
// active cooldown in the set. Returns the count flipped. Used by
// admin / TUI when an operator wants to short-circuit a transient
// quarantine without waiting for the timer.
func (s *SrcSet) forceResurrect() int {
	resurrected := 0
	for i := range s.ips {
		until := s.cooldownUntil[i].Load()
		if until == 0 {
			continue
		}
		if s.cooldownUntil[i].CompareAndSwap(until, 0) {
			resurrected++
			slog.Info("spoof src ip force-resurrected",
				"component", "transport",
				"family", "v4",
				"ip", net4String(s.ips[i]))
		}
	}
	return resurrected
}

// forceResurrectOne searches the set for ip and clears its cooldown
// if any. Returns true when the entry existed AND was on cooldown,
// false when the IP is healthy or not in the pool.
func (s *SrcSet) forceResurrectOne(ip [4]byte) bool {
	for i := range s.ips {
		if s.ips[i] != ip {
			continue
		}
		until := s.cooldownUntil[i].Load()
		if until == 0 {
			return false
		}
		if s.cooldownUntil[i].CompareAndSwap(until, 0) {
			slog.Info("spoof src ip force-resurrected",
				"component", "transport",
				"family", "v4",
				"ip", net4String(s.ips[i]))
			return true
		}
		return false
	}
	return false
}

func (s *SrcSet) statusAt(i int, ip []byte, now time.Time) SrcStatus {
	until := s.cooldownUntil[i].Load()
	last := s.lastSentNanos[i].Load()
	st := SrcStatus{
		IP:            ipString(ip),
		Healthy:       until <= now.UnixNano(),
		DeathStreak:   s.deathStreak[i].Load(),
		CooldownLevel: s.cooldownLevel[i].Load(),
		SentCount:     s.sentCount[i].Load(),
	}
	if until > 0 {
		st.CooldownUntil = time.Unix(0, until)
	}
	if last > 0 {
		st.LastSentAgo = now.Sub(time.Unix(0, last))
	}
	return st
}

// V6 mirror of the SrcSet methods. The body is identical modulo the
// IP byte width; kept duplicated to avoid generics on the hot path.

func (s *SrcSetV6) pick(payload []byte) (*[16]byte, int) {
	if len(s.ips) == 1 {
		return &s.ips[0], 0
	}
	now := time.Now().UnixNano()
	var start uint64
	if len(payload) >= 9 {
		start = fnv1aIndex(payload, uint64(len(s.ips)))
	} else {
		start = uint64(mrand.IntN(len(s.ips)))
	}
	n := uint64(len(s.ips))
	for off := range n {
		idx := (start + off) % n
		if s.cooldownUntil[idx].Load() <= now {
			return &s.ips[idx], int(idx)
		}
	}
	return &s.ips[start], int(start)
}

func (s *SrcSetV6) markConnDead() (out [16]byte, marked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixNano()
	stale := s.cfg.StaleSendThreshold.Nanoseconds()
	active := make([]lastSentCand, 0, len(s.ips))
	for i := range s.ips {
		if s.cooldownUntil[i].Load() > now {
			continue
		}
		active = append(active, lastSentCand{idx: i, lastSent: s.lastSentNanos[i].Load()})
	}
	if len(active) < 2 {
		return out, false
	}
	sortByLastSent(active)
	median := active[len(active)/2].lastSent
	oldest := active[0]
	if median-oldest.lastSent < stale {
		return out, false
	}
	idx := oldest.idx
	streak := s.deathStreak[idx].Add(1)
	if streak < s.cfg.DeathThreshold {
		return out, false
	}
	level := s.cooldownLevel[idx].Add(1)
	dur := s.cfg.InitialCooldown
	for i := uint32(1); i < level && dur < s.cfg.MaxCooldown; i++ {
		dur *= 2
	}
	if dur > s.cfg.MaxCooldown {
		dur = s.cfg.MaxCooldown
	}
	s.cooldownUntil[idx].Store(time.Now().Add(dur).UnixNano())
	s.deathStreak[idx].Store(0)
	out = s.ips[idx]
	slog.Warn("spoof src ip quarantined",
		"component", "transport",
		"family", "v6",
		"ip", ipString(out[:]),
		"cooldown", dur.Round(time.Second),
		"level", level)
	return out, true
}

func (s *SrcSetV6) resurrect(now int64) int {
	resurrected := 0
	for i := range s.ips {
		until := s.cooldownUntil[i].Load()
		if until == 0 || until > now {
			continue
		}
		if s.cooldownUntil[i].CompareAndSwap(until, 0) {
			resurrected++
			slog.Info("spoof src ip resurrected",
				"component", "transport",
				"family", "v6",
				"ip", ipString(s.ips[i][:]))
		}
	}
	return resurrected
}

// forceResurrect / forceResurrectOne mirror SrcSet's helpers for
// v6. Kept as separate methods (rather than a generic) so the
// log family field stays accurate without runtime branching.
func (s *SrcSetV6) forceResurrect() int {
	resurrected := 0
	for i := range s.ips {
		until := s.cooldownUntil[i].Load()
		if until == 0 {
			continue
		}
		if s.cooldownUntil[i].CompareAndSwap(until, 0) {
			resurrected++
			slog.Info("spoof src ip force-resurrected",
				"component", "transport",
				"family", "v6",
				"ip", ipString(s.ips[i][:]))
		}
	}
	return resurrected
}

func (s *SrcSetV6) forceResurrectOne(ip [16]byte) bool {
	for i := range s.ips {
		if s.ips[i] != ip {
			continue
		}
		until := s.cooldownUntil[i].Load()
		if until == 0 {
			return false
		}
		if s.cooldownUntil[i].CompareAndSwap(until, 0) {
			slog.Info("spoof src ip force-resurrected",
				"component", "transport",
				"family", "v6",
				"ip", ipString(s.ips[i][:]))
			return true
		}
		return false
	}
	return false
}

func (s *SrcSetV6) statusAt(i int, ip []byte, now time.Time) SrcStatus {
	until := s.cooldownUntil[i].Load()
	last := s.lastSentNanos[i].Load()
	st := SrcStatus{
		IP:            ipString(ip),
		Healthy:       until <= now.UnixNano(),
		DeathStreak:   s.deathStreak[i].Load(),
		CooldownLevel: s.cooldownLevel[i].Load(),
		SentCount:     s.sentCount[i].Load(),
	}
	if until > 0 {
		st.CooldownUntil = time.Unix(0, until)
	}
	if last > 0 {
		st.LastSentAgo = now.Sub(time.Unix(0, last))
	}
	return st
}

// IndexOfV4 returns the slice index of ip in the v4 set, or -1.
func (p *SrcPool) IndexOfV4(ip [4]byte) int {
	if p.v4 == nil {
		return -1
	}
	for i, e := range p.v4.ips {
		if e == ip {
			return i
		}
	}
	return -1
}

// IndexOfV6 returns the slice index of ip in the v6 set, or -1.
func (p *SrcPool) IndexOfV6(ip [16]byte) int {
	if p.v6 == nil {
		return -1
	}
	for i, e := range p.v6.ips {
		if e == ip {
			return i
		}
	}
	return -1
}

// sortByLastSent is a tiny insertion sort over (idx,lastSent) entries.
// Pool sizes are typically 1..8 so insertion sort beats sort.Slice
// here both in code size and in allocation count (zero).
type lastSentCand = struct {
	idx      int
	lastSent int64
}

func sortByLastSent(a []lastSentCand) {
	for i := 1; i < len(a); i++ {
		c := a[i]
		j := i - 1
		for j >= 0 && a[j].lastSent > c.lastSent {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = c
	}
}

// ipString returns a canonical text form for any 4- or 16-byte IP.
// Avoids importing net just for one tiny helper.
func ipString(b []byte) string {
	switch len(b) {
	case 4:
		return net4String([4]byte{b[0], b[1], b[2], b[3]})
	case 16:
		return net6String(b)
	}
	return ""
}

func net4String(a [4]byte) string {
	const digits = "0123456789"
	buf := make([]byte, 0, 15)
	for i, n := range a {
		if i > 0 {
			buf = append(buf, '.')
		}
		switch {
		case n >= 100:
			buf = append(buf, digits[n/100], digits[(n/10)%10], digits[n%10])
		case n >= 10:
			buf = append(buf, digits[n/10], digits[n%10])
		default:
			buf = append(buf, digits[n])
		}
	}
	return string(buf)
}

func net6String(a []byte) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, 39)
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			buf = append(buf, ':')
		}
		// Emit two bytes as a 16-bit hextet without leading zeros.
		v := uint16(a[i])<<8 | uint16(a[i+1])
		if v == 0 {
			buf = append(buf, '0')
			continue
		}
		started := false
		for shift := 12; shift >= 0; shift -= 4 {
			d := (v >> shift) & 0xf
			if d != 0 || started {
				buf = append(buf, hex[d])
				started = true
			}
		}
	}
	return string(buf)
}
