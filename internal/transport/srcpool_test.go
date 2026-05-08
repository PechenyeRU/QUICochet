package transport

import (
	"testing"
	"time"
)

func dcid(b byte) []byte {
	// 16-byte short-header-shaped buffer; bytes [1..9) are hashed.
	out := make([]byte, 16)
	out[1] = b
	out[2] = b ^ 0x55
	return out
}

func TestSrcPool_PickV4_SkipsCooldown(t *testing.T) {
	ips := [][4]byte{
		{1, 1, 1, 1},
		{2, 2, 2, 2},
		{3, 3, 3, 3},
	}
	p := NewSrcPool(ips, nil, SrcPoolConfig{InitialCooldown: time.Hour})
	// Force entry 0 into cooldown directly.
	p.V4().cooldownUntil[0].Store(time.Now().Add(time.Hour).UnixNano())

	for i := range 100 {
		got, _ := p.PickV4(dcid(byte(i)))
		if got == nil {
			t.Fatal("nil pick")
		}
		if *got == ips[0] {
			t.Fatalf("picked quarantined IP: %v", *got)
		}
	}
}

func TestSrcPool_PickV4_FallsBackWhenAllDown(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{})
	now := time.Now().Add(time.Hour).UnixNano()
	p.V4().cooldownUntil[0].Store(now)
	p.V4().cooldownUntil[1].Store(now)
	got, _ := p.PickV4(dcid(7))
	if got == nil {
		t.Fatal("expected fallback, got nil — would drop traffic")
	}
}

func TestSrcPool_MarkConnDead_RequiresStaleness(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}, {3, 3, 3, 3}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{
		DeathThreshold:     1, // strike-out on first call
		StaleSendThreshold: 5 * time.Second,
	})
	now := time.Now()
	// All three entries have similar fresh send timestamps — no clear blame target.
	for i := range ips {
		p.V4().lastSentNanos[i].Store(now.UnixNano())
	}
	if _, ok := p.MarkConnDeadV4(); ok {
		t.Fatal("blamed fresh entry — should abstain when no staleness gap")
	}
}

func TestSrcPool_MarkConnDead_BlamesStalest(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}, {3, 3, 3, 3}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{
		DeathThreshold:     1,
		StaleSendThreshold: 5 * time.Second,
		InitialCooldown:    30 * time.Second,
		MaxCooldown:        5 * time.Minute,
	})
	now := time.Now()
	// IP 0 has stale send (30s ago); IP 1 and 2 are fresh (just now).
	p.V4().lastSentNanos[0].Store(now.Add(-30 * time.Second).UnixNano())
	p.V4().lastSentNanos[1].Store(now.UnixNano())
	p.V4().lastSentNanos[2].Store(now.UnixNano())

	ip, ok := p.MarkConnDeadV4()
	if !ok {
		t.Fatal("expected blame on stalest entry")
	}
	if ip != ips[0] {
		t.Fatalf("blamed wrong IP: got %v want %v", ip, ips[0])
	}
	// Verify cooldown was applied.
	if p.V4().cooldownUntil[0].Load() <= now.UnixNano() {
		t.Fatal("cooldownUntil not set after blame")
	}
}

func TestSrcPool_MinHealthyGuard(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{
		DeathThreshold:     1,
		StaleSendThreshold: 5 * time.Second,
		InitialCooldown:    time.Hour,
	})
	now := time.Now()
	// Quarantine entry 1; only entry 0 is active.
	p.V4().cooldownUntil[1].Store(now.Add(time.Hour).UnixNano())
	p.V4().lastSentNanos[0].Store(now.Add(-30 * time.Second).UnixNano())

	if _, ok := p.MarkConnDeadV4(); ok {
		t.Fatal("min-healthy guard violated: blamed last active IP")
	}
}

func TestSrcPool_DeathThresholdGate(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}, {3, 3, 3, 3}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{
		DeathThreshold:     2, // need 2 consecutive blames
		StaleSendThreshold: 5 * time.Second,
		InitialCooldown:    30 * time.Second,
	})
	now := time.Now()
	p.V4().lastSentNanos[0].Store(now.Add(-30 * time.Second).UnixNano())
	p.V4().lastSentNanos[1].Store(now.UnixNano())
	p.V4().lastSentNanos[2].Store(now.UnixNano())

	if _, ok := p.MarkConnDeadV4(); ok {
		t.Fatal("first strike should not quarantine when threshold=2")
	}
	if _, ok := p.MarkConnDeadV4(); !ok {
		t.Fatal("second strike should quarantine")
	}
}

func TestSrcPool_Resurrect(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{})
	// Set a cooldown that already expired.
	p.V4().cooldownUntil[0].Store(time.Now().Add(-time.Second).UnixNano())
	if got := p.Resurrect(); got != 1 {
		t.Fatalf("resurrected=%d want 1", got)
	}
	if p.V4().cooldownUntil[0].Load() != 0 {
		t.Fatal("cooldown not cleared")
	}
}

func TestSrcPool_ExponentialBackoff(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}}
	cfg := SrcPoolConfig{
		DeathThreshold:     1,
		StaleSendThreshold: time.Second,
		InitialCooldown:    10 * time.Second,
		MaxCooldown:        time.Hour,
	}
	p := NewSrcPool(ips, nil, cfg)
	now := time.Now()

	// Round 1: blame entry 0.
	p.V4().lastSentNanos[0].Store(now.Add(-30 * time.Second).UnixNano())
	p.V4().lastSentNanos[1].Store(now.UnixNano())
	if _, ok := p.MarkConnDeadV4(); !ok {
		t.Fatal("round 1: expected quarantine")
	}
	round1Until := p.V4().cooldownUntil[0].Load()

	// Resurrect manually by setting cooldown in the past.
	p.V4().cooldownUntil[0].Store(0)
	// Round 2: blame entry 0 again — cooldownLevel should now apply 2x.
	p.V4().lastSentNanos[0].Store(now.Add(-30 * time.Second).UnixNano())
	if _, ok := p.MarkConnDeadV4(); !ok {
		t.Fatal("round 2: expected quarantine")
	}
	round2Until := p.V4().cooldownUntil[0].Load()
	round1Dur := round1Until - now.UnixNano()
	round2Dur := round2Until - now.UnixNano()
	if round2Dur <= round1Dur {
		t.Fatalf("expected exponential backoff; round1=%d round2=%d", round1Dur, round2Dur)
	}
}

func TestSrcPool_RecordSendTracksTimestamp(t *testing.T) {
	ips := [][4]byte{{1, 1, 1, 1}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{})
	before := time.Now().UnixNano()
	p.RecordSendV4(0)
	after := time.Now().UnixNano()
	got := p.V4().lastSentNanos[0].Load()
	if got < before || got > after {
		t.Fatalf("timestamp not recorded in window: got=%d range=[%d,%d]", got, before, after)
	}
	if c := p.V4().sentCount[0].Load(); c != 1 {
		t.Fatalf("sentCount=%d want 1", c)
	}
}

func TestSrcPool_Snapshot(t *testing.T) {
	ips := [][4]byte{{10, 0, 0, 1}, {10, 0, 0, 2}}
	p := NewSrcPool(ips, nil, SrcPoolConfig{InitialCooldown: time.Hour})
	p.V4().cooldownUntil[1].Store(time.Now().Add(time.Hour).UnixNano())

	snap := p.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len=%d want 2", len(snap))
	}
	if !snap[0].Healthy {
		t.Errorf("entry 0 should be healthy")
	}
	if snap[1].Healthy {
		t.Errorf("entry 1 should be unhealthy")
	}
	if snap[0].IP != "10.0.0.1" {
		t.Errorf("entry 0 IP = %q want 10.0.0.1", snap[0].IP)
	}
}

func TestSrcPool_PickV6(t *testing.T) {
	v6 := [][16]byte{
		{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	p := NewSrcPool(nil, v6, SrcPoolConfig{InitialCooldown: time.Hour})
	p.V6().cooldownUntil[0].Store(time.Now().Add(time.Hour).UnixNano())
	for i := range 50 {
		got, _ := p.PickV6(dcid(byte(i)))
		if got == nil {
			t.Fatal("nil pick")
		}
		if *got == v6[0] {
			t.Fatal("picked quarantined v6 IP")
		}
	}
}

func TestNet4String(t *testing.T) {
	cases := []struct {
		in   [4]byte
		want string
	}{
		{[4]byte{0, 0, 0, 0}, "0.0.0.0"},
		{[4]byte{255, 255, 255, 255}, "255.255.255.255"},
		{[4]byte{10, 0, 0, 1}, "10.0.0.1"},
		{[4]byte{192, 168, 1, 100}, "192.168.1.100"},
	}
	for _, c := range cases {
		if got := net4String(c.in); got != c.want {
			t.Errorf("net4String(%v) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestNet6String(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8:0:0:0:0:0:1"},
		{make([]byte, 16), "0:0:0:0:0:0:0:0"},
	}
	for _, c := range cases {
		if got := net6String(c.in); got != c.want {
			t.Errorf("net6String(%x) = %q want %q", c.in, got, c.want)
		}
	}
}
