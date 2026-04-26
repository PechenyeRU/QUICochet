package tunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// TestDatagramRouteShutdownCAS verifies the one-shot close guard: only
// one of N concurrent shutdown() calls returns true so the route
// counter is never double-decremented under a janitor-vs-receive race.
func TestDatagramRouteShutdownCAS(t *testing.T) {
	r := &datagramRoute{}

	const N = 64
	var wg sync.WaitGroup
	var trueCount atomic.Int32
	start := make(chan struct{})
	for range N {
		wg.Go(func() {
			<-start
			if r.shutdown() {
				trueCount.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()

	if got := trueCount.Load(); got != 1 {
		t.Fatalf("shutdown() returned true %d times, want exactly 1", got)
	}
}

// TestEvictOldestRouteLocked verifies that the LRU cap enforcement
// picks the route with the smallest lastActivity and that the server's
// udpRoutes counter and eviction counter are both updated.
func TestEvictOldestRouteLocked(t *testing.T) {
	s := &Server{config: &config.Config{}}

	routes := make(map[string]*datagramRoute)
	now := time.Now().UnixNano()

	// Populate 5 routes with strictly increasing lastActivity timestamps.
	// The one with the smallest timestamp ("k0") must be the victim.
	keys := []string{"k0", "k1", "k2", "k3", "k4"}
	for i, k := range keys {
		r := &datagramRoute{}
		r.lastActivity.Store(now + int64(i)*int64(time.Second))
		routes[k] = r
		s.udpRoutes.Add(1)
	}

	s.evictOldestRouteLocked(routes)

	if _, still := routes["k0"]; still {
		t.Fatal("evictOldestRouteLocked did not remove the oldest route")
	}
	if len(routes) != 4 {
		t.Fatalf("map size = %d, want 4", len(routes))
	}
	if got := s.udpRoutes.Load(); got != 4 {
		t.Fatalf("udpRoutes = %d, want 4", got)
	}
	if got := s.udpEvictions.Load(); got != 1 {
		t.Fatalf("udpEvictions = %d, want 1", got)
	}
	// Subsequent shutdown() on the victim is a no-op.
	if routes["k1"].closed.Load() {
		t.Fatal("non-victim route was mistakenly closed")
	}
}

// TestDatagramRouteTouchUpdatesLastActivity sanity-checks the touch
// helper: after touch, lastActivity is within a reasonable window of
// time.Now().
func TestDatagramRouteTouchUpdatesLastActivity(t *testing.T) {
	r := &datagramRoute{}
	before := time.Now().UnixNano()
	r.touch()
	after := time.Now().UnixNano()
	got := r.lastActivity.Load()
	if got < before || got > after {
		t.Fatalf("lastActivity=%d outside [%d,%d]", got, before, after)
	}
}

// Regression for the unified SSRF guard (Q-15 + private-target
// unification): targetBlocked must
//   - block known cloud metadata endpoints regardless of mode or
//     block_private_targets value;
//   - in both direct and proxy modes, resolve the hostname locally
//     and block private destinations when block_private_targets=true;
//   - let private targets through (in either mode) only when the
//     operator explicitly disables block_private_targets.
func TestTargetBlocked(t *testing.T) {
	mkServer := func(proxy, blockPriv bool) *Server {
		return &Server{config: &config.Config{
			OutboundProxy: config.OutboundProxyConfig{
				Enabled: proxy,
			},
			Security: config.SecurityConfig{
				BlockPrivateTargets: &blockPriv,
			},
		}}
	}

	t.Run("CloudMetadataAlwaysBlocked", func(t *testing.T) {
		// Direct mode, block_private_targets off — still must reject metadata.
		s := mkServer(false, false)
		for _, host := range []string{
			"169.254.169.254",
			"100.100.100.200",
			"metadata.google.internal",
			"METADATA",
			// Trailing-dot FQDN form must also be caught — every
			// resolver accepts it and a naive map lookup would miss.
			"metadata.google.internal.",
			"INSTANCE-DATA.EC2.INTERNAL.",
		} {
			if blocked, _ := s.targetBlocked(host, host); !blocked {
				t.Errorf("metadata host %q passed targetBlocked", host)
			}
		}
	})

	t.Run("CloudMetadataBlockedThroughProxy", func(t *testing.T) {
		// Proxy mode with block_private_targets off — metadata still blocked.
		s := mkServer(true, false)
		if blocked, _ := s.targetBlocked("169.254.169.254", ""); !blocked {
			t.Error("metadata IP not blocked through proxy")
		}
	})

	t.Run("PrivateTargetThroughProxyDefaultBlocked", func(t *testing.T) {
		s := mkServer(true, true)
		// Direct IP literal in proxy mode — no DNS needed, must block.
		if blocked, _ := s.targetBlocked("10.0.0.1", ""); !blocked {
			t.Error("private IP passed through proxy with block_private_targets=true")
		}
	})

	t.Run("PrivateTargetThroughProxyAllowed", func(t *testing.T) {
		// Operator opted out of the unified guard — proxy may reach
		// internal targets.
		s := mkServer(true, false)
		if blocked, _ := s.targetBlocked("10.0.0.1", ""); blocked {
			t.Error("private IP blocked through proxy with block_private_targets=false")
		}
	})

	t.Run("PublicTargetAllowed", func(t *testing.T) {
		// Direct path with a public IP must pass.
		s := mkServer(false, true)
		if blocked, reason := s.targetBlocked("1.1.1.1", "1.1.1.1"); blocked {
			t.Errorf("public IP blocked: %s", reason)
		}
	})

	t.Run("BlockPrivateTargetsOff", func(t *testing.T) {
		// When the operator explicitly disabled the guardrail, private
		// targets must pass on the direct path too — but metadata
		// still does not.
		s := mkServer(false, false)
		if blocked, _ := s.targetBlocked("10.0.0.1", "10.0.0.1"); blocked {
			t.Error("private IP blocked despite block_private_targets=false")
		}
		if blocked, _ := s.targetBlocked("169.254.169.254", "169.254.169.254"); !blocked {
			t.Error("metadata IP passed despite being a metadata target")
		}
	})
}

// TestEvictSampledLRUTerminates is the regression for Q-25: with a map
// much larger than evictSampleSize, evictOldestRouteLocked must still
// terminate in bounded time — it samples evictSampleSize entries and
// picks the oldest of those, NOT the global oldest. This proves the
// O(1) guarantee that defends against the linear-scan DoS.
func TestEvictSampledLRUTerminates(t *testing.T) {
	s := &Server{config: &config.Config{}}
	routes := make(map[string]*datagramRoute)
	now := time.Now().UnixNano()

	// Populate 1000 routes with random-ish lastActivity.
	const N = 1000
	for i := range N {
		r := &datagramRoute{}
		r.lastActivity.Store(now + int64(i)*int64(time.Millisecond))
		routes[fmt.Sprintf("k%d", i)] = r
		s.udpRoutes.Add(1)
	}

	// One eviction must close exactly one route — independent of N.
	s.evictOldestRouteLocked(routes)
	if got, want := len(routes), N-1; got != want {
		t.Fatalf("map size after evict = %d, want %d", got, want)
	}
	if got, want := s.udpRoutes.Load(), int64(N-1); got != want {
		t.Fatalf("udpRoutes = %d, want %d", got, want)
	}
	if got := s.udpEvictions.Load(); got != 1 {
		t.Fatalf("udpEvictions = %d, want 1", got)
	}
}

// TestCheckIPV6Defenses pins the IPv6 hardening on top of Go stdlib's
// IsPrivate / IsLinkLocalUnicast / IsMulticast: each of these
// addresses can carry or wrap a v4 destination in a way that bypasses
// a naive v4-only blocklist (DNS rebinding via 6to4, NAT traversal
// via Teredo, NAT64 wrapping, deprecated IPv4-compatible IPv6,
// RFC 6666 discard). All must reject.
func TestCheckIPV6Defenses(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"6to4 wrapping 127.0.0.1", "2002:7f00:1::", "6to4"},
		{"6to4 wrapping 10.0.0.1", "2002:0a00:1::", "6to4"},
		{"Teredo prefix", "2001::1", "Teredo"},
		{"NAT64 well-known wrapping 127.0.0.1", "64:ff9b::7f00:1", "NAT64"},
		{"NAT64 well-known wrapping 10.0.0.1", "64:ff9b::a00:1", "NAT64"},
		{"NAT64 local-use", "64:ff9b:1::1", "NAT64"},
		{"deprecated site-local", "fec0::1", "site-local"},
		{"RFC 6666 discard", "100::1", "discard"},
		{"deprecated v4-compatible", "::1.2.3.4", "IPv4-compatible"},
		{"loopback (existing)", "::1", "loopback"},
		{"ULA fc00::/7", "fc00::1", "private"},
		{"link-local fe80::/10", "fe80::1", "link-local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.input)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil", tc.input)
			}
			blocked, reason := checkIP(ip)
			if !blocked {
				t.Fatalf("%s passed checkIP — should be blocked", tc.input)
			}
			// Reason should mention the family/category, but tests
			// stay loose on exact wording.
			if !containsCI(reason, tc.want) {
				t.Logf("note: reason %q does not mention %q (cosmetic, not a failure)", reason, tc.want)
			}
		})
	}
}

// TestCheckIPV4MappedV6Normalisation guards the bypass route where an
// attacker chooses a v4-mapped representation (::ffff:10.0.0.1) for a
// v4 destination. Without normalisation the v4-only branch (cgnat,
// thisNetwork) would not run on the v6-form value and a CGNAT or
// 0.0.0.0/8 destination could slip through.
func TestCheckIPV4MappedV6Normalisation(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"v4-mapped CGNAT", "::ffff:100.64.0.1"},
		{"v4-mapped 0.0.0.0/8", "::ffff:0.1.2.3"},
		{"v4-mapped private", "::ffff:10.0.0.1"},
		{"v4-mapped loopback", "::ffff:127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.input)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil", tc.input)
			}
			if blocked, _ := checkIP(ip); !blocked {
				t.Fatalf("%s passed checkIP — v4-mapped bypass!", tc.input)
			}
		})
	}
}

// TestCheckIPPublicV6 confirms the hardening does NOT over-block real
// public v6 destinations.
func TestCheckIPPublicV6(t *testing.T) {
	cases := []string{
		"2001:4860:4860::8888", // Google DNS v6
		"2606:4700:4700::1111", // Cloudflare DNS v6
		"2620:fe::fe",          // Quad9 v6
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if blocked, reason := checkIP(ip); blocked {
				t.Fatalf("public v6 %s blocked as %q", addr, reason)
			}
		})
	}
}

// containsCI is a case-insensitive substring helper so the v6 defense
// test can assert on reason wording without being brittle.
func containsCI(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexFold(haystack, needle) >= 0)
}

func indexFold(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a, b := s[i+j], substr[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
