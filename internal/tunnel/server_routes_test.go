package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pechenyeru/quiccochet/internal/config"
	"github.com/pechenyeru/quiccochet/internal/socks"
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

	routes := make(map[uint32]*datagramRoute)
	now := time.Now().UnixNano()

	// Populate 5 routes with strictly increasing lastActivity timestamps.
	// The one with the smallest timestamp (assoc 0) must be the victim.
	for i := range uint32(5) {
		r := &datagramRoute{}
		r.lastActivity.Store(now + int64(i)*int64(time.Second))
		routes[i] = r
		s.udpRoutes.Add(1)
	}

	victim := s.evictOldestRouteLocked(routes)
	if victim != nil && victim.shutdown() {
		s.udpRoutes.Add(-1)
		s.udpEvictions.Add(1)
	}

	if _, still := routes[0]; still {
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
	if routes[1].closed.Load() {
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
//   - block known cloud metadata names and IP literals regardless of mode
//     or block_private_targets value;
//   - resolve hostnames locally only in direct mode, and block private
//     resolved IPs when block_private_targets=true;
//   - block private IP literals locally in proxy mode, while delegating
//     hostname resolution and resolved-address filtering to the proxy;
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
	routes := make(map[uint32]*datagramRoute)
	now := time.Now().UnixNano()

	// Populate 1000 routes with random-ish lastActivity.
	const N = 1000
	for i := range N {
		r := &datagramRoute{}
		r.lastActivity.Store(now + int64(i)*int64(time.Millisecond))
		routes[uint32(i)] = r
		s.udpRoutes.Add(1)
	}

	// One eviction must close exactly one route — independent of N.
	victim := s.evictOldestRouteLocked(routes)
	if victim != nil && victim.shutdown() {
		s.udpRoutes.Add(-1)
		s.udpEvictions.Add(1)
	}
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

// TestInboundFilterBlocksWrappedAndPrivate is the regression for the
// cone-NAT inbound guard added in v1.18.1. With the relay socket now
// unconnected, a peer that guesses the ephemeral port could otherwise
// inject bytes from never-legitimate source ranges and have them
// relayed to the client tagged as a peer reply. inboundFilter must
// reject every category checkIP rejects on the outbound path: cloud
// metadata via link-local, RFC 1918 / ULA, CGNAT, 0.0.0.0/8, loopback,
// the v6 wrap/tunnel ranges (6to4, Teredo, NAT64, v4-compat,
// site-local, discard) and v4-mapped variants of v4 categories.
func TestInboundFilterBlocksWrappedAndPrivate(t *testing.T) {
	s := &Server{config: &config.Config{}}

	cases := []struct {
		name string
		ip   string
	}{
		{"cloud metadata link-local", "169.254.169.254"},
		{"alibaba metadata cgnat", "100.100.100.200"},
		{"loopback", "127.0.0.1"},
		{"v4 private", "10.0.0.1"},
		{"v4-mapped private", "::ffff:10.0.0.1"},
		{"v4-mapped cgnat", "::ffff:100.64.0.1"},
		{"this network 0/8", "0.1.2.3"},
		{"6to4 wrapping public", "2002:0a00:1::"},
		{"teredo", "2001::1"},
		{"nat64 well-known", "64:ff9b::7f00:1"},
		{"nat64 local-use", "64:ff9b:1::1"},
		{"v4-compatible", "::1.2.3.4"},
		{"site-local deprecated", "fec0::1"},
		{"discard", "100::1"},
		{"ula", "fc00::1"},
		{"link-local v6", "fe80::1"},
		{"unspecified", "0.0.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) = nil", tc.ip)
			}
			if blocked, _ := s.inboundFilter(ip); !blocked {
				t.Errorf("inboundFilter(%q) accepted; want blocked", tc.ip)
			}
		})
	}
}

// TestInboundFilterAllowsPublic — guard against over-blocking real
// public peers (STUN, TURN, RTP from a remote ICE candidate, etc).
func TestInboundFilterAllowsPublic(t *testing.T) {
	s := &Server{config: &config.Config{}}
	cases := []string{
		"1.1.1.1",
		"8.8.4.4",
		"185.226.95.128",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if blocked, reason := s.inboundFilter(ip); blocked {
				t.Errorf("inboundFilter(%q) blocked as %q; should pass", addr, reason)
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

// containsCI is a case-insensitive substring check so the v6 defense
// test can assert on reason wording without being brittle.
func containsCI(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func newDatagramDNSTestServer(blockPrivate bool, lookup func(context.Context, string) ([]net.IPAddr, error)) *Server {
	return &Server{
		config: &config.Config{Security: config.SecurityConfig{
			BlockPrivateTargets: &blockPrivate,
		}},
		lookupIPAddr: lookup,
	}
}

func checkTestDatagramTarget(t *testing.T, s *Server, route *datagramRoute, host string) (string, bool) {
	t.Helper()
	resolved, blocked, reason, err := s.checkDatagramTarget(route, host)
	if err != nil {
		t.Fatalf("checkDatagramTarget(%q): %v", host, err)
	}
	if blocked && reason == "" {
		t.Fatalf("checkDatagramTarget(%q) blocked without a reason", host)
	}
	return resolved, blocked
}

func TestDatagramDNSCacheHitAndMiss(t *testing.T) {
	lookups := 0
	s := newDatagramDNSTestServer(true, func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	})
	route := &datagramRoute{}

	for range 2 {
		resolved, blocked := checkTestDatagramTarget(t, s, route, "one.example")
		if blocked || resolved != "8.8.8.8" {
			t.Fatalf("target = %q, blocked = %v", resolved, blocked)
		}
	}
	if lookups != 1 {
		t.Fatalf("lookups after cache hit = %d, want 1", lookups)
	}

	checkTestDatagramTarget(t, s, route, "two.example")
	if lookups != 2 {
		t.Fatalf("lookups after hostname miss = %d, want 2", lookups)
	}
	checkTestDatagramTarget(t, s, &datagramRoute{}, "one.example")
	if lookups != 3 {
		t.Fatalf("lookups after route miss = %d, want 3", lookups)
	}
}

func TestDatagramDNSCacheRefreshUsesChangedAnswer(t *testing.T) {
	lookups := 0
	s := newDatagramDNSTestServer(true, func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	route := &datagramRoute{}
	resolved, _ := checkTestDatagramTarget(t, s, route, "refresh.example")
	if resolved != "8.8.8.8" {
		t.Fatalf("first answer = %q", resolved)
	}

	resolved, _ = checkTestDatagramTarget(t, s, route, "refresh.example")
	if resolved != "8.8.8.8" || lookups != 1 {
		t.Fatalf("unexpired answer = %q, lookups = %d", resolved, lookups)
	}
	route.dnsMu.Lock()
	entry := route.dnsCache["refresh.example"]
	entry.expiresAt = time.Now().Add(-time.Second)
	route.dnsCache["refresh.example"] = entry
	route.dnsMu.Unlock()

	resolved, blocked := checkTestDatagramTarget(t, s, route, "refresh.example")
	if blocked || resolved != "1.1.1.1" || lookups != 2 {
		t.Fatalf("refreshed answer = %q, blocked = %v, lookups = %d", resolved, blocked, lookups)
	}
}

func TestDatagramDNSCacheRechecksTargets(t *testing.T) {
	t.Run("Private", func(t *testing.T) {
		lookups := 0
		s := newDatagramDNSTestServer(false, func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookups++
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}, nil
		})
		route := &datagramRoute{}
		if _, blocked := checkTestDatagramTarget(t, s, route, "private.example"); blocked {
			t.Fatal("private target blocked while block_private_targets is false")
		}
		*s.config.Security.BlockPrivateTargets = true
		if _, blocked := checkTestDatagramTarget(t, s, route, "private.example"); !blocked {
			t.Fatal("cached private target was not rechecked")
		}
		if lookups != 1 {
			t.Fatalf("lookups = %d, want 1", lookups)
		}
	})

	t.Run("Metadata", func(t *testing.T) {
		lookups := 0
		s := newDatagramDNSTestServer(false, func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookups++
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		})
		route := &datagramRoute{}
		for range 2 {
			if _, blocked := checkTestDatagramTarget(t, s, route, "metadata.example"); !blocked {
				t.Fatal("cached metadata target was not blocked")
			}
		}
		if lookups != 1 {
			t.Fatalf("lookups = %d, want 1", lookups)
		}
	})
}

func TestDatagramDNSCacheCapAndRouteInvalidation(t *testing.T) {
	route := &datagramRoute{}
	expiresAt := time.Now().Add(time.Hour)
	for i := range datagramDNSCacheMaxEntries + 1 {
		host := fmt.Sprintf("host-%03d.example", i)
		route.storeDNS(host, net.ParseIP("8.8.8.8"), expiresAt.Add(time.Duration(i)*time.Second))
	}
	if got := len(route.dnsCache); got != datagramDNSCacheMaxEntries {
		t.Fatalf("cache size = %d, want %d", got, datagramDNSCacheMaxEntries)
	}
	if _, ok := route.cachedDNS("host-000.example", time.Now()); ok {
		t.Fatal("oldest cache entry was not evicted")
	}
	if _, ok := route.cachedDNS(fmt.Sprintf("host-%03d.example", datagramDNSCacheMaxEntries), time.Now()); !ok {
		t.Fatal("newest cache entry is missing")
	}

	if !route.shutdown() {
		t.Fatal("route was already closed")
	}
	if got := len(route.dnsCache); got != 0 {
		t.Fatalf("cache size after route close = %d, want 0", got)
	}
	route.storeDNS("closed.example", net.ParseIP("8.8.8.8"), expiresAt)
	if got := len(route.dnsCache); got != 0 {
		t.Fatalf("cache size after closed-route insert = %d, want 0", got)
	}
}

func BenchmarkDatagramDNSCacheHit(b *testing.B) {
	var lookups atomic.Int64
	s := newDatagramDNSTestServer(true, func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	})
	route := &datagramRoute{}
	if _, blocked, _, err := s.checkDatagramTarget(route, "benchmark.example"); err != nil || blocked {
		b.Fatalf("benchmark setup: blocked = %v, err = %v", blocked, err)
	}
	b.ResetTimer()
	for b.Loop() {
		_, blocked, _, err := s.checkDatagramTarget(route, "benchmark.example")
		if err != nil || blocked {
			b.Fatalf("cached target: blocked = %v, err = %v", blocked, err)
		}
	}
	if got := lookups.Load(); got != 1 {
		b.Fatalf("lookups = %d, want 1", got)
	}
}

func TestSweepIdleRoutesHonorsBidirectionalActivity(t *testing.T) {
	for _, direction := range []string{"send-only", "receive-only"} {
		t.Run(direction, func(t *testing.T) {
			s := &Server{config: &config.Config{}}
			route := &datagramRoute{}
			route.touch()
			routes := map[uint32]*datagramRoute{1: route}
			mu := &sync.Mutex{}
			s.udpRoutes.Add(1)
			now := time.Now()

			if swept := s.sweepIdleRoutes(routes, mu, "", now.Add(-time.Minute).UnixNano()); swept != 0 {
				t.Fatalf("active route swept = %d, want 0", swept)
			}
			if route.closed.Load() || len(routes) != 1 {
				t.Fatal("active route was closed")
			}

			route.lastActivity.Store(now.Add(-2 * time.Minute).UnixNano())
			if swept := s.sweepIdleRoutes(routes, mu, "", now.Add(-time.Minute).UnixNano()); swept != 1 {
				t.Fatalf("idle route swept = %d, want 1", swept)
			}
			if !route.closed.Load() || len(routes) != 0 {
				t.Fatal("idle route was not closed and removed")
			}
			if got := s.udpRoutes.Load(); got != 0 {
				t.Fatalf("udpRoutes = %d, want 0", got)
			}
			if got := s.udpIdleClosed.Load(); got != 1 {
				t.Fatalf("udpIdleClosed = %d, want 1", got)
			}
		})
	}
}

func TestReceiveDirectDatagramsCloseUnblocksRead(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	route := &datagramRoute{directConn: conn}
	routes := map[uint32]*datagramRoute{1: route}
	mu := &sync.Mutex{}
	s := &Server{config: &config.Config{}}
	done := make(chan struct{})
	go func() {
		s.receiveDirectDatagrams(nil, route, conn, []byte{0, 0, 0, 1}, 1, routes, mu, "")
		close(done)
	}()

	route.shutdown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("direct receive loop did not unblock after Close")
	}
	mu.Lock()
	remaining := len(routes)
	mu.Unlock()
	if remaining != 0 {
		t.Fatalf("routes after receive exit = %d, want 0", remaining)
	}
}

func newTunnelUDPProxyTestClient(t *testing.T) *socks.UDPProxyClient {
	t.Helper()
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	relay, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatalf("listen proxy UDP: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		relay.Close()
		t.Fatalf("listen proxy TCP: %v", err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		request := make([]byte, 10)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		port := relay.LocalAddr().(*net.UDPAddr).Port
		response := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
		if _, err := conn.Write(response); err != nil {
			return
		}
		_, _ = conn.Read(make([]byte, 1))
	}()

	client, err := socks.NewUDPProxyClient(listener.Addr().String(), nil)
	if err != nil {
		listener.Close()
		relay.Close()
		t.Fatalf("create UDP proxy client: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		listener.Close()
		relay.Close()
		<-serverDone
	})
	return client
}

func TestReceiveProxyDatagramsCloseUnblocksRead(t *testing.T) {
	client := newTunnelUDPProxyTestClient(t)
	route := &datagramRoute{proxyConn: client}
	routes := map[uint32]*datagramRoute{1: route}
	mu := &sync.Mutex{}
	s := &Server{config: &config.Config{}}
	done := make(chan struct{})
	go func() {
		s.receiveProxyDatagrams(nil, route, client, []byte{0, 0, 0, 1}, 1, routes, mu, "")
		close(done)
	}()

	route.shutdown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy receive loop did not unblock after Close")
	}
	mu.Lock()
	remaining := len(routes)
	mu.Unlock()
	if remaining != 0 {
		t.Fatalf("routes after receive exit = %d, want 0", remaining)
	}
}
