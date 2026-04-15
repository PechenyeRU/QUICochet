package tunnel

import (
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
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if r.shutdown() {
				trueCount.Add(1)
			}
		}()
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
