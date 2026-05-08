// Command fake-admin emits a synthetic admin.Snapshot over a Unix
// socket so the TUI evaluation harness has live-looking data without
// a real tunnel. Bytes / packets advance monotonically; bandwidth
// follows a slow sine wave so the dashboard sparklines have visible
// motion; loss spikes occasionally to drive the connection-state
// classifier through degraded → healthy transitions. Used only by
// the TUI evaluation harness; not shipped in any release artifact.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

func main() {
	sock := flag.String("socket", "/tmp/quiccochet-fake.sock", "unix socket path")
	role := flag.String("role", "client", "role: client or server")
	mode := flag.String("mode", "live", "data mode: live (sine-wave bandwidth + loss spikes) or static (frozen snapshot)")
	flag.Parse()

	_ = os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatalf("listen %s: %v", *sock, err)
	}
	if err := os.Chmod(*sock, 0600); err != nil {
		log.Fatalf("chmod: %v", err)
	}
	log.Printf("fake-admin listening on %s (role=%s, mode=%s)", *sock, *role, *mode)

	gen := newGen(*role, *mode)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go handle(c, gen)
	}
}

func handle(c net.Conn, gen *generator) {
	defer c.Close()
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	enc := json.NewEncoder(c)
	switch strings.TrimSpace(line) {
	case "stats":
		_ = enc.Encode(gen.snapshot())
	default:
		_ = enc.Encode(map[string]string{"error": "unknown command"})
	}
}

// generator holds the state that evolves between successive `stats`
// requests so the TUI dashboard sees a moving target rather than the
// frozen canned snapshot the previous fixture emitted.
//
// Concurrency: handle() goroutines call snapshot() concurrently, so
// every mutation is guarded by mu. The work per call is trivial
// (one tick of integer math); locking overhead is irrelevant.
type generator struct {
	mu sync.Mutex

	role    string
	mode    string // "live" or "static"
	started time.Time

	// Cumulative counters returned to the TUI.
	bytesSent     uint64
	bytesRecv     uint64
	packetsSent   uint64
	packetsLost   uint64

	// Pool oscillator: every ~30 s a single spoof IP gets quarantined
	// and recovers, so the dashboard state badge cycles through
	// healthy → degraded → healthy.
	poolPhase float64

	// Internal time used for the sine-wave bandwidth — separate from
	// wall clock so a reset rolls the wave smoothly to zero rather
	// than jumping forward by however long the process has been up.
	t time.Time

	rng *rand.Rand
}

func newGen(role, mode string) *generator {
	now := time.Now()
	g := &generator{
		role:    role,
		mode:    mode,
		started: now.Add(-3*time.Hour - 4*time.Minute),
		t:       now,
		rng:     rand.New(rand.NewPCG(uint64(now.UnixNano()), 0)),
	}
	// Seed the cumulative gauges with plausible values so the
	// dashboard's "Bytes sent" panel doesn't read 0 B on first poll.
	g.bytesSent = 132 * 1024 * 1024
	g.bytesRecv = 482 * 1024 * 1024
	g.packetsSent = 99_834
	g.packetsLost = 47
	return g
}

// snapshot advances the synthetic state by one tick (one second of
// modeled time) and returns the resulting admin.Snapshot. In static
// mode the cumulative gauges are returned untouched so vhs tape
// recordings stay deterministic.
func (g *generator) snapshot() admin.Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.mode != "static" {
		g.advance()
	}

	switch g.role {
	case "server":
		return admin.Snapshot{
			Role:            "server",
			ActiveSessions:  4,
			UDPRoutes:       128,
			UDPEvictions:    2,
			UDPIdleClosed:   17,
			UDPInboundDrops: 0,
			BytesSent:       g.bytesSent,
			BytesReceived:   g.bytesRecv,
			OpenFDs:         92,
			StartedAt:       g.started,
			UptimeSec:       time.Since(g.started).Seconds(),
		}
	}

	// Pool: 8/8 most of the time, drops to 7/8 for a 5-second
	// window every ~30 s so the operator sees the state badge move.
	poolAlive, poolTotal := 8, 8
	if math.Sin(g.poolPhase) > 0.93 {
		poolAlive = 7
	}

	// Spoof IPs: track the pool oscillator. When degraded, IP #3
	// flips unhealthy with a non-zero cooldown so the Spoof IPs
	// tab shows the same event surface.
	ips := []admin.SpoofIPStatus{
		{IP: "192.168.10.79", Healthy: true, SentCount: 9_821 + g.packetsSent/3, LastSentAgoS: 0.4},
		{IP: "192.168.10.80", Healthy: true, SentCount: 8_742 + g.packetsSent/4, LastSentAgoS: 1.1},
		{IP: "192.168.10.81", Healthy: poolAlive == 8, SentCount: 5_300 + g.packetsSent/6, LastSentAgoS: 2.0},
	}
	if poolAlive < 8 {
		ips[2].DeathStreak = 2
		ips[2].CooldownLevel = 2
		ips[2].CooldownLeftS = 47
	}

	return admin.Snapshot{
		Role:          "client",
		PoolAlive:     poolAlive,
		PoolTotal:     poolTotal,
		UDPAssocs:     3,
		BytesSent:     g.bytesSent,
		BytesReceived: g.bytesRecv,
		PacketsSent:   g.packetsSent,
		PacketsLost:   g.packetsLost,
		BytesLost:     uint64(g.packetsLost) * 1300,
		OpenFDs:       56,
		StartedAt:     g.started,
		UptimeSec:     time.Since(g.started).Seconds(),
		SpoofIPs:      ips,
	}
}

// advance models one second of tunnel activity:
//
//   - sent / recv bandwidth follows a sine wave between ~2 MiB/s and
//     ~14 MiB/s with a 60-second period, so a btop-style sparkline
//     fills with visible peaks and troughs in under a minute.
//   - packet rate scales with bandwidth (1 packet ≈ 1.3 KB).
//   - loss is normally 0 but spikes randomly ~3 % of ticks to drive
//     the connection-state classifier through degraded transitions.
//   - pool oscillator advances at a fixed rate so the badge change
//     is visible in a few seconds of recording.
func (g *generator) advance() {
	g.t = g.t.Add(time.Second)
	phase := float64(time.Since(g.started).Seconds()) * (2 * math.Pi / 60)
	// 8 ± 6 MiB/s — fits comfortably into a single-stream UDP
	// envelope without bumping into MAX/PEAK formatting edge cases.
	mibps := 8.0 + 6.0*math.Sin(phase)
	if mibps < 1 {
		mibps = 1
	}
	bytesPerSec := uint64(mibps * 1024 * 1024)
	g.bytesSent += bytesPerSec
	// Recv runs ~30 % below sent so the two sparklines aren't
	// indistinguishable; mirrors a typical client mostly uploading.
	g.bytesRecv += bytesPerSec * 7 / 10

	// 1 packet ≈ 1300 B (after obfuscator overhead).
	pktsPerSec := bytesPerSec / 1300
	g.packetsSent += pktsPerSec
	if g.rng.Float64() < 0.03 {
		// Loss spike: lose ~0.5..1.5 % of this tick's packets.
		spike := pktsPerSec * (5 + uint64(g.rng.IntN(10))) / 1000
		g.packetsLost += spike
	}

	g.poolPhase += 0.21 // ~30 s per cycle at 1 Hz polling
}
