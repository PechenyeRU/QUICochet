// Command fake-admin emits a deterministic admin.Snapshot over a Unix
// socket so vhs tape recordings produce identical pixel output every
// time. Used only by the TUI evaluation harness; not shipped in any
// release artifact.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

func main() {
	sock := flag.String("socket", "/tmp/quiccochet-fake.sock", "unix socket path")
	role := flag.String("role", "client", "role: client or server")
	flag.Parse()

	_ = os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatalf("listen %s: %v", *sock, err)
	}
	if err := os.Chmod(*sock, 0600); err != nil {
		log.Fatalf("chmod: %v", err)
	}
	log.Printf("fake-admin listening on %s (role=%s)", *sock, *role)

	snap := canned(*role)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go handle(c, snap)
	}
}

func handle(c net.Conn, snap admin.Snapshot) {
	defer c.Close()
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	enc := json.NewEncoder(c)
	switch strings.TrimSpace(line) {
	case "stats":
		// Refresh dynamic fields so the dashboard's "last refresh"
		// timestamp visibly updates between recordings.
		s := snap
		s.UptimeSec = time.Since(snap.StartedAt).Seconds()
		_ = enc.Encode(s)
	default:
		_ = enc.Encode(map[string]string{"error": "unknown command"})
	}
}

func canned(role string) admin.Snapshot {
	started := time.Now().Add(-3*time.Hour - 4*time.Minute)
	switch role {
	case "server":
		return admin.Snapshot{
			Role:            "server",
			ActiveSessions:  4,
			UDPRoutes:       128,
			UDPEvictions:    2,
			UDPIdleClosed:   17,
			UDPInboundDrops: 0,
			BytesSent:       482 * 1024 * 1024,
			BytesReceived:   132 * 1024 * 1024,
			OpenFDs:         92,
			StartedAt:       started,
			UptimeSec:       time.Since(started).Seconds(),
		}
	default:
		return admin.Snapshot{
			Role:          "client",
			PoolAlive:     8,
			PoolTotal:     8,
			UDPAssocs:     3,
			BytesSent:     132 * 1024 * 1024,
			BytesReceived: 482 * 1024 * 1024,
			PacketsSent:   99834,
			PacketsLost:   47,
			BytesLost:     61_440,
			OpenFDs:       56,
			StartedAt:     started,
			UptimeSec:     time.Since(started).Seconds(),
			SpoofIPs: []admin.SpoofIPStatus{
				{IP: "192.168.10.79", Healthy: true, SentCount: 9_821, LastSentAgoS: 0.4},
				{IP: "192.168.10.80", Healthy: true, SentCount: 8_742, LastSentAgoS: 1.1},
				{IP: "192.168.10.81", Healthy: false, DeathStreak: 2, CooldownLevel: 2, CooldownLeftS: 47},
			},
		}
	}
}
