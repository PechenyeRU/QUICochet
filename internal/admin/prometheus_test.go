package admin

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrometheusServerLifecycle(t *testing.T) {
	p := NewPrometheusServer()

	if st := p.Status(); st.Running {
		t.Fatal("fresh server should not be running")
	}

	be := &fakeBackend{snap: Snapshot{Role: "client", PoolAlive: 4, PoolTotal: 4}}

	st, err := p.Start("127.0.0.1:0", be)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !st.Running || !strings.HasPrefix(st.Address, "127.0.0.1:") {
		t.Fatalf("unexpected start status: %+v", st)
	}

	// Hit /metrics and confirm we got a Prom text payload back.
	resp, err := http.Get("http://" + st.Address + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("unexpected content-type: %q", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), "quiccochet_up") {
		t.Fatalf("body missing quiccochet_up:\n%s", body)
	}

	// Second Start is a no-op and returns the same address.
	st2, err := p.Start("127.0.0.1:0", be)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if st2.Address != st.Address {
		t.Fatalf("second start changed address: %q -> %q", st.Address, st2.Address)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if st := p.Status(); st.Running {
		t.Fatal("stopped server still reports running")
	}

	// Stop is idempotent.
	if err := p.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}

	// After stop the listener is gone — give the kernel a moment to release.
	time.Sleep(50 * time.Millisecond)
	if _, err := http.Get("http://" + st.Address + "/metrics"); err == nil {
		t.Fatal("expected GET to fail after stop")
	}
}

func TestPrometheusServerNilBackend(t *testing.T) {
	p := NewPrometheusServer()
	if _, err := p.Start("127.0.0.1:0", nil); err == nil {
		t.Fatal("expected error on nil backend")
	}
}

func TestPrometheusFormatClient(t *testing.T) {
	snap := Snapshot{
		Role:          "client",
		PoolAlive:     3,
		PoolTotal:     4,
		UDPAssocs:     7,
		BytesSent:     1024,
		BytesReceived: 2048,
		PacketsSent:   100,
		PacketsLost:   5,
		BytesLost:     200,
		OpenFDs:       42,
		StartedAt:     time.Now().Add(-time.Minute),
		UptimeSec:     60.0,
	}
	var sb strings.Builder
	writeMetrics(&sb, snap)
	out := sb.String()

	expects := []string{
		`quiccochet_up{role="client"} 1`,
		`quiccochet_pool_alive{role="client"} 3`,
		`quiccochet_pool_total{role="client"} 4`,
		`quiccochet_udp_assocs{role="client"} 7`,
		`quiccochet_bytes_sent_total{role="client"} 1024`,
		`quiccochet_bytes_received_total{role="client"} 2048`,
		`quiccochet_quic_packets_sent_total{role="client"} 100`,
		`quiccochet_quic_packets_lost{role="client"} 5`,
		`quiccochet_quic_bytes_lost{role="client"} 200`,
		`quiccochet_open_fds{role="client"} 42`,
		`# TYPE quiccochet_up gauge`,
		`# TYPE quiccochet_bytes_sent_total counter`,
		`# TYPE quiccochet_quic_packets_lost gauge`,
	}
	for _, want := range expects {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in metrics output:\n%s", want, out)
		}
	}

	// Server-only metrics must not appear under the client role.
	for _, never := range []string{
		"quiccochet_active_sessions",
		"quiccochet_udp_routes_total",
		"quiccochet_udp_evictions_total",
	} {
		if strings.Contains(out, never) {
			t.Errorf("client output unexpectedly contains server metric %q:\n%s", never, out)
		}
	}
}

func TestPrometheusFormatServer(t *testing.T) {
	snap := Snapshot{
		Role:            "server",
		ActiveSessions:  12,
		UDPRoutes:       100,
		UDPEvictions:    3,
		UDPIdleClosed:   7,
		UDPInboundDrops: 2,
		BytesSent:       5000,
		BytesReceived:   6000,
		OpenFDs:         60,
		UptimeSec:       1800.5,
	}
	var sb strings.Builder
	writeMetrics(&sb, snap)
	out := sb.String()

	expects := []string{
		`quiccochet_up{role="server"} 1`,
		`quiccochet_active_sessions{role="server"} 12`,
		`quiccochet_udp_routes_total{role="server"} 100`,
		`quiccochet_udp_evictions_total{role="server"} 3`,
		`quiccochet_udp_idle_closed_total{role="server"} 7`,
		`quiccochet_udp_inbound_drops_total{role="server"} 2`,
		`quiccochet_uptime_seconds{role="server"} 1800.5`,
	}
	for _, want := range expects {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in metrics output:\n%s", want, out)
		}
	}

	// Client-only metrics must not appear under the server role.
	for _, never := range []string{
		"quiccochet_pool_alive",
		"quiccochet_pool_total",
		"quiccochet_udp_assocs",
		"quiccochet_quic_packets_sent_total",
		"quiccochet_quic_packets_lost",
	} {
		if strings.Contains(out, never) {
			t.Errorf("server output unexpectedly contains client metric %q:\n%s", never, out)
		}
	}
}

func TestPrometheusFormatSpoofIPs(t *testing.T) {
	snap := Snapshot{
		Role: "client",
		SpoofIPs: []SpoofIPStatus{
			{IP: "10.0.0.1", Healthy: true, SentCount: 42_000, LastSentAgoS: 0.5},
			{IP: "10.0.0.2", Healthy: false, DeathStreak: 0, CooldownLevel: 2, CooldownLeftS: 30},
		},
	}
	var sb strings.Builder
	writeMetrics(&sb, snap)
	out := sb.String()

	expects := []string{
		`quiccochet_spoof_ip_healthy{role="client",ip="10.0.0.1"} 1`,
		`quiccochet_spoof_ip_healthy{role="client",ip="10.0.0.2"} 0`,
		`quiccochet_spoof_ip_cooldown_level{role="client",ip="10.0.0.2"} 2`,
		`quiccochet_spoof_ip_cooldown_left_seconds{role="client",ip="10.0.0.2"} 30`,
		`quiccochet_spoof_ip_sends_total{role="client",ip="10.0.0.1"} 42000`,
	}
	for _, want := range expects {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in metrics output:\n%s", want, out)
		}
	}
}

func TestPrometheusFormatPerPeer(t *testing.T) {
	snap := Snapshot{
		Role:           "server",
		ActiveSessions: 3,
		BytesSent:      1500,
		BytesReceived:  900,
		Peers: []PeerStats{
			{
				Name: "vpn1", BytesSent: 1000, BytesReceived: 600,
				ActiveSessions: 2, UDPRoutes: 5, UDPEvictions: 1,
				UDPIdleClosed: 4, UDPInboundDrops: 2, StreamsOpened: 12,
				LastActivityUnixNano: 1_700_000_000_000_000_000,
			},
			{
				Name: "vpn2", BytesSent: 500, BytesReceived: 300,
				ActiveSessions: 1, UDPRoutes: 1, StreamsOpened: 4,
			},
		},
	}
	var sb strings.Builder
	writeMetrics(&sb, snap)
	out := sb.String()

	expects := []string{
		`quiccochet_peer_bytes_sent_total{role="server",peer="vpn1"} 1000`,
		`quiccochet_peer_bytes_received_total{role="server",peer="vpn1"} 600`,
		`quiccochet_peer_active_sessions{role="server",peer="vpn1"} 2`,
		`quiccochet_peer_udp_routes{role="server",peer="vpn1"} 5`,
		`quiccochet_peer_udp_evictions_total{role="server",peer="vpn1"} 1`,
		`quiccochet_peer_udp_idle_closed_total{role="server",peer="vpn1"} 4`,
		`quiccochet_peer_udp_inbound_drops_total{role="server",peer="vpn1"} 2`,
		`quiccochet_peer_streams_opened_total{role="server",peer="vpn1"} 12`,
		`quiccochet_peer_last_activity_seconds{role="server",peer="vpn1"} 1700000000`,
		`quiccochet_peer_bytes_sent_total{role="server",peer="vpn2"} 500`,
		`quiccochet_peer_last_activity_seconds{role="server",peer="vpn2"} 0`,
		// Aggregated server metrics still emitted alongside per-peer.
		`quiccochet_active_sessions{role="server"} 3`,
		`quiccochet_bytes_sent_total{role="server"} 1500`,
	}
	for _, want := range expects {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in metrics output:\n%s", want, out)
		}
	}
}

func TestPrometheusPerPeerOmittedOnClient(t *testing.T) {
	// Client snapshot must not surface peer_* series even if the
	// snapshot accidentally carries Peers — the writer keys the
	// per-peer block off the slice presence, but the client backend
	// never populates it. Sanity-check the empty-slice path.
	snap := Snapshot{Role: "client", BytesSent: 1, BytesReceived: 1}
	var sb strings.Builder
	writeMetrics(&sb, snap)
	if strings.Contains(sb.String(), "quiccochet_peer_") {
		t.Fatalf("client output unexpectedly contains per-peer metric:\n%s", sb.String())
	}
}

func TestEscapeLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{`with "quote"`, `with \"quote\"`},
		{`back\slash`, `back\\slash`},
		{"line\nbreak", `line\nbreak`},
	}
	for _, c := range cases {
		if got := escapeLabel(c.in); got != c.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
