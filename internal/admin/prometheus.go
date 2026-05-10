package admin

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PrometheusStatus reports the state of the on-demand /metrics endpoint.
type PrometheusStatus struct {
	Running bool   `json:"running"`
	Address string `json:"address,omitempty"`
}

// PrometheusServer owns an opt-in HTTP server exposing tunnel state in
// the Prometheus text exposition format. It is a thin translator over
// the same Backend.Snapshot() that powers the admin unix socket — so
// metrics stay in lock-step with the JSON snapshot exposed to admin
// clients, no separate state path to drift.
//
// Lifecycle is the same shape as PprofServer: dormant until Start(),
// idempotent Stop(), safe for concurrent use.
type PrometheusServer struct {
	mu      sync.Mutex
	srv     *http.Server
	ln      net.Listener
	backend Backend
}

// NewPrometheusServer constructs a dormant instance; Start() binds it.
func NewPrometheusServer() *PrometheusServer { return &PrometheusServer{} }

// Start binds a TCP listener at addr and serves /metrics backed by b.
// An empty addr defaults to 127.0.0.1:9200. Calling Start while
// already running is a no-op and returns the current address.
func (p *PrometheusServer) Start(addr string, b Backend) (PrometheusStatus, error) {
	if b == nil {
		return PrometheusStatus{}, fmt.Errorf("prometheus: nil backend")
	}
	if addr == "" {
		addr = "127.0.0.1:9200"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv != nil {
		return PrometheusStatus{Running: true, Address: p.ln.Addr().String()}, nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return PrometheusStatus{}, fmt.Errorf("bind metrics listener on %q: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeMetrics(w, b.Snapshot())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Tiny landing so a casual GET / doesn't 404.
		_, _ = io.WriteString(w, "quiccochet metrics: GET /metrics\n")
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	p.srv = srv
	p.ln = ln
	p.backend = b
	return PrometheusStatus{Running: true, Address: ln.Addr().String()}, nil
}

// Stop tears down the listener; idempotent.
func (p *PrometheusServer) Stop() error {
	p.mu.Lock()
	srv := p.srv
	ln := p.ln
	p.srv = nil
	p.ln = nil
	p.backend = nil
	p.mu.Unlock()
	if srv == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return err
	}
	return nil
}

// Status returns current state.
func (p *PrometheusServer) Status() PrometheusStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv == nil {
		return PrometheusStatus{Running: false}
	}
	return PrometheusStatus{Running: true, Address: p.ln.Addr().String()}
}

// writeMetrics emits the snapshot in Prometheus text format. Each
// metric carries a role="client"|"server" label so a single Prom
// scrape config can target both daemon roles. Metrics that don't
// apply to a role are simply not emitted, avoiding zero-spam in
// queries that select e.g. client-only fields.
func writeMetrics(w io.Writer, s Snapshot) {
	role := s.Role
	if role == "" {
		role = "unknown"
	}
	lbl := func(extra ...string) string {
		// extra is alternating k,v pairs; role label always first.
		var b strings.Builder
		b.WriteString(`{role="`)
		b.WriteString(escapeLabel(role))
		b.WriteByte('"')
		for i := 0; i+1 < len(extra); i += 2 {
			b.WriteByte(',')
			b.WriteString(extra[i])
			b.WriteString(`="`)
			b.WriteString(escapeLabel(extra[i+1]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
		return b.String()
	}

	gauge(w, "quiccochet_up",
		"Tunnel daemon is up. Always 1 when /metrics responds.",
		lbl(), 1)
	gauge(w, "quiccochet_uptime_seconds",
		"Seconds since the daemon started.",
		lbl(), s.UptimeSec)
	gauge(w, "quiccochet_open_fds",
		"Open file descriptors held by the process.",
		lbl(), float64(s.OpenFDs))

	// Pool — client-only.
	if role == "client" {
		gauge(w, "quiccochet_pool_alive",
			"Healthy QUIC connections in the pool.",
			lbl(), float64(s.PoolAlive))
		gauge(w, "quiccochet_pool_total",
			"Total slots in the QUIC connection pool (configured pool_size).",
			lbl(), float64(s.PoolTotal))
		gauge(w, "quiccochet_udp_assocs",
			"Active SOCKS5 UDP ASSOCIATE associations.",
			lbl(), float64(s.UDPAssocs))
	}

	// Server-only counters of UDP relay state.
	if role == "server" {
		gauge(w, "quiccochet_active_sessions",
			"Active inbound stream/datagram sessions on the server.",
			lbl(), float64(s.ActiveSessions))
		counter(w, "quiccochet_udp_routes_total",
			"Cumulative UDP NAT routes installed by the server.",
			lbl(), float64(s.UDPRoutes))
		counter(w, "quiccochet_udp_evictions_total",
			"UDP NAT routes evicted under pressure.",
			lbl(), float64(s.UDPEvictions))
		counter(w, "quiccochet_udp_idle_closed_total",
			"UDP NAT routes closed by idle timeout.",
			lbl(), float64(s.UDPIdleClosed))
		counter(w, "quiccochet_udp_inbound_drops_total",
			"Inbound UDP packets dropped (pool/queue/back-pressure).",
			lbl(), float64(s.UDPInboundDrops))
	}

	// Bytes through the tunnel — both roles.
	counter(w, "quiccochet_bytes_sent_total",
		"Bytes the daemon transmitted via the tunnel.",
		lbl(), float64(s.BytesSent))
	counter(w, "quiccochet_bytes_received_total",
		"Bytes the daemon received via the tunnel.",
		lbl(), float64(s.BytesReceived))

	// QUIC packet quality (client only — server-side has no central registry).
	if role == "client" {
		// PacketsSent IS monotonic per quic-go, expose as counter.
		counter(w, "quiccochet_quic_packets_sent_total",
			"QUIC packets transmitted, aggregated across the pool.",
			lbl(), float64(s.PacketsSent))
		// PacketsLost / BytesLost are NOT monotonic — quic-go decrements
		// them when a "lost" packet arrives late (spurious-loss recovery).
		// Expose as gauge so PromQL doesn't double-count on negative jumps.
		gauge(w, "quiccochet_quic_packets_lost",
			"QUIC packets currently considered lost (aggregated). Not monotonic: quic-go decrements on spurious-loss recovery — use as gauge, derive ratio with quiccochet_quic_packets_sent_total.",
			lbl(), float64(s.PacketsLost))
		gauge(w, "quiccochet_quic_bytes_lost",
			"QUIC bytes currently considered lost (aggregated). Same non-monotonic semantics as packets_lost.",
			lbl(), float64(s.BytesLost))
	}

	// Per-peer counters (server-only). These coexist with the aggregated
	// server metrics above — peer attribution is additive, not a
	// replacement, so existing dashboards/alerts on the role-only
	// series keep working unchanged. Sum across {peer=...} equals the
	// role-level value (modulo packets from unknown wire IPs, which
	// are counted globally but cannot be attributed to a configured
	// peer — typically scanner traffic before TLS pinning rejects).
	for _, p := range s.Peers {
		pLbl := lbl("peer", p.Name)
		counter(w, "quiccochet_peer_bytes_sent_total",
			"Tunnel bytes the server transmitted to this peer.",
			pLbl, float64(p.BytesSent))
		counter(w, "quiccochet_peer_bytes_received_total",
			"Tunnel bytes the server received from this peer.",
			pLbl, float64(p.BytesReceived))
		gauge(w, "quiccochet_peer_active_sessions",
			"QUIC sessions currently active for this peer.",
			pLbl, float64(p.ActiveSessions))
		gauge(w, "quiccochet_peer_udp_routes",
			"Live UDP NAT routes attributed to this peer.",
			pLbl, float64(p.UDPRoutes))
		counter(w, "quiccochet_peer_udp_evictions_total",
			"UDP NAT routes evicted under pressure for this peer.",
			pLbl, float64(p.UDPEvictions))
		counter(w, "quiccochet_peer_udp_idle_closed_total",
			"UDP NAT routes closed by idle timeout for this peer.",
			pLbl, float64(p.UDPIdleClosed))
		counter(w, "quiccochet_peer_udp_inbound_drops_total",
			"Inbound UDP packets dropped (cone-NAT inbound guard) for this peer.",
			pLbl, float64(p.UDPInboundDrops))
		counter(w, "quiccochet_peer_streams_opened_total",
			"QUIC streams the peer has opened against the server.",
			pLbl, float64(p.StreamsOpened))
		// last activity in unix seconds (0 = never seen). gauge so
		// `time() - quiccochet_peer_last_activity_seconds > 60` works.
		lastActSec := 0.0
		if p.LastActivityUnixNano > 0 {
			lastActSec = float64(p.LastActivityUnixNano) / 1e9
		}
		gauge(w, "quiccochet_peer_last_activity_seconds",
			"Unix timestamp (seconds) of the last per-peer counter bump. 0 if the peer has never been seen since process start.",
			pLbl, lastActSec)
	}

	// IP health-check per-source-IP gauges. Emitted on any role when
	// the transport exposes a SrcPool. Use {ip="..."} to scope queries
	// to a specific spoof source, or aggregate across a deployment.
	for _, ip := range s.SpoofIPs {
		ipLbl := lbl("ip", ip.IP)
		healthy := 0.0
		if ip.Healthy {
			healthy = 1
		}
		gauge(w, "quiccochet_spoof_ip_healthy",
			"1 if the spoof source IP is currently active, 0 if quarantined by the IP health-check.",
			ipLbl, healthy)
		gauge(w, "quiccochet_spoof_ip_death_streak",
			"Consecutive conn-death blame strikes recorded against this IP since the last quarantine.",
			ipLbl, float64(ip.DeathStreak))
		gauge(w, "quiccochet_spoof_ip_cooldown_level",
			"Cooldown back-off level applied to this IP (each level doubles the cooldown duration).",
			ipLbl, float64(ip.CooldownLevel))
		gauge(w, "quiccochet_spoof_ip_cooldown_left_seconds",
			"Seconds remaining on the current quarantine. Zero when healthy.",
			ipLbl, ip.CooldownLeftS)
		counter(w, "quiccochet_spoof_ip_sends_total",
			"Total spoofed packets sent through this source IP.",
			ipLbl, float64(ip.SentCount))
	}
}

func gauge(w io.Writer, name, help, labels string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s%s %s\n", name, labels, formatFloat(value))
}

func counter(w io.Writer, name, help, labels string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s%s %s\n", name, labels, formatFloat(value))
}

// formatFloat avoids scientific notation for integer-valued samples
// (counters of bytes/packets) — Prom parsers accept it but operators
// reading raw output expect plain integers.
func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// escapeLabel handles the three characters Prometheus requires
// escaped inside a label value: backslash, double-quote, newline.
// Snapshot fields used as labels are constants (role) so this is
// belt-and-suspenders, but cheap.
func escapeLabel(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
