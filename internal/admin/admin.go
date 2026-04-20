// Package admin implements a Unix-domain socket control plane for a
// running tunnel daemon. Operators connect to the socket to fetch
// runtime statistics on demand and (in future stages) to trigger
// in-link benchmarks without disturbing the live session.
//
// Protocol: one request per connection, single line terminated by \n.
// The response is a single line of JSON followed by EOF. Unknown
// commands return {"error": "..."}.
package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Snapshot is a point-in-time view of tunnel state, emitted by the
// `stats` command as JSON. Fields that don't apply to the current
// role (client vs server) are omitted via omitempty.
type Snapshot struct {
	Role           string    `json:"role"`
	PoolAlive      int       `json:"pool_alive,omitempty"`
	PoolTotal      int       `json:"pool_total,omitempty"`
	UDPAssocs      int       `json:"udp_assocs,omitempty"`
	ActiveSessions int32     `json:"active_sessions,omitempty"`
	UDPRoutes      int64     `json:"udp_routes,omitempty"`
	UDPEvictions   uint64    `json:"udp_evictions,omitempty"`
	UDPIdleClosed  uint64    `json:"udp_idle_closed,omitempty"`
	BytesSent      uint64    `json:"bytes_sent"`
	BytesReceived  uint64    `json:"bytes_received"`
	OpenFDs        int       `json:"open_fds"`
	StartedAt      time.Time `json:"started_at"`
	UptimeSec      float64   `json:"uptime_sec"`
}

// Backend is implemented by the tunnel roles (Client, Server) to
// expose the operations the admin server can invoke.
type Backend interface {
	Snapshot() Snapshot
}

// BenchBackend is the optional capability to run an in-link benchmark
// on the live tunnel. Only the client role implements it — the server
// is passive with respect to bench requests. Admin falls back to an
// error response when the live backend doesn't satisfy this interface.
type BenchBackend interface {
	Backend
	RunBench(ctx context.Context, mode string, duration time.Duration) (BenchResult, error)
}

// BenchResult carries the outcome of a bench run. Fields are populated
// conditionally on Mode: latency fills Samples+percentiles; throughput
// fills Bytes+BytesPerSec. Durations are reported in nanoseconds to
// keep the JSON representation loss-free for sub-ms samples.
type BenchResult struct {
	Mode        string  `json:"mode"`
	DurationSec float64 `json:"duration_sec"`

	// Latency mode.
	Samples int   `json:"samples,omitempty"`
	MinNs   int64 `json:"min_ns,omitempty"`
	MaxNs   int64 `json:"max_ns,omitempty"`
	MeanNs  int64 `json:"mean_ns,omitempty"`
	P50Ns   int64 `json:"p50_ns,omitempty"`
	P90Ns   int64 `json:"p90_ns,omitempty"`
	P99Ns   int64 `json:"p99_ns,omitempty"`

	// Throughput mode.
	Bytes       uint64  `json:"bytes,omitempty"`
	BytesPerSec float64 `json:"bytes_per_sec,omitempty"`
}

// Server is an admin Unix socket listener. Safe for concurrent use.
type Server struct {
	path    string
	backend Backend

	listener net.Listener
	wg       sync.WaitGroup

	stopMu sync.Mutex
	closed bool
}

// New creates a Server bound to the given path, backed by b.
// Start() must be called to begin accepting.
func New(path string, b Backend) *Server {
	return &Server{path: path, backend: b}
}

// Start binds the listener, sets the socket file to mode 0600, and
// begins accepting in the background. If another live daemon is
// already listening on the same path, Start returns an error rather
// than silently unlinking.
func (s *Server) Start() error {
	if _, err := net.DialTimeout("unix", s.path, 200*time.Millisecond); err == nil {
		return fmt.Errorf("admin socket %q already in use by another daemon", s.path)
	}
	_ = os.Remove(s.path)

	l, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("bind admin socket %q: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0600); err != nil {
		l.Close()
		_ = os.Remove(s.path)
		return fmt.Errorf("chmod admin socket: %w", err)
	}
	s.listener = l

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Path returns the socket path the server is (or will be) bound to.
func (s *Server) Path() string { return s.path }

// Stop closes the listener, removes the socket file, and waits for
// in-flight handlers to return. Idempotent.
func (s *Server) Stop() {
	s.stopMu.Lock()
	if s.closed {
		s.stopMu.Unlock()
		return
	}
	s.closed = true
	s.stopMu.Unlock()

	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	_ = os.Remove(s.path)
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("admin accept error", "component", "admin", "err", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	// Short deadline for the command line itself; per-command branches
	// extend it when they need more time (bench can take several seconds).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	cmd := strings.TrimSpace(line)
	enc := json.NewEncoder(conn)
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		_ = enc.Encode(map[string]string{"error": "empty command"})
		return
	}
	switch fields[0] {
	case "stats":
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = enc.Encode(s.backend.Snapshot())
	case "bench":
		s.handleBench(conn, enc, fields[1:])
	default:
		_ = enc.Encode(map[string]string{"error": fmt.Sprintf("unknown command: %s", cmd)})
	}
}

// handleBench parses `bench <mode> [duration]` and drives the tunnel
// backend's RunBench. Default duration is 5s. The connection's write
// deadline is set to the bench duration plus generous slack.
func (s *Server) handleBench(conn net.Conn, enc *json.Encoder, args []string) {
	bb, ok := s.backend.(BenchBackend)
	if !ok {
		_ = enc.Encode(map[string]string{"error": "bench is only supported in client mode"})
		return
	}
	if len(args) < 1 {
		_ = enc.Encode(map[string]string{"error": "usage: bench <latency|throughput> [duration]"})
		return
	}
	mode := args[0]
	dur := 5 * time.Second
	if len(args) >= 2 {
		d, err := time.ParseDuration(args[1])
		if err != nil || d <= 0 {
			_ = enc.Encode(map[string]string{"error": fmt.Sprintf("invalid duration %q: %v", args[1], err)})
			return
		}
		dur = d
	}

	_ = conn.SetWriteDeadline(time.Now().Add(dur + 15*time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), dur+10*time.Second)
	defer cancel()
	res, err := bb.RunBench(ctx, mode, dur)
	if err != nil {
		_ = enc.Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = enc.Encode(res)
}
