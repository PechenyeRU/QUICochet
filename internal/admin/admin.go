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
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return
	}
	cmd := strings.TrimSpace(line)
	enc := json.NewEncoder(conn)
	switch cmd {
	case "stats":
		_ = enc.Encode(s.backend.Snapshot())
	case "":
		_ = enc.Encode(map[string]string{"error": "empty command"})
	default:
		_ = enc.Encode(map[string]string{"error": fmt.Sprintf("unknown command: %s", cmd)})
	}
}
