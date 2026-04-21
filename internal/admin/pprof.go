package admin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	nethttppprof "net/http/pprof"
	"sync"
	"time"
)

// PprofStatus reports the state of the on-demand pprof HTTP endpoint.
type PprofStatus struct {
	Running bool   `json:"running"`
	Address string `json:"address,omitempty"`
}

// PprofServer owns an opt-in HTTP server exposing net/http/pprof
// handlers. It binds lazily on Start() and releases on Stop() so a
// daemon pays zero ongoing overhead while debugging is off — the Go
// runtime's built-in heap sampling is always active, so a profile
// captured right after Start() still reflects the full process
// lifetime. Safe for concurrent use.
type PprofServer struct {
	mu  sync.Mutex
	srv *http.Server
	ln  net.Listener
}

// NewPprofServer constructs a dormant instance; Start() binds it.
func NewPprofServer() *PprofServer { return &PprofServer{} }

// Start binds a TCP listener at addr and serves the standard
// /debug/pprof/* handlers. An empty addr defaults to 127.0.0.1:6060.
// Calling Start while already running is a no-op and returns the
// current address.
func (p *PprofServer) Start(addr string) (PprofStatus, error) {
	if addr == "" {
		addr = "127.0.0.1:6060"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv != nil {
		return PprofStatus{Running: true, Address: p.ln.Addr().String()}, nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return PprofStatus{}, fmt.Errorf("bind pprof listener on %q: %w", addr, err)
	}

	mux := http.NewServeMux()
	// pprof.Index handles the directory listing AND every named
	// subprofile (heap, goroutine, allocs, …) by internal dispatch.
	mux.HandleFunc("/debug/pprof/", nethttppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", nethttppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", nethttppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", nethttppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", nethttppprof.Trace)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	p.srv = srv
	p.ln = ln
	return PprofStatus{Running: true, Address: ln.Addr().String()}, nil
}

// Stop tears down the listener; idempotent.
func (p *PprofServer) Stop() error {
	p.mu.Lock()
	srv := p.srv
	ln := p.ln
	p.srv = nil
	p.ln = nil
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

// Status returns current state; lock-free readers get a consistent
// snapshot of the address-while-running invariant.
func (p *PprofServer) Status() PprofStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv == nil {
		return PprofStatus{Running: false}
	}
	return PprofStatus{Running: true, Address: p.ln.Addr().String()}
}
