package admin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pechenyeru/quiccochet/internal/config"
)

// fakeSrcpoolBackend implements both Backend and SrcpoolBackend so
// the dispatcher takes the resurrect branch. It records the last
// (ip) it was called with so the test can assert the wire shape.
type fakeSrcpoolBackend struct {
	fakeBackend
	calledWith string
	count      int
	found      bool
	err        error
}

func (f *fakeSrcpoolBackend) ForceResurrect(ip string) (int, bool, error) {
	f.calledWith = ip
	return f.count, f.found, f.err
}

// TestServerSrcpoolResurrectAll: an unqualified `srcpool resurrect`
// reaches the backend with ip=="" and the count is echoed in the
// JSON response.
func TestServerSrcpoolResurrectAll(t *testing.T) {
	backend := &fakeSrcpoolBackend{count: 3}
	srv := New(sockPath(t), backend)
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "srcpool resurrect")
	if backend.calledWith != "" {
		t.Errorf("backend called with %q, want \"\"", backend.calledWith)
	}
	var got SrcpoolResurrectResult
	if err := json.Unmarshal([]byte(resp), &got); err != nil {
		t.Fatalf("decode %q: %v", resp, err)
	}
	if got.Resurrected != 3 || got.IP != "" {
		t.Errorf("response = %+v, want resurrected=3 ip=\"\"", got)
	}
}

// TestServerSrcpoolResurrectByIP: with an IP arg the dispatcher
// passes it through to the backend and echoes it in the response.
func TestServerSrcpoolResurrectByIP(t *testing.T) {
	backend := &fakeSrcpoolBackend{count: 1, found: true}
	srv := New(sockPath(t), backend)
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "srcpool resurrect 10.0.0.5")
	if backend.calledWith != "10.0.0.5" {
		t.Errorf("backend called with %q, want 10.0.0.5", backend.calledWith)
	}
	var got SrcpoolResurrectResult
	if err := json.Unmarshal([]byte(resp), &got); err != nil {
		t.Fatalf("decode %q: %v", resp, err)
	}
	if got.IP != "10.0.0.5" {
		t.Errorf("ip echo = %q, want 10.0.0.5", got.IP)
	}
}

// TestServerSrcpoolNotSupported: a backend that doesn't implement
// SrcpoolBackend (e.g. server role) gets a clear error rather than
// a silent ignore.
func TestServerSrcpoolNotSupported(t *testing.T) {
	srv := New(sockPath(t), &fakeBackend{})
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "srcpool resurrect")
	if !strings.Contains(resp, "not supported") {
		t.Errorf("error response should mention 'not supported'; got %q", resp)
	}
}

// fakeConfigBackend implements Backend + ConfigBackend so the
// `config get` path returns a marshalled cfg the test can decode.
type fakeConfigBackend struct {
	fakeBackend
	cfg *config.Config
}

func (f *fakeConfigBackend) Config() *config.Config { return f.cfg }

// TestServerConfigGet: the response is the same JSON shape config.
// Config produces, so the TUI's ConfigGet client can unmarshal it
// without special-case decoding.
func TestServerConfigGet(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeClient}
	cfg.Server.Address = "203.0.113.10"
	cfg.Server.Port = 4242
	srv := New(sockPath(t), &fakeConfigBackend{cfg: cfg})
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "config get")
	var got config.Config
	if err := json.Unmarshal([]byte(resp), &got); err != nil {
		t.Fatalf("decode %q: %v", resp, err)
	}
	if got.Mode != config.ModeClient || got.Server.Address != "203.0.113.10" || got.Server.Port != 4242 {
		t.Errorf("decoded cfg mismatch: %+v", got)
	}
}
