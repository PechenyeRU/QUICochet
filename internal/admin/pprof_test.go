package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPprofServerLifecycle(t *testing.T) {
	p := NewPprofServer()

	if st := p.Status(); st.Running {
		t.Fatal("fresh server should not be running")
	}

	// 127.0.0.1:0 picks an ephemeral port to avoid collisions.
	st, err := p.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !st.Running || !strings.HasPrefix(st.Address, "127.0.0.1:") {
		t.Fatalf("unexpected start status: %+v", st)
	}

	// Hit the /debug/pprof/ index to prove the mux is actually serving.
	resp, err := http.Get("http://" + st.Address + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET pprof index: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "heap") {
		t.Fatalf("pprof index doesn't look right: status=%d body=%q", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	// Second Start is a no-op and returns the existing address.
	st2, err := p.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if st2.Address != st.Address {
		t.Fatalf("second start should return existing address; got %q vs %q", st2.Address, st.Address)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if st := p.Status(); st.Running {
		t.Fatal("server should be stopped after Stop()")
	}

	// Stop is idempotent.
	if err := p.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}

	// After stop the port must actually be released — listener closed.
	// Give the OS a short grace window for TCP FIN cleanup, then confirm
	// Get fails.
	time.Sleep(50 * time.Millisecond)
	if _, err := http.Get("http://" + st.Address + "/debug/pprof/"); err == nil {
		t.Fatal("pprof endpoint should be unreachable after Stop()")
	}
}

// pprofFakeBackend wires a fakeBackend with a real PprofServer so the
// admin command dispatcher exercises the full path (not just a mock).
type pprofFakeBackend struct {
	fakeBackend
	p *PprofServer
}

func (b *pprofFakeBackend) StartPprof(addr string) (PprofStatus, error) {
	return b.p.Start(addr)
}
func (b *pprofFakeBackend) StopPprof() error        { return b.p.Stop() }
func (b *pprofFakeBackend) PprofStatus() PprofStatus { return b.p.Status() }

func TestAdminPprofCommands(t *testing.T) {
	backend := &pprofFakeBackend{p: NewPprofServer()}
	srv := New(sockPath(t), backend)
	if err := srv.Start(); err != nil {
		t.Fatalf("admin start: %v", err)
	}
	defer srv.Stop()
	defer backend.p.Stop()

	// status on a cold server
	resp := dialAndExec(t, srv.Path(), "pprof status")
	var st PprofStatus
	if err := json.Unmarshal([]byte(resp), &st); err != nil {
		t.Fatalf("status unmarshal: %v (resp=%q)", err, resp)
	}
	if st.Running {
		t.Fatalf("expected cold server not running, got %+v", st)
	}

	// start with ephemeral port
	resp = dialAndExec(t, srv.Path(), "pprof start 127.0.0.1:0")
	if err := json.Unmarshal([]byte(resp), &st); err != nil {
		t.Fatalf("start unmarshal: %v (resp=%q)", err, resp)
	}
	if !st.Running || !strings.HasPrefix(st.Address, "127.0.0.1:") {
		t.Fatalf("unexpected start result: %+v", st)
	}

	// stop
	resp = dialAndExec(t, srv.Path(), "pprof stop")
	if err := json.Unmarshal([]byte(resp), &st); err != nil {
		t.Fatalf("stop unmarshal: %v (resp=%q)", err, resp)
	}
	if st.Running {
		t.Fatalf("expected stopped after stop(); got %+v", st)
	}
}

func TestAdminPprofNotSupportedBackend(t *testing.T) {
	// fakeBackend doesn't implement PprofBackend.
	srv := New(sockPath(t), &fakeBackend{})
	if err := srv.Start(); err != nil {
		t.Fatalf("admin start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "pprof status")
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp), &errResp); err != nil {
		t.Fatalf("unmarshal: %v (resp=%q)", err, resp)
	}
	if !strings.Contains(errResp.Error, "not supported") {
		t.Fatalf("expected 'not supported' error, got %q", errResp.Error)
	}
}
