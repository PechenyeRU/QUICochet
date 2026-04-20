package admin

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct{ snap Snapshot }

func (f *fakeBackend) Snapshot() Snapshot { return f.snap }

func sockPath(t *testing.T) string {
	t.Helper()
	// Unix socket path length is capped at 108 bytes on Linux;
	// t.TempDir() under /tmp is short enough.
	return filepath.Join(t.TempDir(), "admin.sock")
}

func dialAndExec(t *testing.T, path, cmd string) string {
	t.Helper()
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte(cmd + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(line)
}

func TestServerStatsCommand(t *testing.T) {
	backend := &fakeBackend{snap: Snapshot{
		Role:          "client",
		PoolAlive:     4,
		PoolTotal:     4,
		BytesSent:     1024,
		BytesReceived: 2048,
		OpenFDs:       16,
		StartedAt:     time.Now(),
		UptimeSec:     1.5,
	}}
	srv := New(sockPath(t), backend)
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "stats")

	var got Snapshot
	if err := json.Unmarshal([]byte(resp), &got); err != nil {
		t.Fatalf("unmarshal response %q: %v", resp, err)
	}
	if got.Role != "client" || got.PoolAlive != 4 || got.BytesSent != 1024 || got.BytesReceived != 2048 {
		t.Fatalf("snapshot mismatch: %+v", got)
	}
}

func TestServerUnknownCommand(t *testing.T) {
	srv := New(sockPath(t), &fakeBackend{})
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, srv.Path(), "garbage")
	var got map[string]string
	if err := json.Unmarshal([]byte(resp), &got); err != nil {
		t.Fatalf("unmarshal %q: %v", resp, err)
	}
	if !strings.Contains(got["error"], "unknown command") {
		t.Fatalf("expected unknown command error, got %v", got)
	}
}

func TestServerRejectsDuplicateBinding(t *testing.T) {
	path := sockPath(t)
	a := New(path, &fakeBackend{})
	if err := a.Start(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	defer a.Stop()

	b := New(path, &fakeBackend{})
	if err := b.Start(); err == nil {
		b.Stop()
		t.Fatal("expected second Start() to fail while first is running")
	}
}

func TestServerClearsStaleSocketFile(t *testing.T) {
	path := sockPath(t)
	// Simulate a previous crash that left the socket file behind.
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatalf("pre-create stale file: %v", err)
	}

	srv := New(path, &fakeBackend{})
	if err := srv.Start(); err != nil {
		t.Fatalf("start over stale file: %v", err)
	}
	defer srv.Stop()

	resp := dialAndExec(t, path, "stats")
	if !strings.Contains(resp, `"bytes_sent":0`) {
		t.Fatalf("expected empty snapshot fields, got %q", resp)
	}
}
