// Package ipc is a thin client over the daemon's admin Unix socket.
// It mirrors the protocol implemented by internal/admin: one request
// line, one JSON response line, EOF. The TUI uses it for read-only
// queries (stats, pprof status) — never to modify daemon state in
// stage 1, so an unreliable connection only degrades the dashboard
// gracefully.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pechenyeru/quiccochet/internal/admin"
)

// Client wraps an admin socket path. It performs one-shot dials per
// request — the admin protocol is single-shot per connection so
// connection pooling would buy nothing and complicate failure modes.
type Client struct {
	socketPath string
}

// New returns a Client targeting socketPath. An empty path is
// permitted; later calls will fail with a clear error so the TUI can
// surface "configure --socket" rather than panicking on dial.
func New(socketPath string) *Client { return &Client{socketPath: socketPath} }

// SocketPath exposes the configured path for status display.
func (c *Client) SocketPath() string { return c.socketPath }

// Reachable returns nil when a connection to the socket succeeds and
// an error describing why otherwise. The 200 ms budget keeps the home
// tab responsive even when the socket file lingers from a crashed
// daemon (kernel-level connect-refused is fast, but we guard against
// listener-less stale paths too).
func (c *Client) Reachable() error {
	if c.socketPath == "" {
		return errors.New("socket path not configured")
	}
	if _, err := os.Stat(c.socketPath); err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", c.socketPath, 200*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// Stats requests a snapshot. The 5-second budget covers a daemon under
// load without making the dashboard's 1 Hz poll loop pile up requests.
func (c *Client) Stats() (admin.Snapshot, error) {
	resp, err := c.sendCmd("stats", 5*time.Second)
	if err != nil {
		return admin.Snapshot{}, err
	}
	if errMsg := decodeError(resp); errMsg != "" {
		return admin.Snapshot{}, errors.New(errMsg)
	}
	var s admin.Snapshot
	if err := json.Unmarshal([]byte(resp), &s); err != nil {
		return admin.Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return s, nil
}

// PprofStatus issues `pprof status` and returns the running state +
// bound address. Empty addr + Running=false is the steady state of
// a daemon that has never been profiled.
func (c *Client) PprofStatus() (admin.PprofStatus, error) {
	return c.sendPprof("pprof status")
}

// PprofStart issues `pprof start [addr]`. Pass "" to let the daemon
// pick a port (it returns the resolved address in PprofStatus.Address).
func (c *Client) PprofStart(addr string) (admin.PprofStatus, error) {
	cmd := "pprof start"
	if addr != "" {
		cmd += " " + addr
	}
	return c.sendPprof(cmd)
}

// PprofStop issues `pprof stop`. Returns the final status (Running
// should be false, Address blank) for symmetry with Start.
func (c *Client) PprofStop() (admin.PprofStatus, error) {
	return c.sendPprof("pprof stop")
}

// SrcpoolResurrect issues `srcpool resurrect [ip]`. With ip == ""
// it clears every active cooldown across the daemon's v4 + v6 pool
// sets; with a specific ip it force-clears that single entry. The
// returned struct reports the count actually flipped.
func (c *Client) SrcpoolResurrect(ip string) (admin.SrcpoolResurrectResult, error) {
	cmd := "srcpool resurrect"
	if ip != "" {
		cmd += " " + ip
	}
	resp, err := c.sendCmd(cmd, 5*time.Second)
	if err != nil {
		return admin.SrcpoolResurrectResult{}, err
	}
	if errMsg := decodeError(resp); errMsg != "" {
		return admin.SrcpoolResurrectResult{}, errors.New(errMsg)
	}
	var r admin.SrcpoolResurrectResult
	if err := json.Unmarshal([]byte(resp), &r); err != nil {
		return admin.SrcpoolResurrectResult{}, fmt.Errorf("decode resurrect result: %w", err)
	}
	return r, nil
}

// Bench issues `bench <mode> [duration] [parallel]` and returns the
// result. Timeout is duration + 15 s of slack so a slow handshake
// or graceful drain doesn't kill the request before the daemon
// finishes its own response. parallel == 0 lets the daemon pick
// the default fan-out for the chosen mode.
func (c *Client) Bench(mode string, duration time.Duration, parallel int) (admin.BenchResult, error) {
	cmd := fmt.Sprintf("bench %s %s", mode, duration.String())
	if parallel > 0 {
		cmd = fmt.Sprintf("%s %d", cmd, parallel)
	}
	resp, err := c.sendCmd(cmd, duration+15*time.Second)
	if err != nil {
		return admin.BenchResult{}, err
	}
	if errMsg := decodeError(resp); errMsg != "" {
		return admin.BenchResult{}, errors.New(errMsg)
	}
	var r admin.BenchResult
	if err := json.Unmarshal([]byte(resp), &r); err != nil {
		return admin.BenchResult{}, fmt.Errorf("decode bench result: %w", err)
	}
	return r, nil
}

func (c *Client) sendPprof(cmd string) (admin.PprofStatus, error) {
	resp, err := c.sendCmd(cmd, 5*time.Second)
	if err != nil {
		return admin.PprofStatus{}, err
	}
	if errMsg := decodeError(resp); errMsg != "" {
		return admin.PprofStatus{}, errors.New(errMsg)
	}
	var st admin.PprofStatus
	if err := json.Unmarshal([]byte(resp), &st); err != nil {
		return admin.PprofStatus{}, fmt.Errorf("decode pprof status: %w", err)
	}
	return st, nil
}

func (c *Client) sendCmd(cmd string, timeout time.Duration) (string, error) {
	if c.socketPath == "" {
		return "", errors.New("socket path not configured")
	}
	conn, err := net.DialTimeout("unix", c.socketPath, 2*time.Second)
	if err != nil {
		// net.DialTimeout already includes "dial unix <path>" in its
		// error string, so we don't re-wrap with a path prefix here:
		// "dial /tmp/admin.sock: dial unix /tmp/admin.sock: refused"
		// reads as a duplicate to the operator.
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintln(conn, cmd); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func decodeError(resp string) string {
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp), &e); err != nil {
		return ""
	}
	return e.Error
}
