package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseLogLineJSON checks that a slog JSON line is decoded
// into the level and message fields the view consumes. catches a
// regression where the daemon's level was lower-case in the JSON
// output but the filter compared upper-case.
func TestParseLogLineJSON(t *testing.T) {
	line := `{"time":"2026-05-09T01:02:03Z","level":"info","msg":"hello","extra":1}`
	e := parseLogLine(line)
	if e.Level != "INFO" {
		t.Errorf("level = %q, want INFO", e.Level)
	}
	if e.Msg != "hello" {
		t.Errorf("msg = %q, want hello", e.Msg)
	}
	if e.Time.Year() != 2026 {
		t.Errorf("time year = %d, want 2026", e.Time.Year())
	}
}

// TestParseLogLineRawFallback: a non-JSON line (panic stack, raw
// stderr) renders with level RAW so the operator can still see it
// in the tail rather than having it silently dropped.
func TestParseLogLineRawFallback(t *testing.T) {
	e := parseLogLine("goroutine 1 [running]:")
	if e.Level != "RAW" {
		t.Errorf("level = %q, want RAW", e.Level)
	}
	if e.Msg != "goroutine 1 [running]:" {
		t.Errorf("msg = %q, want raw line preserved", e.Msg)
	}
}

// TestFilterByLevel: empty want returns everything; a specific
// level returns only matching rows.
func TestFilterByLevel(t *testing.T) {
	entries := []logEntry{
		{Level: "INFO", Msg: "a"},
		{Level: "WARN", Msg: "b"},
		{Level: "ERROR", Msg: "c"},
		{Level: "INFO", Msg: "d"},
	}
	if got := filterByLevel(entries, ""); len(got) != 4 {
		t.Errorf("filter='' = %d, want 4", len(got))
	}
	got := filterByLevel(entries, "INFO")
	if len(got) != 2 {
		t.Fatalf("filter=INFO len = %d, want 2", len(got))
	}
	if got[0].Msg != "a" || got[1].Msg != "d" {
		t.Errorf("filtered messages = %v, want [a d]", []string{got[0].Msg, got[1].Msg})
	}
	// Case-insensitive match on the want side.
	if got := filterByLevel(entries, "info"); len(got) != 2 {
		t.Errorf("case-insensitive filter len = %d, want 2", len(got))
	}
}

// TestTailLogReadsRecentBytes seeds a temp file with three log
// lines and verifies tailLog returns them. Also covers the
// "smaller than tailWindow" branch where the whole file is read
// without dropping a partial first line.
func TestTailLogReadsRecentBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	content := strings.Join([]string{
		`{"time":"2026-05-09T01:02:03Z","level":"INFO","msg":"first"}`,
		`{"time":"2026-05-09T01:02:04Z","level":"WARN","msg":"second"}`,
		`{"time":"2026-05-09T01:02:05Z","level":"ERROR","msg":"third"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := tailLog(path, 64*1024)
	if err != nil {
		t.Fatalf("tailLog: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	wantLevels := []string{"INFO", "WARN", "ERROR"}
	for i, e := range got {
		if e.Level != wantLevels[i] {
			t.Errorf("entry %d level = %q, want %q", i, e.Level, wantLevels[i])
		}
	}
}

// TestTailLogEmptyPath: a missing path returns an error rather
// than panicking, so the view can report "logging.file not set"
// instead of crashing.
func TestTailLogEmptyPath(t *testing.T) {
	if _, err := tailLog("", 1024); err == nil {
		t.Error("tailLog with empty path returned nil error")
	}
}
