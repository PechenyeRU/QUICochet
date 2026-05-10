package tui

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// logEntry is one parsed line of the daemon's slog JSON output.
// Raw stores the original line so a malformed entry (e.g. a panic
// stack-trace dumped without JSON wrapping) still renders rather
// than silently disappearing from the tail view.
//
// Peer is the configured peer name extracted from the slog `peer`
// field on server-side log lines (handleSession / handleStream /
// handleDatagrams and the receive loops). Empty on client logs and
// on server lines that pre-date a peer-aware code path.
type logEntry struct {
	Time  time.Time
	Level string // DEBUG / INFO / WARN / ERROR; uppercase for filter parity
	Msg   string
	Peer  string
	Raw   string
}

// tailLog reads the last tailBytes bytes of the file at path,
// splits on newlines, parses each line as slog JSON, and returns
// the resulting entries oldest-first. Files smaller than tailBytes
// are read whole. The first partial line at the start of the
// window is dropped — we can't tell if its parser would have
// produced the same result with the missing prefix.
//
// Errors are returned to the caller rather than swallowed so the
// view can show "log file not configured" or "permission denied"
// instead of an empty pane.
func tailLog(path string, tailBytes int64) ([]logEntry, error) {
	if path == "" {
		return nil, errors.New("logging.file is empty in the loaded config")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}

	start := int64(0)
	dropFirst := false
	if size > tailBytes && tailBytes > 0 {
		start = size - tailBytes
		dropFirst = true
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}

	r := bufio.NewReader(f)
	if dropFirst {
		_, _ = r.ReadString('\n') // discard the (likely partial) first line
	}

	var out []logEntry
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				out = append(out, parseLogLine(line))
			}
		}
		if err != nil {
			break
		}
	}
	return out, nil
}

// parseLogLine handles both the JSON output produced when
// logging.file is set and the text output written to stderr (which
// the operator would only see in this tab if they redirected
// stderr into a file). JSON parse failures fall through to a Raw-
// only entry whose level reads "RAW" — useful for fishing panic
// traces out of the tail.
func parseLogLine(line string) logEntry {
	type slogJSON struct {
		Time  time.Time `json:"time"`
		Level string    `json:"level"`
		Msg   string    `json:"msg"`
		Peer  string    `json:"peer"`
	}
	var j slogJSON
	if err := json.Unmarshal([]byte(line), &j); err == nil && j.Level != "" {
		return logEntry{
			Time:  j.Time,
			Level: strings.ToUpper(j.Level),
			Msg:   j.Msg,
			Peer:  j.Peer,
			Raw:   line,
		}
	}
	return logEntry{Level: "RAW", Msg: line, Raw: line}
}

// filterByLevel returns the subset of entries whose Level matches
// want (case-insensitive). want == "" returns everything; useful
// for the "all" hotkey on the logs tab.
func filterByLevel(entries []logEntry, want string) []logEntry {
	if want == "" {
		return entries
	}
	want = strings.ToUpper(want)
	out := make([]logEntry, 0, len(entries))
	for _, e := range entries {
		if e.Level == want {
			out = append(out, e)
		}
	}
	return out
}

// filterByPeer keeps entries whose Peer field matches want exactly.
// want == "" passes everything through (no peer filter active). Used
// only on the server role; client logs never carry a peer field.
func filterByPeer(entries []logEntry, want string) []logEntry {
	if want == "" {
		return entries
	}
	out := make([]logEntry, 0, len(entries))
	for _, e := range entries {
		if e.Peer == want {
			out = append(out, e)
		}
	}
	return out
}

// observedPeers returns the set of distinct peer names seen in the
// current tail window, sorted alphabetically. Used by the logs tab
// to drive the peer-cycling hotkey when no live Snapshot is
// available (e.g. before the first poll completes).
func observedPeers(entries []logEntry) []string {
	seen := make(map[string]struct{})
	for _, e := range entries {
		if e.Peer != "" {
			seen[e.Peer] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// sortStrings is the std-lib sort wrapper kept inline so log_tail.go
// has no dependency on sort just for one call. The slice is small
// (peer count, typically ≤ 10) so insertion-sort is fine.
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
