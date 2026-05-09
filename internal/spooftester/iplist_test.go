package spooftester

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func writeList(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestParseIPList_SingleAndComments(t *testing.T) {
	path := writeList(t, "# header\n\n1.2.3.4\n  2001:db8::1  \n# trailing\n")
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2001:db8::1"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %v want %v", i, got[i], want[i])
		}
	}
}

func TestParseIPList_CIDRv4SkipsEdges(t *testing.T) {
	path := writeList(t, "10.0.0.0/30\n")
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// /30 has 4 addrs: .0 .1 .2 .3 — drop .0 (network) and .3 (broadcast)
	want := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %v want %v", i, got[i], want[i])
		}
	}
}

func TestParseIPList_CIDRv4_31KeepsBoth(t *testing.T) {
	// /31 (RFC 3021) has only 2 addrs and both are usable.
	path := writeList(t, "10.0.0.0/31\n")
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("/31 should keep both: %v", got)
	}
}

func TestParseIPList_CIDRv6(t *testing.T) {
	path := writeList(t, "2001:db8::/126\n") // 4 addrs, no edge skip
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d, want 4", len(got))
	}
}

func TestParseIPList_RangeV4(t *testing.T) {
	path := writeList(t, "10.0.0.5-10.0.0.7\n")
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("got %v want %s", got[i], w)
		}
	}
}

func TestParseIPList_DedupePreservesOrder(t *testing.T) {
	path := writeList(t, "1.1.1.1\n2.2.2.2\n1.1.1.1\n3.3.3.3\n")
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("entry %d: got %v want %s", i, got[i], w)
		}
	}
}

func TestParseIPList_RejectsHugePrefix(t *testing.T) {
	path := writeList(t, "10.0.0.0/8\n")
	_, err := ParseIPList(path)
	if err == nil {
		t.Fatal("expected error on /8, got nil")
	}
}

func TestParseIPList_AllowLargeBypassesCap(t *testing.T) {
	// /15 expands to 131072 addresses minus the two v4 edges → 131070.
	// With AllowLarge=false this is rejected; AllowLarge=true accepts it.
	path := writeList(t, "10.0.0.0/15\n")
	if _, err := ParseIPList(path); err == nil {
		t.Fatal("default mode should still reject prefixes above the soft cap")
	}
	got, err := ParseIPListWithOpts(path, ParseOpts{AllowLarge: true})
	if err != nil {
		t.Fatalf("AllowLarge parse: %v", err)
	}
	if want := 131070; len(got) != want {
		t.Fatalf("got %d entries, want %d", len(got), want)
	}
}

func TestParseIPList_AllowLargeRange(t *testing.T) {
	// 1.0.0.0-1.1.0.0 spans 65537 addresses, just over the soft cap.
	path := writeList(t, "1.0.0.0-1.1.0.0\n")
	if _, err := ParseIPList(path); err == nil {
		t.Fatal("default mode should reject ranges above the soft cap")
	}
	got, err := ParseIPListWithOpts(path, ParseOpts{AllowLarge: true})
	if err != nil {
		t.Fatalf("AllowLarge range parse: %v", err)
	}
	if want := 65537; len(got) != want {
		t.Fatalf("got %d entries, want %d", len(got), want)
	}
}

func TestParseIPList_InvalidLineSkipped(t *testing.T) {
	path := writeList(t, "garbage\n1.2.3.4\n")
	got, err := ParseIPList(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Errorf("got %v, want [1.2.3.4]", got)
	}
}

func TestParseIPList_EmptyFile(t *testing.T) {
	path := writeList(t, "# only comments\n\n")
	if _, err := ParseIPList(path); err == nil {
		t.Fatal("expected error on empty list, got nil")
	}
}
