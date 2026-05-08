package tui

import "testing"

// TestBundleLoadsEN asserts the embedded English bundle loads cleanly
// and a representative key resolves to its English copy. Catches a
// JSON syntax error or missing file at build time.
func TestBundleLoadsEN(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if got := b.S("tab.home"); got != "Home" {
		t.Errorf("S(tab.home) = %q, want \"Home\"", got)
	}
}

// TestBundleMissingKeyFallsBack confirms an unknown key returns the
// key itself rather than panicking or returning an empty string, so a
// typo in a view file is visible to the operator.
func TestBundleMissingKeyFallsBack(t *testing.T) {
	b, err := NewBundle()
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	if got := b.S("does.not.exist"); got != "does.not.exist" {
		t.Errorf("S(unknown) = %q, want the key itself", got)
	}
}
