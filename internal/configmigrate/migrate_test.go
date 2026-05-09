package configmigrate

import (
	"testing"
)

// Internal-package tests: cover unexported helpers (parseOrdered,
// prependDedup) that the external test package cannot reach. The bulk
// of the migrator's behavioural coverage lives in
// migrate_external_test.go (package configmigrate_test) so it can
// import internal/config for round-trip Validate() without creating
// an import cycle (config now auto-runs MigrateV1ToV2 inside Load).

func TestOrderedMapRoundTrip(t *testing.T) {
	// Field order must be preserved: verify by checking the parsed key sequence.
	input := `{"z": 1, "a": 2, "m": 3}`
	m, err := parseOrdered([]byte(input))
	if err != nil {
		t.Fatalf("parseOrdered: %v", err)
	}
	if m[0].Key != "z" || m[1].Key != "a" || m[2].Key != "m" {
		t.Errorf("field order not preserved: %v", []string{m[0].Key, m[1].Key, m[2].Key})
	}
}

func TestPrependDedup(t *testing.T) {
	tests := []struct {
		singular string
		existing []string
		want     []string
	}{
		{"a", []string{"b", "c"}, []string{"a", "b", "c"}},
		{"a", []string{"a", "b"}, []string{"a", "b"}}, // dedup: "a" not added twice
		{"", []string{"b", "c"}, []string{"b", "c"}},  // empty singular: unchanged
		{"a", nil, []string{"a"}},
	}
	for _, tt := range tests {
		got := prependDedup(tt.singular, tt.existing)
		if len(got) != len(tt.want) {
			t.Errorf("prependDedup(%q, %v) = %v, want %v", tt.singular, tt.existing, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("prependDedup(%q, %v)[%d] = %q, want %q", tt.singular, tt.existing, i, got[i], tt.want[i])
			}
		}
	}
}
