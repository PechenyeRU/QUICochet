package tui

import "testing"

// TestDiffLinesIdentical: equal inputs produce only context lines,
// no adds or removes. catches a regression where the LCS backtrack
// dropped an equal line into the wrong bucket.
func TestDiffLinesIdentical(t *testing.T) {
	a := []string{"alpha", "bravo", "charlie"}
	got := diffLines(a, a)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, l := range got {
		if l.op != diffEq {
			t.Errorf("line %d: op = %q, want eq", i, l.op)
		}
		if l.text != a[i] {
			t.Errorf("line %d: text = %q, want %q", i, l.text, a[i])
		}
	}
	added, removed := diffCounts(got)
	if added != 0 || removed != 0 {
		t.Errorf("counts on identical input: added=%d removed=%d", added, removed)
	}
}

// TestDiffLinesSingleSubstitution: changing one line in the
// middle should produce one delete and one add, with surrounding
// context preserved.
func TestDiffLinesSingleSubstitution(t *testing.T) {
	a := []string{"alpha", "bravo", "charlie"}
	b := []string{"alpha", "BRAVO", "charlie"}
	got := diffLines(a, b)
	added, removed := diffCounts(got)
	if added != 1 || removed != 1 {
		t.Errorf("substitution counts: added=%d removed=%d, want 1/1", added, removed)
	}
	// The first and last lines must remain context.
	if got[0].op != diffEq || got[0].text != "alpha" {
		t.Errorf("first line = %+v, want eq alpha", got[0])
	}
	if got[len(got)-1].op != diffEq || got[len(got)-1].text != "charlie" {
		t.Errorf("last line = %+v, want eq charlie", got[len(got)-1])
	}
}

// TestDiffLinesEmptyInputs covers the two zero-length branches:
// every line of the non-empty side must show up as add or delete.
func TestDiffLinesEmptyInputs(t *testing.T) {
	got := diffLines(nil, []string{"x", "y"})
	if len(got) != 2 || got[0].op != diffAdd || got[1].op != diffAdd {
		t.Errorf("nil→[x y] diff = %+v", got)
	}
	got = diffLines([]string{"x", "y"}, nil)
	if len(got) != 2 || got[0].op != diffDel || got[1].op != diffDel {
		t.Errorf("[x y]→nil diff = %+v", got)
	}
}

// TestDiffLinesAppendInsertion: appending lines at the end of the
// right side produces N adds, no deletes, with the original input
// kept as context. exercises the "j > 0" tail-drain branch in the
// backtrack.
func TestDiffLinesAppendInsertion(t *testing.T) {
	a := []string{"alpha", "bravo"}
	b := []string{"alpha", "bravo", "charlie", "delta"}
	got := diffLines(a, b)
	added, removed := diffCounts(got)
	if added != 2 || removed != 0 {
		t.Errorf("append counts: added=%d removed=%d, want 2/0", added, removed)
	}
}
