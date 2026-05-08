package tui

// diffOp marks a single line in a unified-diff render.
//
//	' ' — line is identical in both inputs (context)
//	'-' — line exists only in the left input (removed)
//	'+' — line exists only in the right input (added)
type diffOp rune

const (
	diffEq  diffOp = ' '
	diffDel diffOp = '-'
	diffAdd diffOp = '+'
)

// diffLine is one row of the rendered diff.
type diffLine struct {
	op   diffOp
	text string
}

// diffLines computes a line-level diff between a and b using the
// classic O(n·m) longest-common-subsequence DP. It's an exact
// algorithm (not heuristic), which matters on a config diff where
// the operator wants to spot a single-line change reliably; the
// quadratic cost is fine because configs are at most a few hundred
// lines.
//
// The returned slice is a unified-style stream: equal lines kept as
// context, deletions before the corresponding additions when both
// sides changed in the same hunk. Compatible with the TUI's diff
// renderer which colours by op.
func diffLines(a, b []string) []diffLine {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil
	}
	if n == 0 {
		out := make([]diffLine, m)
		for i, l := range b {
			out[i] = diffLine{op: diffAdd, text: l}
		}
		return out
	}
	if m == 0 {
		out := make([]diffLine, n)
		for i, l := range a {
			out[i] = diffLine{op: diffDel, text: l}
		}
		return out
	}

	// dp[i][j] = LCS length of a[:i] and b[:j].
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	// Backtrack to produce the edit script. We walk diagonally when
	// possible (equal lines), otherwise prefer up (delete from a)
	// when dp[i-1][j] >= dp[i][j-1] — keeps deletions before adds
	// in the rendered hunk so an operator who reads top-to-bottom
	// sees "what was there → what is there" naturally.
	var rev []diffLine
	i, j := n, m
	for i > 0 && j > 0 {
		switch {
		case a[i-1] == b[j-1]:
			rev = append(rev, diffLine{op: diffEq, text: a[i-1]})
			i--
			j--
		case dp[i-1][j] >= dp[i][j-1]:
			rev = append(rev, diffLine{op: diffDel, text: a[i-1]})
			i--
		default:
			rev = append(rev, diffLine{op: diffAdd, text: b[j-1]})
			j--
		}
	}
	for i > 0 {
		rev = append(rev, diffLine{op: diffDel, text: a[i-1]})
		i--
	}
	for j > 0 {
		rev = append(rev, diffLine{op: diffAdd, text: b[j-1]})
		j--
	}

	// Reverse in place.
	for i, k := 0, len(rev)-1; i < k; i, k = i+1, k-1 {
		rev[i], rev[k] = rev[k], rev[i]
	}
	return rev
}

// diffCounts returns (added, removed) summary counts from a diff
// stream. Used by the Diff view's header so the operator sees a
// "+12 −7" badge before scrolling through the body.
func diffCounts(d []diffLine) (added, removed int) {
	for _, l := range d {
		switch l.op {
		case diffAdd:
			added++
		case diffDel:
			removed++
		}
	}
	return
}
