package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
)

// streamRules is the rule catalog the writer uses to resolve titles and
// severities for the streamed rows. Plain (color=false) output keeps the
// assertions deterministic.
func streamRules() []*api.Rule {
	return []*api.Rule{
		{ID: "rule-a", Title: "Rule A title", Severity: "high"},
		{ID: "rule-b", Title: "Rule B title", Severity: "low"},
		{ID: "rule-c", Title: "Rule C title", Severity: "medium"},
		{ID: "rule-d", Title: "Rule D title", Severity: "critical"},
	}
}

// TestStreamScanWriter_RowPerUpdateInOrder confirms one row per RuleChecked
// update, in arrival order, with the STATUS/SEVERITY/RULE-ID/DESCRIPTION
// columns, and that a non-RuleChecked update produces no row.
// @spec output-stream-scan
// @ac AC-01
func TestStreamScanWriter_RowPerUpdateInOrder(t *testing.T) {
	t.Run("output-stream-scan/AC-01", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewStreamScanWriter(&buf, false, streamRules())

		// A non-RuleChecked update must be ignored (no row).
		w.Update(progress.Update{Kind: progress.ScanStart})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-a", OK: true})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-b", OK: false})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-c", OK: true})

		lines := nonEmptyLines(buf.String())
		if len(lines) != 3 {
			t.Fatalf("got %d rows, want 3 (one per RuleChecked update); output:\n%s", len(lines), buf.String())
		}

		// Order: a, b, c.
		wantIDs := []string{"rule-a", "rule-b", "rule-c"}
		for i, id := range wantIDs {
			if !strings.Contains(lines[i], id) {
				t.Errorf("row %d = %q, want it to contain rule id %q", i, lines[i], id)
			}
		}

		// Column presence on the first row: STATUS word, SEVERITY badge,
		// RULE-ID, and DESCRIPTION (the rule title).
		first := lines[0]
		for _, tok := range []string{"PASS", "HIGH", "rule-a", "Rule A title"} {
			if !strings.Contains(first, tok) {
				t.Errorf("first row %q missing column token %q", first, tok)
			}
		}
		// STATUS precedes RULE-ID which precedes DESCRIPTION.
		if !(strings.Index(first, "PASS") < strings.Index(first, "rule-a") &&
			strings.Index(first, "rule-a") < strings.Index(first, "Rule A title")) {
			t.Errorf("column order wrong in %q; want STATUS < RULE-ID < DESCRIPTION", first)
		}
	})
}

// TestStreamScanWriter_StatusMapping pins OK→PASS, Errored→ERROR,
// Fixed→FIXED, and !OK&&!Errored→FAIL.
// @spec output-stream-scan
// @ac AC-02
func TestStreamScanWriter_StatusMapping(t *testing.T) {
	t.Run("output-stream-scan/AC-02", func(t *testing.T) {
		cases := []struct {
			id   string
			u    progress.Update
			want string
		}{
			{"rule-a", progress.Update{Kind: progress.RuleChecked, RuleID: "rule-a", OK: true}, "PASS"},
			{"rule-b", progress.Update{Kind: progress.RuleChecked, RuleID: "rule-b", OK: false}, "FAIL"},
			{"rule-c", progress.Update{Kind: progress.RuleChecked, RuleID: "rule-c", OK: true, Fixed: true}, "FIXED"},
			{"rule-d", progress.Update{Kind: progress.RuleChecked, RuleID: "rule-d", Errored: true}, "ERROR"},
			{"rule-e", progress.Update{Kind: progress.RuleChecked, RuleID: "rule-e", Skipped: true}, "SKIP"},
		}
		for _, c := range cases {
			var buf bytes.Buffer
			w := NewStreamScanWriter(&buf, false, streamRules())
			w.Update(c.u)
			got := buf.String()
			if !strings.Contains(got, c.want) {
				t.Errorf("update %+v rendered %q, want STATUS %q", c.u, got, c.want)
			}
		}
	})
}

// TestStreamScanWriter_PlainWhenColorFalse confirms no ANSI escape bytes are
// emitted when color is disabled.
// @spec output-stream-scan
// @ac AC-03
func TestStreamScanWriter_PlainWhenColorFalse(t *testing.T) {
	t.Run("output-stream-scan/AC-03", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewStreamScanWriter(&buf, false, streamRules())
		w.Banner("host-1", "RHEL 9.6")
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-a", OK: true})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-d", Errored: true})
		w.Summary()
		if strings.ContainsRune(buf.String(), '\x1b') {
			t.Errorf("color=false output contains an ANSI ESC byte:\n%q", buf.String())
		}
	})
}

// TestStreamScanWriter_SummaryTally confirms the trailing Summary line tallies
// passed / fixed / failed / errored and the total.
// @spec output-stream-scan
// @ac AC-04
func TestStreamScanWriter_SummaryTally(t *testing.T) {
	t.Run("output-stream-scan/AC-04", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewStreamScanWriter(&buf, false, streamRules())
		// 2 pass, 1 fixed, 1 fail, 1 error, 1 skip => total 6.
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-a", OK: true})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-b", OK: true})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-c", OK: true, Fixed: true})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-d", OK: false})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-a", Errored: true})
		w.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "rule-e", Skipped: true})

		// Reset the rendered rows; only assert against the Summary line.
		buf.Reset()
		w.Summary()
		got := buf.String()
		for _, want := range []string{"2 passed", "1 fixed", "1 failed", "1 errored", "1 skipped", "(of 6)"} {
			if !strings.Contains(got, want) {
				t.Errorf("summary %q missing %q", got, want)
			}
		}
	})
}

// nonEmptyLines splits s into lines and drops blank ones (the writer emits a
// leading blank line before Summary; row assertions ignore blanks).
func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}
