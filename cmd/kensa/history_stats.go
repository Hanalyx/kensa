package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/Hanalyx/kensa/internal/store"
)

// writeHistoryStatsText renders the C-042 stats summary in the
// operator-facing text format. JSON output (`-o json`) is
// handled by the JSON writer in runHistory; this function is
// the human path.
//
// Layout (single column, key: value pairs grouped by axis):
//
//	kensa history --stats
//	  scope: host=<H> since=<S>           (omitted when neither is set)
//	  window: <earliest> → <latest>
//	  sessions:     N
//	  transactions: M
//
//	  by status:
//	    committed         N
//	    rolled_back       N
//	    ...
//
//	  by severity:
//	    critical          N
//	    high              N
//	    ...
//
//	  by host (top 10; remaining rolled into (other)):
//	    <hostA>           N
//	    <hostB>           N
//	    ...
func writeHistoryStatsText(w io.Writer, st *store.Stats, host, since string) {
	fmt.Fprintln(w, "kensa history --stats")
	if host != "" || since != "" {
		fmt.Fprint(w, "  scope:")
		if host != "" {
			fmt.Fprintf(w, " host=%s", host)
		}
		if since != "" {
			fmt.Fprintf(w, " since=%s", since)
		}
		fmt.Fprintln(w)
	}
	if !st.EarliestStartedAt.IsZero() {
		fmt.Fprintf(w, "  window:       %s → %s\n",
			st.EarliestStartedAt.Format("2006-01-02 15:04:05Z"),
			st.LatestFinishedAt.Format("2006-01-02 15:04:05Z"))
	}
	fmt.Fprintf(w, "  sessions:     %d\n", st.SessionsTotal)
	fmt.Fprintf(w, "  transactions: %d\n", st.TransactionsTotal)

	if st.TransactionsTotal == 0 {
		// Nothing else to render; skip the by-axis sections.
		return
	}

	writeCountMap(w, "by status", st.ByStatus, statusOrder)
	writeCountMap(w, "by severity", st.BySeverity, severityOrder)
	writeCountMap(w, "by host (top 10)", st.ByHost, nil)

	// Footer legend: status terminology is overloaded between
	// check (rolled_back = "non-compliant") and remediate
	// (rolled_back = "engine actually rolled back"). Spell it
	// out for operators new to the surface, since the status
	// map alone can't disambiguate.
	if st.ByStatus["committed"] > 0 || st.ByStatus["rolled_back"] > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  legend: in check sessions, committed=passed and rolled_back=failed-check;")
		fmt.Fprintln(w, "          in remediate sessions, committed=remediated and rolled_back=actual rollback")
	}
}

// statusOrder is the canonical render order for transaction
// statuses. Keys not in this list appear sorted alphabetically
// after the canonical ones.
var statusOrder = []string{
	"committed",
	"rolled_back",
	"partially_applied",
	"errored",
}

// severityOrder is highest-first so the operator's eye lands
// on critical/high counts before sliding down.
var severityOrder = []string{
	"critical",
	"high",
	"medium",
	"low",
	"(unset)",
}

// writeCountMap renders a "by X" section. The preferred slice
// lists keys in a fixed order; remaining keys appear sorted by
// descending count then alphabetically.
func writeCountMap(w io.Writer, title string, m map[string]int, preferred []string) {
	if len(m) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  %s:\n", title)

	seen := make(map[string]bool, len(preferred))
	for _, k := range preferred {
		if v, ok := m[k]; ok {
			fmt.Fprintf(w, "    %-18s %d\n", k, v)
			seen[k] = true
		}
	}
	// Remaining keys (e.g., "(other)" rollup, or any custom
	// status) sorted by count descending.
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		if m[rest[i]] != m[rest[j]] {
			return m[rest[i]] > m[rest[j]]
		}
		return rest[i] < rest[j]
	})
	for _, k := range rest {
		fmt.Fprintf(w, "    %-18s %d\n", k, m[k])
	}
}
