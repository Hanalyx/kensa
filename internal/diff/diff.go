// Package diff computes the C-048 SessionDiff: per-rule drift
// between two stored sessions. The data layer is in
// internal/store (TransactionsForSession); this package handles
// only the comparison logic + structured output.
package diff

import (
	"sort"

	"github.com/Hanalyx/kensa/internal/store"
)

// RuleChange is one row in a SessionDiff. Section is implicit
// from which slice the row appears in (Added / Removed /
// Changed / Unchanged) — but FromStatus/ToStatus carry the
// before/after for serialization clarity:
//
//   - Added:     FromStatus = "",   ToStatus = <session2 status>
//   - Removed:   FromStatus = <s1>, ToStatus = ""
//   - Changed:   FromStatus = <s1>, ToStatus = <s2>, s1 != s2
//   - Unchanged: FromStatus = <s>,  ToStatus = <s>,  s1 == s2
type RuleChange struct {
	RuleID     string `json:"rule_id"`
	FromStatus string `json:"from_status"`
	ToStatus   string `json:"to_status"`
}

// SessionDiff is the operator-facing shape of the comparison.
// SessionIDs and hostnames are echoed back so JSON consumers
// can correlate the report with audit trails.
//
// JSON contract: every section field is always present and
// always a JSON array (never null). When a section is empty
// the array is `[]`. The --show-unchanged flag governs only
// the TEXT rendering — the JSON shape always carries every
// section so consumer code doesn't have to special-case
// "field present" vs "field meaningful." Costs a few extra
// bytes per response; eliminates a class of consumer bugs.
type SessionDiff struct {
	SessionIDFrom string       `json:"session_id_from"`
	SessionIDTo   string       `json:"session_id_to"`
	HostnameFrom  string       `json:"hostname_from"`
	HostnameTo    string       `json:"hostname_to"`
	Added         []RuleChange `json:"added"`
	Removed       []RuleChange `json:"removed"`
	Changed       []RuleChange `json:"changed"`
	Unchanged     []RuleChange `json:"unchanged"`
}

// ComputeSessionDiff compares two slices of SessionTxn (the
// slim per-rule projection from store.TransactionsForSession)
// and returns the drift shape. Caller is responsible for
// loading the SessionTxn slices and the metadata fields
// (session IDs + hostnames).
//
// Determinism: each output slice is sorted alphabetically by
// rule_id (per spec C-03). Multiple transactions for the same
// rule within one slice dedup to the LAST entry (latest
// started_at, which the store query orders ascending — so the
// last position wins) per spec C-04.
func ComputeSessionDiff(from, to []store.SessionTxn) (added, removed, changed, unchanged []RuleChange) {
	fromMap := dedupByRule(from)
	toMap := dedupByRule(to)

	// Iterate rule_ids from BOTH maps to build the diff.
	allRules := make(map[string]struct{}, len(fromMap)+len(toMap))
	for r := range fromMap {
		allRules[r] = struct{}{}
	}
	for r := range toMap {
		allRules[r] = struct{}{}
	}

	for rule := range allRules {
		fromStatus, inFrom := fromMap[rule]
		toStatus, inTo := toMap[rule]
		switch {
		case !inFrom && inTo:
			added = append(added, RuleChange{RuleID: rule, ToStatus: toStatus})
		case inFrom && !inTo:
			removed = append(removed, RuleChange{RuleID: rule, FromStatus: fromStatus})
		case fromStatus != toStatus:
			changed = append(changed, RuleChange{RuleID: rule, FromStatus: fromStatus, ToStatus: toStatus})
		default:
			unchanged = append(unchanged, RuleChange{RuleID: rule, FromStatus: fromStatus, ToStatus: toStatus})
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].RuleID < added[j].RuleID })
	sort.Slice(removed, func(i, j int) bool { return removed[i].RuleID < removed[j].RuleID })
	sort.Slice(changed, func(i, j int) bool { return changed[i].RuleID < changed[j].RuleID })
	sort.Slice(unchanged, func(i, j int) bool { return unchanged[i].RuleID < unchanged[j].RuleID })
	return added, removed, changed, unchanged
}

// dedupByRule reduces the input txn slice to a map of
// rule_id → status, keeping the LAST occurrence per rule
// (latest started_at; store query orders ASC so iteration
// order = chronological).
func dedupByRule(txns []store.SessionTxn) map[string]string {
	out := make(map[string]string, len(txns))
	for _, t := range txns {
		out[t.RuleID] = t.Status
	}
	return out
}
