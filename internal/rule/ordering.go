package rule

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
)

// Rule ordering, conflict detection, and supersedes resolution.
//
// Ports the algorithm from Python kensa's runner/ordering.py
// (referenced as the design template per the C-021 deliverable in
// docs/roadmap/DELIVERABLES.md). The algorithm is pure: given a
// list of rules with depends_on / conflicts_with / supersedes
// metadata, produces an execution order, detects cycles, and lists
// which rules to skip.
//
// Operator semantics:
//
//   - depends_on:    rule X needs rule Y to be in place first.
//                    Y runs before X. If Y is missing or fails,
//                    X is skipped (helper: ShouldSkip).
//   - conflicts_with: rule X is mutually exclusive with rule Y.
//                    Both run, but the engine surfaces a warning
//                    so the operator can decide which to keep.
//   - supersedes:    rule X replaces rule Y. When both are
//                    present, Y is silently skipped (auto-
//                    resolution). This is the "N conflicts
//                    auto-resolved" count in the operator UX.

// ResolvedRules is the output of Resolve. It carries the ordered
// active rule list plus diagnostic context (cycles, conflicts,
// superseded mapping) so the operator-facing layer can surface
// "N conflicts auto-resolved" and similar.
//
// Intentionally NOT exposed via api/. The shape will evolve as the
// CLI Phase 2.5 operator UX matures (adding fields like skip-by-
// capability, deterministic-supersede-tie-break, etc.); api/ is
// frozen v1 and can't absorb that churn. cmd/kensa carries
// ResolvedRules across the resolve→scan→render boundary directly.
type ResolvedRules struct {
	// Order is the active rules in dependency-first execution
	// order. EXCLUDES both superseded rules AND cycle members
	// (Kahn's algorithm cannot linearize cycles). Operators see
	// the cycle on stderr via FormatIssues; CycleMembers carries
	// the consequence (which specific rules will not run).
	Order []*api.Rule

	// Cycles lists every detected dependency cycle. Each cycle is
	// the rule-ID path that closes the loop (e.g., [a, b, c, a]
	// for a → b → c → a). Empty when the dependency graph is a
	// DAG.
	Cycles [][]string

	// CycleMembers lists every rule ID that appears in any cycle,
	// deduped and sorted. These rules are excluded from Order
	// because Kahn's algorithm can't produce a linear order over
	// cyclic dependencies. Operators reading the resolution summary
	// see "N rules dropped due to circular dependency: ..." so the
	// consequence of a detected cycle is visible, not just the
	// existence.
	CycleMembers []string

	// Conflicts lists (rule_id, conflicts_with_id) pairs where
	// both rules are in the active set. Advisory only — neither
	// rule is removed, but the operator-facing layer surfaces a
	// warning so the conflict is visible.
	Conflicts []ConflictPair

	// Superseded maps superseded_rule_id → superseding_rule_id.
	// Superseded rules are excluded from Order. On double-
	// supersede (two rules both claiming to supersede the same
	// target), the alphabetically-smallest superseder wins — a
	// deterministic policy that doesn't depend on input load
	// order. (Python kensa is last-in-input-order wins, which is
	// load-order-dependent; the Go port intentionally improves on
	// this.)
	Superseded map[string]string

	// Skipped lists every rule_id excluded from Order. Today the
	// only exclusion mechanism is supersedes; future deliverables
	// may add more (e.g., capability-gated skips).
	Skipped []string
}

// ConflictPair represents one mutual-exclusion conflict between
// two rules that are both in the active set. Surfaced in the
// operator UX as a warning.
type ConflictPair struct {
	RuleID         string
	ConflictsWith  string
}

// Resolve takes a list of rules and produces the resolved execution
// plan. The input list is not mutated. The returned ResolvedRules
// is safe to share across goroutines (read-only).
//
// Algorithm:
//  1. Detect cycles in the depends_on graph.
//  2. Apply supersedes: any rule whose ID appears in another rule's
//     supersedes list is marked skipped.
//  3. Detect conflicts among the active (non-skipped) rules.
//  4. Topologically sort active rules by depends_on.
//
// Cross-rule references (depends_on / conflicts_with / supersedes
// pointing at IDs not in the input set) are silently ignored. They
// often refer to rules from a different framework that operators
// chose not to include.
func Resolve(rules []*api.Rule) *ResolvedRules {
	result := &ResolvedRules{
		Superseded: map[string]string{},
	}
	if len(rules) == 0 {
		return result
	}

	rulesByID := make(map[string]*api.Rule, len(rules))
	ruleIDs := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		rulesByID[r.ID] = r
		ruleIDs[r.ID] = struct{}{}
	}

	// Extract dependencies, filtering to in-set IDs only.
	deps := make(map[string][]string, len(rules))
	for _, r := range rules {
		filtered := make([]string, 0, len(r.DependsOn))
		for _, d := range r.DependsOn {
			if _, ok := ruleIDs[d]; ok {
				filtered = append(filtered, d)
			}
		}
		deps[r.ID] = filtered
	}

	result.Cycles = detectCycles(ruleIDs, deps)
	// CycleMembers: every rule ID that appears in any cycle,
	// deduped and sorted. These rules can't be linearized by
	// Kahn's algorithm, so they're excluded from Order. Surface
	// the consequence to the operator-facing layer.
	cycleMemberSet := map[string]struct{}{}
	for _, cycle := range result.Cycles {
		for _, id := range cycle {
			cycleMemberSet[id] = struct{}{}
		}
	}
	result.CycleMembers = sortedKeys(cycleMemberSet)

	// Apply supersedes. Iterate rules in sorted-by-ID order so
	// double-supersede (two rules both claiming to supersede the
	// same target) is decided by alphabetical-smallest-superseder-
	// wins — a deterministic policy that doesn't depend on input
	// load order. Python kensa overwrites unconditionally, making
	// it last-in-input-order wins (load-order-dependent); the Go
	// port intentionally improves on this.
	sortedRules := make([]*api.Rule, len(rules))
	copy(sortedRules, rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].ID < sortedRules[j].ID
	})
	skipped := map[string]struct{}{}
	for _, r := range sortedRules {
		for _, supersededID := range r.Supersedes {
			if _, ok := ruleIDs[supersededID]; ok {
				if _, already := result.Superseded[supersededID]; already {
					continue
				}
				result.Superseded[supersededID] = r.ID
				skipped[supersededID] = struct{}{}
			}
		}
	}
	result.Skipped = sortedKeys(skipped)

	// Active set excludes skipped rules.
	active := make(map[string]struct{}, len(ruleIDs)-len(skipped))
	for id := range ruleIDs {
		if _, isSkipped := skipped[id]; !isSkipped {
			active[id] = struct{}{}
		}
	}

	// Conflict detection on active set. We dedupe by canonical
	// ordering: each (a, b) pair is recorded with a < b so the
	// reverse pair is not added separately.
	seen := map[string]struct{}{}
	for _, r := range rules {
		if _, isActive := active[r.ID]; !isActive {
			continue
		}
		for _, conflictID := range r.ConflictsWith {
			if _, otherActive := active[conflictID]; !otherActive {
				continue
			}
			a, b := r.ID, conflictID
			if a > b {
				a, b = b, a
			}
			key := a + "\x00" + b
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			result.Conflicts = append(result.Conflicts, ConflictPair{
				RuleID:        r.ID,
				ConflictsWith: conflictID,
			})
		}
	}

	// Topological sort over active set.
	sortedIDs := topologicalSort(active, deps)

	// Build the ordered Rule list. Drop any IDs that vanished
	// from rulesByID (defense in depth — should never happen).
	result.Order = make([]*api.Rule, 0, len(sortedIDs))
	for _, id := range sortedIDs {
		if r, ok := rulesByID[id]; ok {
			result.Order = append(result.Order, r)
		}
	}
	return result
}

// detectCycles runs a coloring DFS over the depends_on graph and
// returns every cycle found. Each returned cycle is the rule-ID path
// that closes the loop (the node that triggered the cycle is repeated
// at the end so callers can render "A → B → C → A").
func detectCycles(ruleIDs map[string]struct{}, deps map[string][]string) [][]string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(ruleIDs))
	for id := range ruleIDs {
		color[id] = white
	}
	var cycles [][]string

	// Iterate in sorted order so cycle output is deterministic
	// across runs.
	roots := sortedKeys(ruleIDs)

	var dfs func(node string, path []string)
	dfs = func(node string, path []string) {
		c, known := color[node]
		if !known {
			return
		}
		if c == gray {
			// Found a back-edge into the current DFS path; the
			// cycle is the suffix from the first occurrence of
			// node to the end, plus node again.
			start := slices.Index(path, node)
			if start < 0 {
				// Shouldn't happen if the algorithm is correct,
				// but defensive: skip rather than crash.
				return
			}
			cycle := make([]string, 0, len(path)-start+1)
			cycle = append(cycle, path[start:]...)
			cycle = append(cycle, node)
			cycles = append(cycles, cycle)
			return
		}
		if c == black {
			return
		}
		color[node] = gray
		path = append(path, node)
		// Visit deps in sorted order for deterministic output.
		neighbors := append([]string(nil), deps[node]...)
		sort.Strings(neighbors)
		for _, n := range neighbors {
			dfs(n, path)
		}
		color[node] = black
	}

	for _, id := range roots {
		if color[id] == white {
			dfs(id, nil)
		}
	}
	return cycles
}

// topologicalSort runs Kahn's algorithm over the depends_on graph
// restricted to ruleIDs. Returns rule IDs in dependency-first order
// (a rule X with depends_on Y comes after Y).
//
// Stable across runs: when multiple rules have zero in-degree at
// the same step, they're emitted in alphabetical ID order.
func topologicalSort(ruleIDs map[string]struct{}, deps map[string][]string) []string {
	inDegree := make(map[string]int, len(ruleIDs))
	for id := range ruleIDs {
		inDegree[id] = 0
	}
	for id := range ruleIDs {
		for _, d := range deps[id] {
			if _, ok := ruleIDs[d]; ok {
				inDegree[id]++
			}
		}
	}

	queue := make([]string, 0, len(ruleIDs))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	result := make([]string, 0, len(ruleIDs))
	for len(queue) > 0 {
		sort.Strings(queue) // deterministic emission order
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		// Decrement in-degree for every rule that depends on `node`.
		// We have to scan all rules because deps maps id→its-deps,
		// not the reverse. For 539-rule corpora this is O(N·D)
		// where D is avg dependencies per rule (typically 1-3).
		for id := range ruleIDs {
			for _, d := range deps[id] {
				if d == node {
					inDegree[id]--
					if inDegree[id] == 0 {
						queue = append(queue, id)
					}
					break // one decrement per (id, node) pair
				}
			}
		}
	}
	return result
}

// FailedDependencies returns the list of failed rule IDs that the
// given rule directly depends on. Used by the engine's commit
// phase to surface "rule X skipped because dep Y failed".
//
// EXPOSED FOR ENGINE WIRING — no in-tree caller as of C-021. The
// engine-side wiring (transaction-coordinator skip-when-dep-failed)
// lands in a follow-up post-CLI-Phase-2.5 deliverable. Keep the
// function exported so the engine PR doesn't have to revisit
// visibility.
func FailedDependencies(ruleID string, rules []*api.Rule, failed map[string]struct{}) []string {
	for _, r := range rules {
		if r.ID != ruleID {
			continue
		}
		var out []string
		for _, dep := range r.DependsOn {
			if _, isFailed := failed[dep]; isFailed {
				out = append(out, dep)
			}
		}
		return out
	}
	return nil
}

// ShouldSkip reports whether ruleID should be skipped given the set
// of failed rules. When transitive is true (the default for the
// engine), ShouldSkip walks the full depends_on graph; when false,
// it only checks direct dependencies.
//
// The returned reason string is an operator-facing description of
// the skip cause, e.g., "dependency failed: aide-installed" or
// "transitive dependency failed: package-aide-installed".
//
// EXPOSED FOR ENGINE WIRING — no in-tree caller as of C-021. The
// engine-side wiring (transaction-coordinator skip-when-dep-failed)
// lands in a follow-up post-CLI-Phase-2.5 deliverable. Keep the
// function exported so the engine PR doesn't have to revisit
// visibility.
func ShouldSkip(ruleID string, rules []*api.Rule, failed map[string]struct{}, transitive bool) (bool, string) {
	rulesByID := make(map[string]*api.Rule, len(rules))
	for _, r := range rules {
		rulesByID[r.ID] = r
	}
	target, ok := rulesByID[ruleID]
	if !ok {
		return false, ""
	}

	// Direct dependency check.
	var failedDirect []string
	for _, dep := range target.DependsOn {
		if _, isFailed := failed[dep]; isFailed {
			failedDirect = append(failedDirect, dep)
		}
	}
	if len(failedDirect) > 0 {
		return true, "dependency failed: " + strings.Join(failedDirect, ", ")
	}

	if !transitive {
		return false, ""
	}

	// Transitive walk: BFS over depends_on graph.
	visited := map[string]struct{}{}
	queue := append([]string(nil), target.DependsOn...)
	for len(queue) > 0 {
		dep := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, seen := visited[dep]; seen {
			continue
		}
		visited[dep] = struct{}{}
		if _, isFailed := failed[dep]; isFailed {
			return true, "transitive dependency failed: " + dep
		}
		if depRule, ok := rulesByID[dep]; ok {
			queue = append(queue, depRule.DependsOn...)
		}
	}
	return false, ""
}

// FormatIssues renders the resolution result's cycles, conflicts,
// supersedes, and cycle-member exclusions as a slice of operator-
// facing diagnostic lines. Used by cmd/kensa to print the
// resolution summary above the scan output.
//
// Lines are prefixed by severity: "error:" for cycles (a real
// configuration problem), "warning:" for conflicts (advisory; both
// rules still run), "info:" for supersedes (auto-resolution; the
// older rule is skipped). cmd/kensa's --quiet flag suppresses
// info: lines but keeps error: and warning: visible.
func FormatIssues(result *ResolvedRules) []string {
	if result == nil {
		return nil
	}
	var msgs []string
	for _, cycle := range result.Cycles {
		msgs = append(msgs, fmt.Sprintf("error: circular dependency: %s",
			strings.Join(cycle, " → ")))
	}
	if len(result.CycleMembers) > 0 {
		msgs = append(msgs, fmt.Sprintf("error: %d rule(s) dropped due to circular dependency: %s",
			len(result.CycleMembers), strings.Join(result.CycleMembers, ", ")))
	}
	for _, c := range result.Conflicts {
		msgs = append(msgs, fmt.Sprintf("warning: conflict: %s conflicts with %s (both active)",
			c.RuleID, c.ConflictsWith))
	}
	// Iterate superseded in sorted order for determinism.
	for _, k := range sortedKeys(toSet(result.Superseded)) {
		msgs = append(msgs, fmt.Sprintf("info: skipping %s (superseded by %s)", k, result.Superseded[k]))
	}
	return msgs
}

// IssueSeverity returns the severity prefix of a FormatIssues line:
// "error", "warning", "info", or "" if the line is malformed.
// Used by cmd/kensa to gate info: lines under --quiet.
func IssueSeverity(line string) string {
	switch {
	case strings.HasPrefix(line, "error:"):
		return "error"
	case strings.HasPrefix(line, "warning:"):
		return "warning"
	case strings.HasPrefix(line, "info:"):
		return "info"
	}
	return ""
}

// sortedKeys returns the keys of a set-shaped map in sorted order.
// Used for deterministic test output.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// toSet converts a map[string]string to a map[string]struct{} so
// sortedKeys's generic signature matches.
func toSet(m map[string]string) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

