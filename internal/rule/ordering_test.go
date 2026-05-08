package rule

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

// makeRule is a tiny factory so the tests below stay terse.
func makeRule(id string, opts ...func(*api.Rule)) *api.Rule {
	r := &api.Rule{ID: id}
	for _, o := range opts {
		o(r)
	}
	return r
}
func dependsOn(deps ...string) func(*api.Rule) {
	return func(r *api.Rule) { r.DependsOn = deps }
}
func conflictsWith(conflicts ...string) func(*api.Rule) {
	return func(r *api.Rule) { r.ConflictsWith = conflicts }
}
func supersedes(supers ...string) func(*api.Rule) {
	return func(r *api.Rule) { r.Supersedes = supers }
}

func TestResolve_EmptyInput(t *testing.T) {
	r := Resolve(nil)
	if len(r.Order) != 0 {
		t.Errorf("Order = %v, want empty", r.Order)
	}
	if len(r.Cycles) != 0 || len(r.Conflicts) != 0 || len(r.Skipped) != 0 {
		t.Errorf("expected empty result; got %+v", r)
	}
}

func TestResolve_NoDependencies_PreservesAllRules(t *testing.T) {
	rules := []*api.Rule{
		makeRule("a"), makeRule("b"), makeRule("c"),
	}
	r := Resolve(rules)
	if len(r.Order) != 3 {
		t.Errorf("Order length = %d, want 3", len(r.Order))
	}
	// With no dependencies, ordering is alphabetical (deterministic).
	want := []string{"a", "b", "c"}
	for i, w := range want {
		if r.Order[i].ID != w {
			t.Errorf("Order[%d] = %q, want %q", i, r.Order[i].ID, w)
		}
	}
}

func TestResolve_DependsOn_OrdersDependenciesFirst(t *testing.T) {
	// a depends on b; b depends on c. Topological order: c, b, a.
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b", dependsOn("c")),
		makeRule("c"),
	}
	r := Resolve(rules)
	want := []string{"c", "b", "a"}
	if len(r.Order) != len(want) {
		t.Fatalf("Order length = %d, want %d", len(r.Order), len(want))
	}
	for i, w := range want {
		if r.Order[i].ID != w {
			t.Errorf("Order[%d] = %q, want %q", i, r.Order[i].ID, w)
		}
	}
}

func TestResolve_DependsOn_IgnoresExternalRefs(t *testing.T) {
	// a depends on a rule not in the input set. The external dep
	// is filtered out; a still runs.
	rules := []*api.Rule{
		makeRule("a", dependsOn("not-in-set")),
	}
	r := Resolve(rules)
	if len(r.Order) != 1 || r.Order[0].ID != "a" {
		t.Errorf("expected [a], got %v", ruleIDs(r.Order))
	}
	if len(r.Cycles) != 0 {
		t.Errorf("external ref shouldn't trigger cycle: %v", r.Cycles)
	}
}

func TestResolve_Cycles_Detected(t *testing.T) {
	// a → b → c → a (cycle).
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b", dependsOn("c")),
		makeRule("c", dependsOn("a")),
	}
	r := Resolve(rules)
	if len(r.Cycles) == 0 {
		t.Fatal("expected cycle detection")
	}
	// Every cycle path closes with a repeat of its first element.
	for _, cycle := range r.Cycles {
		if len(cycle) < 2 {
			t.Errorf("cycle too short: %v", cycle)
			continue
		}
		if cycle[0] != cycle[len(cycle)-1] {
			t.Errorf("cycle should close with repeat of first element: %v", cycle)
		}
	}
}

func TestResolve_Cycles_MembersDroppedFromOrder(t *testing.T) {
	// Cycle members can't be linearized by Kahn's algorithm, so
	// they're excluded from Order. CycleMembers carries the
	// consequence so the operator-facing layer can surface
	// "N rules dropped due to circular dependency".
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b", dependsOn("c")),
		makeRule("c", dependsOn("a")),
		makeRule("standalone"),
	}
	r := Resolve(rules)
	if got := ruleIDs(r.Order); !equalSlice(got, []string{"standalone"}) {
		t.Errorf("Order should only contain non-cycle rules; got %v", got)
	}
	if !equalSlice(r.CycleMembers, []string{"a", "b", "c"}) {
		t.Errorf("CycleMembers = %v, want [a b c]", r.CycleMembers)
	}
}

func TestResolve_CycleMembers_DedupedAcrossCycles(t *testing.T) {
	// Two overlapping cycles share node b. CycleMembers dedupes.
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b", dependsOn("a", "c")),
		makeRule("c", dependsOn("b")),
	}
	r := Resolve(rules)
	// CycleMembers should contain a, b, c each exactly once,
	// alphabetically sorted.
	if !equalSlice(r.CycleMembers, []string{"a", "b", "c"}) {
		t.Errorf("CycleMembers = %v, want [a b c] sorted", r.CycleMembers)
	}
}

func TestResolve_Cycles_SelfLoop(t *testing.T) {
	// a → a (self-loop).
	rules := []*api.Rule{makeRule("a", dependsOn("a"))}
	r := Resolve(rules)
	if len(r.Cycles) != 1 {
		t.Errorf("expected 1 cycle (self-loop); got %v", r.Cycles)
	}
}

func TestResolve_Supersedes_SkipsOlder(t *testing.T) {
	// new-rule supersedes old-rule. Both in input; old-rule excluded
	// from Order and recorded in Superseded.
	rules := []*api.Rule{
		makeRule("old-rule"),
		makeRule("new-rule", supersedes("old-rule")),
	}
	r := Resolve(rules)
	if got := ruleIDs(r.Order); !equalSlice(got, []string{"new-rule"}) {
		t.Errorf("Order = %v, want [new-rule]", got)
	}
	if r.Superseded["old-rule"] != "new-rule" {
		t.Errorf("Superseded[old-rule] = %q, want new-rule", r.Superseded["old-rule"])
	}
	if !contains(r.Skipped, "old-rule") {
		t.Errorf("Skipped should contain old-rule: %v", r.Skipped)
	}
}

func TestResolve_Supersedes_FirstWinsOnDoubleSupersede(t *testing.T) {
	// Both b and c claim to supersede a. First-rule-wins (b in
	// alphabetical order; matches Python kensa behavior).
	rules := []*api.Rule{
		makeRule("a"),
		makeRule("b", supersedes("a")),
		makeRule("c", supersedes("a")),
	}
	r := Resolve(rules)
	if r.Superseded["a"] != "b" {
		t.Errorf("Superseded[a] = %q, want b (first-rule-wins)", r.Superseded["a"])
	}
}

func TestResolve_Supersedes_IgnoresExternalRefs(t *testing.T) {
	// rule supersedes an ID not in the set. Nothing happens; the
	// rule itself runs.
	rules := []*api.Rule{
		makeRule("a", supersedes("ghost")),
	}
	r := Resolve(rules)
	if len(r.Order) != 1 || r.Order[0].ID != "a" {
		t.Errorf("expected [a], got %v", ruleIDs(r.Order))
	}
	if len(r.Superseded) != 0 {
		t.Errorf("Superseded should be empty: %v", r.Superseded)
	}
}

func TestResolve_Conflicts_DetectedAmongActive(t *testing.T) {
	// pam-direct conflicts with pam-authselect. Both active.
	// One conflict pair recorded (deduped by canonical ordering).
	rules := []*api.Rule{
		makeRule("pam-direct", conflictsWith("pam-authselect")),
		makeRule("pam-authselect"),
	}
	r := Resolve(rules)
	if len(r.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %+v", len(r.Conflicts), r.Conflicts)
	}
	c := r.Conflicts[0]
	if !((c.RuleID == "pam-direct" && c.ConflictsWith == "pam-authselect") ||
		(c.RuleID == "pam-authselect" && c.ConflictsWith == "pam-direct")) {
		t.Errorf("unexpected conflict pair: %+v", c)
	}
}

func TestResolve_Conflicts_DedupedAcrossDirections(t *testing.T) {
	// Both rules declare conflicts_with mutually. One pair only.
	rules := []*api.Rule{
		makeRule("a", conflictsWith("b")),
		makeRule("b", conflictsWith("a")),
	}
	r := Resolve(rules)
	if len(r.Conflicts) != 1 {
		t.Errorf("expected 1 deduped conflict, got %d: %+v", len(r.Conflicts), r.Conflicts)
	}
}

func TestResolve_Conflicts_SkippedRulesIgnored(t *testing.T) {
	// pam-direct conflicts with pam-authselect, but pam-direct is
	// superseded by pam-modern. The conflict no longer applies
	// (pam-direct isn't active).
	rules := []*api.Rule{
		makeRule("pam-direct", conflictsWith("pam-authselect")),
		makeRule("pam-authselect"),
		makeRule("pam-modern", supersedes("pam-direct")),
	}
	r := Resolve(rules)
	if len(r.Conflicts) != 0 {
		t.Errorf("conflict should be elided when one side is superseded: %+v", r.Conflicts)
	}
}

func TestResolve_Combined_DepsConflictsSupersedes(t *testing.T) {
	// Realistic mix: A→B (deps), C supersedes A, D conflicts with C.
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b"),
		makeRule("c", supersedes("a")),
		makeRule("d", conflictsWith("c")),
	}
	r := Resolve(rules)
	if !contains(r.Skipped, "a") {
		t.Errorf("a should be skipped (superseded by c): %v", r.Skipped)
	}
	if r.Superseded["a"] != "c" {
		t.Errorf("Superseded[a] = %q, want c", r.Superseded["a"])
	}
	// Active set: b, c, d. Topological: b before any deps on it
	// (none after a is removed), c, d. Actual order: b, c, d
	// alphabetical at each in-degree-0 step.
	got := ruleIDs(r.Order)
	if !contains(got, "b") || !contains(got, "c") || !contains(got, "d") {
		t.Errorf("Order missing expected IDs: got %v", got)
	}
	if contains(got, "a") {
		t.Errorf("Order should not contain superseded rule a: %v", got)
	}
	// d ↔ c conflict surfaced.
	if len(r.Conflicts) != 1 {
		t.Errorf("expected 1 conflict (c↔d), got %+v", r.Conflicts)
	}
}

func TestResolve_DeterministicAcrossRuns(t *testing.T) {
	// Same input, same output across runs AND across input
	// permutations. Running the same slice 3 times only catches
	// hidden mutation; a real determinism test must scramble input
	// order and assert identical output. The supersedes algorithm
	// is alphabetical-smallest-superseder-wins precisely so the
	// outcome doesn't depend on load order.
	build := func(order []int) []*api.Rule {
		all := []*api.Rule{
			makeRule("a", dependsOn("b")),
			makeRule("b", dependsOn("c", "d")),
			makeRule("c"),
			makeRule("d"),
			makeRule("e", supersedes("c")),
		}
		out := make([]*api.Rule, len(order))
		for i, idx := range order {
			out[i] = all[idx]
		}
		return out
	}

	first := ruleIDs(Resolve(build([]int{0, 1, 2, 3, 4})).Order)
	scrambles := [][]int{
		{4, 3, 2, 1, 0}, // reversed
		{2, 0, 4, 1, 3}, // arbitrary
		{1, 4, 0, 3, 2}, // arbitrary
	}
	for i, perm := range scrambles {
		got := ruleIDs(Resolve(build(perm)).Order)
		if !equalSlice(got, first) {
			t.Errorf("permutation %d (%v) produced %v, expected %v",
				i, perm, got, first)
		}
	}
}

func TestResolve_Supersedes_AlphabeticalWinsRegardlessOfInputOrder(t *testing.T) {
	// b and c both supersede a. b should win (smallest superseder
	// ID alphabetically), regardless of input order. This is the
	// Go improvement over Python's last-in-input-order behavior.
	cases := [][]*api.Rule{
		{makeRule("a"), makeRule("b", supersedes("a")), makeRule("c", supersedes("a"))},
		{makeRule("c", supersedes("a")), makeRule("a"), makeRule("b", supersedes("a"))},
		{makeRule("b", supersedes("a")), makeRule("c", supersedes("a")), makeRule("a")},
	}
	for i, rules := range cases {
		r := Resolve(rules)
		if r.Superseded["a"] != "b" {
			t.Errorf("case %d: Superseded[a] = %q, want b (alphabetical-smallest)",
				i, r.Superseded["a"])
		}
	}
}

func TestFailedDependencies(t *testing.T) {
	rules := []*api.Rule{
		makeRule("a", dependsOn("b", "c")),
		makeRule("b"),
		makeRule("c"),
	}
	failed := map[string]struct{}{"b": {}}
	got := FailedDependencies("a", rules, failed)
	if !equalSlice(got, []string{"b"}) {
		t.Errorf("got %v, want [b]", got)
	}
	// No failures.
	got = FailedDependencies("a", rules, map[string]struct{}{})
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
	// Unknown rule.
	got = FailedDependencies("nonexistent", rules, failed)
	if len(got) != 0 {
		t.Errorf("got %v, want empty for unknown rule", got)
	}
}

func TestShouldSkip_DirectFailure(t *testing.T) {
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b"),
	}
	skip, reason := ShouldSkip("a", rules, map[string]struct{}{"b": {}}, false)
	if !skip {
		t.Error("should skip when direct dep failed")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestShouldSkip_TransitiveFailure(t *testing.T) {
	// a → b → c, c failed. a should be transitively skipped.
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b", dependsOn("c")),
		makeRule("c"),
	}
	skip, reason := ShouldSkip("a", rules, map[string]struct{}{"c": {}}, true)
	if !skip {
		t.Error("should skip transitively when c (a→b→c) failed")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
	// Without transitive, skip should be false (direct dep b is
	// not in failed set).
	skip, _ = ShouldSkip("a", rules, map[string]struct{}{"c": {}}, false)
	if skip {
		t.Error("non-transitive should not skip when only indirect dep failed")
	}
}

func TestShouldSkip_NoFailures(t *testing.T) {
	rules := []*api.Rule{
		makeRule("a", dependsOn("b")),
		makeRule("b"),
	}
	skip, _ := ShouldSkip("a", rules, map[string]struct{}{}, true)
	if skip {
		t.Error("should not skip when no deps failed")
	}
}

func TestFormatIssues_AllCategories(t *testing.T) {
	r := &ResolvedRules{
		Cycles:       [][]string{{"a", "b", "a"}},
		CycleMembers: []string{"a", "b"},
		Conflicts:    []ConflictPair{{RuleID: "x", ConflictsWith: "y"}},
		Superseded: map[string]string{
			"old": "new",
		},
	}
	msgs := FormatIssues(r)
	wantSubstrings := []string{
		"error: circular dependency: a → b → a",
		"error: 2 rule(s) dropped due to circular dependency: a, b",
		"warning: conflict: x conflicts with y (both active)",
		"info: skipping old (superseded by new)",
	}
	for _, want := range wantSubstrings {
		found := false
		for _, m := range msgs {
			if strings.Contains(m, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("FormatIssues missing %q\nactual: %v", want, msgs)
		}
	}
}

func TestIssueSeverity(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"error: circular dependency: a → b", "error"},
		{"warning: conflict: x conflicts with y (both active)", "warning"},
		{"info: skipping old (superseded by new)", "info"},
		{"random text without prefix", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.line, func(t *testing.T) {
			if got := IssueSeverity(tc.line); got != tc.want {
				t.Errorf("IssueSeverity(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestFormatIssues_NilResult(t *testing.T) {
	if msgs := FormatIssues(nil); msgs != nil {
		t.Errorf("FormatIssues(nil) = %v, want nil", msgs)
	}
}

// ruleIDs extracts IDs from a slice of rule pointers in order.
func ruleIDs(rules []*api.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ID
	}
	return out
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s []string, target string) bool {
	for _, x := range s {
		if x == target {
			return true
		}
	}
	return false
}
