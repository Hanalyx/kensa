// Package coverage computes framework control coverage reports
// from a loaded rule corpus. C-045 introduces this as the
// repurposed semantics for `kensa coverage`; C-044 moved the
// previous mechanism-listing semantics to `kensa mechanisms`.
//
// Coverage means: for a given framework (e.g. cis_rhel9),
// enumerate the distinct controls referenced by rules in the
// corpus and the rules that map to each. The output is operator-
// auditable proof of "which controls do my rules cover" — input
// to compliance dashboards without database round-trips.
//
// Denominator-based percentage ("212 / 318 = 66.7%") would
// require an external control catalog (CIS publishes RHEL9
// benchmarks; NIST 800-53 has a defined set; STIG has STIG-IDs).
// kensa has no such catalog at v1.0; this package ships
// numerator-only. JSON shape is forward-compatible: adding
// ControlsTotal later is additive.
package coverage

import (
	"sort"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/mappings"
)

// CoverageReport is the operator-facing shape of a coverage
// computation. JSON tags use snake_case to match the rest of
// kensa's API surface (consistent with PruneReport,
// store.Stats, etc.).
type CoverageReport struct {
	Framework      string            `json:"framework"`
	RulesScanned   int               `json:"rules_scanned"`
	RulesMatching  int               `json:"rules_matching"`
	ControlsMapped int               `json:"controls_mapped"`
	Controls       []ControlCoverage `json:"controls"`
}

// ControlCoverage is the per-control row in CoverageReport.
// RuleCount is len(Rules) but exposed for fast JSON-consumer
// summary access.
type ControlCoverage struct {
	ControlID string   `json:"control_id"`
	RuleCount int      `json:"rule_count"`
	Rules     []string `json:"rules"`
}

// ComputeReport walks rules and emits a CoverageReport for the
// given framework. The framework value MUST be a canonical
// framework_id as returned by mappings.RefsFromReferences (e.g.
// "cis_rhel9", "nist_800_53", "stig_rhel9"); the caller is
// expected to have validated and normalized the operator's
// input upstream.
//
// Determinism: ControlsMapped order is by control_id natural
// sort; each ControlCoverage.Rules slice is sorted by rule ID.
// JSON output is byte-identical across runs for the same
// corpus, suitable for diff-based dashboards.
func ComputeReport(framework string, rules []*api.Rule) CoverageReport {
	report := CoverageReport{
		Framework:    framework,
		RulesScanned: len(rules),
	}

	// control_id → set of rule IDs that map to it. Set
	// (map[string]struct{}) so multiple references to the
	// same control from one rule don't double-count, and so
	// duplicate rule IDs across the corpus collapse.
	byControl := make(map[string]map[string]struct{})
	matchingRules := make(map[string]struct{})

	for _, r := range rules {
		refs := mappings.RefsFromReferences(r.References)
		var rMatches bool
		for _, ref := range refs {
			if ref.FrameworkID != framework {
				continue
			}
			rMatches = true
			set, ok := byControl[ref.ControlID]
			if !ok {
				set = make(map[string]struct{})
				byControl[ref.ControlID] = set
			}
			set[r.ID] = struct{}{}
		}
		if rMatches {
			matchingRules[r.ID] = struct{}{}
		}
	}

	report.RulesMatching = len(matchingRules)
	report.ControlsMapped = len(byControl)

	controls := make([]ControlCoverage, 0, len(byControl))
	for ctrl, set := range byControl {
		ruleIDs := make([]string, 0, len(set))
		for id := range set {
			ruleIDs = append(ruleIDs, id)
		}
		sort.Strings(ruleIDs)
		controls = append(controls, ControlCoverage{
			ControlID: ctrl,
			RuleCount: len(ruleIDs),
			Rules:     ruleIDs,
		})
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})
	report.Controls = controls

	return report
}
