// Package info computes the four C-047 query shapes against a
// loaded rule corpus: single-rule details, rules-mapping-to-
// control, list-controls-in-framework, and free-text search.
//
// All four functions are deterministic (sorted output) and
// side-effect-free. The CLI surface in cmd/kensa/info.go wires
// them through pflag + writers.
package info

import (
	"sort"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/mappings"
)

// RuleDetails is the shape returned by DescribeRule. The full
// rule body (Implementations, Rationale) is intentionally not
// exposed in the structured output — operators wanting that
// can read the rule YAML directly. RuleDetails covers the
// fields that answer "what does this rule check, who cares
// (severity), where does it apply (platforms), what
// frameworks claim it (refs)?"
type RuleDetails struct {
	ID            string                  `json:"id"`
	Title         string                  `json:"title"`
	Description   string                  `json:"description"`
	Severity      string                  `json:"severity"`
	Category      string                  `json:"category"`
	Tags          []string                `json:"tags"`
	Platforms     []PlatformSummary       `json:"platforms"`
	FrameworkRefs []api.FrameworkRef      `json:"framework_refs"`
}

// PlatformSummary mirrors api.Platform with snake_case JSON
// tags so the C-047 shape is consistent with PruneReport /
// FrameworkSummary / CoverageReport.
type PlatformSummary struct {
	Family      string `json:"family"`
	MinVersion  int    `json:"min_version"`
	MaxVersion  int    `json:"max_version"`
	Derivatives bool   `json:"derivatives"`
}

// ControlMatch is the shape returned by RulesForControl.
type ControlMatch struct {
	FrameworkID string   `json:"framework_id"`
	ControlID   string   `json:"control_id"`
	Rules       []string `json:"rules"`
}

// ControlListing is the shape returned by ListFrameworkControls.
// Each ControlEntry is one (control_id, mapping rule count) row.
type ControlListing struct {
	FrameworkID string         `json:"framework_id"`
	Controls    []ControlEntry `json:"controls"`
}

// ControlEntry is one row in a ControlListing.
type ControlEntry struct {
	ControlID string `json:"control_id"`
	RuleCount int    `json:"rule_count"`
}

// SearchHit is one row in a free-text search result.
type SearchHit struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

// ErrNotFound signals "the lookup turned up empty." Distinct
// from invalid-input errors so the CLI dispatch can map
// not-found to exit 1 (runtime) and bad-input to exit 2
// (usage) per spec C-07. Specifically NOT a UsageError —
// runCLI's exit-code mapping treats UsageError as exit 2,
// everything else as exit 1, which is the desired contract:
// the invocation was syntactically correct, the corpus just
// doesn't contain the requested key. A future refactor
// should preserve this distinction.
type ErrNotFound struct {
	What string // "rule" or "control"
	Key  string // operator-typed value
}

func (e *ErrNotFound) Error() string {
	return e.What + " not found: " + e.Key
}

// DescribeRule returns the rule whose ID matches id, wrapped
// in the C-047 RuleDetails shape. Returns *ErrNotFound when
// the rule isn't in the loaded corpus.
func DescribeRule(id string, rules []*api.Rule) (*RuleDetails, error) {
	for _, r := range rules {
		if r.ID == id {
			return ruleToDetails(r), nil
		}
	}
	return nil, &ErrNotFound{What: "rule", Key: id}
}

// RulesForControl returns every rule ID whose framework_refs
// include (framework, control). Returns *ErrNotFound when no
// rule maps to that control.
func RulesForControl(framework, control string, rules []*api.Rule) (*ControlMatch, error) {
	var matched []string
	seen := make(map[string]struct{})
	for _, r := range rules {
		for _, ref := range mappings.RefsFromReferences(r.References) {
			if ref.FrameworkID == framework && ref.ControlID == control {
				if _, dup := seen[r.ID]; !dup {
					matched = append(matched, r.ID)
					seen[r.ID] = struct{}{}
				}
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil, &ErrNotFound{What: "control", Key: framework + ":" + control}
	}
	sort.Strings(matched)
	return &ControlMatch{
		FrameworkID: framework,
		ControlID:   control,
		Rules:       matched,
	}, nil
}

// ListFrameworkControls walks every rule's framework_refs and
// returns the listing of distinct controls under the named
// framework with per-control rule counts. Returns
// *ErrNotFound if the framework has no references in the
// corpus (consistent with C-07 — invocation was syntactically
// correct, the lookup is empty).
func ListFrameworkControls(framework string, rules []*api.Rule) (*ControlListing, error) {
	byControl := make(map[string]map[string]struct{})
	for _, r := range rules {
		for _, ref := range mappings.RefsFromReferences(r.References) {
			if ref.FrameworkID != framework {
				continue
			}
			set, ok := byControl[ref.ControlID]
			if !ok {
				set = make(map[string]struct{})
				byControl[ref.ControlID] = set
			}
			set[r.ID] = struct{}{}
		}
	}
	if len(byControl) == 0 {
		return nil, &ErrNotFound{What: "framework", Key: framework}
	}
	entries := make([]ControlEntry, 0, len(byControl))
	for ctrl, ruleSet := range byControl {
		entries = append(entries, ControlEntry{
			ControlID: ctrl,
			RuleCount: len(ruleSet),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ControlID < entries[j].ControlID
	})
	return &ControlListing{
		FrameworkID: framework,
		Controls:    entries,
	}, nil
}

// SearchFilters narrows the SearchRules result. Empty fields
// pass through. FamilyPrefix is a framework_id prefix match
// (e.g. "cis_" matches cis_rhel8 + cis_rhel9 + cis_rhel10).
// Rhel constrains rule.Platforms to RHEL/version when set.
type SearchFilters struct {
	FamilyPrefix string // "cis_" / "stig_" / "nist_" — empty = no filter
	Rhel         int    // 8 / 9 / 10 — zero = no filter
}

// SearchRules returns rules whose Title or Description matches
// the (case-insensitive) substring query, narrowed by filters.
// Empty query returns every rule (subject to filters), so
// `kensa info --cis --rhel 9` yields all CIS RHEL9 rules with
// no text search.
func SearchRules(query string, filters SearchFilters, rules []*api.Rule) []SearchHit {
	q := strings.ToLower(strings.TrimSpace(query))
	var hits []SearchHit

	for _, r := range rules {
		if q != "" {
			t := strings.ToLower(r.Title)
			d := strings.ToLower(r.Description)
			if !strings.Contains(t, q) && !strings.Contains(d, q) {
				continue
			}
		}
		if filters.FamilyPrefix != "" && !ruleHasFrameworkFamily(r, filters.FamilyPrefix) {
			continue
		}
		if filters.Rhel != 0 && !rulePlatformIncludesRhel(r, filters.Rhel) {
			continue
		}
		hits = append(hits, SearchHit{
			ID:       r.ID,
			Title:    r.Title,
			Severity: r.Severity,
			Category: r.Category,
		})
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].ID < hits[j].ID
	})
	return hits
}

// ruleHasFrameworkFamily returns true iff any framework_id
// referenced by the rule starts with prefix.
func ruleHasFrameworkFamily(r *api.Rule, prefix string) bool {
	for _, ref := range mappings.RefsFromReferences(r.References) {
		if strings.HasPrefix(ref.FrameworkID, prefix) {
			return true
		}
	}
	return false
}

// rulePlatformIncludesRhel returns true iff any rule.Platforms
// entry covers RHEL at the given version. The match is "RHEL
// family AND version is in [MinVersion, MaxVersion if set,
// else MinVersion only]". Family match is case-insensitive
// against "rhel"; rule corpora occasionally use "redhat" so
// we accept both.
func rulePlatformIncludesRhel(r *api.Rule, version int) bool {
	for _, p := range r.Platforms {
		fam := strings.ToLower(p.Family)
		if fam != "rhel" && fam != "redhat" {
			continue
		}
		if p.MinVersion != 0 && version < p.MinVersion {
			continue
		}
		if p.MaxVersion != 0 && version > p.MaxVersion {
			continue
		}
		return true
	}
	return false
}

// ruleToDetails converts an api.Rule into the C-047
// RuleDetails shape. Rationale and Implementations are
// intentionally dropped — operators wanting them can read
// the YAML directly. ConflictsWith / DependsOn / Supersedes
// are also dropped (relevant to the engine, not to "what is
// this rule about").
func ruleToDetails(r *api.Rule) *RuleDetails {
	platforms := make([]PlatformSummary, 0, len(r.Platforms))
	for _, p := range r.Platforms {
		platforms = append(platforms, PlatformSummary{
			Family:      p.Family,
			MinVersion:  p.MinVersion,
			MaxVersion:  p.MaxVersion,
			Derivatives: p.Derivatives,
		})
	}
	refs := mappings.RefsFromReferences(r.References)
	// Sort for determinism.
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].FrameworkID != refs[j].FrameworkID {
			return refs[i].FrameworkID < refs[j].FrameworkID
		}
		return refs[i].ControlID < refs[j].ControlID
	})
	return &RuleDetails{
		ID:            r.ID,
		Title:         r.Title,
		Description:   r.Description,
		Severity:      r.Severity,
		Category:      r.Category,
		Tags:          append([]string(nil), r.Tags...),
		Platforms:     platforms,
		FrameworkRefs: refs,
	}
}
