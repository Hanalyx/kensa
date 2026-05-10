package coverage

import (
	"sort"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/mappings"
)

// FrameworkSummary is one row of the `kensa list frameworks`
// output. Counts are over the loaded corpus only — frameworks
// not referenced by any rule don't appear (the listing is "what
// is IN the corpus", not "what frameworks exist anywhere").
type FrameworkSummary struct {
	FrameworkID string `json:"framework_id"`
	Controls    int    `json:"controls"`
	Rules       int    `json:"rules"`
}

// ListFrameworks walks every rule's framework_refs and returns
// one FrameworkSummary per distinct framework_id, sorted
// alphabetically. `controls` counts distinct control_ids in
// that framework; `rules` counts distinct rule IDs that
// reference at least one control in the framework.
//
// Determinism: framework_id ordering is alphabetical so JSON-
// consumer diff dashboards see no spurious churn across runs.
func ListFrameworks(rules []*api.Rule) []FrameworkSummary {
	type sets struct {
		controls map[string]struct{}
		rules    map[string]struct{}
	}
	byFramework := make(map[string]*sets)

	for _, r := range rules {
		for _, ref := range mappings.RefsFromReferences(r.References) {
			s, ok := byFramework[ref.FrameworkID]
			if !ok {
				s = &sets{
					controls: make(map[string]struct{}),
					rules:    make(map[string]struct{}),
				}
				byFramework[ref.FrameworkID] = s
			}
			s.controls[ref.ControlID] = struct{}{}
			s.rules[r.ID] = struct{}{}
		}
	}

	out := make([]FrameworkSummary, 0, len(byFramework))
	for fid, s := range byFramework {
		out = append(out, FrameworkSummary{
			FrameworkID: fid,
			Controls:    len(s.controls),
			Rules:       len(s.rules),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FrameworkID < out[j].FrameworkID
	})
	return out
}
