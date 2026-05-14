package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/mappings"
)

// registerControlFilterFlag wires `--control` as a repeatable
// FRAMEWORK:CONTROL filter. Operators pass
// `--control cis-rhel9:5.1.12` (or `cis_rhel9:5.1.12` — hyphens
// and underscores in the framework portion are interchangeable
// per C-033). Long-only — no short letter, since `-c` is taken
// by --category (C-032).
//
// Multiple --control values are OR-across-values: a rule
// matches if ANY of its FrameworkRefs matches ANY of the
// operator's controls. Composes AND with --severity, --tag,
// --category, --framework.
func registerControlFilterFlag(fs *pflag.FlagSet, dst *[]string) {
	fs.StringArrayVar(dst, "control", nil,
		"filter rules by FRAMEWORK:CONTROL (--control cis-rhel9:5.1.12); repeatable, OR across values; framework portion accepts hyphen or underscore")
}

// controlFilter is one parsed FRAMEWORK:CONTROL pair.
type controlFilter struct {
	frameworkID string // canonical (underscore form, lowercase)
	controlID   string // case-preserved (control IDs may be case-sensitive)
}

// parseControlFilters parses raw operator entries into
// controlFilter structs. Format: `FRAMEWORK:CONTROL`. The
// framework portion is normalized via normalizeFrameworkID
// (lowercase, hyphen→underscore); the control portion is kept
// as-typed because corpus IDs vary in case (e.g., NIST `AC-1`,
// CIS `5.1.12`).
//
// Empty input returns (nil, nil). Malformed entries (no colon,
// empty framework, empty control) produce a usage error.
func parseControlFilters(raw []string) ([]controlFilter, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]controlFilter, 0, len(raw))
	for _, entry := range raw {
		fw, ctrl, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("--control %q: expected FRAMEWORK:CONTROL form (missing ':')", entry)
		}
		fwNorm := normalizeFrameworkID(fw)
		ctrlTrim := strings.TrimSpace(ctrl)
		if fwNorm == "" {
			return nil, fmt.Errorf("--control %q: empty FRAMEWORK", entry)
		}
		if ctrlTrim == "" {
			return nil, fmt.Errorf("--control %q: empty CONTROL", entry)
		}
		out = append(out, controlFilter{frameworkID: fwNorm, controlID: ctrlTrim})
	}
	return out, nil
}

// validateControls confirms every parsed filter's
// (frameworkID, controlID) pair appears in the loaded corpus.
// Unknown pairs produce a usage error listing the available
// controls for the named framework (when the framework is
// known) or available frameworks (when it isn't).
func validateControls(filters []controlFilter, rules []*api.Rule) error {
	if len(filters) == 0 {
		return nil
	}
	// Build the set of (framework, control) pairs that appear in
	// the loaded corpus. Done once; reused per filter.
	pairs := make(map[string]map[string]struct{}) // framework → controls
	for _, r := range rules {
		for _, ref := range mappings.RefsFromReferences(r.References) {
			if pairs[ref.FrameworkID] == nil {
				pairs[ref.FrameworkID] = make(map[string]struct{})
			}
			pairs[ref.FrameworkID][ref.ControlID] = struct{}{}
		}
	}
	for _, f := range filters {
		fwSet, fwOK := pairs[f.frameworkID]
		if !fwOK {
			return fmt.Errorf("--control %s:%s: unknown framework %q; available: %s",
				f.frameworkID, f.controlID, f.frameworkID, strings.Join(availableFrameworksFromPairs(pairs), ", "))
		}
		if _, ctrlOK := fwSet[f.controlID]; !ctrlOK {
			sample := sampleControlsFor(fwSet, 8)
			return fmt.Errorf("--control %s:%s: control %q not found under framework %q (sample available: %s)",
				f.frameworkID, f.controlID, f.controlID, f.frameworkID, strings.Join(sample, ", "))
		}
	}
	return nil
}

// availableFrameworksFromPairs returns the framework IDs in the
// pairs map, sorted. Helper for usage-error formatting.
func availableFrameworksFromPairs(pairs map[string]map[string]struct{}) []string {
	out := make([]string, 0, len(pairs))
	for fw := range pairs {
		out = append(out, fw)
	}
	sort.Strings(out)
	return out
}

// sampleControlsFor returns up to limit control IDs from set,
// sorted, for use in operator-error messages so the operator
// has examples of what a valid control under that framework
// looks like.
func sampleControlsFor(set map[string]struct{}, limit int) []string {
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// filterRulesByControl returns rules whose parsed FrameworkRefs
// intersect with the filter set. Empty filters returns the
// input unchanged. Match: framework exact (canonical), control
// exact (case-preserved). OR across the filter list (a rule
// matches if any of its refs matches any filter).
func filterRulesByControl(rules []*api.Rule, filters []controlFilter) []*api.Rule {
	if len(filters) == 0 {
		return rules
	}
	out := make([]*api.Rule, 0, len(rules))
	for _, r := range rules {
		refs := mappings.RefsFromReferences(r.References)
		if matchesAnyControl(refs, filters) {
			out = append(out, r)
		}
	}
	return out
}

// matchesAnyControl returns true when any FrameworkRef in refs
// matches any filter. Hot path; no allocations.
func matchesAnyControl(refs []api.FrameworkRef, filters []controlFilter) bool {
	for _, ref := range refs {
		for _, f := range filters {
			if ref.FrameworkID == f.frameworkID && ref.ControlID == f.controlID {
				return true
			}
		}
	}
	return false
}
