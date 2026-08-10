package rule

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/detect"
	"github.com/Hanalyx/kensa/internal/mappings"
)

// ValidationError is one schema-constraint violation found by [Validate].
type ValidationError struct {
	// Field is a dot-path identifier for the failing field
	// (e.g., "implementations[0].remediation.mechanism").
	Field string
	// Msg describes the constraint that was violated.
	Msg string
}

// Error implements error.
func (e ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Msg)
	}
	return e.Msg
}

// ValidateOptions controls strictness of [Validate].
type ValidateOptions struct {
	// Filename is the source filename; when set, Validate checks that
	// the filename stem (without extension) matches rule.ID (§6.2 rule 2).
	Filename string

	// ExpectedCategory is the parent directory name; when set, Validate
	// checks that rule.Category matches it (§6.2 rule 3).
	ExpectedCategory string

	// KnownCapabilities, when non-nil, is the set of valid capability
	// names. When nil, capability-reference checking is skipped.
	KnownCapabilities map[string]struct{}
}

// Validate checks rule against the V1 schema constraints.
//
// Constraints checked:
//
//  1. Required fields (id, title, description, rationale, severity, category).
//  2. Severity is one of: critical, high, medium, low.
//  3. At least one implementation exists.
//  4. Exactly one implementation has default=true.
//  5. Atomicity consistency: transactional:true rules must not use non-capturable mechanisms.
//  6. File naming: filename stem must match rule ID (when opts.Filename is set).
//  7. Category consistency: category must match opts.ExpectedCategory (when set).
//  8. Capability references: when expressions must name known capabilities (when opts.KnownCapabilities is set).
//  9. A declared framework reference key carries a value.
//  10. CMMC Level 2 refs match the derivation from the rule's own 800-171 refs.
//  11. Remediation params satisfy the mechanism contract.
//  12. Check params satisfy the check-method contract.
//  13. Param values are within the engine's accepted domain.
//
// Validate returns all violations found, never stopping early, so callers
// can report every problem at once.
func Validate(rule *api.Rule, opts ValidateOptions) []ValidationError {
	var errs []ValidationError
	add := func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Msg: msg})
	}

	// (1) Required fields.
	if rule.ID == "" {
		add("id", "required field is empty")
	}
	if rule.Title == "" {
		add("title", "required field is empty")
	}
	if rule.Description == "" {
		add("description", "required field is empty")
	}
	if rule.Rationale == "" {
		add("rationale", "required field is empty")
	}
	if rule.Severity == "" {
		add("severity", "required field is empty")
	}
	if rule.Category == "" {
		add("category", "required field is empty")
	}

	// (2) Severity enum.
	switch rule.Severity {
	case "critical", "high", "medium", "low", "":
		// "" handled above
	default:
		add("severity", fmt.Sprintf("must be critical|high|medium|low, got %q", rule.Severity))
	}

	// (3) At least one implementation.
	if len(rule.Implementations) == 0 {
		add("implementations", "at least one implementation is required")
	}

	// (4) Exactly one default implementation.
	defaultCount := 0
	for i, impl := range rule.Implementations {
		if impl.Default {
			defaultCount++
			_ = i
		}
	}
	if len(rule.Implementations) > 0 && defaultCount == 0 {
		// Zero default is allowed ONLY when every implementation is
		// capability-gated (when != nil). Such a rule is intentionally
		// not-applicable — and SKIPPED (ErrNoImplementation → compliance
		// "skipped") — on a host lacking the capability, instead of falling
		// back to a default that runs everywhere. A rule with any ungated
		// non-default implementation still requires the default fallback.
		allGated := true
		for _, impl := range rule.Implementations {
			if impl.When == nil {
				allGated = false
				break
			}
		}
		if !allGated {
			add("implementations", "exactly one implementation must have default:true, or every implementation must be capability-gated (when:); found neither")
		}
	}
	if defaultCount > 1 {
		add("implementations", fmt.Sprintf("exactly one implementation must have default:true; found %d", defaultCount))
	}

	// (5) Atomicity consistency.
	if rule.Transactional {
		for i, impl := range rule.Implementations {
			checkAtomicity(rule.ID, i, &impl.Remediation, add)
		}
	}

	// (6) File naming.
	if opts.Filename != "" && rule.ID != "" {
		stem := strings.TrimSuffix(filepath.Base(opts.Filename), filepath.Ext(opts.Filename))
		if stem != rule.ID {
			add("id", fmt.Sprintf("filename stem %q must match id %q", stem, rule.ID))
		}
	}

	// (7) Category consistency.
	if opts.ExpectedCategory != "" && rule.Category != "" {
		if rule.Category != opts.ExpectedCategory {
			add("category", fmt.Sprintf("category %q must match parent directory %q", rule.Category, opts.ExpectedCategory))
		}
	}

	// (8) Capability references.
	if opts.KnownCapabilities != nil {
		for i, impl := range rule.Implementations {
			if impl.When == nil {
				continue
			}
			caps := collectCapabilityRefs(impl.When)
			for _, cap := range caps {
				if _, known := opts.KnownCapabilities[cap]; !known {
					add(fmt.Sprintf("implementations[%d].when", i),
						fmt.Sprintf("capability %q is not in the known capability set", cap))
				}
			}
		}
	}

	// (9) A declared framework key must carry a value. An empty key reads as
	// "this rule is mapped to that framework" everywhere it is consumed, while
	// contributing nothing: it produces no FrameworkRef, so a coverage query
	// counts the rule as unmapped while a human reading the YAML counts it as
	// mapped. Twelve rules carried one before this check existed.
	for family, v := range rule.References {
		if isEmptyRef(v) {
			add("references."+family,
				fmt.Sprintf("framework key %q is declared but carries no value; "+
					"populate it or remove the key", family))
		}
	}

	// (10) CMMC Level 2 refs must equal what derivation produces from this
	// rule's own reviewed 800-171 refs.
	//
	// CMMC Level 2 IS the 110 NIST SP 800-171 Rev 2 requirements, one for one,
	// per 32 CFR 170. So a practice id carries no claim the 800-171 ref did not
	// already carry, and the only way it can go wrong is by drifting from it:
	// an extra practice asserts a mapping nobody reviewed, and a missing one
	// means the emission is stale. Both are caught here rather than trusted to
	// whoever last edited the file, because these refs are generated and a
	// generated file invites hand editing.
	validateCMMCDerivation(rule, add)

	// (11) Remediation params satisfy the mechanism contract (internal/mechanism).
	validateRemediationParams(rule, add)

	// (12) Check params satisfy the check-method contract (internal/check),
	// closed-world: unknown check params (e.g. an unread 'comparator') are
	// rejected at load instead of silently ignored at scan time.
	validateCheckParams(rule, add)

	// (13) Param VALUES are within the engine's accepted domain (separators,
	// state enums). Rejects e.g. a config_set separator "\t" at load instead
	// of at Capture on a live host.
	validateValueDomains(rule, add)

	return errs
}

// nonCapturableMechanisms is the set of mechanism names that cannot
// provide pre-state capture. A transactional:true rule that uses any of
// these has an atomicity consistency violation.
var nonCapturableMechanisms = map[string]bool{
	"command_exec":          true,
	"manual":                true,
	"grub_parameter_set":    true,
	"grub_parameter_remove": true,
}

// checkAtomicity appends ValidationErrors for any non-capturable mechanisms
// found in rem.
func checkAtomicity(ruleID string, implIdx int, rem *api.Remediation, add func(string, string)) {
	if rem.Mechanism != "" {
		if nonCapturableMechanisms[rem.Mechanism] {
			add(
				fmt.Sprintf("implementations[%d].remediation.mechanism", implIdx),
				fmt.Sprintf(
					"mechanism %q is non-capturable but rule declares transactional:true; add transactional:false to the rule",
					rem.Mechanism,
				),
			)
		}
		return
	}
	for j, step := range rem.Steps {
		if nonCapturableMechanisms[step.Mechanism] {
			add(
				fmt.Sprintf("implementations[%d].remediation.steps[%d].mechanism", implIdx, j),
				fmt.Sprintf(
					"mechanism %q is non-capturable but rule declares transactional:true; add transactional:false to the rule",
					step.Mechanism,
				),
			)
		}
	}
}

// collectCapabilityRefs extracts all capability name strings referenced in
// a when expression (string, all/any/not map).
func collectCapabilityRefs(when interface{}) []string {
	switch v := when.(type) {
	case string:
		return []string{v}
	case map[string]interface{}:
		var out []string
		if all, ok := v["all"]; ok {
			if list, err := toStringList(all); err == nil {
				out = append(out, list...)
			}
		}
		if any, ok := v["any"]; ok {
			if list, err := toStringList(any); err == nil {
				out = append(out, list...)
			}
		}
		if not, ok := v["not"]; ok {
			if s, ok := not.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// KnownCapabilities is the canonical set of capability names defined in the
// V1 schema. Callers may pass this to [ValidateOptions.KnownCapabilities] to enable
// capability-reference checking.
// KnownCapabilities is the set of capability names a rule may gate on. It is
// DERIVED from the probe list in internal/detect rather than maintained by hand.
// The two had drifted: ufw, apt, apparmor, dpkg and three others were probed
// while absent here, so a rule gating on any of them would fail validation for a
// capability the engine does in fact detect. Deriving it makes that impossible.
var KnownCapabilities = func() map[string]struct{} {
	names := detect.KnownCapabilities()
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}()

// isEmptyRef reports whether a references block entry carries nothing. nil
// covers the bare "cis:" form; the len checks cover an explicit empty list, map
// or string, which parse to a value that is present but says nothing.
func isEmptyRef(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case []interface{}:
		return len(t) == 0
	case map[string]interface{}:
		return len(t) == 0
	case string:
		return strings.TrimSpace(t) == ""
	}
	return false
}

// validateCMMCDerivation enforces that cmmc_l2 refs are exactly the derivation
// of the rule's reviewed nist_800_171 refs (spec rule-cmmc-l2-derived-refs
// C-01). A rule with no 800-171 refs must carry no cmmc_l2 refs at all:
// derivation never invents a mapping for an unmapped rule.
func validateCMMCDerivation(rule *api.Rule, add func(field, msg string)) {
	declared := refStrings(rule.References[mappings.CMMCLevel2Framework])
	nist := refStrings(rule.References["nist_800_171"])
	want := mappings.CMMCLevel2Practices(nist)

	if len(declared) == 0 && len(want) == 0 {
		return
	}
	if equalStringSets(declared, want) {
		return
	}
	extra := setDifference(declared, want)
	missing := setDifference(want, declared)
	switch {
	case len(nist) == 0:
		add("references."+mappings.CMMCLevel2Framework,
			fmt.Sprintf("declares CMMC practices %v but the rule has no reviewed "+
				"nist_800_171 references to derive them from", extra))
	case len(extra) > 0 && len(missing) > 0:
		add("references."+mappings.CMMCLevel2Framework,
			fmt.Sprintf("does not match the derivation from nist_800_171: "+
				"unreviewed %v, missing %v; regenerate with scripts/gen_cmmc_refs.py",
				extra, missing))
	case len(extra) > 0:
		add("references."+mappings.CMMCLevel2Framework,
			fmt.Sprintf("declares %v, which does not follow from this rule's "+
				"nist_800_171 references", extra))
	default:
		add("references."+mappings.CMMCLevel2Framework,
			fmt.Sprintf("is missing %v, which its nist_800_171 references imply; "+
				"regenerate with scripts/gen_cmmc_refs.py", missing))
	}
}

// refStrings flattens a reference value into the strings it holds. Framework
// values are a list, a bare scalar, or absent.
func refStrings(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func equalStringSets(a, b []string) bool {
	return len(setDifference(a, b)) == 0 && len(setDifference(b, a)) == 0
}

// setDifference returns the members of a that are not in b, sorted.
func setDifference(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
