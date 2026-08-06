package rule

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/detect"
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

// Validate checks rule against the V1 schema constraints from
// docs/CANONICAL_RULE_SCHEMA_V1.md §6.2.
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

	// (10) A declared framework key must carry a value. An empty key reads as
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

	// (9) Remediation params satisfy the mechanism contract (internal/mechanism).
	validateRemediationParams(rule, add)

	// (10) Check params satisfy the check-method contract (internal/check),
	// closed-world: unknown check params (e.g. an unread 'comparator') are
	// rejected at load instead of silently ignored at scan time.
	validateCheckParams(rule, add)

	// (11) Param VALUES are within the engine's accepted domain (separators,
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
// V1 schema (from docs/CANONICAL_RULE_SCHEMA_V0.md §4, carried forward to V1).
// Callers may pass this to [ValidateOptions.KnownCapabilities] to enable
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
