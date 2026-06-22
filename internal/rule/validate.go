package rule

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Hanalyx/kensa/api"
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
var KnownCapabilities = map[string]struct{}{
	"sshd_config_d":        {},
	"authselect":           {},
	"crypto_policies":      {},
	"fips_mode":            {},
	"firewalld_nftables":   {},
	"pam_faillock":         {},
	"pam_tally2":           {},
	"pam_pwquality":        {},
	"grub_bls":             {},
	"selinux":              {},
	"aide":                 {},
	"fapolicyd":            {},
	"usbguard":             {},
	"systemd_resolved":     {},
	"nftables":             {},
	"firewalld":            {},
	"rsyslog":              {},
	"journald":             {},
	"auditd":               {},
	"cron":                 {},
	"at":                   {},
	"coredump_systemd":     {},
	"sssd":                 {},
	"chronyd":              {},
	"dnf_automatic":        {},
	"subscription_manager": {},
	"dconf":                {},
	"gdm":                  {},
}
