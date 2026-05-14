package main

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/api"
)

// validSeverities is the canonical severity vocabulary (the same
// enum the rule validator enforces in internal/rule/validate.go).
// Keep in sync if a future rule schema change adds a level.
var validSeverities = map[string]struct{}{
	"critical": {},
	"high":     {},
	"medium":   {},
	"low":      {},
}

// registerSeverityFlag wires `--severity / -s` as a repeatable
// choice. Operators pass `-s critical -s high` to scan/remediate
// only the rules whose severity is in their set. Empty set
// (default) means all severities pass through.
//
// Uses StringArrayVarP rather than StringSliceVarP for symmetry
// with --capability (C-028) and to leave room for future severity
// VALUEs that might contain commas (e.g., date-stamped levels).
func registerSeverityFlag(fs *pflag.FlagSet, dst *[]string) {
	fs.StringArrayVarP(dst, "severity", ShortSeverity, nil,
		"filter rules by severity, repeatable (-s critical -s high); choices: critical|high|medium|low")
}

// validateSeverities checks that every value the operator
// supplied is in the canonical vocabulary. Case-insensitive
// match; unknown values produce a usage error mentioning the
// valid set.
func validateSeverities(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, s := range raw {
		v := strings.ToLower(strings.TrimSpace(s))
		if _, ok := validSeverities[v]; !ok {
			return nil, fmt.Errorf("--severity %q: unknown severity (choices: critical, high, medium, low)", s)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

// filterRulesBySeverity returns a new slice containing only the
// rules whose Severity is in the allowed set. Empty allowed
// returns rules unchanged. Allowed is expected to be the output
// of validateSeverities (already lowercase, deduped).
func filterRulesBySeverity(rules []*api.Rule, allowed []string) []*api.Rule {
	if len(allowed) == 0 {
		return rules
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allow[s] = struct{}{}
	}
	out := make([]*api.Rule, 0, len(rules))
	for _, r := range rules {
		if _, ok := allow[strings.ToLower(r.Severity)]; ok {
			out = append(out, r)
		}
	}
	return out
}
