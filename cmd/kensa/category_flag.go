package main

import (
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/api"
)

// registerCategoryFlag wires `--category / -c` as a single-value
// string. Operators pass `-c access-control` to filter rules by
// the Rule.Category field. Empty (default) is pass-through.
//
// Single value (not repeatable): operators wanting OR across
// categories should use --tag instead, since rules carry both
// (--category is a single field per rule, --tag is a list).
//
// No vocabulary validation — categories are free-form strings
// authored by rule writers; an unknown value will produce an
// empty filter, surfaced by the empty-after-filter usage error.
func registerCategoryFlag(fs *pflag.FlagSet, dst *string) {
	fs.StringVarP(dst, "category", ShortCategory, "",
		"filter rules by category (-c access-control); single value (NOT repeatable like -s/-t — later -c overrides earlier)")
}

// filterRulesByCategory returns the subset of rules whose
// Category exactly matches `allowed` (case-insensitive). Empty
// allowed returns the input unchanged. Order preserved.
func filterRulesByCategory(rules []*api.Rule, allowed string) []*api.Rule {
	target := strings.ToLower(strings.TrimSpace(allowed))
	if target == "" {
		return rules
	}
	out := make([]*api.Rule, 0, len(rules))
	for _, r := range rules {
		if strings.ToLower(strings.TrimSpace(r.Category)) == target {
			out = append(out, r)
		}
	}
	return out
}
