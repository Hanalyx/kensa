package main

import (
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/api"
)

// registerTagFilterFlag wires `--tag / -t` as a repeatable
// free-form string. Operators pass `-t pci -t cis` to filter
// rules whose `tags:` field intersects their set. OR semantics
// across operator-supplied values: a rule with EITHER tag
// matches. Empty set (default) is pass-through.
//
// No vocabulary validation: tags are free-form strings written
// by rule authors. A typo will silently match nothing rather
// than producing a usage error — but the empty-after-filter
// guard surfaces the typo as "no rules matched".
func registerTagFilterFlag(fs *pflag.FlagSet, dst *[]string) {
	fs.StringArrayVarP(dst, "tag", ShortTag, nil,
		"filter rules by tag, repeatable (-t pci -t cis); rules whose tags: array contains any of these match")
}

// normalizeTags lowercases and trims each tag. Returns a deduped
// slice preserving first-occurrence order. Empty input returns
// nil.
func normalizeTags(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, t := range raw {
		v := strings.ToLower(strings.TrimSpace(t))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// filterRulesByTag returns the subset of rules whose Tags
// intersect with the allowed set. Empty allowed returns the
// input unchanged. Match is case-insensitive on both sides
// (rule corpora may have any casing). Order of input is
// preserved.
func filterRulesByTag(rules []*api.Rule, allowed []string) []*api.Rule {
	if len(allowed) == 0 {
		return rules
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, t := range allowed {
		allow[t] = struct{}{}
	}
	out := make([]*api.Rule, 0, len(rules))
	for _, r := range rules {
		for _, t := range r.Tags {
			if _, ok := allow[strings.ToLower(strings.TrimSpace(t))]; ok {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
