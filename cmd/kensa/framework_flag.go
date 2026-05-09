package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/mappings"
)

// registerFrameworkFlag wires `--framework / -f` as a single
// value. Operators pass `-f cis_rhel9` or `-f nist_800_53` to
// filter rules to only those that map a control under the
// named framework. Empty (default) is pass-through.
//
// Single value (NOT repeatable like -s/-t — pflag's StringVarP
// silently last-write-wins on `-f x -f y`). The help text
// discloses this so operators don't get surprised.
//
// Hyphens and underscores are interchangeable on input
// (`-f cis-rhel9` and `-f cis_rhel9` produce the same filter)
// because the deliverable spec used the hyphen form in its
// example while the actual mappings module emits underscore-
// joined framework IDs.
func registerFrameworkFlag(fs *pflag.FlagSet, dst *string) {
	fs.StringVarP(dst, "framework", ShortFramework, "",
		"filter rules to those mapping a control under FRAMEWORK (-f cis_rhel9). Single value (NOT repeatable like -s/-t). Hyphen and underscore are interchangeable: `-f cis-rhel9` == `-f cis_rhel9`.")
}

// availableFrameworks returns the sorted union of every
// FrameworkID that any rule in the loaded corpus exposes via
// mappings.RefsFromReferences(rule.References). Used both for
// validation (the operator's value must appear here) and for
// the usage-error message when validation fails.
func availableFrameworks(rules []*api.Rule) []string {
	seen := make(map[string]struct{})
	for _, r := range rules {
		for _, ref := range mappings.RefsFromReferences(r.References) {
			seen[ref.FrameworkID] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// validateFramework checks that input is in the available set.
// Comparison is case-insensitive after normalizing hyphens to
// underscores. Returns the canonical (matched) framework ID on
// success, or an error listing the available frameworks.
//
// Pass an empty input through with (empty, nil); empty means
// "no filter, pass-through".
func validateFramework(input string, available []string) (string, error) {
	target := normalizeFrameworkID(input)
	if target == "" {
		return "", nil
	}
	for _, id := range available {
		if normalizeFrameworkID(id) == target {
			return id, nil
		}
	}
	if len(available) == 0 {
		return "", fmt.Errorf("--framework %q: no rules in the loaded corpus expose framework references", input)
	}
	return "", fmt.Errorf("--framework %q: unknown framework; available in the loaded corpus: %s", input, strings.Join(available, ", "))
}

// normalizeFrameworkID lowercases input and replaces hyphens
// with underscores so `cis-rhel9` and `cis_rhel9` collide.
// Whitespace is trimmed.
func normalizeFrameworkID(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(v, "-", "_")
}

// filterRulesByFramework returns the subset of rules whose
// references include the given canonical framework ID. Empty
// allowed returns the input unchanged. Match is exact on the
// canonical ID (caller is expected to have validated against
// availableFrameworks first).
func filterRulesByFramework(rules []*api.Rule, allowed string) []*api.Rule {
	if allowed == "" {
		return rules
	}
	out := make([]*api.Rule, 0, len(rules))
	for _, r := range rules {
		for _, ref := range mappings.RefsFromReferences(r.References) {
			if ref.FrameworkID == allowed {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
