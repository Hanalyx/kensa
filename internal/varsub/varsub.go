// Package varsub implements rule-variable
// substitution layer.
//
// The kensa rule corpus uses Jinja-style `{{ name }}` templates
// in fields like check.expected and remediation.value (see e.g.
// rules/access-control/pam-faillock-deny.yml). Before variable substitution,
// kensa did NOT substitute these — those rules silently
// failed evaluation because the comparator compared host output
// against the literal string `{{ pam_faillock_deny }}`.
//
// Substitution runs against the raw YAML bytes BEFORE the
// loader decodes them. This keeps the implementation single-
// point: any new YAML field that contains a template gets
// substituted automatically, no enumeration of fields needed.
//
// Resolution priority (highest first), simplified for the
// initial cut:
//  1. CLI --var KEY=VALUE  (operator override)
//  2. <config-dir>/defaults.yml `variables:` block
//
// Future work may add intermediate tiers (per-host
// config, per-group config, conf.d overlay) per the Python
// kensa 5-tier scheme. The current shape is forward-compatible:
// callers build a Variables map by merging sources in priority
// order, then pass the merged map to Substitute.
//
// Unknown-variable handling: an undefined `{{ varname }}` in
// the YAML produces an error rather than being left literal.
// Operators get a clear "undefined variable" error citing the
// rule file and the unknown name, matching the security stance
// that silent silent-pass is unacceptable for compliance rules.
package varsub

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ErrUndefined is the sentinel returned (wrapped) when Substitute
// finds a `{{ name }}` whose name is not in the supplied
// Variables map. Callers can errors.Is-check this sentinel to
// distinguish undefined-variable failures from other errors —
// e.g., loadRulesSkipInvalid uses this to count and surface
// undefined-variable skips at end-of-load rather than burying
// them in a generic "skip" warning.
var ErrUndefined = errors.New("undefined variable")

// templateRe matches {{ NAME }} with whitespace tolerance.
// NAME is [A-Za-z][A-Za-z0-9_]*. Doesn't match {{}} or {{ }}.
var templateRe = regexp.MustCompile(`\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}`)

// Variables is the merged variable set passed to Substitute.
// Keys are case-sensitive variable names; values are the
// strings to splice into the YAML at template sites.
type Variables map[string]string

// Substitute replaces every `{{ name }}` template in input with
// its value from vars. Returns an error listing every undefined
// variable (collected, not first-failure, so operators see all
// missing vars in one pass).
//
// The substitution is purely textual — Substitute does NOT
// quote, escape, or YAML-validate the substituted value. A
// caller passing a value with embedded YAML metacharacters
// (newlines, colons, quotes) is responsible for the resulting
// document validity.
func Substitute(input string, vars Variables) (string, error) {
	missing := make(map[string]bool)
	out := templateRe.ReplaceAllStringFunc(input, func(match string) string {
		// templateRe's submatch is the captured name; recompute
		// here to keep the map closure simple.
		name := templateRe.FindStringSubmatch(match)[1]
		if v, ok := vars[name]; ok {
			return v
		}
		missing[name] = true
		return match // leave as-is for the operator-facing error
	})
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for n := range missing {
			names = append(names, n)
		}
		sort.Strings(names)
		return "", fmt.Errorf("%w(s) in template: %s — define via --var KEY=VALUE or in <config-dir>/defaults.yml", ErrUndefined, strings.Join(names, ", "))
	}
	return out, nil
}

// SubstituteFile is a convenience wrapper for the rule-loader
// path: substitute first, return the error if any template was
// undefined, otherwise return the rendered bytes ready for YAML
// decoding. The path argument is only used for the error
// message context.
func SubstituteFile(path string, raw []byte, vars Variables) ([]byte, error) {
	rendered, err := Substitute(string(raw), vars)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return []byte(rendered), nil
}

// Merge returns a new Variables map combining base and override.
// The override map's values win on key collision. Useful for
// stacking CLI overrides on top of file defaults.
func Merge(base, override Variables) Variables {
	out := make(Variables, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}
