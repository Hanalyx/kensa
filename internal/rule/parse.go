// Package rule provides the V1 rule YAML parser, implementation selector,
// schema validator, and effective-vs-static linter for Kensa canonical rules.
//
// # Parser
//
// [Parse] and [ParseFile] decode a V1 rule YAML file into an [api.Rule].
// The raw YAML is decoded into internal structs that mirror the schema
// (rawRule, rawImplementation, rawCheck, rawRemediation), then mapped to
// the public api types. Unknown YAML fields inside mechanism-parameter
// blocks are preserved as [api.Params] entries.
//
// # Selector
//
// [Select] takes an [api.Rule] and an [api.CapabilitySet] and returns the
// first [api.Implementation] whose `when` gate is satisfied. If no gated
// implementation matches, the `default: true` fallback is returned.
//
// # Validator
//
// [Validate] checks a parsed [api.Rule] against the V1 schema constraints
// from docs/CANONICAL_RULE_SCHEMA_V1.md §6.2. Errors are returned as a
// slice of [ValidationError] values rather than a single error so callers
// can report all problems at once.
//
// # Linter
//
// [Lint] applies the effective-vs-static heuristics described in
// docs/KENSA_GO_DAY1_PLAN.md §7.5. Linter findings are advisory: they are
// [LintWarning] values, not errors.
package rule

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/varsub"
)

// rawRule is the YAML-decode target for a V1 rule file.
type rawRule struct {
	ID              string                 `yaml:"id"`
	Title           string                 `yaml:"title"`
	Description     string                 `yaml:"description"`
	Rationale       string                 `yaml:"rationale"`
	Severity        string                 `yaml:"severity"`
	Category        string                 `yaml:"category"`
	Tags            []string               `yaml:"tags"`
	Transactional   *bool                  `yaml:"transactional"` // nil → default true
	References      map[string]interface{} `yaml:"references"`
	Platforms       []rawPlatform          `yaml:"platforms"`
	Implementations []rawImplementation    `yaml:"implementations"`
	DependsOn       []string               `yaml:"depends_on"`
	ConflictsWith   []string               `yaml:"conflicts_with"`
	Supersedes      []string               `yaml:"supersedes"`
}

type rawPlatform struct {
	Family      string `yaml:"family"`
	MinVersion  int    `yaml:"min_version"`
	MaxVersion  int    `yaml:"max_version"`
	Derivatives *bool  `yaml:"derivatives"` // nil → default true
}

type rawImplementation struct {
	// When is the capability gate. Nil means no gate (unconditionally
	// matches). Yaml can decode it as string, or map (all/any/not).
	When        interface{}    `yaml:"when"`
	Default     bool           `yaml:"default"`
	Check       rawCheck       `yaml:"check"`
	Remediation rawRemediation `yaml:"remediation"`
}

// rawCheck holds a single check or a multi-check list. The YAML inline
// field captures all method-specific parameters (path, key, expected, …).
type rawCheck struct {
	Method string                 `yaml:"method"`
	Checks []rawCheck             `yaml:"checks"`
	Params map[string]interface{} `yaml:",inline"`
}

// rawRemediation holds a single-mechanism or multi-step remediation. The
// inline field captures mechanism-specific parameters.
type rawRemediation struct {
	Mechanism string                 `yaml:"mechanism"`
	Steps     []rawRemStep           `yaml:"steps"`
	Reload    string                 `yaml:"reload"`
	Restart   string                 `yaml:"restart"`
	Notify    string                 `yaml:"notify"`
	Params    map[string]interface{} `yaml:",inline"`
}

// rawRemStep is one step in a multi-step remediation.
type rawRemStep struct {
	Mechanism string                 `yaml:"mechanism"`
	Params    map[string]interface{} `yaml:",inline"`
}

// ParseFile opens path and delegates to [Parse]. No variable
// substitution: the file's `{{ name }}` templates pass through
// to evaluation as literals. Use [ParseFileWithVars] when
// templates are in play (Phase 3.5).
func ParseFile(path string) (*api.Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("rule: open %q: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// ParseFileWithVars opens path, substitutes `{{ name }}` templates
// using vars, then decodes the resulting YAML into an
// [api.Rule]. Wired in Phase 3.5 (C-034 + C-036) so the rule
// corpus's pam_faillock_deny / pam_pwquality_minlen / etc.
// templates resolve to the operator's chosen values before
// evaluation.
//
// If vars is nil/empty, behaves identically to ParseFile —
// templates pass through. If a template names a variable not in
// vars, returns the substitution error verbatim (operator-
// facing).
func ParseFileWithVars(path string, vars varsub.Variables) (*api.Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rule: open %q: %w", path, err)
	}
	// Always run substitution so a rule containing `{{ var }}`
	// without a matching definition is detected, not silently
	// loaded with literal templates that would later fail
	// evaluation. The substitution helper is fast and is a
	// no-op for rules that contain no templates.
	raw, err = varsub.SubstituteFile(path, raw, vars)
	if err != nil {
		return nil, fmt.Errorf("rule: %w", err)
	}
	return Parse(bytes.NewReader(raw))
}

// Parse decodes a V1 rule YAML document from r and returns an [api.Rule].
// Only the YAML structure is checked here; schema-level constraints
// (required fields, atomicity consistency) are enforced by [Validate].
func Parse(r io.Reader) (*api.Rule, error) {
	var raw rawRule
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("rule: yaml decode: %w", err)
	}
	return toRule(&raw), nil
}

// toRule converts a rawRule into an api.Rule.
func toRule(raw *rawRule) *api.Rule {
	transactional := true
	if raw.Transactional != nil {
		transactional = *raw.Transactional
	}

	impls := make([]api.Implementation, len(raw.Implementations))
	for i, ri := range raw.Implementations {
		impls[i] = toImpl(ri)
	}

	platforms := make([]api.Platform, len(raw.Platforms))
	for i, p := range raw.Platforms {
		derivatives := true
		if p.Derivatives != nil {
			derivatives = *p.Derivatives
		}
		platforms[i] = api.Platform{
			Family:      p.Family,
			MinVersion:  p.MinVersion,
			MaxVersion:  p.MaxVersion,
			Derivatives: derivatives,
		}
	}

	return &api.Rule{
		ID:              raw.ID,
		Title:           raw.Title,
		Description:     raw.Description,
		Rationale:       raw.Rationale,
		Severity:        raw.Severity,
		Category:        raw.Category,
		Tags:            raw.Tags,
		Transactional:   transactional,
		References:      raw.References,
		Platforms:       platforms,
		Implementations: impls,
		DependsOn:       raw.DependsOn,
		ConflictsWith:   raw.ConflictsWith,
		Supersedes:      raw.Supersedes,
	}
}

func toImpl(ri rawImplementation) api.Implementation {
	return api.Implementation{
		Default:     ri.Default,
		When:        ri.When,
		Check:       toCheck(ri.Check),
		Remediation: toRemediation(ri.Remediation),
	}
}

func toCheck(rc rawCheck) api.Check {
	if len(rc.Checks) > 0 {
		checks := make([]api.Check, len(rc.Checks))
		for i, c := range rc.Checks {
			checks[i] = toCheck(c)
		}
		return api.Check{Checks: checks}
	}
	params := make(api.Params, len(rc.Params))
	for k, v := range rc.Params {
		params[k] = v
	}
	return api.Check{Method: rc.Method, Params: params}
}

func toRemediation(rr rawRemediation) api.Remediation {
	if len(rr.Steps) > 0 {
		steps := make([]api.RemediationStep, len(rr.Steps))
		for i, s := range rr.Steps {
			params := make(api.Params, len(s.Params))
			for k, v := range s.Params {
				params[k] = v
			}
			steps[i] = api.RemediationStep{
				Mechanism: s.Mechanism,
				Params:    params,
			}
		}
		return api.Remediation{
			Steps:   steps,
			Reload:  rr.Reload,
			Restart: rr.Restart,
			Notify:  rr.Notify,
		}
	}
	params := make(api.Params, len(rr.Params))
	for k, v := range rr.Params {
		params[k] = v
	}
	return api.Remediation{
		Mechanism: rr.Mechanism,
		Params:    params,
		Reload:    rr.Reload,
		Restart:   rr.Restart,
		Notify:    rr.Notify,
	}
}
