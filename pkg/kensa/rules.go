package kensa

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/rule"
	rulespath "github.com/Hanalyx/kensa/internal/rules"
	"github.com/Hanalyx/kensa/internal/varsub"
)

// LoadRules parses a rule corpus into []*api.Rule, ready for
// [api.Kensa.Scan] / Remediate. It is the public counterpart of the
// kensa CLI's rule loader, intended for programs that import the api
// (e.g. OpenWatch) and must not re-implement YAML normalization or
// variable substitution.
//
// Sources, mirroring the CLI's resolution policy
// (specs/rule/default-path-resolution.spec.yaml):
//
//   - dir, when non-empty, is walked for *.yml files (recursive).
//   - paths are explicit rule files, loaded in addition to dir.
//   - When both are empty, the kensa-rules package's installed corpus
//     at the default path (/usr/share/kensa/rules) is used if present;
//     otherwise an error names the fix paths.
//
// Variable substitution: each file's `{{ name }}` templates are
// resolved against kensa's embedded built-in defaults (see
// [BuiltInVars]) merged with the caller's vars — caller values win on
// collision. This is how an orchestrator injects operator-configured
// values (e.g. ssh_max_sessions) per scan; pass nil to use the
// built-in defaults alone.
//
// Strictness: unlike the CLI's directory walk (which warns on stderr
// and skips unparseable draft rules), LoadRules is STRICT — any file
// that fails to parse, or references an undefined variable, fails the
// whole load with the file named in the error. A library must neither
// write to a caller's stderr nor silently drop rules from a compliance
// corpus. Callers who want draft tolerance should load files
// individually and handle errors per file.
//
// The returned rules are parsed and normalized but not semantically
// validated; run kensa-validate (or internal validation at scan time)
// for the full constraint set.
func LoadRules(dir string, paths []string, vars map[string]string) ([]*api.Rule, error) {
	merged, err := effectiveVars(vars)
	if err != nil {
		return nil, err
	}

	resolved, err := rulespath.Resolve(dir, paths, os.Stat)
	if err != nil {
		return nil, err
	}
	dir = resolved

	var files []string
	if dir != "" {
		files, err = walkRuleFiles(dir)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 && len(paths) == 0 {
			return nil, fmt.Errorf("no *.yml files found in %s", dir)
		}
	}
	files = append(files, paths...)

	rules := make([]*api.Rule, 0, len(files))
	for _, p := range files {
		r, err := rule.ParseFileWithVars(p, merged)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// BuiltInVars returns the embedded built-in variable defaults that
// ship inside the kensa binary — the lowest-priority tier of the
// variable resolution chain, covering every `{{ name }}` template in
// the production rule corpus with STIG-strict values.
//
// Orchestrators use this to render a configuration UI: each key is a
// variable name an operator may override (via LoadRules' vars
// argument), and each value is the default in effect when they don't.
// Note that a few defaults are organization-specific placeholders
// (rsyslog_remote_server, chrony_ntp_pool, banner_text) that operators
// should always review.
//
// The returned map is a copy; mutating it does not affect kensa.
func BuiltInVars() (map[string]string, error) {
	defaults, err := varsub.BuiltInDefaults()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(defaults))
	for k, v := range defaults {
		out[k] = v
	}
	return out, nil
}

// RuleVariables reports which `{{ name }}` template variables the rule
// corpus under dir consumes, as a map of variable name to the sorted
// rule IDs that use it. Orchestrators use this to show operators which
// rules a variable override will affect.
//
// The scan is textual (template extraction on the raw YAML, before
// substitution), so it works regardless of whether the variables have
// values. The rule ID is taken from the file's top-level `id:` field;
// a file whose id cannot be decoded falls back to its base filename
// without the .yml suffix. Files with no templates are omitted.
func RuleVariables(dir string) (map[string][]string, error) {
	files, err := walkRuleFiles(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		names := varsub.Names(string(raw))
		if len(names) == 0 {
			continue
		}
		id := ruleIDFromYAML(raw)
		if id == "" {
			id = strings.TrimSuffix(filepath.Base(p), ".yml")
		}
		for _, n := range names {
			out[n] = append(out[n], id)
		}
	}
	for n := range out {
		sort.Strings(out[n])
	}
	return out, nil
}

// effectiveVars merges kensa's embedded built-in defaults with the
// caller's overrides (caller wins). The chain matches the CLI's
// lowest tier + operator override; intermediate file tiers
// (config-dir defaults.yml, conf.d, per-group, per-host) are the
// CLI's concern — a library caller owns its own storage and passes
// the already-merged result.
func effectiveVars(vars map[string]string) (varsub.Variables, error) {
	embedded, err := varsub.BuiltInDefaults()
	if err != nil {
		return nil, fmt.Errorf("built-in variable defaults: %w", err)
	}
	return varsub.Merge(embedded, varsub.Variables(vars)), nil
}

// walkRuleFiles returns every *.yml file under dir, sorted, so load
// order (and therefore scan order) is deterministic across runs and
// platforms.
func walkRuleFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	sort.Strings(files)
	return files, nil
}

// ruleIDFromYAML decodes just the top-level `id:` scalar from raw rule
// YAML. Returns "" when the document doesn't decode or has no id —
// callers fall back to the filename. Decoding only the id keeps this
// robust on templated rules whose other fields may not be valid YAML
// until substitution.
func ruleIDFromYAML(raw []byte) string {
	var doc struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	return doc.ID
}
