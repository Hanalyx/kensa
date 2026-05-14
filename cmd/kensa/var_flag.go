package main

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/internal/varsub"
)

// registerVarFlag wires `--var / -x` as a repeatable
// KEY=VALUE flag. Operators pass `-x pam_faillock_deny=5`
// to override rule-variable values at evaluation time.
//
// Repeatable. Composes with --config-dir/defaults.yml: CLI
// values win on key collision (highest priority in the
// substitution chain).
//
// Naming note: the flag is `--var` (Python kensa parity). The
// short form is `-x` because `-V` is taken by `--version` and
// `-v` by `--verbose`. Documented in flags.go.
func registerVarFlag(fs *pflag.FlagSet, dst *[]string) {
	fs.StringArrayVarP(dst, "var", ShortVar, nil,
		"override a rule variable, KEY=VALUE; repeatable (e.g. -x pam_faillock_deny=5). Wins over --config-dir/defaults.yml. VALUE is spliced literally into rule YAML and may flow into shell commands run by handlers — pass only trusted input.")
}

// registerConfigDirFlag wires `--config-dir` as a single-value
// path. Operators pass `--config-dir /etc/kensa` to load
// variable defaults from <DIR>/defaults.yml.
//
// Long-only (no short letter). Default empty: when unset, no
// defaults file is loaded and only --var values are in scope.
//
// Phase 3.5 ships the minimum: just defaults.yml. Future Phase
// 3.6 will layer per-host / per-group / conf.d overrides on
// top.
func registerConfigDirFlag(fs *pflag.FlagSet, dst *string) {
	fs.StringVar(dst, "config-dir", "",
		"directory holding defaults.yml (variable defaults source). Phase 3.5 minimum: only defaults.yml is read; per-host / per-group / conf.d overrides land in Phase 3.6.")
}

// resolveVarOverrides parses raw -x KEY=VALUE entries. Used in
// the same place validateSeverities and friends are called —
// before SSH setup, against the raw flag input.
func resolveVarOverrides(raw []string) (varsub.Variables, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(varsub.Variables, len(raw))
	for _, entry := range raw {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("--var %q: missing '='; use KEY=VALUE form", entry)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("--var %q: empty KEY (use KEY=VALUE form)", entry)
		}
		// Reject keys that wouldn't match the templateRe
		// vocabulary [A-Za-z][A-Za-z0-9_]*. A typo'd key never
		// matches a template, so the substitution would silently
		// pass through with nothing to do — surface the typo here.
		if !validVarName(key) {
			return nil, fmt.Errorf("--var %q: KEY must match [A-Za-z][A-Za-z0-9_]* (rule templates use this vocabulary)", entry)
		}
		// Empty VALUE is allowed: an operator may legitimately
		// want to substitute the empty string. Whitespace is NOT
		// trimmed from VALUE because a template like
		// `expected: "{{ banner }}"` may genuinely want
		// trailing spaces.
		out[key] = value
	}
	return out, nil
}

// validVarName mirrors the templateRe vocabulary in
// internal/varsub. Local copy keeps the cmd/kensa layer from
// reaching into varsub internals.
func validVarName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		first := i == 0
		isAlpha := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		isDigit := r >= '0' && r <= '9'
		isUnder := r == '_'
		if first {
			if !isAlpha {
				return false
			}
		} else if !(isAlpha || isDigit || isUnder) {
			return false
		}
	}
	return true
}
