package main

import (
	"github.com/spf13/pflag"
)

// registerRuleFileFlag wires `--rule` as a repeatable file-path
// argument. Long-only (no short letter): `-R` is reserved in
// flags.go for a future filter-by-ID feature whose semantic
// differs from this file-loader form, and operators reaching for
// `-R` would expect that filter behavior, not a file path.
//
// Multiple --rule values combine with each other and with the
// positional `*.yml` arg form and with --rules-dir; all sources
// are loaded additively.
//
// Strict loading: a `--rule PATH` whose YAML fails to parse
// produces a usage error. Operators who named the file
// deliberately should see the failure rather than have it
// silently skipped.
func registerRuleFileFlag(fs *pflag.FlagSet, dst *[]string) {
	fs.StringArrayVar(dst, "rule", nil,
		"load this single rule YAML file (strict — parse errors fail the command); long-only, repeatable, additive with --rules-dir and positional *.yml args")
}

// concatPaths returns a fresh slice containing the elements of a
// followed by b. Used to combine --rule (or similar repeatable
// path flags) with the FlagSet's positional args before passing
// to loadRulesFromDirOrFiles. Allocates once; doesn't mutate
// either input.
func concatPaths(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}
