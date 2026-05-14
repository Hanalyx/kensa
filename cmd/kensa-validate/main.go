// Command kensa-validate validates Kensa V1 rule YAML files against the
// canonical rule schema (docs/CANONICAL_RULE_SCHEMA_V1.md) and applies
// the effective-vs-static linter from docs/KENSA_GO_DAY1_PLAN.md §7.5.
//
// Usage:
//
//	kensa-validate [--rules-dir DIR] [--cap-check] [--format json|table] [FILE...]
//
// When FILE arguments are given, only those files are validated. When
// --rules-dir is given, all *.yml files under that directory tree are
// validated. Providing both FILE and --rules-dir is an error.
//
// Exit codes:
//
//	0   All files valid; zero validation errors (warnings may be present).
//	1   At least one file has one or more validation errors.
//	2   Usage or I/O error.
//
// Flags:
//
//	--rules-dir DIR   Root directory to scan for *.yml rule files.
//	--cap-check       Enable known-capability reference checking.
//	--format FORMAT   Output format: "table" (default) or "json".
//	--no-lint         Skip the effective-vs-static linter.
//	--strict          Treat lint warnings as errors (non-zero exit).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/internal/rule"
)

// Short-letter constants for kensa-validate. Mirror the kensa CLI
// conventions where they apply (per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md
// §4): -h is help, -f is format, -r is rules-dir. --cap-check and
// --no-lint are long-only (rare flags). --strict gets uppercase -S
// since lowercase -s in the kensa CLI is sudo (cross-binary mental
// consistency: capital letters connote "treat-as-error" / serious flag).
const (
	shortHelp     = "h"
	shortVersion  = "V"
	shortFormat   = "f"
	shortRulesDir = "r"
	shortStrict   = "S"
)

// version is the binary version printed by --version / -V.
// Kept in sync with cmd/kensa/main.go's version constant.
// (B7 fix, 2026-05-13.)
const version = "v0.1.0-dev"

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

// runCLI parses argv, validates the requested rule files, and returns
// the process exit code per the documented contract:
//
//	0  all files valid, zero validation errors (warnings may be present)
//	1  at least one file has validation errors (or warnings under --strict)
//	2  usage or I/O error
//
// Extracted from main for testability — call runCLI directly from
// tests with synthetic argv slices.
func runCLI(argv []string) int {
	// Backward-compat: stdlib flag accepted single-dash long forms
	// like `-rules-dir /path`. Rewrite to pflag's `--rules-dir /path`
	// with a deprecation warning. Removed in v0.2.
	argv = rewriteLegacyLongForm(argv, map[string]bool{
		"rules-dir": true, "cap-check": true, "format": true,
		"no-lint": true, "strict": true,
	})

	fs := pflag.NewFlagSet("kensa-validate", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp    bool
		showVersion bool
		rulesDir    string
		capCheck    bool
		format      string
		noLint      bool
		strict      bool
	)
	fs.BoolVarP(&showHelp, "help", shortHelp, false, "show this help and exit")
	fs.BoolVarP(&showVersion, "version", shortVersion, false, "print version and exit")
	fs.StringVarP(&rulesDir, "rules-dir", shortRulesDir, "", "root directory to scan for *.yml rule files")
	fs.BoolVar(&capCheck, "cap-check", false, "validate capability references against known set (long-only)")
	fs.StringVarP(&format, "format", shortFormat, "table", "output format: table or json")
	fs.BoolVar(&noLint, "no-lint", false, "skip effective-vs-static linter (long-only)")
	fs.BoolVarP(&strict, "strict", shortStrict, false, "treat lint warnings as errors")

	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printUsage(os.Stdout, fs)
			return 0
		}
		fmt.Fprintf(os.Stderr, "kensa-validate: %v\n", err)
		fmt.Fprintln(os.Stderr, "Try 'kensa-validate --help' for usage.")
		return 2
	}
	if showVersion {
		fmt.Fprintf(os.Stdout, "kensa-validate %s\n", version)
		return 0
	}
	if showHelp {
		printUsage(os.Stdout, fs)
		return 0
	}

	var files []string
	switch {
	case rulesDir != "" && fs.NArg() > 0:
		fmt.Fprintln(os.Stderr, "kensa-validate: cannot use both --rules-dir and file arguments")
		return 2
	case rulesDir != "":
		var err error
		files, err = findYAMLFiles(rulesDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kensa-validate: scan %s: %v\n", rulesDir, err)
			return 2
		}
	case fs.NArg() > 0:
		files = fs.Args()
	default:
		printUsage(os.Stderr, fs)
		return 2
	}

	var knownCaps map[string]struct{}
	if capCheck {
		knownCaps = rule.KnownCapabilities
	}

	results := make([]fileResult, 0, len(files))
	hasErrors := false

	for _, path := range files {
		res := validateFile(path, knownCaps, !noLint)
		if len(res.Errors) > 0 {
			hasErrors = true
		}
		if strict && len(res.Warnings) > 0 {
			hasErrors = true
		}
		results = append(results, res)
	}

	switch format {
	case "json":
		printJSON(results)
	default:
		printTable(results, strict)
	}

	if hasErrors {
		return 1
	}
	return 0
}

// printUsage writes the kensa-validate help text. --help → stdout per
// GNU; usage errors → stderr; caller picks the writer.
func printUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa-validate [flags] [FILE...]

Validate Kensa V1 rule YAML files against the canonical rule schema
(docs/foundation_docs/CANONICAL_RULE_SCHEMA_V1.md) and apply the
effective-vs-static linter.

When FILE arguments are given, only those files are validated. When
--rules-dir is given, all *.yml files under that directory tree are
validated. Providing both FILE and --rules-dir is a usage error.

Flags:
%s
Exit codes:
  0  all files valid; zero validation errors (warnings may be present)
  1  at least one file has validation errors (or warnings under --strict)
  2  usage or I/O error

Examples:
  kensa-validate rule1.yml rule2.yml
  kensa-validate -r /path/to/rules
  kensa-validate -r /path/to/rules -S -f json
`, fs.FlagUsages())
}

// rewriteLegacyLongForm converts stdlib-flag-style single-dash long
// forms (`-rules-dir foo`, `-strict`) to pflag's double-dash form.
// Mirrors the helper in cmd/kensa/main.go but scoped to this binary.
// Removed in v0.2.
func rewriteLegacyLongForm(argv []string, longNames map[string]bool) []string {
	out := make([]string, 0, len(argv))
	warned := false
	for _, a := range argv {
		if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
			out = append(out, a)
			continue
		}
		name := a[1:]
		if eq := strings.Index(name, "="); eq != -1 {
			name = name[:eq]
		}
		if len(name) > 1 && longNames[name] {
			if !warned {
				fmt.Fprintln(os.Stderr, "kensa-validate: warning: stdlib-style single-dash long flags are deprecated; use --"+name+" (will be removed in v0.2)")
				warned = true
			}
			out = append(out, "-"+a)
			continue
		}
		out = append(out, a)
	}
	return out
}

// fileResult holds the validation and lint findings for one file.
type fileResult struct {
	File     string                 `json:"file"`
	RuleID   string                 `json:"rule_id,omitempty"`
	Errors   []rule.ValidationError `json:"errors,omitempty"`
	Warnings []rule.LintWarning     `json:"warnings,omitempty"`
}

// validateFile parses and validates path, optionally running the linter.
func validateFile(path string, knownCaps map[string]struct{}, lint bool) fileResult {
	res := fileResult{File: path}

	r, err := rule.ParseFile(path)
	if err != nil {
		res.Errors = append(res.Errors, rule.ValidationError{Msg: err.Error()})
		return res
	}
	res.RuleID = r.ID

	opts := rule.ValidateOptions{
		Filename:          path,
		ExpectedCategory:  categoryFromPath(path),
		KnownCapabilities: knownCaps,
	}
	res.Errors = rule.Validate(r, opts)

	if lint {
		res.Warnings = rule.Lint(r)
	}

	return res
}

// knownCategories is the set of valid parent-directory names that indicate
// the caller is walking a structured rules/ tree. Only these names trigger
// category-consistency checking; generic directory names ("testdata", "tmp",
// etc.) are ignored.
var knownCategories = map[string]bool{
	"access-control": true,
	"audit":          true,
	"filesystem":     true,
	"kernel":         true,
	"logging":        true,
	"network":        true,
	"services":       true,
	"system":         true,
}

// categoryFromPath infers the expected category from the parent directory
// name. Returns "" when the parent is not a recognized category directory.
func categoryFromPath(path string) string {
	dir := filepath.Dir(filepath.Clean(path))
	base := filepath.Base(dir)
	if knownCategories[base] {
		return base
	}
	return ""
}

// findYAMLFiles returns all *.yml files under root.
func findYAMLFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yml") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// printTable writes human-readable per-file output to stdout.
func printTable(results []fileResult, strict bool) {
	totalErrors := 0
	totalWarnings := 0
	for _, r := range results {
		totalErrors += len(r.Errors)
		totalWarnings += len(r.Warnings)

		if len(r.Errors) == 0 && len(r.Warnings) == 0 {
			fmt.Printf("OK   %s\n", r.File)
			continue
		}
		label := "OK  "
		if len(r.Errors) > 0 {
			label = "FAIL"
		} else if strict && len(r.Warnings) > 0 {
			label = "FAIL"
		}
		fmt.Printf("%s %s", label, r.File)
		if r.RuleID != "" {
			fmt.Printf(" (id: %s)", r.RuleID)
		}
		fmt.Println()

		for _, e := range r.Errors {
			fmt.Printf("  ERROR  %s\n", e)
		}
		for _, w := range r.Warnings {
			fmt.Printf("  WARN   [%s] impl[%d] %s: %s\n", w.Code, w.ImplIndex, w.Path, w.Msg)
		}
	}

	fmt.Printf("\n%d file(s): %d error(s), %d warning(s)\n",
		len(results), totalErrors, totalWarnings)
}

// printJSON writes results to stdout as a JSON array.
func printJSON(results []fileResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}
