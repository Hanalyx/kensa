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
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Hanalyx/kensa-go/internal/rule"
)

func main() {
	rulesDir := flag.String("rules-dir", "", "root directory to scan for *.yml rule files")
	capCheck := flag.Bool("cap-check", false, "validate capability references against known set")
	format := flag.String("format", "table", "output format: table or json")
	noLint := flag.Bool("no-lint", false, "skip effective-vs-static linter")
	strict := flag.Bool("strict", false, "treat lint warnings as errors")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: kensa-validate [flags] [FILE...]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var files []string
	switch {
	case *rulesDir != "" && flag.NArg() > 0:
		fmt.Fprintln(os.Stderr, "kensa-validate: cannot use both --rules-dir and file arguments")
		os.Exit(2)
	case *rulesDir != "":
		var err error
		files, err = findYAMLFiles(*rulesDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kensa-validate: scan %s: %v\n", *rulesDir, err)
			os.Exit(2)
		}
	case flag.NArg() > 0:
		files = flag.Args()
	default:
		flag.Usage()
		os.Exit(2)
	}

	var knownCaps map[string]struct{}
	if *capCheck {
		knownCaps = rule.KnownCapabilities
	}

	results := make([]fileResult, 0, len(files))
	hasErrors := false

	for _, path := range files {
		res := validateFile(path, knownCaps, !*noLint)
		if len(res.Errors) > 0 {
			hasErrors = true
		}
		if *strict && len(res.Warnings) > 0 {
			hasErrors = true
		}
		results = append(results, res)
	}

	switch *format {
	case "json":
		printJSON(results)
	default:
		printTable(results, *strict)
	}

	if hasErrors {
		os.Exit(1)
	}
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
