//go:build ignore

// parity_check.go is a standalone script that validates every rule file
// under a rules directory against the Go rule parser and schema validator,
// reporting any rules that fail validation or produce lint warnings.
//
// This is the Week 26 parity scaffold: it runs the same Go rule validator
// that cmd/kensa-validate uses, making it easy to measure how many rules
// from the full corpus are already valid under the Go implementation.
//
// Usage:
//
//	go run scripts/parity_check.go --rules-dir ./rules [--cap-check] [--strict]
//
// Exit codes:
//
//	0   All rules valid (zero errors).
//	1   At least one rule has validation errors.
//	2   Usage error.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Hanalyx/kensa-go/internal/rule"
)

func main() {
	rulesDir := flag.String("rules-dir", "", "root directory to scan for *.yml rule files (required)")
	capCheck := flag.Bool("cap-check", false, "validate capability references against known set")
	strict := flag.Bool("strict", false, "treat lint warnings as errors")
	flag.Parse()

	if *rulesDir == "" {
		fmt.Fprintln(os.Stderr, "parity_check: --rules-dir is required")
		flag.Usage()
		os.Exit(2)
	}

	files, err := findYAMLFiles(*rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parity_check: scan %s: %v\n", *rulesDir, err)
		os.Exit(2)
	}

	var knownCaps map[string]struct{}
	if *capCheck {
		knownCaps = rule.KnownCapabilities
	}

	pass, fail, warn := 0, 0, 0
	for _, path := range files {
		r, parseErr := rule.ParseFile(path)
		if parseErr != nil {
			fmt.Printf("FAIL  %s\n  PARSE ERROR: %v\n", path, parseErr)
			fail++
			continue
		}

		dir := filepath.Base(filepath.Dir(filepath.Clean(path)))
		opts := rule.ValidateOptions{
			Filename:          path,
			KnownCapabilities: knownCaps,
		}
		if knownCategory(dir) {
			opts.ExpectedCategory = dir
		}

		errs := rule.Validate(r, opts)
		warns := rule.Lint(r)

		hasErr := len(errs) > 0
		hasWarn := len(warns) > 0

		if !hasErr && (!hasWarn || !*strict) {
			pass++
			fmt.Printf("OK    %s\n", path)
			continue
		}

		fail++
		fmt.Printf("FAIL  %s (id: %s)\n", path, r.ID)
		for _, e := range errs {
			fmt.Printf("  ERROR  %s\n", e)
		}
		if hasWarn {
			warn += len(warns)
			for _, w := range warns {
				fmt.Printf("  WARN   [%s] impl[%d] %s: %s\n",
					w.Code, w.ImplIndex, w.Path, w.Msg)
			}
		}
	}

	fmt.Printf("\n%d/%d rules valid, %d warning(s)\n", pass, pass+fail, warn)
	if fail > 0 {
		os.Exit(1)
	}
}

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

func knownCategory(name string) bool {
	return knownCategories[name]
}
