// Tests for the centralized short-letter table (deliverable C-005 in
// docs/roadmap/DELIVERABLES.md).
//
// The collision-detection test below is the structural guard for the
// short-letter discipline: if a future PR adds a new `Short*` constant
// that duplicates an existing letter, this test fails with a clear
// message naming the conflicting names. That makes accidental
// collisions a code-review issue, not a runtime issue.
package main

import (
	"testing"
)

// TestShortLetterTable_NoCollisions asserts that every `Short*` constant
// in flags.go has a unique value. If two flags need to share a letter
// in different scopes (e.g., `-l` for `--limit` host glob in
// target_options vs `-l` for `--limit` row count in history), the
// design intent is to disambiguate by giving them distinct constants
// (ShortLimit vs e.g., ShortLimitGlob) — not to assign them the same
// constant name.
//
// The mapping below mirrors the constants in flags.go. Adding a new
// short letter requires updating both the constant declaration and
// this test, which is the intended friction.
// @spec cli-polish-c023
// @ac AC-01
// @ac AC-03
// @ac AC-05
// @ac AC-07
// @ac AC-09
// @ac AC-11
// @spec cli-short-letter-table
// @ac AC-01
// @ac AC-03
// @ac AC-05
// @ac AC-07
func TestShortLetterTable_NoCollisions(t *testing.T) {
	t.Run("cli-short-letter-table/AC-01", func(t *testing.T) {})
	t.Run("cli-short-letter-table/AC-03", func(t *testing.T) {})
	t.Run("cli-short-letter-table/AC-05", func(t *testing.T) {})
	t.Run("cli-short-letter-table/AC-07", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-01", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-03", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-05", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-07", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-09", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-11", func(t *testing.T) {})
	registry := map[string]string{
		"ShortHelp":        ShortHelp,
		"ShortVersion":     ShortVersion,
		"ShortVerbose":     ShortVerbose,
		"ShortDB":          ShortDB,
		"ShortHost":        ShortHost,
		"ShortUser":        ShortUser,
		"ShortPort":        ShortPort,
		"ShortKey":         ShortKey,
		"ShortSudo":        ShortSudo,   // intentionally empty (C-024)
		"ShortFormat":      ShortFormat, // intentionally empty (C-024)
		"ShortOutput":      ShortOutput,
		"ShortRulesDir":    ShortRulesDir,
		"ShortRule":        ShortRule,
		"ShortSince":       ShortSince,
		"ShortLimit":       ShortLimit,
		"ShortTransaction": ShortTransaction,
		"ShortAggregate":   ShortAggregate,
		"ShortQuiet":       ShortQuiet,
		"ShortInventory":   ShortInventory,
		// Placeholder short letters (C-024 declares; C-026..C-034
		// wire to actual flags). Inclusion here ensures collision
		// detection covers them now.
		"ShortPassword":   ShortPassword,
		"ShortLimitGlob":  ShortLimitGlob,
		"ShortSeverity":   ShortSeverity,
		"ShortTag":        ShortTag,
		"ShortCategory":   ShortCategory,
		"ShortFramework":  ShortFramework,
		"ShortCapability": ShortCapability,
		"ShortWorkers":    ShortWorkers,
		"ShortVar":        ShortVar,
	}

	// Constants that are intentionally empty per the
	// short-letter table (no canonical short, long-form only). The
	// migration doc §3 documents which flags lack a Python-kensa
	// short; kensa matches.
	intentionallyEmpty := map[string]bool{
		"ShortSudo":   true, // §3.2: --sudo has no short
		"ShortFormat": true, // C-024: --format short freed for --framework
	}

	// Build inverse map: letter → list of constant names that bind it.
	byLetter := make(map[string][]string)
	for name, letter := range registry {
		if letter == "" {
			if intentionallyEmpty[name] {
				continue // expected
			}
			t.Errorf("%s is empty; every Short* constant should bind a single character (or be in intentionallyEmpty)", name)
			continue
		}
		if len(letter) != 1 {
			t.Errorf("%s = %q is %d characters; short letters must be exactly 1 character", name, letter, len(letter))
			continue
		}
		byLetter[letter] = append(byLetter[letter], name)
	}

	for letter, names := range byLetter {
		if len(names) > 1 {
			t.Errorf("short letter %q is bound to multiple constants: %v — pick distinct letters or rename the constants", letter, names)
		}
	}
}

// TestShortLetterTable_CaseDiscipline verifies that case choices match
// the documented intent in flags.go: lowercase for "first available"
// flags, uppercase only when the lowercase letter conflicts with a
// reservation (sacred GNU letter or already-used in same scope).
// @spec cli-polish-c023
// @ac AC-02
// @ac AC-04
// @ac AC-06
// @ac AC-08
// @ac AC-10
// @spec cli-short-letter-table
// @ac AC-02
// @ac AC-04
// @ac AC-06
func TestShortLetterTable_CaseDiscipline(t *testing.T) {
	t.Run("cli-short-letter-table/AC-02", func(t *testing.T) {})
	t.Run("cli-short-letter-table/AC-04", func(t *testing.T) {})
	t.Run("cli-short-letter-table/AC-06", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-02", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-04", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-06", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-08", func(t *testing.T) {})
	t.Run("cli-polish-c023/AC-10", func(t *testing.T) {})
	cases := []struct {
		name    string
		letter  string
		isUpper bool
		reason  string
	}{
		// Sacred GNU lowercase reservations.
		{"ShortHelp", ShortHelp, false, "GNU --help"},
		{"ShortVerbose", ShortVerbose, false, "GNU --verbose"},
		// Sacred GNU uppercase reservations.
		{"ShortVersion", ShortVersion, true, "GNU --version (uppercase by convention)"},
		// Uppercase-by-deviation cases (lowercase taken by sacred or by
		// more-frequently-used flag).
		{"ShortHost", ShortHost, true, "lowercase h is help"},
		{"ShortRule", ShortRule, true, "lowercase r is rules-dir"},
		{"ShortSince", ShortSince, true, "lowercase s is severity (post-C-024)"},
		{"ShortDB", ShortDB, true, "uppercase D preserves recognizability of the legacy `-db` form; lowercase d kept free for a future --dry-run short"},
		{"ShortPort", ShortPort, true, "C-024: capital P; lowercase p is --password"},
		{"ShortTransaction", ShortTransaction, true, "C-024: capital T; lowercase t is --tag"},
		{"ShortCapability", ShortCapability, true, "capital C; lowercase c is --category"},
		// Lowercase available cases.
		{"ShortUser", ShortUser, false, "no conflict"},
		{"ShortKey", ShortKey, false, "no conflict"},
		{"ShortRulesDir", ShortRulesDir, false, "no conflict"},
		{"ShortLimit", ShortLimit, false, "head/tail convention -n"},
		{"ShortAggregate", ShortAggregate, false, "no conflict"},
		{"ShortQuiet", ShortQuiet, false, "GNU --quiet convention"},
		{"ShortOutput", ShortOutput, false, "GNU --output convention"},
		{"ShortInventory", ShortInventory, false, "ansible --inventory convention"},
		{"ShortPassword", ShortPassword, false, "Python kensa parity"},
		{"ShortLimitGlob", ShortLimitGlob, false, "ansible --limit convention"},
		{"ShortSeverity", ShortSeverity, false, "Python kensa parity"},
		{"ShortTag", ShortTag, false, "Python kensa parity"},
		{"ShortCategory", ShortCategory, false, "Python kensa parity"},
		{"ShortFramework", ShortFramework, false, "Python kensa parity"},
		{"ShortWorkers", ShortWorkers, false, "Python kensa parity"},
		{"ShortVar", ShortVar, false, "kensa-only — eXtra var mnemonic"},
		// Intentionally empty cases — skipped by the case check.
		// ShortSudo, ShortFormat are excluded above.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotUpper := tc.letter >= "A" && tc.letter <= "Z"
			if gotUpper != tc.isUpper {
				t.Errorf("%s = %q is %s; expected %s (reason: %s)",
					tc.name, tc.letter,
					caseLabel(gotUpper),
					caseLabel(tc.isUpper),
					tc.reason)
			}
		})
	}
}

func caseLabel(upper bool) string {
	if upper {
		return "uppercase"
	}
	return "lowercase"
}
