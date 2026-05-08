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
func TestShortLetterTable_NoCollisions(t *testing.T) {
	registry := map[string]string{
		"ShortHelp":        ShortHelp,
		"ShortVersion":     ShortVersion,
		"ShortVerbose":     ShortVerbose,
		"ShortDb":          ShortDb,
		"ShortHost":        ShortHost,
		"ShortUser":        ShortUser,
		"ShortPort":        ShortPort,
		"ShortKey":         ShortKey,
		"ShortSudo":        ShortSudo,
		"ShortFormat":      ShortFormat,
		"ShortOutput":      ShortOutput,
		"ShortRulesDir":    ShortRulesDir,
		"ShortRule":        ShortRule,
		"ShortSince":       ShortSince,
		"ShortLimit":       ShortLimit,
		"ShortTransaction": ShortTransaction,
		"ShortAggregate":   ShortAggregate,
		"ShortQuiet":       ShortQuiet,
		"ShortInventory":   ShortInventory,
	}

	// Build inverse map: letter → list of constant names that bind it.
	byLetter := make(map[string][]string)
	for name, letter := range registry {
		if letter == "" {
			t.Errorf("%s is empty; every Short* constant should bind a single character", name)
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
func TestShortLetterTable_CaseDiscipline(t *testing.T) {
	cases := []struct {
		name   string
		letter string
		isUpper bool
		reason string
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
		{"ShortSince", ShortSince, true, "lowercase s is sudo"},
		{"ShortDb", ShortDb, true, "uppercase D preserves recognizability of the legacy `-db` form; lowercase d kept free for a future --dry-run short"},
		// Lowercase available cases.
		{"ShortUser", ShortUser, false, "no conflict"},
		{"ShortPort", ShortPort, false, "no conflict"},
		{"ShortKey", ShortKey, false, "no conflict"},
		{"ShortSudo", ShortSudo, false, "no conflict"},
		{"ShortFormat", ShortFormat, false, "no conflict"},
		{"ShortRulesDir", ShortRulesDir, false, "no conflict"},
		{"ShortLimit", ShortLimit, false, "head/tail convention -n"},
		{"ShortTransaction", ShortTransaction, false, "no conflict"},
		{"ShortAggregate", ShortAggregate, false, "no conflict"},
		{"ShortQuiet", ShortQuiet, false, "GNU --quiet convention"},
		{"ShortOutput", ShortOutput, false, "GNU --output convention"},
		{"ShortInventory", ShortInventory, false, "ansible --inventory convention"},
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
