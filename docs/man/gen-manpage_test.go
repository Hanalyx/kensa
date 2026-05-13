// Tests for the C-055 manpage generator.
package main

import (
	"testing"
)

// TestEscapeRoffLine locks the roff-character escape contract from
// spec C-05. Critical cases:
//   - Backslash → \\ (otherwise roff interprets as an escape lead-in)
//   - Hyphen-minus → \- (otherwise rendered as soft-hyphen, broken
//     on flag names like --rules-dir)
//   - Leading "." or "'" at line start → \& prefix (otherwise roff
//     interprets the line as a control directive)
func TestEscapeRoffLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"backslash", `path\to\file`, `path\\to\\file`},
		{"hyphen", `--rules-dir`, `\-\-rules\-dir`},
		{"leading dot", `.SS DETECT`, `\&.SS DETECT`},
		{"leading apostrophe", `'foo`, `\&'foo`},
		{"plain text", `Hello world`, `Hello world`},
		{"empty", ``, ``},
		// Backslash ordering — ensure backslash escape runs FIRST
		// so the inserted "\\" doesn't get re-escaped on hyphen pass.
		{"backslash with hyphen", `\-foo`, `\\\-foo`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeRoffLine(tc.in)
			if got != tc.want {
				t.Errorf("escapeRoffLine(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSubcommandList locks the registered set so a future
// contributor adding a new subcommand to cmd/kensa/main.go's
// dispatch ALSO updates the manpage generator. Drift would mean
// the new subcommand silently misses the manpage.
//
// The list intentionally EXCLUDES the deprecated `coverage`
// alias (per C-02 in the spec).
func TestSubcommandList(t *testing.T) {
	expected := []string{
		"detect", "check", "remediate", "rollback", "history",
		"plan", "mechanisms", "list", "info", "diff",
		"agent", "verify", "migrate", "version",
	}
	if len(subcommands) != len(expected) {
		t.Fatalf("subcommand count: got %d want %d", len(subcommands), len(expected))
	}
	for i, want := range expected {
		if subcommands[i] != want {
			t.Errorf("subcommands[%d]: got %q want %q", i, subcommands[i], want)
		}
	}
	// `coverage` MUST NOT appear (deprecated alias).
	for _, s := range subcommands {
		if s == "coverage" {
			t.Errorf("'coverage' should not appear in subcommands list (deprecated alias for 'mechanisms')")
		}
	}
}

// TestSubcommandList_NoDuplicates is a small sanity guard — if a
// duplicate creeps in, the generated manpage gets two .SS sections
// for the same subcommand. Easier to catch here than in eyeball-
// review of a 27 KB roff file.
func TestSubcommandList_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, s := range subcommands {
		if seen[s] {
			t.Errorf("duplicate subcommand: %q", s)
		}
		seen[s] = true
	}
}

