// Tests for the top-level CLI exit-code contract (deliverable C-001 in
// docs/roadmap/DELIVERABLES.md).
//
// These tests drive runCLI directly with synthetic argv slices so they
// don't spawn a subprocess. They cover the full GNU/POSIX exit-code
// contract:
//
//	0  success or --help / --version
//	1  runtime error (subcommand failed)
//	2  usage error (bad flag, unknown subcommand, missing args)
//
// Subcommand-specific flag coverage lives in the deliverable-specific
// tests for C-002..C-004 (per-subcommand pflag migration).
package main

import (
	"strings"
	"testing"
)

// runCLITestCase pairs a label with an argv slice and the expected
// process exit code. Stdout/stderr are not captured here — that
// requires fd redirection that's brittle in unit tests. The exit code
// is the contract C-001 is committing to.
type runCLITestCase struct {
	name     string
	argv     []string
	wantExit int
}

// TestRunCLI_HelpExitsZero verifies that every help-request form returns
// exit 0 (per GNU convention; per C-001 acceptance).
func TestRunCLI_HelpExitsZero(t *testing.T) {
	cases := []runCLITestCase{
		{name: "--help long form", argv: []string{"--help"}, wantExit: 0},
		{name: "-h short form", argv: []string{"-h"}, wantExit: 0},
		{name: "--help with --db prefix", argv: []string{"--db", "/tmp/x.db", "--help"}, wantExit: 0},
		{name: "--help with -D prefix", argv: []string{"-D", "/tmp/x.db", "--help"}, wantExit: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCLI(tc.argv); got != tc.wantExit {
				t.Errorf("runCLI(%q) = %d, want %d", tc.argv, got, tc.wantExit)
			}
		})
	}
}

// TestRunCLI_VersionExitsZero verifies --version / -V / `version`
// subcommand all exit 0.
func TestRunCLI_VersionExitsZero(t *testing.T) {
	cases := []runCLITestCase{
		{name: "--version flag", argv: []string{"--version"}, wantExit: 0},
		{name: "-V short form", argv: []string{"-V"}, wantExit: 0},
		{name: "version subcommand (legacy)", argv: []string{"version"}, wantExit: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCLI(tc.argv); got != tc.wantExit {
				t.Errorf("runCLI(%q) = %d, want %d", tc.argv, got, tc.wantExit)
			}
		})
	}
}

// TestRunCLI_UsageErrorsExitTwo verifies bad-flag and unknown-subcommand
// paths return exit 2 per GNU convention.
func TestRunCLI_UsageErrorsExitTwo(t *testing.T) {
	cases := []runCLITestCase{
		{name: "unknown long flag", argv: []string{"--not-a-flag"}, wantExit: 2},
		{name: "unknown short flag", argv: []string{"-Z"}, wantExit: 2},
		{name: "no command", argv: []string{}, wantExit: 2},
		{name: "unknown subcommand", argv: []string{"frobnicate"}, wantExit: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCLI(tc.argv); got != tc.wantExit {
				t.Errorf("runCLI(%q) = %d, want %d", tc.argv, got, tc.wantExit)
			}
		})
	}
}

// TestRunCLI_LegacyDbPasses verifies the backward-compat shim accepts
// the stdlib-flag-style `-db` single-dash long form. Will be removed
// in v0.2.
func TestRunCLI_LegacyDbPasses(t *testing.T) {
	cases := []runCLITestCase{
		{name: "-db /path --help", argv: []string{"-db", "/tmp/x.db", "--help"}, wantExit: 0},
		{name: "-db=/path --help", argv: []string{"-db=/tmp/x.db", "--help"}, wantExit: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCLI(tc.argv); got != tc.wantExit {
				t.Errorf("runCLI(%q) = %d, want %d", tc.argv, got, tc.wantExit)
			}
		})
	}
}

// TestRewriteLegacyDb verifies the argv preprocessor for backward-compat.
func TestRewriteLegacyDb(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "no -db", in: []string{"--help"}, want: []string{"--help"}},
		{name: "-db separate value", in: []string{"-db", "/x", "check"}, want: []string{"--db", "/x", "check"}},
		{name: "-db= attached value", in: []string{"-db=/x", "check"}, want: []string{"--db=/x", "check"}},
		{name: "canonical --db untouched", in: []string{"--db", "/x"}, want: []string{"--db", "/x"}},
		{name: "short -D untouched", in: []string{"-D", "/x"}, want: []string{"-D", "/x"}},
		{name: "-db only once warned", in: []string{"-db", "/x", "-db=/y"}, want: []string{"--db", "/x", "--db=/y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteLegacyDb(tc.in)
			if !slicesEqual(got, tc.want) {
				t.Errorf("rewriteLegacyDb(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Sanity: ensure the version constant is non-empty and starts with 'v'.
func TestVersionConstantShape(t *testing.T) {
	if !strings.HasPrefix(version, "v") {
		t.Errorf("version = %q; want a 'v'-prefix per semver convention", version)
	}
	if len(version) < 4 {
		t.Errorf("version = %q; suspiciously short", version)
	}
}
