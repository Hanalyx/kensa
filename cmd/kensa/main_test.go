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

// TestRewriteLegacyLongForm verifies the generic single-dash-long-form
// rewriter used by subcommand parsers during the C-002..C-004 transition
// window.
func TestRewriteLegacyLongForm(t *testing.T) {
	known := map[string]bool{"host": true, "user": true, "port": true}
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no flags untouched",
			in:   []string{"foo", "bar"},
			want: []string{"foo", "bar"},
		},
		{
			name: "single-dash long form rewritten",
			in:   []string{"-host", "192.168.1.211"},
			want: []string{"--host", "192.168.1.211"},
		},
		{
			name: "single-dash long form with =value",
			in:   []string{"-host=foo"},
			want: []string{"--host=foo"},
		},
		{
			name: "real short form left alone",
			in:   []string{"-h"},
			want: []string{"-h"},
		},
		{
			name: "double-dash form left alone",
			in:   []string{"--host", "foo"},
			want: []string{"--host", "foo"},
		},
		{
			name: "unknown single-dash name left alone",
			in:   []string{"-bogus"},
			want: []string{"-bogus"},
		},
		{
			name: "mix of known long, value, and short",
			in:   []string{"-host", "foo", "-user", "bar", "-h"},
			want: []string{"--host", "foo", "--user", "bar", "-h"},
		},
		{
			name: "single-letter name not in known set is left alone",
			in:   []string{"-u"}, // would only match if "u" was in known; it isn't (only multi-char)
			want: []string{"-u"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteLegacyLongForm(tc.in, known)
			if !slicesEqual(got, tc.want) {
				t.Errorf("rewriteLegacyLongForm(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestUsageError_BasicShape verifies the UsageError type behaves
// correctly with errors.As / Unwrap, NewUsageError, WrapUsageError.
// Deliverable C-008.
func TestUsageError_BasicShape(t *testing.T) {
	t.Run("NewUsageError is a UsageError", func(t *testing.T) {
		err := NewUsageError("foo")
		if !IsUsageError(err) {
			t.Errorf("IsUsageError(NewUsageError(...)) = false; want true")
		}
		if err.Error() != "foo" {
			t.Errorf("err.Error() = %q; want %q", err.Error(), "foo")
		}
	})

	t.Run("WrapUsageError wraps a non-UsageError", func(t *testing.T) {
		inner := errorString("network fail")
		err := WrapUsageError("connect", inner)
		if !IsUsageError(err) {
			t.Errorf("IsUsageError of wrapped = false; want true")
		}
		if err.Error() != "connect: network fail" {
			t.Errorf("err.Error() = %q; want %q", err.Error(), "connect: network fail")
		}
	})

	t.Run("WrapUsageError is idempotent on existing UsageError", func(t *testing.T) {
		first := NewUsageError("bad input")
		second := WrapUsageError("ignored", first)
		// Should return the existing UsageError unchanged.
		if second.Error() != "bad input" {
			t.Errorf("idempotent wrap = %q; want %q", second.Error(), "bad input")
		}
	})

	t.Run("non-UsageError is not flagged", func(t *testing.T) {
		if IsUsageError(errorString("ordinary")) {
			t.Errorf("IsUsageError of plain error = true; want false")
		}
	})
}

// TestUsageError_UnwrapAndEdgeCases covers UsageError's Unwrap path
// and the empty-Msg branch of Error() that aren't hit by the basic
// shape tests.
func TestUsageError_UnwrapAndEdgeCases(t *testing.T) {
	t.Run("Unwrap returns Cause", func(t *testing.T) {
		inner := errorString("inner-err")
		ue := &UsageError{Msg: "outer", Cause: inner}
		if ue.Unwrap() != inner {
			t.Errorf("Unwrap = %v; want %v", ue.Unwrap(), inner)
		}
	})
	t.Run("Unwrap on no-cause UsageError returns nil", func(t *testing.T) {
		ue := &UsageError{Msg: "alone"}
		if ue.Unwrap() != nil {
			t.Errorf("Unwrap = %v; want nil", ue.Unwrap())
		}
	})
	t.Run("Error with empty Msg returns Cause.Error()", func(t *testing.T) {
		inner := errorString("only-cause")
		ue := &UsageError{Cause: inner}
		if ue.Error() != "only-cause" {
			t.Errorf("Error() = %q; want %q", ue.Error(), "only-cause")
		}
	})
}

// TestRunCLI_UsageVsRuntimeExitCodes verifies the C-008 contract:
// usage errors (bad flags, missing required args, malformed values)
// exit 2; runtime errors exit 1; --help/--version exit 0.
//
// These tests don't make network calls — they only exercise the
// flag-parse / required-flag-check paths which return UsageError
// before any runtime work begins. The "unreachable host" runtime-1
// case is covered by manual / live testing because invoking it from
// here would block on TCP timeouts.
func TestRunCLI_UsageVsRuntimeExitCodes(t *testing.T) {
	cases := []runCLITestCase{
		// Help paths: exit 0
		{name: "kensa --help", argv: []string{"--help"}, wantExit: 0},
		{name: "kensa version --help", argv: []string{"version", "--help"}, wantExit: 0},
		{name: "kensa detect --help", argv: []string{"detect", "--help"}, wantExit: 0},
		{name: "kensa coverage --help", argv: []string{"coverage", "--help"}, wantExit: 0},

		// Usage errors at top level: exit 2
		{name: "kensa unknown-cmd", argv: []string{"frobnicate"}, wantExit: 2},
		{name: "kensa --bogus-flag", argv: []string{"--bogus-flag"}, wantExit: 2},

		// Subcommand usage errors (missing required flag, bad flag): exit 2
		{name: "kensa detect (no host)", argv: []string{"detect"}, wantExit: 2},
		{name: "kensa detect --bogus", argv: []string{"detect", "--bogus"}, wantExit: 2},
		{name: "kensa check (nothing)", argv: []string{"check"}, wantExit: 2},
		{name: "kensa check --bogus", argv: []string{"check", "--bogus"}, wantExit: 2},
		{name: "kensa rollback (no host)", argv: []string{"rollback"}, wantExit: 2},
		{name: "kensa rollback -H foo (no txn)", argv: []string{"rollback", "-H", "foo"}, wantExit: 2},
		{name: "kensa rollback bad UUID", argv: []string{"rollback", "-H", "foo", "-T", "notauuid"}, wantExit: 2},
		{name: "kensa plan (no host, no rule)", argv: []string{"plan"}, wantExit: 2},
		{name: "kensa plan -H foo (no rule)", argv: []string{"plan", "-H", "foo"}, wantExit: 2},
		{name: "kensa remediate (no host)", argv: []string{"remediate"}, wantExit: 2},
		{name: "kensa history --since invalid", argv: []string{"history", "--since", "not-a-duration-or-time"}, wantExit: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCLI(tc.argv); got != tc.wantExit {
				t.Errorf("runCLI(%q) = %d, want %d", tc.argv, got, tc.wantExit)
			}
		})
	}
}

// errorString is a minimal error implementation for tests that need
// to wrap a plain error in a UsageError.
type errorString string

func (e errorString) Error() string { return string(e) }

// Sanity: ensure the version constant is non-empty and starts with 'v'.
func TestVersionConstantShape(t *testing.T) {
	if !strings.HasPrefix(version, "v") {
		t.Errorf("version = %q; want a 'v'-prefix per semver convention", version)
	}
	if len(version) < 4 {
		t.Errorf("version = %q; suspiciously short", version)
	}
}
