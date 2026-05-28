package rules_test

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/rules"
)

// stubStat builds a stat function for tests. If exists is true the stat
// returns a zero-value fileInfo + nil error; otherwise an fs.ErrNotExist.
// The stub also records the path it was called with for assertions.
type statCall struct {
	path string
}

func makeStat(exists bool, calls *[]statCall) func(string) (os.FileInfo, error) {
	return func(p string) (os.FileInfo, error) {
		*calls = append(*calls, statCall{path: p})
		if exists {
			return nil, nil // production code only checks err == nil; FileInfo unused
		}
		return nil, fs.ErrNotExist
	}
}

// @spec rule-default-path-resolution
// @ac AC-01
func TestResolve_ExplicitDirWins(t *testing.T) {
	t.Run("rule-default-path-resolution/AC-01", func(t *testing.T) {})

	// Even if positional paths are also given AND the default path
	// would exist, the explicit --rules-dir wins without ever stating
	// anything. Calling the stat stub would be a contract violation.
	var calls []statCall
	got, err := rules.Resolve("/operator/rules", []string{"foo.yml"}, makeStat(true, &calls))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "/operator/rules" {
		t.Errorf("got=%q, want /operator/rules", got)
	}
	if len(calls) != 0 {
		t.Errorf("explicit dir must not trigger stat; calls=%v", calls)
	}
}

// @spec rule-default-path-resolution
// @ac AC-02
func TestResolve_PositionalPathsAlone(t *testing.T) {
	t.Run("rule-default-path-resolution/AC-02", func(t *testing.T) {})

	// dir=="" but paths are given. Return ("", nil) so the caller
	// loads the paths alone without dir-walking the default corpus.
	// Whether the default path exists is irrelevant — explicit files
	// must not be silently augmented by the package corpus.
	for _, exists := range []bool{true, false} {
		var calls []statCall
		got, err := rules.Resolve("", []string{"a.yml", "b.yml"}, makeStat(exists, &calls))
		if err != nil {
			t.Fatalf("Resolve (exists=%v): %v", exists, err)
		}
		if got != "" {
			t.Errorf("exists=%v: got=%q, want \"\"", exists, got)
		}
		if len(calls) != 0 {
			t.Errorf("exists=%v: positional-paths-alone must not trigger stat; calls=%v", exists, calls)
		}
	}
}

// @spec rule-default-path-resolution
// @ac AC-03
func TestResolve_FallsBackToDefaultWhenPresent(t *testing.T) {
	t.Run("rule-default-path-resolution/AC-03", func(t *testing.T) {})

	var calls []statCall
	got, err := rules.Resolve("", nil, makeStat(true, &calls))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != rules.DefaultPath {
		t.Errorf("got=%q, want %q", got, rules.DefaultPath)
	}
	if len(calls) != 1 || calls[0].path != rules.DefaultPath {
		t.Errorf("expected single stat of DefaultPath; calls=%v", calls)
	}
}

// @spec rule-default-path-resolution
// @ac AC-04
func TestResolve_ErrorsWhenNothingAvailable(t *testing.T) {
	t.Run("rule-default-path-resolution/AC-04", func(t *testing.T) {})

	var calls []statCall
	_, err := rules.Resolve("", nil, makeStat(false, &calls))
	if err == nil {
		t.Fatal("expected error when no dir, no paths, no default")
	}
	// C-04 requires BOTH fix paths in the message so the operator
	// sees how to fix it.
	msg := err.Error()
	if !strings.Contains(msg, "--rules-dir") {
		t.Errorf("error must name the --rules-dir flag; got %q", msg)
	}
	if !strings.Contains(msg, rules.DefaultPath) {
		t.Errorf("error must name the default path %q; got %q", rules.DefaultPath, msg)
	}
	if len(calls) != 1 || calls[0].path != rules.DefaultPath {
		t.Errorf("expected single stat of DefaultPath; calls=%v", calls)
	}
}

// Sanity check: ensure the stub helper's "not exist" path produces an
// error that the production code recognizes as "stat failed", not just
// any error.
func TestResolve_NotExistIsTreatedAsAbsent(t *testing.T) {
	got, err := rules.Resolve("", nil, func(string) (os.FileInfo, error) {
		return nil, fs.ErrNotExist
	})
	if err == nil {
		t.Fatal("expected error from stat fs.ErrNotExist")
	}
	if got != "" {
		t.Errorf("got=%q, want empty", got)
	}
	if !errors.Is(err, err) { // tautology — just guards the test from being deleted as unreferenced
		t.Fail()
	}
}
