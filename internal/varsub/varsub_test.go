// Tests for the Phase 3.5 substitution layer.
package varsub

import (
	"errors"
	"strings"
	"testing"
)

func TestSubstitute_Identity(t *testing.T) {
	got, err := Substitute("plain text, no templates", nil)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if got != "plain text, no templates" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_Single(t *testing.T) {
	got, err := Substitute("expected: {{ deny }}", Variables{"deny": "5"})
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	if got != "expected: 5" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_WhitespaceTolerant(t *testing.T) {
	for _, in := range []string{
		"{{deny}}",
		"{{ deny }}",
		"{{  deny  }}",
		"{{\tdeny\t}}",
	} {
		got, err := Substitute(in, Variables{"deny": "5"})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != "5" {
			t.Errorf("%q → %q; want 5", in, got)
		}
	}
}

func TestSubstitute_MultipleOccurrences(t *testing.T) {
	got, err := Substitute("a={{ x }}, b={{ x }}", Variables{"x": "42"})
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	if got != "a=42, b=42" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_MultipleVars(t *testing.T) {
	got, err := Substitute("{{ a }} / {{ b }}", Variables{"a": "1", "b": "2"})
	if err != nil {
		t.Fatalf("multi-var: %v", err)
	}
	if got != "1 / 2" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_UndefinedSingleError(t *testing.T) {
	_, err := Substitute("{{ unknown }}", Variables{})
	if err == nil {
		t.Fatal("undefined should error")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should name the missing var: %v", err)
	}
	if !strings.Contains(err.Error(), "--var") {
		t.Errorf("error should suggest --var: %v", err)
	}
}

func TestSubstitute_UndefinedMultipleNamed(t *testing.T) {
	// All missing vars must be reported in one error, sorted.
	_, err := Substitute("{{ b }} {{ a }} {{ c }}", Variables{"a": "1"})
	if err == nil {
		t.Fatal("multi-undefined should error")
	}
	if !strings.Contains(err.Error(), "b, c") {
		t.Errorf("error should list missing vars sorted: %v", err)
	}
}

func TestSubstitute_NameVocabulary(t *testing.T) {
	// Underscores and digits allowed after first char.
	got, err := Substitute("{{ pam_faillock_deny_2 }}", Variables{"pam_faillock_deny_2": "5"})
	if err != nil {
		t.Fatalf("vocab: %v", err)
	}
	if got != "5" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_InvalidNameNotMatched(t *testing.T) {
	// {{ 1invalid }} starts with a digit and shouldn't match
	// the template — passes through as literal.
	got, err := Substitute("{{ 1invalid }}", Variables{"1invalid": "x"})
	if err != nil {
		t.Fatalf("invalid: %v", err)
	}
	if got != "{{ 1invalid }}" {
		t.Errorf("digit-leading name should pass through; got %q", got)
	}
}

func TestSubstitute_LiteralBracesNotMatched(t *testing.T) {
	// `{{}}` and `{{  }}` (no name) should pass through.
	for _, in := range []string{"{{}}", "{{  }}", "{{ }}"} {
		got, err := Substitute(in, Variables{})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != in {
			t.Errorf("%q should pass through; got %q", in, got)
		}
	}
}

func TestMerge(t *testing.T) {
	base := Variables{"a": "base-a", "b": "base-b"}
	override := Variables{"b": "over-b", "c": "over-c"}
	got := Merge(base, override)
	if got["a"] != "base-a" || got["b"] != "over-b" || got["c"] != "over-c" {
		t.Errorf("merge wrong; got %v", got)
	}
	// Inputs not mutated.
	if base["b"] != "base-b" {
		t.Error("Merge mutated base")
	}
	if override["b"] != "over-b" {
		t.Error("Merge mutated override")
	}
}

func TestMerge_NilInputs(t *testing.T) {
	got := Merge(nil, nil)
	if len(got) != 0 {
		t.Errorf("nil+nil should produce empty; got %v", got)
	}
	got = Merge(Variables{"a": "1"}, nil)
	if got["a"] != "1" {
		t.Errorf("base+nil lost base; got %v", got)
	}
}

func TestSubstituteFile_Wraps(t *testing.T) {
	// SubstituteFile prefixes errors with the path.
	_, err := SubstituteFile("/path/to/file.yml", []byte("{{ unknown }}"), Variables{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "/path/to/file.yml") {
		t.Errorf("error should include path: %v", err)
	}
}

// TestSubstitute_UndefinedSentinelDetected locks the
// errors.Is(err, ErrUndefined) contract used by
// loadRulesSkipInvalid to aggregate undefined-variable skips.
func TestSubstitute_UndefinedSentinelDetected(t *testing.T) {
	_, err := Substitute("{{ unknown }}", Variables{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUndefined) {
		t.Errorf("error should wrap ErrUndefined; got %T: %v", err, err)
	}
}

// TestMerge_Associative locks Phase 3.6 forward compat: adding
// a third tier (per-host config) on top of (CLI > defaults)
// must not change semantics. Merge must be associative for the
// last-wins map-copy approach to work cleanly.
func TestMerge_Associative(t *testing.T) {
	a := Variables{"x": "a", "y": "a"}
	b := Variables{"x": "b", "z": "b"}
	c := Variables{"y": "c"}
	left := Merge(Merge(a, b), c)
	right := Merge(a, Merge(b, c))
	if left["x"] != right["x"] || left["y"] != right["y"] || left["z"] != right["z"] {
		t.Errorf("Merge not associative; left=%v right=%v", left, right)
	}
	// And independently lock the priority-chain result: c > b > a
	if left["x"] != "b" || left["y"] != "c" || left["z"] != "b" {
		t.Errorf("priority chain wrong; got %v", left)
	}
}

// TestSubstitute_ValueWithColon documents the YAML-bytes
// substitution choice: a substituted value containing a colon
// is spliced literally and may produce malformed YAML for the
// downstream decoder. The corpus uses bare scalar values
// exclusively, so this is non-blocking. Test pins current
// behavior so a future "auto-quote" change is deliberate.
func TestSubstitute_ValueWithColon(t *testing.T) {
	got, err := Substitute("expected: {{ banner }}", Variables{"banner": "foo: bar"})
	if err != nil {
		t.Fatalf("colon: %v", err)
	}
	if got != "expected: foo: bar" {
		t.Errorf("substituted text should splice literally; got %q", got)
	}
}

// TestSubstitute_ValueWithNewline same rationale: pinned
// current literal-splice behavior.
func TestSubstitute_ValueWithNewline(t *testing.T) {
	got, err := Substitute("expected: {{ msg }}", Variables{"msg": "line1\nline2"})
	if err != nil {
		t.Fatalf("newline: %v", err)
	}
	if got != "expected: line1\nline2" {
		t.Errorf("got %q", got)
	}
}
