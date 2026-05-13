// Tests for the --capability / -C flag (C-028). Covers
// parseCapabilityValue, resolveCapabilityOverrides for the empty,
// well-formed, malformed, unknown-key, and bad-value branches.
package main

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/detect"
)

// firstKnownCap returns a capability name guaranteed to be in the
// canonical vocabulary. Used so tests don't hard-code names that a
// future patch could rename.
func firstKnownCap(t *testing.T) string {
	t.Helper()
	names := detect.KnownCapabilities()
	if len(names) == 0 {
		t.Fatal("detect.KnownCapabilities returned empty list")
	}
	return names[0]
}

// secondKnownCap returns a different known capability or skips.
func secondKnownCap(t *testing.T) string {
	t.Helper()
	names := detect.KnownCapabilities()
	if len(names) < 2 {
		t.Skip("vocabulary has fewer than 2 capabilities")
	}
	return names[1]
}

// @spec cli-capability-override
// @ac AC-01
// @ac AC-11
func TestParseCapabilityValue_Truthy(t *testing.T) {
	t.Run("cli-capability-override/AC-01", func(t *testing.T) {})
	t.Run("cli-capability-override/AC-11", func(t *testing.T) {})
	for _, in := range []string{"true", "TRUE", "True", "yes", "y", "on", "1", "  true  "} {
		t.Run(in, func(t *testing.T) {
			got, err := parseCapabilityValue(in)
			if err != nil {
				t.Fatalf("parseCapabilityValue(%q): %v", in, err)
			}
			if !got {
				t.Errorf("parseCapabilityValue(%q) = false; want true", in)
			}
		})
	}
}

// @spec cli-capability-override
// @ac AC-02
func TestParseCapabilityValue_Falsy(t *testing.T) {
	t.Run("cli-capability-override/AC-02", func(t *testing.T) {})
	for _, in := range []string{"false", "FALSE", "no", "n", "off", "0"} {
		t.Run(in, func(t *testing.T) {
			got, err := parseCapabilityValue(in)
			if err != nil {
				t.Fatalf("parseCapabilityValue(%q): %v", in, err)
			}
			if got {
				t.Errorf("parseCapabilityValue(%q) = true; want false", in)
			}
		})
	}
}

// @spec cli-capability-override
// @ac AC-03
func TestParseCapabilityValue_Invalid(t *testing.T) {
	t.Run("cli-capability-override/AC-03", func(t *testing.T) {})
	for _, in := range []string{"", "maybe", "2", "TRUE!", "presence"} {
		t.Run(in, func(t *testing.T) {
			_, err := parseCapabilityValue(in)
			if err == nil {
				t.Errorf("parseCapabilityValue(%q) accepted; should reject", in)
			}
		})
	}
}

// @spec cli-capability-override
// @ac AC-04
func TestResolveCapabilityOverrides_Empty(t *testing.T) {
	t.Run("cli-capability-override/AC-04", func(t *testing.T) {})
	got, err := resolveCapabilityOverrides(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if got != nil {
		t.Errorf("nil input should return nil; got %v", got)
	}
	got, err = resolveCapabilityOverrides([]string{})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if got != nil {
		t.Errorf("empty input should return nil; got %v", got)
	}
}

// @spec cli-capability-override
// @ac AC-05
func TestResolveCapabilityOverrides_WellFormed(t *testing.T) {
	t.Run("cli-capability-override/AC-05", func(t *testing.T) {})
	cap := firstKnownCap(t)
	got, err := resolveCapabilityOverrides([]string{cap + "=true"})
	if err != nil {
		t.Fatalf("%s=true: %v", cap, err)
	}
	if v, ok := got[cap]; !ok || !v {
		t.Errorf("%s=true should produce {%s:true}; got %v", cap, cap, got)
	}
}

// @spec cli-capability-override
// @ac AC-06
func TestResolveCapabilityOverrides_MultipleEntries(t *testing.T) {
	t.Run("cli-capability-override/AC-06", func(t *testing.T) {})
	cap1 := firstKnownCap(t)
	cap2 := secondKnownCap(t)
	got, err := resolveCapabilityOverrides([]string{cap1 + "=false", cap2 + "=true"})
	if err != nil {
		t.Fatalf("multiple: %v", err)
	}
	if got[cap1] != false {
		t.Errorf("%s=false expected; got %v", cap1, got[cap1])
	}
	if got[cap2] != true {
		t.Errorf("%s=true expected; got %v", cap2, got[cap2])
	}
}

// TestResolveCapabilityOverrides_DuplicateKey_LastWins locks the
// repeatable-flag semantic: the last KEY=VALUE wins for a given KEY.
// Documented in registerCapabilityFlag and AC-11.
// @spec cli-capability-override
// @ac AC-07
func TestResolveCapabilityOverrides_DuplicateKey_LastWins(t *testing.T) {
	t.Run("cli-capability-override/AC-07", func(t *testing.T) {})
	cap := firstKnownCap(t)
	got, err := resolveCapabilityOverrides([]string{cap + "=true", cap + "=false"})
	if err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	if got[cap] != false {
		t.Errorf("last value should win; %s expected false, got %v", cap, got[cap])
	}
}

// @spec cli-capability-override
// @ac AC-08
func TestResolveCapabilityOverrides_MalformedEntry(t *testing.T) {
	t.Run("cli-capability-override/AC-08", func(t *testing.T) {})
	cap := firstKnownCap(t)
	cases := []struct {
		in           string
		errSubstring string
	}{
		{cap, "missing '='"},    // bare KEY without separator
		{"=true", "empty KEY"},  // separator but empty key
		{"", "missing '='"},     // empty entry
		{cap + "=", "expected"}, // empty value (parser rejects)
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := resolveCapabilityOverrides([]string{tc.in})
			if err == nil {
				t.Errorf("malformed %q should error", tc.in)
				return
			}
			if tc.errSubstring != "" && !strings.Contains(err.Error(), tc.errSubstring) {
				t.Errorf("expected substring %q in error %q", tc.errSubstring, err.Error())
			}
		})
	}
}

// @spec cli-capability-override
// @ac AC-09
func TestResolveCapabilityOverrides_UnknownKey(t *testing.T) {
	t.Run("cli-capability-override/AC-09", func(t *testing.T) {})
	_, err := resolveCapabilityOverrides([]string{"not-a-real-cap=true"})
	if err == nil {
		t.Fatal("unknown capability key should error")
	}
	if !strings.Contains(err.Error(), "unknown capability key") {
		t.Errorf("error should mention unknown key: %v", err)
	}
	// Error must list the valid keys so the operator can self-correct.
	if !strings.Contains(err.Error(), "valid keys:") {
		t.Errorf("error should list valid keys: %v", err)
	}
}

// @spec cli-capability-override
// @ac AC-10
func TestResolveCapabilityOverrides_BadValue(t *testing.T) {
	t.Run("cli-capability-override/AC-10", func(t *testing.T) {})
	cap := firstKnownCap(t)
	_, err := resolveCapabilityOverrides([]string{cap + "=maybe"})
	if err == nil {
		t.Fatal("bad value should error")
	}
	if !strings.Contains(err.Error(), "true|false") {
		t.Errorf("error should mention valid forms: %v", err)
	}
}
