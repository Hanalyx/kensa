package mappings

import (
	"reflect"
	"testing"
)

// spec rule-cmmc-l2-derived-refs. CMMC Level 2 IS the 110 NIST SP 800-171 Rev 2
// requirements, one for one, so these tests are about the derivation carrying
// no claim the 800-171 reference did not already carry.

// @spec rule-cmmc-l2-derived-refs
// @ac AC-03
//
// Kensa cites 800-171 at assessment-objective granularity because that is what
// a C3PAO scores. CMMC practices exist only at requirement granularity, so two
// objectives of one requirement must collapse to one practice. Emitting one per
// objective would multiply a single claim into several.
func TestCMMCLevel2Practices_ObjectivesCollapseToOnePractice(t *testing.T) {
	t.Run("rule-cmmc-l2-derived-refs/AC-03", func(t *testing.T) {})

	got := CMMCLevel2Practices([]string{"3.1.7[a]", "3.1.7[d]", "3.1.7[f]"})
	want := []string{"AC.L2-3.1.7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v — one requirement must yield one practice", got, want)
	}
}

// @spec rule-cmmc-l2-derived-refs
// @ac AC-05
//
// Derivation never invents a mapping. A rule with nothing reviewed gets
// nothing, which is what keeps this a renaming rather than a claim.
func TestCMMCLevel2Practices_NoRefsInNoRefsOut(t *testing.T) {
	t.Run("rule-cmmc-l2-derived-refs/AC-05", func(t *testing.T) {})

	for _, in := range [][]string{nil, {}, {""}, {"   "}} {
		if got := CMMCLevel2Practices(in); len(got) != 0 {
			t.Errorf("input %q produced %v; derivation must invent nothing", in, got)
		}
	}
	// An unparseable reference is skipped, never guessed at.
	if got := CMMCLevel2Practices([]string{"not-a-requirement", "3.1", "9.9.9"}); len(got) != 0 {
		t.Errorf("unparseable refs produced %v", got)
	}
}

// @spec rule-cmmc-l2-derived-refs
// @ac AC-04
//
// The family prefix decides the identifier, so an incomplete or ambiguous map
// would silently emit wrong practice ids. It is checked against 32 CFR 170 by
// the generator; this asserts the compiled copy is complete.
func TestCMMCFamilyMap_CoversAllFourteenGroups(t *testing.T) {
	t.Run("rule-cmmc-l2-derived-refs/AC-04", func(t *testing.T) {})

	groups := CMMCFamilyGroups()
	if len(groups) != 14 {
		t.Fatalf("family map covers %d groups, want 14", len(groups))
	}
	// Spot-check the boundaries and the two-digit groups, which are where a
	// naive string split goes wrong.
	cases := map[string]string{
		"3.1.1":   "AC.L2-3.1.1",
		"3.10.1":  "PE.L2-3.10.1",
		"3.12.4":  "CA.L2-3.12.4",
		"3.14.7":  "SI.L2-3.14.7",
		"3.13.16": "SC.L2-3.13.16",
	}
	for in, want := range cases {
		got := CMMCLevel2Practices([]string{in})
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s -> %v, want [%s]", in, got, want)
		}
	}
}

// Unlettered single-objective requirements cite the bare requirement, and that
// is the correct form for the eleven that NIST writes that way. They must
// derive identically to a lettered objective.
//
// @spec rule-cmmc-l2-derived-refs
// @ac AC-03
func TestCMMCLevel2Practices_BareRequirementsDeriveTheSame(t *testing.T) {
	bare := CMMCLevel2Practices([]string{"3.13.16"})
	lettered := CMMCLevel2Practices([]string{"3.13.16[a]"})
	if !reflect.DeepEqual(bare, lettered) {
		t.Errorf("bare %v and lettered %v must derive the same practice", bare, lettered)
	}
}

// The result is sorted and deduplicated so a regeneration produces a stable
// diff rather than reordering noise across 324 files.
func TestCMMCLevel2Practices_StableAndDeduplicated(t *testing.T) {
	got := CMMCLevel2Practices([]string{"3.5.3[d]", "3.1.1[a]", "3.5.3[c]", "3.1.1[a]"})
	want := []string{"AC.L2-3.1.1", "IA.L2-3.5.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
