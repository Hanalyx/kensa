package coverage

import (
	"testing"
)

// S-10. The denominator is the whole point of this report, so every test here
// is about a way the number could be quoted dishonestly.

// @spec cli-nist-800-171-denominator
// @ac AC-01
//
// The numerator is reviewed mapping status, not scan posture. Coverage answers
// "can kensa evidence this objective at all", which is a property of the
// corpus. Whether a rule passed on a host answers a different question, and
// letting it move this number would make a fleet of broken hosts look worse at
// framework coverage than an identical fleet of healthy ones.
func TestNIST800171_NumeratorIsMappingNotScanPosture(t *testing.T) {
	t.Run("cli-nist-800-171-denominator/AC-01", func(t *testing.T) {})

	// Two fleets of the same size and architecture, one healthy and one not,
	// are indistinguishable to this report because it never reads outcomes.
	healthy := ComputeNIST800171(ArchLocalAccounts, 12)
	broken := ComputeNIST800171(ArchLocalAccounts, 12)
	if healthy.Satisfied != broken.Satisfied {
		t.Fatalf("scan posture leaked into the numerator: %d vs %d",
			healthy.Satisfied, broken.Satisfied)
	}
	// And the numerator counts only reviewed 'satisfies'.
	want := 0
	for _, e := range nist800171Catalog.Objectives {
		if e.Verdict == "satisfies" && nist800171Catalog.assessable(e, ArchLocalAccounts) {
			want++
		}
	}
	if healthy.Satisfied != want {
		t.Errorf("Satisfied = %d, want %d (reviewed 'satisfies' within the denominator)",
			healthy.Satisfied, want)
	}
	if healthy.Partial == 0 {
		t.Error("partial must be reported separately, never folded into satisfied")
	}
}

// @spec cli-nist-800-171-denominator
// @ac AC-02
//
// A percentage without its denominator and its boundary is the failure mode
// this whole report exists to prevent. Most of 800-171 is not host state, so a
// number quoted against 320 measures the standard rather than the product.
func TestNIST800171_BucketsTravelWithEveryNumber(t *testing.T) {
	t.Run("cli-nist-800-171-denominator/AC-02", func(t *testing.T) {})

	for _, arch := range []Architecture{ArchLocalAccounts, ArchDirectoryJoined} {
		r := ComputeNIST800171(arch, 1)
		if r.Buckets == nil {
			t.Fatalf("%s: no buckets", arch)
		}
		b := *r.Buckets
		if b.Assessable == 0 || b.Boundary == 0 {
			t.Errorf("%s: a bucket is empty, so the number could be quoted alone: %s", arch, b)
		}
		if got := b.Assessable + b.Boundary + b.Unclassified; got != b.Total {
			t.Errorf("%s: buckets sum to %d, want %d — an objective is unaccounted for",
				arch, got, b.Total)
		}
		if r.Satisfied > b.Assessable {
			t.Errorf("%s: numerator %d exceeds denominator %d", arch, r.Satisfied, b.Assessable)
		}
	}
}

// @spec cli-nist-800-171-denominator
// @ac AC-03
//
// KN-KN-029: 39 objectives (CA, MA, MP) carry no tier and are in neither the
// assessable set nor the published boundary. At least one, 3.8.7, has a shipped
// rule that plausibly evidences it. Folding them either way asserts a
// disposition nobody made.
func TestNIST800171_UnclassifiedIsItsOwnBucket(t *testing.T) {
	t.Run("cli-nist-800-171-denominator/AC-03", func(t *testing.T) {})

	r := ComputeNIST800171(ArchLocalAccounts, 1)
	if r.Buckets.Unclassified == 0 {
		t.Fatal("unclassified is zero; either the corpus was completed (update this test " +
			"and KN-KN-029) or the bucket has been silently folded away")
	}
	if len(r.UnclassifiedIDs) != r.Buckets.Unclassified {
		t.Errorf("unclassified count %d but %d ids listed; the bucket must be auditable",
			r.Buckets.Unclassified, len(r.UnclassifiedIDs))
	}
	// The three families that own the hole. If a classification pass lands,
	// this test should fail and be updated deliberately.
	fams := map[string]bool{}
	for _, id := range r.UnclassifiedIDs {
		fams[nist800171Catalog.Objectives[id].Family] = true
	}
	for _, want := range []string{"CA", "MA", "MP"} {
		if !fams[want] {
			t.Errorf("family %s no longer unclassified; if that was intended, "+
				"update KN-KN-029 and the boundary document too", want)
		}
	}
	// And they are counted nowhere else.
	if r.Buckets.Assessable+r.Buckets.Boundary+r.Buckets.Unclassified != r.Buckets.Total {
		t.Error("unclassified objectives are being double counted")
	}
}

// @spec cli-nist-800-171-denominator
// @ac AC-04
//
// DEC-1: the denominator is per fleet. Seven objectives are answerable when the
// host owns its accounts and not when a directory does, so the architecture
// changes both the denominator and the numerator.
func TestNIST800171_ArchitectureMovesTheDenominator(t *testing.T) {
	t.Run("cli-nist-800-171-denominator/AC-04", func(t *testing.T) {})

	local := ComputeNIST800171(ArchLocalAccounts, 3)
	joined := ComputeNIST800171(ArchDirectoryJoined, 3)

	if joined.Buckets.Assessable >= local.Buckets.Assessable {
		t.Errorf("a joined fleet must have the smaller denominator: joined=%d local=%d",
			joined.Buckets.Assessable, local.Buckets.Assessable)
	}
	// The T3 objectives leave the denominator rather than sitting in it as
	// permanent failures, so the numerator falls too.
	if joined.Satisfied >= local.Satisfied {
		t.Errorf("T3 satisfied objectives must leave the numerator when joined: "+
			"joined=%d local=%d", joined.Satisfied, local.Satisfied)
	}
	// Nothing is lost: what leaves the denominator is accounted as boundary.
	if local.Buckets.Total != joined.Buckets.Total {
		t.Error("total changed with architecture; objectives were dropped, not moved")
	}
}

// @spec cli-nist-800-171-denominator
// @ac AC-04
//
// Any joined host makes the fleet joined. A denominator that ignored the joined
// hosts would report a ceiling the fleet cannot reach.
func TestNIST800171_ArchitectureFromCapabilities(t *testing.T) {
	cases := []struct {
		name string
		caps []map[string]bool
		want Architecture
	}{
		{"no hosts", nil, ArchUnknown},
		{"all local", []map[string]bool{{"directory_joined": false}, {"directory_joined": false}}, ArchLocalAccounts},
		{"one joined among many", []map[string]bool{{"directory_joined": false}, {"directory_joined": true}}, ArchDirectoryJoined},
		{"capability absent entirely", []map[string]bool{{"auditd": true}}, ArchLocalAccounts},
	}
	for _, c := range cases {
		if got := ArchitectureFromCapabilities(c.caps); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// @spec cli-nist-800-171-denominator
// @ac AC-05
//
// DEC-1 decided no single published percentage is honest. Defaulting to the
// local-accounts figure when the architecture is unknown would reintroduce one
// under another name.
func TestNIST800171_StaticShowsBothCeilings(t *testing.T) {
	t.Run("cli-nist-800-171-denominator/AC-05", func(t *testing.T) {})

	r := ComputeNIST800171(ArchUnknown, 0)
	if r.Buckets != nil {
		t.Error("a single denominator was chosen despite an unknown architecture")
	}
	if len(r.Ceilings) != 2 {
		t.Fatalf("want both ceilings, got %d", len(r.Ceilings))
	}
	l, j := r.Ceilings[ArchLocalAccounts], r.Ceilings[ArchDirectoryJoined]
	if l.Buckets.Assessable == j.Buckets.Assessable {
		t.Error("the two ceilings are identical; the architecture distinction has been lost")
	}
	if l.Satisfied == j.Satisfied {
		t.Error("both ceilings report the same numerator; T3 is not being excluded when joined")
	}
}

// @spec cli-nist-800-171-denominator
// @ac AC-06
//
// The embedded catalog is generated from a gitignored corpus, so its integrity
// cannot be checked by reading the repository. These are the invariants that
// would catch a short or stale generation.
func TestNIST800171_EmbeddedCatalogMatchesTheStandard(t *testing.T) {
	t.Run("cli-nist-800-171-denominator/AC-06", func(t *testing.T) {})

	c := nist800171Catalog
	if c.Total != 320 || len(c.Objectives) != 320 {
		t.Fatalf("catalog holds %d objectives (Total=%d), want 320 for Rev 2",
			len(c.Objectives), c.Total)
	}
	if c.Revision != "r2" {
		t.Errorf("revision = %q, want r2; the published claim is pinned to Rev 2", c.Revision)
	}
	if c.SourceDigest == "" {
		t.Error("no source digest; the numbers cannot be tied to the corpus they came from")
	}
	// Per-family counts from NIST SP 800-171A. A short catalog inflates every
	// percentage computed from it.
	want := map[string]int{"3.1": 70, "3.2": 9, "3.3": 29, "3.4": 44, "3.5": 25,
		"3.6": 14, "3.7": 10, "3.8": 15, "3.9": 4, "3.10": 16, "3.11": 9,
		"3.12": 14, "3.13": 41, "3.14": 20}
	got := map[string]int{}
	for id := range c.Objectives {
		parts := id
		if i := len(parts); i > 0 {
			// group is the first two dotted components: "3.1.1[a]" -> "3.1"
			n, dots := 0, 0
			for n < len(parts) {
				if parts[n] == '.' {
					dots++
					if dots == 2 {
						break
					}
				}
				n++
			}
			got[parts[:n]]++
		}
	}
	for g, w := range want {
		if got[g] != w {
			t.Errorf("family %s has %d objectives, want %d", g, got[g], w)
		}
	}
}
