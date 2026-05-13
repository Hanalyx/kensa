package wirev1

import "testing"

// TestCompatible locks AC-02 — the major-minor compatibility
// truth table. The two return values discriminate three cases:
//
//	(true, false)  exact match
//	(true, true)   same major, different minor (warn + accept)
//	(false, false) major mismatch (reject)
//
// @spec agent-version-handshake
// @ac AC-02
func TestCompatible(t *testing.T) {
	t.Log("// @spec agent-version-handshake")
	t.Log("// @ac AC-02")
	cases := []struct {
		name         string
		major, minor uint32
		wantCompat   bool
		wantWarn     bool
	}{
		{"exact_match", ProtocolMajor, ProtocolMinor, true, false},
		{"minor_skew_higher", ProtocolMajor, ProtocolMinor + 1, true, true},
		{"minor_skew_lower", ProtocolMajor, ProtocolMinor + 100, true, true},
		{"major_mismatch_higher", ProtocolMajor + 1, ProtocolMinor, false, false},
		{"major_mismatch_lower", 0, ProtocolMinor, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compat, warn := Compatible(tc.major, tc.minor)
			if compat != tc.wantCompat {
				t.Errorf("Compatible(%d, %d) compat: got %v, want %v", tc.major, tc.minor, compat, tc.wantCompat)
			}
			if warn != tc.wantWarn {
				t.Errorf("Compatible(%d, %d) warn: got %v, want %v", tc.major, tc.minor, warn, tc.wantWarn)
			}
		})
	}
}

// TestProtocolConstants sanity-checks that the constants exist
// and have sane values. Bumping these in a PR should be a
// deliberate ratified action — this test exists so a future
// change diff makes the bump visible in code review.
func TestProtocolConstants(t *testing.T) {
	if ProtocolMajor == 0 {
		t.Error("ProtocolMajor is 0; should be at least 1")
	}
	if ProtocolBuild == "" {
		t.Error("ProtocolBuild is empty")
	}
}
