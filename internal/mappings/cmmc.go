package mappings

import (
	"regexp"
	"sort"
	"strings"
)

// CMMCLevel2Framework is the framework id CMMC Level 2 practices are filed
// under. It has been registered in the catalog since framework labels landed.
const CMMCLevel2Framework = "cmmc_l2"

// cmmcFamilyPrefix maps a NIST SP 800-171 requirement group to the family
// prefix CMMC uses in a practice identifier.
//
// These are not remembered or inferred. They were extracted from
// 32 CFR 170 (as of 2026-07-28) by reading every practice identifier the
// regulation names and grouping them by requirement: all 14 groups appear, and
// no group carries more than one prefix. The derivation is in
// scripts/gen_cmmc_refs.py so the source can be re-run rather than trusted.
var cmmcFamilyPrefix = map[string]string{
	"3.1":  "AC", // access control
	"3.2":  "AT", // awareness and training
	"3.3":  "AU", // audit and accountability
	"3.4":  "CM", // configuration management
	"3.5":  "IA", // identification and authentication
	"3.6":  "IR", // incident response
	"3.7":  "MA", // maintenance
	"3.8":  "MP", // media protection
	"3.9":  "PS", // personnel security
	"3.10": "PE", // physical protection
	"3.11": "RA", // risk assessment
	"3.12": "CA", // security assessment
	"3.13": "SC", // system and communications protection
	"3.14": "SI", // system and information integrity
}

// requirementOf strips an 800-171A assessment objective down to its
// requirement: "3.1.7[d]" -> "3.1.7". A bare requirement is returned unchanged,
// which is the correct citation for the eleven requirements whose assessment
// objective is a single unlettered sentence.
var objectiveSuffix = regexp.MustCompile(`\[[a-z]\]$`)

func requirementOf(ref string) string {
	return objectiveSuffix.ReplaceAllString(strings.TrimSpace(ref), "")
}

// CMMCLevel2Practices derives the CMMC Level 2 practice identifiers implied by
// a set of reviewed NIST SP 800-171 Rev 2 references.
//
// This is a renaming, not a crosswalk. 32 CFR 170 defines Level 2 as the 110
// Rev 2 requirements, one for one, so a practice id follows from a reviewed
// requirement citation with no new judgment and no new claim. That is the only
// reason deriving it mechanically is legitimate; the 800-53 to 800-171 hop is
// many-to-many and produces candidates a human must review.
//
// Objective-level refs collapse to one practice per requirement. Kensa cites
// 800-171 at assessment-objective granularity because that is what a C3PAO
// scores, but CMMC practices exist only at requirement granularity, so
// "3.1.7[a]" and "3.1.7[d]" both yield "AC.L2-3.1.7", once. Emitting one per
// objective would multiply a single claim.
//
// A ref this cannot parse is skipped rather than guessed. The result is sorted
// and deduplicated, so it is stable to diff.
func CMMCLevel2Practices(nist800171Refs []string) []string {
	seen := make(map[string]bool, len(nist800171Refs))
	for _, ref := range nist800171Refs {
		req := requirementOf(ref)
		parts := strings.Split(req, ".")
		if len(parts) != 3 {
			continue
		}
		prefix, ok := cmmcFamilyPrefix[parts[0]+"."+parts[1]]
		if !ok {
			continue
		}
		seen[prefix+".L2-"+req] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// CMMCFamilyGroups returns the requirement groups the family map covers. Used
// by validation to assert the map is complete before anything is emitted from
// it.
func CMMCFamilyGroups() []string {
	out := make([]string, 0, len(cmmcFamilyPrefix))
	for g := range cmmcFamilyPrefix {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
