package detect

import (
	"strconv"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// elFamilies are the Enterprise-Linux /etc/os-release IDs treated as one family
// when a platform entry opts into Derivatives. "rhel" and "redhat" are also
// aliased unconditionally (some corpora use "redhat").
var elFamilies = map[string]bool{
	"rhel": true, "redhat": true, "centos": true, "rocky": true,
	"almalinux": true, "alma": true, "ol": true, "oracle": true,
}

// MajorVersion returns the leading integer of the OS VERSION_ID — "9.6" -> 9,
// "22.04" -> 22, "8" -> 8. It returns 0 when Version is empty or has no leading
// digits; callers treat 0 as "version unknown" and do not version-gate.
func (o OSInfo) MajorVersion() int {
	end := 0
	for end < len(o.Version) && o.Version[end] >= '0' && o.Version[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(o.Version[:end])
	if err != nil {
		return 0
	}
	return n
}

// AppliesTo reports whether a rule scoped to the given platforms should be
// evaluated on a host described by o.
//
// It is deliberately lenient — it returns true ("applies") when:
//   - platforms is empty (the rule declares no OS constraint), or
//   - o.Family is empty (the host OS could not be detected): a caller MUST NOT
//     silently skip rules on an undetectable host.
//
// Otherwise the rule applies iff some platform entry matches the host family
// (with rhel/redhat aliasing, and EL-family equivalence when Derivatives is
// set) AND the host major version is within [MinVersion, MaxVersion] (each
// bound ignored when zero). A zero/unknown host major version skips the version
// bounds, so a family match alone suffices.
func AppliesTo(platforms []api.Platform, o OSInfo) bool {
	if len(platforms) == 0 || o.Family == "" {
		return true
	}
	host := strings.ToLower(o.Family)
	v := o.MajorVersion()
	for _, p := range platforms {
		if !familyMatches(strings.ToLower(p.Family), host, p.Derivatives) {
			continue
		}
		if v != 0 {
			if p.MinVersion != 0 && v < p.MinVersion {
				continue
			}
			if p.MaxVersion != 0 && v > p.MaxVersion {
				continue
			}
		}
		return true
	}
	return false
}

// familyMatches reports whether a rule's platform family covers a host family.
func familyMatches(ruleFam, hostFam string, derivatives bool) bool {
	if ruleFam == hostFam {
		return true
	}
	// rhel/redhat are the same family under different os-release IDs.
	rhelLike := func(f string) bool { return f == "rhel" || f == "redhat" }
	if rhelLike(ruleFam) && rhelLike(hostFam) {
		return true
	}
	// Derivatives: an EL-family rule covers EL-family hosts.
	if derivatives && elFamilies[ruleFam] && elFamilies[hostFam] {
		return true
	}
	return false
}
