package kensa

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/mappings"
)

// This file is the public, normalized rule read model — the catalog projection
// an external consumer (e.g. OpenWatch's rule browser) needs without parsing
// the heterogeneous raw `references` map or loading the full []*api.Rule just to
// render a list. It publishes derivations Kensa already owns:
//
//   - RuleFrameworkRefs wraps internal/mappings (the SAME normalization the
//     scanner uses on ScanResult.Outcomes), so consumers stop re-parsing the
//     raw References map and drifting from Kensa's framework-id scheme.
//   - RuleSummary / RemediationSummary are a lightweight projection of fields
//     api.Rule already carries.
//
// These types live on pkg/kensa (public-but-not-frozen), not api/, deliberately:
// the read model is a derivation that will grow, and api/ is frozen. Per the
// Kensa/OpenWatch boundary (docs/KENSA_OPENWATCH_BOUNDARY.md §3.3) it carries
// only FACTS Kensa can derive — it intentionally does NOT carry a remediation
// risk level (that is operator policy, computed by the consumer) or a blanket
// RequiresReboot boolean (not derivable for the change-specific cases; see
// RebootBehavior).

// FrameworkRef is re-exported from api for the read model's convenience; it is
// the same type the scanner puts on every outcome.
type FrameworkRef = api.FrameworkRef

// Framework is a normalized descriptor for one compliance framework (or
// framework-version), so consumers render labels and group by family
// consistently instead of hardcoding prefix strings.
type Framework struct {
	// ID is the canonical framework id exactly as it appears on
	// [api.FrameworkRef.FrameworkID] — e.g. "cis_rhel9", "nist_800_53".
	ID string
	// Family is the framework family without the version discriminator —
	// e.g. "cis", "stig", "nist_800_53".
	Family string
	// Version is the version/profile discriminator for versioned frameworks
	// (e.g. "rhel9"), or "" for unversioned flat-list frameworks.
	Version string
	// Label is a human display string, e.g. "CIS (RHEL 9)" or "NIST 800-53".
	Label string
}

// frameworkFamilies maps a framework family key to its human label. Kensa owns
// the rule-schema framework vocabulary, so this is the canonical label source;
// adding a framework to the corpus means adding its label here. Unknown
// families degrade gracefully (see FrameworkFromID).
var frameworkFamilies = map[string]string{
	"cis":           "CIS",
	"stig":          "STIG",
	"nist_800_53":   "NIST 800-53",
	"pci_dss_4":     "PCI DSS 4.0",
	"srg":           "SRG",
	"iso27001_2022": "ISO 27001:2022",
	"cmmc_l2":       "CMMC Level 2",
	"hipaa":         "HIPAA",
}

// FrameworkFromID parses a framework id (as found on
// [api.FrameworkRef.FrameworkID]) into its normalized [Framework] descriptor.
// It is a pure function — no corpus needed — so a consumer can render any
// FrameworkRef it holds. Unknown families degrade gracefully: Family is the
// whole id, Version is empty, and Label is the id verbatim, so a framework
// added to rule YAML before this map is updated still renders (just without a
// pretty label) rather than breaking the consumer.
func FrameworkFromID(id string) Framework {
	// Match the longest known family first so families that are prefixes of
	// others (none today, but future-proof) resolve correctly.
	fams := make([]string, 0, len(frameworkFamilies))
	for f := range frameworkFamilies {
		fams = append(fams, f)
	}
	sort.Slice(fams, func(i, j int) bool { return len(fams[i]) > len(fams[j]) })

	for _, fam := range fams {
		switch {
		case id == fam:
			return Framework{ID: id, Family: fam, Version: "", Label: frameworkFamilies[fam]}
		case strings.HasPrefix(id, fam+"_"):
			version := strings.TrimPrefix(id, fam+"_")
			return Framework{
				ID:      id,
				Family:  fam,
				Version: version,
				Label:   frameworkFamilies[fam] + " (" + humanizeVersion(version) + ")",
			}
		}
	}
	// Unknown framework: degrade to the raw id.
	return Framework{ID: id, Family: id, Version: "", Label: id}
}

// humanizeVersion renders a version discriminator for display. It special-cases
// the "rhelN" OS-version form the corpus uses ("rhel9" -> "RHEL 9"); anything
// else is returned verbatim.
func humanizeVersion(v string) string {
	if rest, ok := strings.CutPrefix(v, "rhel"); ok {
		if _, err := strconv.Atoi(rest); err == nil {
			return "RHEL " + rest
		}
	}
	return v
}

// RuleFrameworkRefs returns the rule's compliance-framework references in
// normalized [api.FrameworkRef] form. It is the public entry point to the SAME
// normalization the scanner applies to every outcome
// (internal/mappings.RefsFromReferences), so a consumer reads the typed tuple
// instead of re-parsing the heterogeneous raw [api.Rule.References] map and
// re-deriving Kensa's framework-id scheme. Nil rule yields nil.
func RuleFrameworkRefs(r *api.Rule) []api.FrameworkRef {
	if r == nil {
		return nil
	}
	return mappings.RefsFromReferences(r.References)
}

// Frameworks returns the distinct frameworks referenced across a set of rules,
// each as a normalized [Framework], sorted by id. Useful for building a catalog
// filter ("show me the frameworks this corpus covers") without the consumer
// deduping framework ids itself.
func Frameworks(rules []*api.Rule) []Framework {
	seen := map[string]bool{}
	var out []Framework
	for _, r := range rules {
		for _, ref := range RuleFrameworkRefs(r) {
			if !seen[ref.FrameworkID] {
				seen[ref.FrameworkID] = true
				out = append(out, FrameworkFromID(ref.FrameworkID))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RuleSummary is the lightweight catalog projection of an [api.Rule] — the
// fields a rule browser shows in a list/detail view, with the framework refs
// normalized and the remediation summarized. It deliberately omits the heavy
// Implementations/Check internals; load those via [LoadRules] when a consumer
// actually needs to scan or remediate.
type RuleSummary struct {
	ID            string
	Title         string
	Description   string
	Rationale     string
	Severity      string
	Category      string
	Tags          []string
	FrameworkRefs []api.FrameworkRef
	Platforms     []api.Platform
	// Transactional reports whether the rule's apply path is a capturable,
	// atomic transaction (vs. a non-capturable best-effort or staged change).
	Transactional bool
	Remediation   RemediationSummary
}

// RemediationSummary is the host-independent, FACTUAL summary of a rule's
// remediation — what an operator wants to know before remediating, derived
// only from data the rule already carries. Per the Kensa/OpenWatch boundary it
// carries no risk level (operator policy) and no blanket RequiresReboot (not
// derivable; see RebootBehavior).
type RemediationSummary struct {
	// Available reports whether the rule has an automated (non-manual)
	// remediation in any implementation.
	Available bool
	// Mechanisms are the distinct remediation mechanisms across all
	// implementations (e.g. "config_set", "service_masked"), sorted. Host-
	// independent: a host selects one implementation, but the catalog row has
	// no host, so all candidate mechanisms are listed.
	Mechanisms []string
	// RestartsServices are the distinct services the remediation reloads or
	// restarts (from the rule's Reload/Restart hooks), sorted. A signal that
	// applying the rule will bounce a service.
	RestartsServices []string
	// RebootBehavior is the derivable reboot signal:
	//   - "boot-param": the remediation stages a boot parameter (grub),
	//     PENDING until the operator reboots — Kensa models this directly.
	//   - "none": no reboot is inherent to the mechanism.
	// This is NOT a complete "requires reboot" answer: a few rules require a
	// reboot because of the SPECIFIC change (e.g. the auditd `-e 2` immutable
	// flag, enabling SELinux from disabled) using mechanisms that hundreds of
	// non-reboot rules also use. Deriving reboot from mechanism there would be
	// a dangerous false-negative; a complete signal needs an authored
	// `requires_reboot:` rule-schema field (deferred). See
	// docs/KENSA_OPENWATCH_BOUNDARY.md §3.3.
	RebootBehavior string
}

// Reboot behavior values for [RemediationSummary.RebootBehavior].
const (
	RebootNone      = "none"
	RebootBootParam = "boot-param"
)

// bootParamMechanisms are the remediation mechanisms that stage a boot
// parameter (PENDING until reboot).
var bootParamMechanisms = map[string]bool{
	"grub_parameter_set":    true,
	"grub_parameter_remove": true,
}

// RuleToSummary projects an [api.Rule] into its [RuleSummary]. Nil yields a
// zero RuleSummary.
func RuleToSummary(r *api.Rule) RuleSummary {
	if r == nil {
		return RuleSummary{}
	}
	return RuleSummary{
		ID:            r.ID,
		Title:         r.Title,
		Description:   r.Description,
		Rationale:     r.Rationale,
		Severity:      r.Severity,
		Category:      r.Category,
		Tags:          r.Tags,
		FrameworkRefs: RuleFrameworkRefs(r),
		Platforms:     r.Platforms,
		Transactional: r.Transactional,
		Remediation:   remediationSummary(r),
	}
}

// remediationSummary derives the factual remediation summary from a rule's
// implementations.
func remediationSummary(r *api.Rule) RemediationSummary {
	mechSet := map[string]bool{}
	svcSet := map[string]bool{}
	available := false
	reboot := RebootNone

	for _, impl := range r.Implementations {
		m := impl.Remediation.Mechanism
		if m != "" {
			mechSet[m] = true
			if m != "manual" {
				available = true
			}
			if bootParamMechanisms[m] {
				reboot = RebootBootParam
			}
		}
		for _, svc := range []string{impl.Remediation.Restart, impl.Remediation.Reload} {
			if svc != "" {
				svcSet[svc] = true
			}
		}
	}

	return RemediationSummary{
		Available:        available,
		Mechanisms:       sortedKeys(mechSet),
		RestartsServices: sortedKeys(svcSet),
		RebootBehavior:   reboot,
	}
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LoadRuleSummaries loads the rule corpus and projects each rule to a
// [RuleSummary] — the catalog read path. It reuses [LoadRules] for
// path-resolution, variable substitution, and strict parsing, so the same
// corpus a scan would run is what the catalog shows. Arguments match LoadRules.
func LoadRuleSummaries(dir string, paths []string, vars map[string]string) ([]RuleSummary, error) {
	rules, err := LoadRules(dir, paths, vars)
	if err != nil {
		return nil, err
	}
	out := make([]RuleSummary, len(rules))
	for i, r := range rules {
		out[i] = RuleToSummary(r)
	}
	return out, nil
}
