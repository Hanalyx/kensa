package kensa

import (
	"reflect"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// sampleRule builds an api.Rule exercising the read-model projection: CIS
// versioned + NIST flat refs, two implementations (an automated config_set and
// a service restart), platforms, transactional.
func sampleRule() *api.Rule {
	return &api.Rule{
		ID:            "sshd_permit_root_login",
		Title:         "Disable SSH root login",
		Description:   "PermitRootLogin must be no",
		Rationale:     "Direct root login bypasses accountability",
		Severity:      "high",
		Category:      "access-control",
		Tags:          []string{"ssh", "cis"},
		Transactional: true,
		Platforms:     []api.Platform{{Family: "rhel", MinVersion: 9}},
		References: map[string]interface{}{
			"cis":         map[string]interface{}{"rhel9": map[string]interface{}{"section": "5.2.8"}},
			"nist_800_53": []interface{}{"AC-6", "AC-17"},
		},
		Implementations: []api.Implementation{
			{
				Remediation: api.Remediation{Mechanism: "config_set", Restart: "sshd"},
			},
			{
				Remediation: api.Remediation{Mechanism: "config_set_dropin", Reload: "sshd"},
			},
		},
	}
}

// @spec rule-read-model
// @ac AC-01
func TestRuleFrameworkRefs_NormalizesViaMappings(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-01")
	refs := RuleFrameworkRefs(sampleRule())
	// Expect the CIS versioned ref + both NIST flat refs, normalized to the
	// same FrameworkRef tuples the scanner produces.
	want := map[string]string{
		"cis_rhel9":   "5.2.8",
		"nist_800_53": "", // two entries; checked below
	}
	got := map[string][]string{}
	for _, r := range refs {
		got[r.FrameworkID] = append(got[r.FrameworkID], r.ControlID)
	}
	if len(got["cis_rhel9"]) != 1 || got["cis_rhel9"][0] != want["cis_rhel9"] {
		t.Errorf("cis_rhel9 refs = %v, want [5.2.8]", got["cis_rhel9"])
	}
	if len(got["nist_800_53"]) != 2 {
		t.Errorf("nist_800_53 refs = %v, want 2 entries (AC-6, AC-17)", got["nist_800_53"])
	}
	if RuleFrameworkRefs(nil) != nil {
		t.Error("nil rule should yield nil refs")
	}
}

// @spec rule-read-model
// @ac AC-02
func TestFrameworkFromID(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-02")
	cases := []struct {
		id, family, version, label string
	}{
		{"cis_rhel9", "cis", "rhel9", "CIS (RHEL 9)"},
		{"stig_rhel10", "stig", "rhel10", "STIG (RHEL 10)"},
		{"nist_800_53", "nist_800_53", "", "NIST 800-53"},
		{"pci_dss_4", "pci_dss_4", "", "PCI DSS 4.0"},
		// Unknown framework degrades gracefully to the raw id.
		{"acme_framework_v9", "acme_framework_v9", "", "acme_framework_v9"},
	}
	for _, c := range cases {
		got := FrameworkFromID(c.id)
		if got.Family != c.family || got.Version != c.version || got.Label != c.label {
			t.Errorf("FrameworkFromID(%q) = %+v, want family=%q version=%q label=%q",
				c.id, got, c.family, c.version, c.label)
		}
	}
}

// @spec rule-read-model
// @ac AC-03
func TestRuleToSummary_ProjectsFields(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-03")
	s := RuleToSummary(sampleRule())
	if s.ID != "sshd_permit_root_login" || s.Title != "Disable SSH root login" ||
		s.Severity != "high" || s.Category != "access-control" || !s.Transactional {
		t.Errorf("scalar projection wrong: %+v", s)
	}
	if !reflect.DeepEqual(s.Tags, []string{"ssh", "cis"}) {
		t.Errorf("tags = %v", s.Tags)
	}
	if len(s.FrameworkRefs) != 3 {
		t.Errorf("expected 3 framework refs, got %d", len(s.FrameworkRefs))
	}
	if len(s.Platforms) != 1 || s.Platforms[0].Family != "rhel" {
		t.Errorf("platforms = %v", s.Platforms)
	}
	if RuleToSummary(nil).ID != "" {
		t.Error("nil rule should yield zero summary")
	}
}

// @spec rule-read-model
// @ac AC-04
func TestRemediationSummary_DerivesFacts(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-04")
	s := RuleToSummary(sampleRule()).Remediation
	if !s.Available {
		t.Error("expected Available=true for a config_set rule")
	}
	if !reflect.DeepEqual(s.Mechanisms, []string{"config_set", "config_set_dropin"}) {
		t.Errorf("mechanisms = %v (want sorted distinct)", s.Mechanisms)
	}
	if !reflect.DeepEqual(s.RestartsServices, []string{"sshd"}) {
		t.Errorf("restarts = %v (want distinct [sshd])", s.RestartsServices)
	}
	// A manual-only rule is not "available".
	manual := &api.Rule{ID: "m", Implementations: []api.Implementation{{Remediation: api.Remediation{Mechanism: "manual"}}}}
	if RuleToSummary(manual).Remediation.Available {
		t.Error("manual-only rule must have Available=false")
	}
}

// @spec rule-read-model
// @ac AC-05
func TestRemediationSummary_RebootBehavior(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-05")
	// grub mechanism -> boot-param.
	grub := &api.Rule{ID: "g", Implementations: []api.Implementation{{Remediation: api.Remediation{Mechanism: "grub_parameter_set"}}}}
	if got := RuleToSummary(grub).Remediation.RebootBehavior; got != RebootBootParam {
		t.Errorf("grub rule RebootBehavior = %q, want %q", got, RebootBootParam)
	}
	// non-boot mechanism -> none (even for audit_rule_set, whose change-specific
	// reboot cases are deliberately NOT derived here — see the boundary).
	audit := &api.Rule{ID: "a", Implementations: []api.Implementation{{Remediation: api.Remediation{Mechanism: "audit_rule_set"}}}}
	if got := RuleToSummary(audit).Remediation.RebootBehavior; got != RebootNone {
		t.Errorf("audit rule RebootBehavior = %q, want %q", got, RebootNone)
	}
}

// @spec rule-read-model
// @ac AC-06
func TestLoadRuleSummaries_ProductionCorpus(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-06")
	sums, err := LoadRuleSummaries("../../rules", nil, nil)
	if err != nil {
		t.Fatalf("LoadRuleSummaries on production corpus: %v", err)
	}
	if len(sums) != 623 {
		t.Errorf("expected 623 rule summaries, got %d", len(sums))
	}
	// Every summary has an ID and at least the NIST ref (corpus-wide).
	for _, s := range sums {
		if s.ID == "" {
			t.Fatal("summary with empty ID")
		}
		if len(s.FrameworkRefs) == 0 {
			t.Errorf("rule %s projected zero framework refs", s.ID)
		}
	}
}

// @spec rule-read-model
// @ac AC-07
func TestFrameworks_DistinctSorted(t *testing.T) {
	t.Log("// @spec rule-read-model")
	t.Log("// @ac AC-07")
	rules := []*api.Rule{sampleRule(), sampleRule()} // duplicate refs
	fws := Frameworks(rules)
	// Distinct: cis_rhel9 + nist_800_53, sorted by id.
	if len(fws) != 2 {
		t.Fatalf("expected 2 distinct frameworks, got %d: %+v", len(fws), fws)
	}
	if fws[0].ID != "cis_rhel9" || fws[1].ID != "nist_800_53" {
		t.Errorf("frameworks not sorted/distinct: %+v", fws)
	}
}
