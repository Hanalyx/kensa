package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// deferredDuplicateCites is the ratcheting allowlist for the cross-rule
// duplicate-citation gate (v0.7.3): a framework control (STIG vuln_id or CIS
// section, per OS) that is legitimately, or not-yet-resolvably, cited by more
// than one rule. Keyed by "framework|os|control" → a written reason.
//
// A duplicate cite is a cross-rule bug: two rules both claim to satisfy one
// control, so coverage double-counts and a scan reports the control as covered
// twice (the banner-rule dedup, the faillock pairing). The fix is to merge the
// rules, re-home the cite, or — only for a genuine same-control-two-mechanisms
// case — keep both with a written reason here.
//
// This list MUST ONLY SHRINK. Removing an entry (after resolving the dup) is
// the intended direction; a brand-new duplicate means a cross-rule mis-cite
// slipped in and CI must fail.
var deferredDuplicateCites = map[string]string{
	"cis|rhel8|6.3.3.9":      "KEEP (compound control): audit-perm-mod, audit-unsuccessful-perm, audit-xattr-changes split the syscalls of one CIS RHEL8 v4.0.0 DAC-permission-modification recommendation (chmod/chown, chmod+EACCES, setxattr/removexattr) across three rules; re-homed here from mis-numbered 6.3.3.13/6.3.3.21 (file-deletion / audit-immutable) after benchmark verification",
	"cis|rhel9|6.3.3.9":      "KEEP (compound control): audit-perm-mod, audit-unsuccessful-perm, audit-xattr-changes split the syscalls of one CIS RHEL9 v2.0.0 DAC-permission-modification recommendation across three rules; re-homed from mis-numbered 6.3.3.13/6.3.3.20 after benchmark verification",
	"cis|rhel8|5.3.3.1.1":    "KEEP: pam-faillock-deny cites this CIS RHEL8 v4.0.0 lockout recommendation; fail_interval has no independently-scored CIS recommendation (it is a pam_faillock module parameter listed only under the parent 5.3.3.1 overview), so pam-faillock-fail-interval is homed to the closest scored recommendation — the deny lockout rec — rather than left mis-cited on the 5.4.2.x root-account block",
	"cis|rhel9|5.3.3.1.1":    "KEEP: pam-faillock-deny already cites this CIS RHEL9 v2.0.0 lockout recommendation; fail_interval has no independently-scored CIS recommendation (a pam_faillock module parameter under the parent 5.3.3.1 overview), so pam-faillock-fail-interval is homed to the closest scored recommendation rather than left mis-cited on the 5.4.2.3 root-account section",
	"cis|rhel10|5.3.2.1.1":   "KEEP: pam-faillock-deny already cites this CIS RHEL10 v1.0.1 lockout recommendation; fail_interval has no independently-scored CIS recommendation (a pam_faillock module parameter under the parent 5.3.2.1 overview), so pam-faillock-fail-interval is homed to the closest scored recommendation rather than left mis-cited on the 5.4.2.3 root-account section",
	"cis|rhel10|5.3.2.2.3":   "KEEP (compound control): the five pam-pwquality complexity rules (dcredit, ucredit, lcredit, ocredit, minclass) jointly satisfy one CIS RHEL10 v1.0.1 section; re-homed from the mis-numbered 5.4.1.x block after benchmark verification (5.3.2.2.2=length, 5.3.2.2.3=complexity)",
	"cis|rhel8|5.3.3.2.3":    "KEEP (compound control): the four pam-pwquality credit rules (dcredit, ucredit, lcredit, ocredit) jointly satisfy one CIS RHEL8 v4.0.0 section, which rhel9 already cites identically for the same rules; re-homed here from the mis-numbered 5.4.1.x block after benchmark verification",
	"cis|rhel10|2.1.21":      "KEEP (compound control): mta-local-only (port check via ss) and postfix-local-only (inet_interfaces config check) verify the single CIS rhel10 MTA-local-only recommendation two ways; postfix-local-only additionally carries STIG V-230550, so both are retained",
	"cis|rhel10|2.3.1":       "KEEP (compound control): chrony-installed (package) and chrony-enabled (service) jointly satisfy the single CIS rhel10 \"time synchronization is in use\" recommendation (2.3.1 is the only time-sync section; it requires chrony installed AND active), split across two rules by mechanism",
	"cis|rhel8|1.4.2":        "KEEP (compound control): grub-config-permissions and grub-user-cfg-permissions both harden CIS RHEL8 v4.0.0 1.4.2 \"access to bootloader config\" — there is no separate user.cfg section (1.4.1=bootloader password, 1.4.2=access to the bootloader config files), so both grub config files legitimately map to 1.4.2",
	"cis|rhel10|1.4.2":       "KEEP (compound control): same as rhel8 — grub-config-permissions and grub-user-cfg-permissions both harden CIS RHEL10 v1.0.1 1.4.2 \"access to bootloader config\"; the benchmark has only 1.4.1 (bootloader password) and 1.4.2 (access to the config files), no separate user.cfg section, so both grub config files legitimately map to 1.4.2",
	"cis|rhel8|2.1.23":       "KEEP (compound control): mta-local-only (port check via ss) and postfix-local-only (inet_interfaces config check) verify the single CIS rhel8 MTA-local-only recommendation two ways; postfix-local-only additionally carries STIG V-230550, so both are retained",
	"cis|rhel8|2.3.1":        "KEEP (compound control): chrony-installed (package) and chrony-enabled (service) jointly satisfy the single CIS rhel8 \"time synchronization is in use\" recommendation (2.3.1 is the only time-sync section; it requires chrony installed AND active), split across two rules by mechanism",
	"cis|rhel9|2.1.21":       "KEEP (compound control): mta-local-only (port check via ss) and postfix-local-only (inet_interfaces config check) verify the single CIS rhel9 MTA-local-only recommendation two ways; postfix-local-only additionally carries STIG V-230550, so both are retained",
	"cis|rhel9|2.3.1":        "KEEP (compound control): chrony-installed (package) and chrony-enabled (service) jointly satisfy the single CIS rhel9 \"time synchronization is in use\" recommendation (2.3.1 is the only time-sync section; it requires chrony installed AND active), split across two rules by mechanism",
	"cis|rhel9|4.1.2":        "KEEP (compound control): firewall-single-utility (the 4.1.2 check) and nftables-service-disabled (disables nftables so firewalld is the single utility) both serve CIS RHEL9 v2.0.0 4.1.2 \"a single firewall configuration utility is in use\"; nftables-service-disabled is the enforcement mechanism for the single-utility requirement",
	"cis|rhel9|5.3.3.2.3":    "KEEP (compound control): the five pam-pwquality complexity rules (dcredit, ucredit, lcredit, ocredit, minclass) jointly satisfy one CIS RHEL9 v2.0.0 section; all five already correctly cite it (this is the correctly-numbered template the rhel8/rhel10 re-homes matched)",
	"stig|ubuntu22|V-260526": "KEEP (authoritative, XCCDF-verified): this STIG control requires BOTH the PermitEmptyPasswords and PermitUserEnvironment directives both disabled (its check greps for both); the two rules (ssh-deny-empty-passwords, ssh-disable-user-environment) each implement one setting and both correctly cite it",
	"stig|ubuntu24|V-270717": "KEEP (authoritative, XCCDF-verified): this STIG control requires BOTH the PermitEmptyPasswords and PermitUserEnvironment directives both disabled (its check greps for both); the two rules (ssh-deny-empty-passwords, ssh-disable-user-environment) each implement one setting and both correctly cite it",
}

// dupRuleRefsDoc parses just the id + references block of a rule for the gate.
type dupRuleRefsDoc struct {
	ID         string                 `yaml:"id"`
	References map[string]interface{} `yaml:"references"`
}

// controlKeyField names the per-OS control-identity field for each framework
// whose controls are meant to be satisfied by exactly one rule. Only these
// frameworks are gated. Every other framework in the corpus is deliberately out
// of scope, on principle: a control is not one-rule-per-control there. That
// covers the flat many-to-many mappings (nist_800_53 — many rules legitimately
// cite AC-3, CM-7, ... so duplicate 800-53 cites are expected, not a bug) and
// the sparse cross-reference labels (pci_dss_4, srg) that are metadata tags, not
// a per-OS benchmark control identity. Adding a framework here opts it into the
// duplicate gate.
var controlKeyField = map[string]string{
	"stig": "vuln_id",
	"cis":  "section",
}

// TestCrossRuleDuplicateCitations enforces the cross-rule duplicate-cite
// invariant: no framework control (STIG vuln_id / CIS section, per OS) is cited
// by more than one rule, except the ratcheting deferredDuplicateCites allowlist.
// A single grouped rule (schema v1.1 list form) citing many controls is not a
// duplicate — each control is still cited by exactly one rule — so grouped rules
// self-exempt; a grouped rule overlapping a standalone rule's cite IS flagged.
//
// @spec catalog-coverage-crosswalk
// @ac AC-12
func TestCrossRuleDuplicateCitations(t *testing.T) {
	t.Log("// @spec catalog-coverage-crosswalk")
	t.Log("// @ac AC-12")

	rulesDir := filepath.Join("..", "..", "rules")
	cites, err := collectCiteMap(rulesDir)
	if err != nil {
		t.Fatalf("walk rules: %v", err)
	}

	usedAllow := map[string]bool{}
	var violations []string
	for _, key := range duplicateKeys(cites) {
		if _, ok := deferredDuplicateCites[key]; ok {
			usedAllow[key] = true
			continue
		}
		rules := sortedKeys(cites[key])
		violations = append(violations, fmt.Sprintf("%s cited by %d rules: %s",
			key, len(rules), strings.Join(rules, ", ")))
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("duplicate framework-control citation: %s", v)
	}
	if len(violations) > 0 {
		t.Logf("%d control(s) cited by >1 rule — merge the rules, re-home the cite, "+
			"or (only for a genuine same-control-two-mechanisms case) add to "+
			"deferredDuplicateCites with a written reason", len(violations))
	}

	// The allowlist may only shrink: a stale entry (the dup was resolved) must be
	// removed so the list reflects reality.
	for key := range deferredDuplicateCites {
		if !usedAllow[key] {
			t.Errorf("stale deferredDuplicateCites entry %q: no longer a duplicate — remove it (the allowlist may only shrink)", key)
		}
	}
}

// TestCrossRuleDuplicateCitations_GroupedForm locks the grouped-rule semantics
// of the gate (schema v1.1 list form) against synthetic fixtures: (a) one
// grouped rule citing many controls does NOT false-flag, and (b) a grouped rule
// overlapping a standalone rule's cite IS flagged.
//
// @spec catalog-coverage-crosswalk
// @ac AC-12
func TestCrossRuleDuplicateCitations_GroupedForm(t *testing.T) {
	t.Log("// @spec catalog-coverage-crosswalk")
	t.Log("// @ac AC-12")

	dir := t.TempDir()
	// grouped-only: one rule cites three STIG controls via the list form.
	writeFixtureRule(t, dir, "grouped.yml", `id: grouped-audit
references:
  stig:
    rhel9:
      - vuln_id: "V-100001"
      - vuln_id: "V-100002"
      - vuln_id: "V-100003"
`)
	// standalone that does NOT overlap the grouped rule.
	writeFixtureRule(t, dir, "standalone-clean.yml", `id: standalone-clean
references:
  stig:
    rhel9:
      vuln_id: "V-100009"
`)
	// standalone that DOES overlap the grouped rule on V-100002.
	writeFixtureRule(t, dir, "standalone-overlap.yml", `id: standalone-overlap
references:
  stig:
    rhel9:
      vuln_id: "V-100002"
`)

	cites, err := collectCiteMap(dir)
	if err != nil {
		t.Fatalf("collectCiteMap: %v", err)
	}
	dups := duplicateKeys(cites)

	// (a) The grouped rule's non-overlapped controls must NOT be flagged.
	for _, k := range []string{"stig|rhel9|V-100001", "stig|rhel9|V-100003", "stig|rhel9|V-100009"} {
		if contains(dups, k) {
			t.Errorf("grouped/standalone control %q false-flagged as duplicate", k)
		}
	}
	// (b) The grouped↔standalone overlap on V-100002 MUST be flagged, naming both rules.
	overlap := "stig|rhel9|V-100002"
	if !contains(dups, overlap) {
		t.Fatalf("grouped rule overlapping a standalone cite on %q was NOT flagged", overlap)
	}
	got := sortedKeys(cites[overlap])
	want := []string{"grouped-audit", "standalone-overlap"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("overlap %q rules = %v, want %v", overlap, got, want)
	}
}

// collectCiteMap walks a rules directory and returns
// "framework|os|control" -> set of citing rule IDs, for the frameworks whose
// controls are meant to be satisfied by exactly one rule (controlKeyField).
func collectCiteMap(rulesDir string) (map[string]map[string]bool, error) {
	cites := map[string]map[string]bool{}
	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var d dupRuleRefsDoc
		if err := yaml.Unmarshal(data, &d); err != nil {
			return nil // not a single-doc rule; skip (validator covers parse errors)
		}
		if d.ID == "" {
			return nil
		}
		for framework, field := range controlKeyField {
			fw, ok := d.References[framework].(map[string]interface{})
			if !ok {
				continue
			}
			for osKey, v := range fw {
				for _, entry := range asList(v) {
					control := dupCiteStr(entry[field])
					if control == "" {
						continue
					}
					key := framework + "|" + osKey + "|" + control
					if cites[key] == nil {
						cites[key] = map[string]bool{}
					}
					cites[key][d.ID] = true
				}
			}
		}
		return nil
	})
	return cites, err
}

// duplicateKeys returns the sorted control keys cited by more than one rule.
func duplicateKeys(cites map[string]map[string]bool) []string {
	var keys []string
	for key, ruleSet := range cites {
		if len(ruleSet) >= 2 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// writeFixtureRule writes a single rule YAML fixture into dir for the gate tests.
func writeFixtureRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
}

// dupCiteStr normalizes a control-id value (string, or a YAML-parsed number like
// a CIS section 3.3) to a trimmed string for stable keying.
func dupCiteStr(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}
