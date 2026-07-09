package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// deferredCheckCiteMismatches is the ratcheting allowlist for the check-vs-cite
// heuristic (v0.7.3 item 4): a rule whose own check reads a subject DISJOINT from
// the subject its cited STIG control's check/fix text is about. Keyed by
// "ruleID|os|vuln_id" → a written reason.
//
// This is a HEURISTIC (warn-tier, STIG-only for v1): CIS carries no check prose
// (copyrighted) so it cannot be cross-checked this way. A flag means "the rule's
// check target and the control's command-extracted target do not overlap" — the
// signal that caught sudo-reauth-not-disabled and ssh-client-alive-count-max. It
// can be a real mis-cite OR a heuristic false positive (the rule and control name
// the same subject in ways the extractors don't unify). Both are allowlisted with
// a reason; the list may only shrink. A NEW disjoint pair fails CI, so the signal
// ratchets toward clean and can be promoted to a hard invariant later.
var deferredCheckCiteMismatches = map[string]string{
	"aide-installed|rhel10|V-280977":               "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"audit-config-dir-group|rhel8|V-230401":        "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"audit-config-dir-owner|rhel8|V-230400":        "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"audit-log-dir-permissions|rhel8|V-230399":     "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"ctrl-alt-del-disabled|rhel9|V-257784":         "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"gdm-dconf-database-current|rhel9|V-258028":    "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"gdm-removed|rhel8|V-230553":                   "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"gpgcheck-enabled|rhel9|V-257819":              "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"mount-boot-efi-nosuid|rhel8|V-244530":         "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"mount-boot-efi-nosuid|rhel9|V-257862":         "HEURISTIC FALSE-POSITIVE (triaged W5): V-257862 = \"prevent setuid/setgid execution on /boot/efi\"; the rule's `nosuid` mount_option on /boot/efi is exactly the enforcing mechanism. Same control+title as the allowlisted rhel8 V-244530; the heuristic doesn't equate nosuid with no-setuid/setgid.",
	"mount-home-noexec|rhel8|V-230302":             "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"mount-home-nosuid|rhel8|V-230299":             "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pam-faillock-audit|rhel8|V-230342":            "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pam-faillock-even-deny-root|rhel8|V-230344":   "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-audispd-plugins-present|rhel8|V-230477":   "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-fapolicyd-present|rhel8|V-230523":         "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-firewalld-present|rhel8|V-230505":         "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-nfs-utils-absent|ubuntu22|V-279937":       "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-nfs-utils-absent|ubuntu24|V-279938":       "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-opensc-present|rhel8|V-230273":            "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-openssh-server-present|rhel8|V-230526":    "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-openssh-server-present|rhel8|V-244549":    "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-openssh-server-present|ubuntu22|V-260523": "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-openssh-server-present|ubuntu24|V-270665": "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"pkg-usbguard-present|rhel8|V-244547":          "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"ssh-log-level|rhel9|V-257982":                 "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"sshd-config-permissions|rhel9|V-257997":       "v0.7.3 item-4 heuristic seed: rule check target disjoint from cited control target; pending triage (real mis-cite or extractor false-positive)",
	"sshd-config-permissions|rhel10|V-281047":      "HEURISTIC FALSE-POSITIVE (triaged W6): V-281047 = sshd_config group-owned by root; the rule stats /etc/ssh/sshd_config for %U %G %a (owner+group+mode). Same rule/check as the allowlisted rhel9 V-257997/998. The heuristic doesn't unify the rule's `stat` with the control's ls/stat prose.",
	"sshd-config-permissions|rhel10|V-281048":      "HEURISTIC FALSE-POSITIVE (triaged W6): V-281048 = sshd_config owned by root; the rule stats /etc/ssh/sshd_config for owner=root (+group+mode). Same rule/check as the allowlisted rhel9 V-257997/998.",
	"sshd-config-permissions|rhel10|V-281262":      "HEURISTIC FALSE-POSITIVE (triaged W6): V-281262 = sshd_config file permissions not modified (mode); the rule stats /etc/ssh/sshd_config for mode 0600 (+owner+group). Same rule/check as the allowlisted rhel9 V-257997/998.",
	"ssh-log-level|rhel10|V-281115":                "HEURISTIC FALSE-POSITIVE (triaged W6): V-281115 = log SSH connection attempts (LogLevel VERBOSE in sshd_config); the rule asserts LogLevel=VERBOSE via `sshd -T`. Same subject; the heuristic doesn't unify `sshd -T | grep loglevel` with the control's `sshd -dd | grep loglevel /etc/ssh/sshd_config`.",
	"sshd-config-permissions|rhel9|V-257998":       "HEURISTIC FALSE-POSITIVE (triaged W5): V-257998 = sshd config OWNED by root; the rule asserts owner=root (+group+mode) on sshd_config — same rule/check as the already-allowlisted V-257997 (255105 perms), grouped 255110.",
	"xorg-removed|rhel9|V-257837":                  "HEURISTIC FALSE-POSITIVE (triaged W5): V-257837 (215070) STIG check is literally `dnf list --installed xorg-x11-server-common`; the rule's package_state xorg-x11-server* absent is exactly that. The heuristic doesn't equate the xorg package with the 'graphical display manager' title.",
}

// TestCheckVsCiteHeuristic enforces the check-vs-cite invariant for STIG-cited
// rules: a rule's check target must overlap its cited control's check/fix target,
// except the ratcheting deferredCheckCiteMismatches allowlist. Only rules and
// controls that BOTH yield a structured target are judged (precision-first: an
// unextractable check or control is skipped, never guessed).
//
// @spec catalog-coverage-crosswalk
// @ac AC-13
func TestCheckVsCiteHeuristic(t *testing.T) {
	t.Log("// @spec catalog-coverage-crosswalk")
	t.Log("// @ac AC-13")

	root := filepath.Join("..", "..")
	srcDir := filepath.Join(root, "catalog", "sources")
	rulesDir := filepath.Join(root, "rules")

	// Build os -> (vuln_id -> check/fix text) from the vendored XCCDF sources.
	raw, err := os.ReadFile(filepath.Join(srcDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifestDoc
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	vulnToCheck := map[string]map[string]string{}
	for _, b := range m.Stig {
		_, controls, err := parseSTIG(filepath.Join(srcDir, b.File))
		if err != nil {
			t.Fatalf("parseSTIG %s: %v", b.File, err)
		}
		cm := map[string]string{}
		for _, c := range controls {
			cm[c.ControlID] = c.CheckText
		}
		vulnToCheck[b.OS] = cm
	}

	usedAllow := map[string]bool{}
	var flags []string
	err = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var rr ruleRefs
		if err := yaml.Unmarshal(data, &rr); err != nil || rr.ID == "" {
			return nil
		}
		ruleTgts := ruleTargetsOf(rr)
		if len(ruleTgts) == 0 {
			return nil // rule's check yields no structured target — cannot judge
		}
		stig, ok := rr.References["stig"].(map[string]interface{})
		if !ok {
			return nil
		}
		for osKey, v := range stig {
			cm, known := vulnToCheck[osKey]
			if !known {
				continue
			}
			for _, entry := range asList(v) {
				vid := dupCiteStr(entry["vuln_id"])
				if vid == "" {
					continue
				}
				checkText, has := cm[vid]
				if !has {
					continue
				}
				controlTgts := ExtractCommandTargets(checkText)
				if len(controlTgts) == 0 {
					continue // control prose yields no structured target — cannot judge
				}
				if targetsOverlap(ruleTgts, controlTgts) {
					continue
				}
				key := rr.ID + "|" + osKey + "|" + vid
				if _, ok := deferredCheckCiteMismatches[key]; ok {
					usedAllow[key] = true
					continue
				}
				flags = append(flags, key)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules: %v", err)
	}

	sort.Strings(flags)
	for _, f := range flags {
		t.Errorf("check-vs-cite mismatch: %s (rule check target is disjoint from the cited control's target)", f)
	}
	if len(flags) > 0 {
		t.Logf("%d check-vs-cite mismatch(es) — fix the mis-cite/mis-check, or (if a heuristic "+
			"false positive) add to deferredCheckCiteMismatches with a written reason", len(flags))
	}

	for key := range deferredCheckCiteMismatches {
		if !usedAllow[key] {
			t.Errorf("stale deferredCheckCiteMismatches entry %q: no longer a mismatch — remove it (the allowlist may only shrink)", key)
		}
	}
}

// targetsOverlap reports whether the two target sets share a subject. Overlap is
// exact (kind+value), except that a path target subsumes another whose value is a
// prefix of it (same file/dir domain), so a rule stat'ing /etc/ssh/sshd_config
// matches a control whose fix edits /etc/ssh/sshd_config.d/50-x.conf.
func targetsOverlap(a, b []Target) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Kind != y.Kind {
				continue
			}
			if x.Value == y.Value {
				return true
			}
			if x.Kind == "path" && pathDomainMatch(x.Value, y.Value) {
				return true
			}
		}
	}
	return false
}

// pathDomainMatch reports whether two paths share a file/directory domain: one is
// a prefix of the other at a path boundary (e.g. /etc/ssh/sshd_config vs
// /etc/ssh/sshd_config.d/x.conf, or /etc/pam.d vs /etc/pam.d/system-auth).
func pathDomainMatch(p, q string) bool {
	if len(p) > len(q) {
		p, q = q, p
	}
	if p == q {
		return true
	}
	if len(q) > len(p) && (q[len(p)] == '/' || q[len(p)] == '.') {
		return q[:len(p)] == p
	}
	return false
}
