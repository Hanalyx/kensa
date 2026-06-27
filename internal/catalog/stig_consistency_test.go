package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// deferredSTIGMiscites is the ratcheting allowlist for C-10: rules whose cited
// STIG (vuln_id, stig_id) pair is known-inconsistent and whose correct control
// has not yet been resolved (the vuln_id itself is wrong — a verdict bug — so
// syncing the stig_id would entrench the error). Keyed by "ruleID|os|vuln_id".
//
// This list MUST ONLY SHRINK. Removing an entry (after fixing the rule's
// vuln_id) is the intended direction; adding one is forbidden — a brand-new
// inconsistency means a mis-citation slipped in and CI must fail.
var deferredSTIGMiscites = map[string]bool{
	"audit-time-change|rhel9|V-257849":        true, // cites a mount control; correct audit-time control unresolved
	"audit-network-change|rhel9|V-257850":     true, // loose -k system-locale check; control unresolved
	"audit-mount-operations|rhel9|V-257873":   true, // cites a mount control; correct audit-mount control unresolved
	"audit-user-group-changes|rhel9|V-258217": true, // V-258217 is /etc/sudoers; rule watches the /etc/passwd family
	"root-only-gid0|rhel9|V-257890":           true, // cites a home-dir-mode control
}

type manifestDoc struct {
	Stig []struct {
		OS   string `json:"os"`
		File string `json:"file"`
	} `json:"stig"`
}

type ruleRefsDoc struct {
	ID         string                 `yaml:"id"`
	References map[string]interface{} `yaml:"references"`
}

// TestSTIGCitationConsistency_ProductionCorpus enforces C-10 / AC-11: every STIG
// citation's stig_id resolves to the same control as its vuln_id in the vendored
// XCCDF, except the ratcheting deferredSTIGMiscites allowlist.
//
// @spec catalog-coverage-crosswalk
// @ac AC-11
func TestSTIGCitationConsistency_ProductionCorpus(t *testing.T) {
	t.Log("// @spec catalog-coverage-crosswalk")
	t.Log("// @ac AC-11")

	root := filepath.Join("..", "..")
	srcDir := filepath.Join(root, "catalog", "sources")
	rulesDir := filepath.Join(root, "rules")

	// Build os -> (vuln_id -> stig_id) from the vendored XCCDF sources.
	raw, err := os.ReadFile(filepath.Join(srcDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifestDoc
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	vulnToStig := map[string]map[string]string{}
	for _, b := range m.Stig {
		_, controls, err := parseSTIG(filepath.Join(srcDir, b.File))
		if err != nil {
			t.Fatalf("parseSTIG %s: %v", b.File, err)
		}
		osMap := map[string]string{}
		for _, c := range controls {
			osMap[c.ControlID] = c.SecondaryID
		}
		vulnToStig[b.OS] = osMap
	}

	// Walk the corpus; check every STIG cite carrying both vuln_id and stig_id.
	var violations []string
	usedAllow := map[string]bool{}
	err = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var d ruleRefsDoc
		if err := yaml.Unmarshal(data, &d); err != nil {
			return nil // not a single-doc rule; skip (validator covers parse errors)
		}
		stig, ok := d.References["stig"].(map[string]interface{})
		if !ok {
			return nil
		}
		for osKey, v := range stig {
			osMap, known := vulnToStig[osKey]
			if !known {
				continue // OS not in our vendored sources (e.g. an unvendored release)
			}
			for _, entry := range asList(v) {
				vid, _ := entry["vuln_id"].(string)
				sid, _ := entry["stig_id"].(string)
				if vid == "" || sid == "" {
					continue // need both fields to cross-check
				}
				actual, inSource := osMap[vid]
				if !inSource || actual == sid {
					continue
				}
				key := d.ID + "|" + osKey + "|" + vid
				if deferredSTIGMiscites[key] {
					usedAllow[key] = true
					continue
				}
				violations = append(violations,
					d.ID+" ["+osKey+"] cites "+vid+"+"+sid+" but "+vid+" is "+actual+" in the XCCDF")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules: %v", err)
	}

	for _, vmsg := range violations {
		t.Errorf("inconsistent STIG citation: %s", vmsg)
	}
	if len(violations) > 0 {
		t.Logf("%d new inconsistent citation(s) — fix the vuln_id, or (only if a genuine deferred verdict bug) add to deferredSTIGMiscites", len(violations))
	}

	// The allowlist may only shrink: a stale entry (the rule was fixed) must be
	// removed so the list reflects reality.
	for key := range deferredSTIGMiscites {
		if !usedAllow[key] {
			t.Errorf("stale deferredSTIGMiscites entry %q: no longer inconsistent — remove it (the allowlist may only shrink)", key)
		}
	}
}

// asList normalizes a versioned-framework OS value (single object or list of
// objects) to a slice of maps, mirroring schema V1.1 §3.3.
func asList(v interface{}) []map[string]interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{t}
	case []interface{}:
		var out []map[string]interface{}
		for _, e := range t {
			if mm, ok := e.(map[string]interface{}); ok {
				out = append(out, mm)
			}
		}
		return out
	}
	return nil
}
