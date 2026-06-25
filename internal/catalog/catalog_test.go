package catalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return p
}

func newStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, ctx
}

const fixtureXCCDF = `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
 <title>Test STIG</title>
 <Group id="V-1">
   <Rule severity="medium">
     <version>TEST-00-000001</version>
     <title>Rule one</title>
     <ident system="http://cyber.mil/cci">CCI-000196</ident>
   </Rule>
 </Group>
 <Group id="V-2">
   <Rule severity="high">
     <version>TEST-00-000002</version>
     <title>Rule two</title>
   </Rule>
 </Group>
</Benchmark>`

const fixtureCorpus = `{"rules":[
 {"id":"rule-a","stig":{"rhel9":{"vuln_id":"V-1"}}},
 {"id":"rule-b","stig":{"rhel9":{"vuln_id":"V-999"}}},
 {"id":"rule-c","stig":{"rhel9":{"vuln_id":"V-999"}}}
]}`

// @spec catalog-coverage-crosswalk
// @ac AC-01
func TestParseSTIG(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-01", func(t *testing.T) {
		dir := t.TempDir()
		path := writeFixture(t, dir, "x.xml", fixtureXCCDF)
		title, controls, err := parseSTIG(path)
		if err != nil {
			t.Fatalf("parseSTIG: %v", err)
		}
		if title != "Test STIG" {
			t.Errorf("title = %q, want %q", title, "Test STIG")
		}
		if len(controls) != 2 {
			t.Fatalf("got %d controls, want 2", len(controls))
		}
		if controls[0].ControlID != "V-1" || controls[0].Severity != "medium" {
			t.Errorf("control[0] = %+v", controls[0])
		}
		if len(controls[0].CCIs) != 1 || controls[0].CCIs[0] != "CCI-000196" {
			t.Errorf("control[0] CCIs = %v, want [CCI-000196]", controls[0].CCIs)
		}
		if len(controls[1].CCIs) != 0 {
			t.Errorf("control[1] should have no CCIs, got %v", controls[1].CCIs)
		}
	})
}

// @spec catalog-coverage-crosswalk
// @ac AC-02
func TestIngestCIS_FactsOnly(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-02", func(t *testing.T) {
		s, ctx := newStore(t)
		dir := t.TempDir()
		facts := `{"framework":"cis","os":"rhel9","version":"vT","recommendations":[
            {"section":"1.1.1","level":"L1","automatable":true},
            {"section":"1.1.2","level":"L2","automatable":false}]}`
		path := writeFixture(t, dir, "cis.json", facts)
		n, err := s.IngestCIS(ctx, path)
		if err != nil || n != 2 {
			t.Fatalf("IngestCIS n=%d err=%v", n, err)
		}
		// Every CIS control title must be empty — no copyrighted prose stored.
		var nonEmpty int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM control WHERE title IS NOT NULL AND title != ''`).Scan(&nonEmpty); err != nil {
			t.Fatal(err)
		}
		if nonEmpty != 0 {
			t.Errorf("found %d CIS controls with a stored title; facts-only requires none", nonEmpty)
		}
	})
}

// @spec catalog-coverage-crosswalk
// @ac AC-03
func TestCoverageMatrix_DriftIsDistinct(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-03", func(t *testing.T) {
		s, ctx := newStore(t)
		dir := t.TempDir()
		if _, err := s.IngestSTIG(ctx, "rhel9", "vT", writeFixture(t, dir, "x.xml", fixtureXCCDF)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.IngestCoverageFromCorpus(ctx, writeFixture(t, dir, "c.json", fixtureCorpus)); err != nil {
			t.Fatal(err)
		}
		rows, err := s.CoverageMatrix(ctx, "stig")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want 1", len(rows))
		}
		r := rows[0]
		// rule-a covers V-1; rule-b and rule-c both cite the absent V-999 -> ONE drift.
		if r.Total != 2 || r.Covered != 1 {
			t.Errorf("total/covered = %d/%d, want 2/1", r.Total, r.Covered)
		}
		if r.Drifted != 1 {
			t.Errorf("drift = %d, want 1 (distinct controls, not the 2 citation rows)", r.Drifted)
		}
	})
}

// @spec catalog-coverage-crosswalk
// @ac AC-04
func TestSplitVersionedFramework(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-04", func(t *testing.T) {
		if fw, os, ok := splitVersionedFramework("cis_rhel9"); !ok || fw != "cis" || os != "rhel9" {
			t.Errorf("cis_rhel9 -> %q,%q,%v", fw, os, ok)
		}
		if fw, os, ok := splitVersionedFramework("stig_ubuntu24"); !ok || fw != "stig" || os != "ubuntu24" {
			t.Errorf("stig_ubuntu24 -> %q,%q,%v", fw, os, ok)
		}
		if _, _, ok := splitVersionedFramework("nist_800_53"); ok {
			t.Error("nist_800_53 should not split (flat-list framework, no os join)")
		}
	})
}

// @spec catalog-coverage-crosswalk
// @ac AC-05
func TestControlCrosswalk(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-05", func(t *testing.T) {
		s, ctx := newStore(t)
		dir := t.TempDir()
		if _, err := s.IngestSTIG(ctx, "rhel9", "vT", writeFixture(t, dir, "x.xml", fixtureXCCDF)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.IngestNISTCatalog(ctx, writeFixture(t, dir, "nist.json",
			`[{"id":"ia-5.1","family":"ia","title":"Password-Based Authentication"}]`)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.IngestCCIList(ctx, writeFixture(t, dir, "cci.json",
			`[{"cci":"CCI-000196","control":"ia-5.1"}]`)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.IngestCoverageFromCorpus(ctx, writeFixture(t, dir, "c.json",
			`{"rules":[{"id":"rule-a","stig":{"rhel9":{"vuln_id":"V-1"}}}]}`)); err != nil {
			t.Fatal(err)
		}
		xw, err := s.ControlCrosswalk(ctx, "stig", "rhel9", "V-1")
		if err != nil || xw == nil {
			t.Fatalf("crosswalk err=%v nil=%v", err, xw == nil)
		}
		if len(xw.CCIs) != 1 || xw.CCIs[0] != "CCI-000196" {
			t.Errorf("CCIs = %v", xw.CCIs)
		}
		if len(xw.NIST80053) != 1 || xw.NIST80053[0] != "ia-5.1" {
			t.Errorf("derived 800-53 = %v, want [ia-5.1]", xw.NIST80053)
		}
		if len(xw.CoveringRules) != 1 || xw.CoveringRules[0] != "rule-a" {
			t.Errorf("covering rules = %v, want [rule-a]", xw.CoveringRules)
		}
	})
}

// @spec catalog-coverage-crosswalk
// @ac AC-06
func TestMissingControls(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-06", func(t *testing.T) {
		s, ctx := newStore(t)
		dir := t.TempDir()
		if _, err := s.IngestSTIG(ctx, "rhel9", "vT", writeFixture(t, dir, "x.xml", fixtureXCCDF)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.IngestCoverageFromCorpus(ctx, writeFixture(t, dir, "c.json",
			`{"rules":[{"id":"rule-a","stig":{"rhel9":{"vuln_id":"V-1"}}}]}`)); err != nil {
			t.Fatal(err)
		}
		missing, err := s.MissingControls(ctx, "stig", "rhel9")
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 1 || missing[0].ControlID != "V-2" {
			t.Fatalf("missing = %+v, want [V-2]", missing)
		}
	})
}

// @spec catalog-coverage-crosswalk
// @ac AC-09
func TestVerifications(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-09", func(t *testing.T) {
		s, ctx := newStore(t)
		dir := t.TempDir()
		// A benchmark + coverage so "rule-mapped" has a rhel9 citation.
		if _, err := s.IngestSTIG(ctx, "rhel9", "vT", writeFixture(t, dir, "x.xml", fixtureXCCDF)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.IngestCoverageFromCorpus(ctx, writeFixture(t, dir, "c.json",
			`{"rules":[{"id":"rule-mapped","stig":{"rhel9":{"vuln_id":"V-1"}}}]}`)); err != nil {
			t.Fatal(err)
		}
		// rule-mapped verified on rhel9 (has coverage); rule-proven verified on
		// ubuntu26 (no benchmark/coverage -> proven-but-unmapped).
		vf := `{"verifications":[
            {"rule_id":"rule-mapped","os":"rhel9","scope":"full","host":"c","verified_at":"2026-06-24"},
            {"rule_id":"rule-proven","os":"ubuntu26","scope":"check","host":"c","verified_at":"2026-06-24"}]}`
		if n, err := s.IngestVerifications(ctx, writeFixture(t, dir, "v.json", vf)); err != nil || n != 2 {
			t.Fatalf("IngestVerifications n=%d err=%v", n, err)
		}
		all, err := s.VerifiedRules(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 2 {
			t.Fatalf("want 2 verifications, got %d", len(all))
		}
		// os filter narrows to one.
		u, err := s.VerifiedRules(ctx, "ubuntu26")
		if err != nil {
			t.Fatal(err)
		}
		if len(u) != 1 || u[0].RuleID != "rule-proven" || u[0].Mapped {
			t.Errorf("ubuntu26 filter = %+v, want one unmapped rule-proven", u)
		}
		// mapped flag reflects coverage presence for that os.
		byID := map[string]VerifiedRule{}
		for _, v := range all {
			byID[v.RuleID] = v
		}
		if !byID["rule-mapped"].Mapped {
			t.Error("rule-mapped has rhel9 coverage; Mapped should be true")
		}
		if byID["rule-proven"].Mapped {
			t.Error("rule-proven has no coverage; Mapped should be false (proven-but-unmapped)")
		}
	})
}

func hasTarget(ts []Target, kind, val string) bool {
	for _, t := range ts {
		if t.Kind == kind && t.Value == val {
			return true
		}
	}
	return false
}

// @spec catalog-coverage-crosswalk
// @ac AC-10
func TestCrosswalk(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-10", func(t *testing.T) {
		// Extractor precision: command argument, not prose.
		tg := ExtractCommandTargets("Verify:\n$ dpkg -l | grep telnetd\nFix:\n$ sudo apt remove telnetd")
		if !hasTarget(tg, "package", "telnetd") {
			t.Errorf("expected (package,telnetd) from the command, got %v", tg)
		}
		if hasTarget(tg, "package", "sudo") || hasTarget(tg, "package", "grep") {
			t.Errorf("prose words leaked into targets: %v", tg)
		}

		s, ctx := newStore(t)
		dir := t.TempDir()
		xccdf := `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>T</title>
 <Group id="V-100"><Rule severity="high"><version>X-1</version><title>no telnetd</title>
   <check system="x"><check-content>$ dpkg -l | grep telnetd</check-content></check>
   <fixtext>$ sudo apt remove telnetd</fixtext></Rule></Group>
 <Group id="V-101"><Rule severity="medium"><version>X-2</version><title>sysctl foo</title>
   <check system="x"><check-content>$ sysctl kernel.foo</check-content></check></Rule></Group>
 <Group id="V-102"><Rule severity="low"><version>X-3</version><title>manual review</title>
   <check system="x"><check-content>Review the policy manually.</check-content></check></Rule></Group>
</Benchmark>`
		if _, err := s.IngestSTIG(ctx, "ubuntu24", "vT", writeFixture(t, dir, "x.xml", xccdf)); err != nil {
			t.Fatal(err)
		}
		// rule-a targets telnetd (-> extend V-100); rule-b cites V-101 (-> covered).
		rulesDir := t.TempDir()
		writeFixture(t, rulesDir, "a.yml",
			"id: rule-a\nimplementations:\n  - default: true\n    check:\n      method: package_state\n      name: telnetd\n")
		writeFixture(t, rulesDir, "b.yml",
			"id: rule-b\nreferences:\n  stig:\n    ubuntu24:\n      vuln_id: V-101\nimplementations:\n  - default: true\n    check:\n      method: sysctl_value\n      key: kernel.foo\n")
		if _, err := s.IngestCoverageFromRules(ctx, rulesDir); err != nil {
			t.Fatal(err)
		}
		r, err := s.Crosswalk(ctx, "stig", "ubuntu24")
		if err != nil {
			t.Fatal(err)
		}
		if r.Total != 3 || r.Covered != 1 || r.Extend != 1 || r.NetNew != 1 {
			t.Fatalf("crosswalk = total %d / covered %d / extend %d / net-new %d; want 3/1/1/1", r.Total, r.Covered, r.Extend, r.NetNew)
		}
		if len(r.ExtendList) != 1 || r.ExtendList[0].ControlID != "V-100" || r.ExtendList[0].Rule != "rule-a" {
			t.Errorf("extend candidate = %+v, want V-100 -> rule-a", r.ExtendList)
		}
	})
}

// TestConfigKeyTargets covers the config-directive crosswalk: a control whose check
// targets a config KEY (pwquality "dcredit = -1", login.defs "PASS_MAX_DAYS 60",
// sshd "X11UseLocalhost yes") matches a config_value / sshd_effective_config rule on
// that key, so it is classified extend rather than net-new. Without this the crosswalk
// under-counted reuse for every check-method rule that doesn't shell out to a command.
//
// @spec catalog-coverage-crosswalk
// @ac AC-10
func TestConfigKeyTargets(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-10", func(t *testing.T) {
		// Extraction: key=value anywhere; CamelCase only with an ssh_config anchor;
		// UPPERCASE only with a login.defs anchor.
		assign := ExtractCommandTargets("add the following line to /etc/security/pwquality.conf: dcredit = -1")
		if !hasTarget(assign, "config", "dcredit") {
			t.Errorf("expected (config,dcredit) from assignment, got %v", assign)
		}
		sshd := ExtractCommandTargets(`Edit the "/etc/ssh/sshd_config" file: X11UseLocalhost yes`)
		if !hasTarget(sshd, "config", "x11uselocalhost") {
			t.Errorf("expected (config,x11uselocalhost) from sshd directive, got %v", sshd)
		}
		ldefs := ExtractCommandTargets(`add or modify the following line in /etc/login.defs: PASS_MAX_DAYS 60`)
		if !hasTarget(ldefs, "config", "pass_max_days") {
			t.Errorf("expected (config,pass_max_days) from login.defs, got %v", ldefs)
		}
		// CamelCase must NOT fire without an ssh_config anchor (avoids prose false positives).
		noAnchor := ExtractCommandTargets("Configure Ubuntu to set X11UseLocalhost yes somewhere")
		if hasTarget(noAnchor, "config", "x11uselocalhost") {
			t.Errorf("CamelCase fired without ssh_config anchor: %v", noAnchor)
		}
		// configStop kills the generic "audit" collision (grub "audit=1" is not faillock).
		grub := ExtractCommandTargets(`add "audit=1" to the "GRUB_CMDLINE_LINUX" option`)
		if hasTarget(grub, "config", "audit") {
			t.Errorf("generic config key 'audit' should be stopped, got %v", grub)
		}

		// End-to-end: a login.defs control matches a config_value rule on the key.
		s, ctx := newStore(t)
		dir := t.TempDir()
		xccdf := `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>T</title>
 <Group id="V-200"><Rule severity="medium"><version>Y-1</version><title>max age</title>
   <check system="x"><check-content>Verify /etc/login.defs PASS_MAX_DAYS is 60</check-content></check>
   <fixtext>add or modify the following line in /etc/login.defs: PASS_MAX_DAYS 60</fixtext></Rule></Group>
</Benchmark>`
		if _, err := s.IngestSTIG(ctx, "ubuntu24", "vT", writeFixture(t, dir, "y.xml", xccdf)); err != nil {
			t.Fatal(err)
		}
		rulesDir := t.TempDir()
		writeFixture(t, rulesDir, "c.yml",
			"id: rule-maxage\nimplementations:\n  - default: true\n    check:\n      method: config_value\n      path: /etc/login.defs\n      key: PASS_MAX_DAYS\n")
		if _, err := s.IngestCoverageFromRules(ctx, rulesDir); err != nil {
			t.Fatal(err)
		}
		r, err := s.Crosswalk(ctx, "stig", "ubuntu24")
		if err != nil {
			t.Fatal(err)
		}
		if r.Extend != 1 || len(r.ExtendList) != 1 || r.ExtendList[0].Rule != "rule-maxage" {
			t.Fatalf("config-key crosswalk = extend %d %+v; want 1 -> rule-maxage", r.Extend, r.ExtendList)
		}
	})
}

// TestRuleTargetsOf_ComposedChecks locks the composed-check recursion: a rule
// whose check is a "checks:" list (AND-combined sub-checks) must yield a target
// for each sub-check. Without it, network-hardening sysctl rules (which check
// several keys in one composed check) produced no target and the crosswalk
// misclassified their controls as net-new instead of extend.
//
// @spec catalog-coverage-crosswalk
// @ac AC-01
func TestRuleTargetsOf_ComposedChecks(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-01", func(t *testing.T) {
		rr := ruleRefs{ID: "x"}
		rr.Implementations = append(rr.Implementations, struct {
			Check map[string]interface{} `yaml:"check"`
		}{Check: map[string]interface{}{
			"checks": []interface{}{
				map[string]interface{}{"method": "sysctl_value", "key": "net.ipv4.conf.all.accept_redirects"},
				map[string]interface{}{"method": "sysctl_value", "key": "net.ipv6.conf.default.accept_redirects"},
			},
		}})
		got := map[string]bool{}
		for _, tg := range ruleTargetsOf(rr) {
			got[tg.Kind+":"+tg.Value] = true
		}
		for _, want := range []string{"sysctl:net.ipv4.conf.all.accept_redirects", "sysctl:net.ipv6.conf.default.accept_redirects"} {
			if !got[want] {
				t.Errorf("composed sub-check target %q not extracted; got %v", want, got)
			}
		}
	})
}

// TestMountTargetExtraction locks per-(mount-point, option) matching for mount
// controls: the control-side extractor and ruleTargetsOf must agree on
// "mount:<path>:<option>" so a "/tmp with nosuid" control matches the
// mount-tmp-nosuid rule and NOT mount-tmp-nodev.
//
// @spec catalog-coverage-crosswalk
// @ac AC-01
func TestMountTargetExtraction(t *testing.T) {
	t.Run("catalog-coverage-crosswalk/AC-01", func(t *testing.T) {
		ct := ExtractCommandTargets(`Verify "/tmp" is mounted with the "nosuid" option with the following command`)
		if !hasTarget(ct, "mount", "/tmp:nosuid") {
			t.Errorf("control extractor: want mount:/tmp:nosuid, got %v", ct)
		}
		if hasTarget(ct, "mount", "/tmp:nodev") {
			t.Errorf("control extractor wrongly produced /tmp:nodev")
		}
		rr := ruleRefs{ID: "mount-tmp-nosuid"}
		rr.Implementations = append(rr.Implementations, struct {
			Check map[string]interface{} `yaml:"check"`
		}{Check: map[string]interface{}{
			"method": "mount_option", "mount_point": "/tmp",
			"options": []interface{}{"nosuid"},
		}})
		got := map[string]bool{}
		for _, tg := range ruleTargetsOf(rr) {
			got[tg.Kind+":"+tg.Value] = true
		}
		if !got["mount:/tmp:nosuid"] {
			t.Errorf("ruleTargetsOf: want mount:/tmp:nosuid, got %v", got)
		}
	})
}
