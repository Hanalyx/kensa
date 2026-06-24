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
