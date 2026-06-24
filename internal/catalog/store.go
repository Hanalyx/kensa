// Package catalog is a queryable, normalized store of compliance-benchmark
// controls and their cross-references, built from authoritative source files
// (DISA STIG XCCDF, NIST 800-53 OSCAL and the CCI list, and CIS benchmark facts).
//
// It exists so coverage and crosswalk questions are answered by a query against a
// single SQLite file instead of by re-parsing PDFs and XML each time. It is a
// dev and CI authoring asset, not part of the frozen api/ contract: frameworks are
// metadata, not host-config mechanism, so this store publishes reference facts the
// rule-authoring process consumes rather than anything OpenWatch executes.
//
// Licensing is encoded per row. STIG and NIST and CCI content is public domain or
// openly licensed and carries full text. CIS rows carry only non-copyrightable
// facts (recommendation number, level, automatable flag); CIS prose is never stored.
package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, shared with internal/store
)

// Store is the catalog database handle. It backs both the kensa-catalog CLI and
// any in-module caller that wants to query the catalog programmatically.
type Store struct {
	db *sql.DB
}

// Open opens or creates the catalog database at path and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("catalog: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("catalog: %s: %w", pragma, err)
		}
	}
	if _, err := db.ExecContext(ctx, schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("catalog: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// IngestSTIG parses a STIG XCCDF file and upserts its benchmark, controls, and
// CCI idents under the given os and release label. Re-ingesting the same
// (framework, os, version) replaces its controls.
func (s *Store) IngestSTIG(ctx context.Context, osID, release, path string) (int, error) {
	title, controls, err := parseSTIG(path)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM benchmark WHERE framework='stig' AND os=? AND version=?`, osID, release); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
        INSERT INTO benchmark (framework, os, version, source_file, license)
        VALUES ('stig', ?, ?, ?, 'public-domain')`,
		osID, release, fmt.Sprintf("%s (%s)", title, path))
	if err != nil {
		return 0, fmt.Errorf("catalog: insert benchmark: %w", err)
	}
	benchID, _ := res.LastInsertId()

	for _, c := range controls {
		auto := 0 // STIG manual XCCDF marks no automatable subset; recorded as unknown-leaning-manual
		cres, err := tx.ExecContext(ctx, `
            INSERT INTO control (benchmark_id, control_id, secondary_id, severity, automatable, title)
            VALUES (?, ?, ?, ?, ?, ?)`,
			benchID, c.ControlID, nullStr(c.SecondaryID), c.Severity, sqlNullInt(auto, false), c.Title)
		if err != nil {
			return 0, fmt.Errorf("catalog: insert control %s: %w", c.ControlID, err)
		}
		ctlPK, _ := cres.LastInsertId()
		for _, cci := range c.CCIs {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO ident (control_pk, system, value) VALUES (?, 'cci', ?)`, ctlPK, cci); err != nil {
				return 0, fmt.Errorf("catalog: insert ident %s: %w", cci, err)
			}
		}
		for _, t := range ExtractCommandTargets(c.CheckText) {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO control_target (control_pk, kind, value) VALUES (?, ?, ?)`,
				ctlPK, t.Kind, t.Value); err != nil {
				return 0, fmt.Errorf("catalog: insert control_target %s/%s: %w", t.Kind, t.Value, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(controls), nil
}

// IngestCIS loads a CIS facts export (cis_facts_<os>.json) as a benchmark whose
// controls are recommendation numbers with their level and automatable flag. No
// CIS prose is stored; the benchmark is marked cis-restricted. Re-ingesting the
// same (os, version) replaces it.
func (s *Store) IngestCIS(ctx context.Context, path string) (int, error) {
	f, err := parseCISFacts(path)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM benchmark WHERE framework='cis' AND os=? AND version=?`, f.OS, f.Version); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
        INSERT INTO benchmark (framework, os, version, source_file, license)
        VALUES ('cis', ?, ?, ?, 'cis-restricted')`, f.OS, f.Version, path)
	if err != nil {
		return 0, fmt.Errorf("catalog: insert cis benchmark: %w", err)
	}
	benchID, _ := res.LastInsertId()
	for _, r := range f.Recommendations {
		auto := 0
		if r.Automatable {
			auto = 1
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO control (benchmark_id, control_id, secondary_id, automatable, title)
            VALUES (?, ?, ?, ?, NULL)`,
			benchID, r.Section, nullStr(r.Level), sqlNullInt(auto, true)); err != nil {
			return 0, fmt.Errorf("catalog: insert cis control %s: %w", r.Section, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(f.Recommendations), nil
}

// IngestVerifications loads the functional-verification facts (a rule's
// check/remediate/rollback proven on a live OS) and records them. Independent of
// any benchmark: recorded facts, replaced wholesale on re-ingest.
func (s *Store) IngestVerifications(ctx context.Context, path string) (int, error) {
	vs, err := parseVerifications(path)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM verification`); err != nil {
		return 0, err
	}
	for _, v := range vs {
		if v.RuleID == "" || v.OS == "" || v.Scope == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT OR IGNORE INTO verification (rule_id, os, scope, host, verified_at, notes)
            VALUES (?, ?, ?, ?, ?, ?)`,
			v.RuleID, v.OS, v.Scope, nullStr(v.Host), nullStr(v.VerifiedAt), nullStr(v.Notes)); err != nil {
			return 0, fmt.Errorf("catalog: insert verification %s/%s: %w", v.RuleID, v.OS, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(vs), nil
}

// IngestCoverageFromCorpus reads a corpus-coverage.json index and records which
// rule cites which STIG vuln id and which CIS section, per os. Citations are
// stored raw; a citation matching no ingested control is later reported as drift.
func (s *Store) IngestCoverageFromCorpus(ctx context.Context, corpusPath string) (int, error) {
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		return 0, fmt.Errorf("catalog: read corpus: %w", err)
	}
	var corpus struct {
		Rules []struct {
			ID   string `json:"id"`
			Stig map[string]struct {
				VulnID string `json:"vuln_id"`
			} `json:"stig"`
			Cis map[string]string `json:"cis"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		return 0, fmt.Errorf("catalog: parse corpus: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM coverage WHERE framework IN ('stig','cis')`); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range corpus.Rules {
		for osID, detail := range r.Stig {
			if detail.VulnID == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
                INSERT OR IGNORE INTO coverage (rule_id, framework, os, control_id)
                VALUES (?, 'stig', ?, ?)`, r.ID, osID, detail.VulnID); err != nil {
				return 0, err
			}
			n++
		}
		for osID, section := range r.Cis {
			if section == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
                INSERT OR IGNORE INTO coverage (rule_id, framework, os, control_id)
                VALUES (?, 'cis', ?, ?)`, r.ID, osID, section); err != nil {
				return 0, err
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// IngestNISTCatalog loads the slim 800-53 rev5 controls facts as a single
// benchmark (framework nist_800_53, os "any", version rev5) whose controls are the
// catalog controls and enhancements. Re-ingesting replaces it.
func (s *Store) IngestNISTCatalog(ctx context.Context, path string) (int, error) {
	controls, err := parseNISTControls(path)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM benchmark WHERE framework='nist_800_53' AND os='any' AND version='rev5'`); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
        INSERT INTO benchmark (framework, os, version, source_file, license)
        VALUES ('nist_800_53', 'any', 'rev5', ?, 'public-domain')`, path)
	if err != nil {
		return 0, fmt.Errorf("catalog: insert nist benchmark: %w", err)
	}
	benchID, _ := res.LastInsertId()
	for _, c := range controls {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO control (benchmark_id, control_id, secondary_id, title)
            VALUES (?, ?, ?, ?)`, benchID, c.ID, c.Family, c.Title); err != nil {
			return 0, fmt.Errorf("catalog: insert nist control %s: %w", c.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(controls), nil
}

// IngestCCIList loads the slim CCI-to-800-53-rev5 edges and records each in
// crossref. Re-ingesting replaces the cci-to-nist edges.
func (s *Store) IngestCCIList(ctx context.Context, path string) (int, error) {
	edges, err := parseCCIEdges(path)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM crossref WHERE from_system='cci' AND to_system='nist_800_53_rev5'`); err != nil {
		return 0, err
	}
	for _, e := range edges {
		if _, err := tx.ExecContext(ctx, `
            INSERT OR IGNORE INTO crossref (from_system, from_id, to_system, to_id)
            VALUES ('cci', ?, 'nist_800_53_rev5', ?)`, e.CCI, e.ControlID); err != nil {
			return 0, fmt.Errorf("catalog: insert crossref %s: %w", e.CCI, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(edges), nil
}

// NISTFamilyCount is the derived 800-53 control count for one family.
type NISTFamilyCount struct {
	Family    string
	Touched   int // distinct rev5 controls touched by covered STIG controls
	InCatalog int // distinct rev5 controls in the catalog for this family
}

// DerivedNISTByFamily computes, per 800-53 family, how many distinct Revision 5
// controls Kensa touches through the CCIs of the STIG requirements it covers,
// alongside the catalog total for that family. This is the controls-touched
// surface derived from source data, not a hand-maintained mapping. It is never a
// catalog-coverage percentage: most of 800-53 is procedural and out of host scope.
func (s *Store) DerivedNISTByFamily(ctx context.Context) ([]NISTFamilyCount, int, error) {
	// Distinct rev5 controls reachable from the STIG requirements the corpus covers.
	touched := map[string]map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `
        SELECT DISTINCT xr.to_id
        FROM coverage cov
        JOIN benchmark b ON b.framework = cov.framework AND b.os = cov.os
        JOIN control c   ON c.benchmark_id = b.id AND c.control_id = cov.control_id
        JOIN ident i     ON i.control_pk = c.id AND i.system = 'cci'
        JOIN crossref xr ON xr.from_system = 'cci' AND xr.from_id = i.value
                        AND xr.to_system = 'nist_800_53_rev5'
        WHERE cov.framework = 'stig'`)
	if err != nil {
		return nil, 0, err
	}
	total := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, 0, err
		}
		fam := familyOf(id)
		if touched[fam] == nil {
			touched[fam] = map[string]bool{}
		}
		touched[fam][id] = true
		total++
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	_ = rows.Close()

	// Catalog totals per family.
	catRows, err := s.db.QueryContext(ctx, `
        SELECT c.control_id FROM control c
        JOIN benchmark b ON c.benchmark_id = b.id
        WHERE b.framework = 'nist_800_53' AND b.version = 'rev5'`)
	if err != nil {
		return nil, 0, err
	}
	catalog := map[string]int{}
	for catRows.Next() {
		var id string
		if err := catRows.Scan(&id); err != nil {
			_ = catRows.Close()
			return nil, 0, err
		}
		catalog[familyOf(id)]++
	}
	if err := catRows.Err(); err != nil {
		return nil, 0, err
	}
	_ = catRows.Close()

	fams := map[string]bool{}
	for f := range touched {
		fams[f] = true
	}
	for f := range catalog {
		fams[f] = true
	}
	var out []NISTFamilyCount
	for f := range fams {
		out = append(out, NISTFamilyCount{Family: f, Touched: len(touched[f]), InCatalog: catalog[f]})
	}
	sortFamilies(out)
	return out, total, nil
}

func familyOf(controlID string) string {
	if i := strings.IndexByte(controlID, '-'); i > 0 {
		return controlID[:i]
	}
	return controlID
}

func sortFamilies(rows []NISTFamilyCount) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j-1].Family > rows[j].Family; j-- {
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}
}

// CoverageRow is one (framework, os) cell of the coverage matrix.
type CoverageRow struct {
	Framework, OS, Version           string
	Total, Covered, Missing, Drifted int
}

// CoverageMatrix computes covered, missing, and drifted counts per benchmark for
// the given framework, joining the corpus coverage citations against the ingested
// controls. This is the query that replaces the ad-hoc crosswalk scripts.
func (s *Store) CoverageMatrix(ctx context.Context, framework string) ([]CoverageRow, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT b.os, b.version,
            (SELECT COUNT(*) FROM control c WHERE c.benchmark_id = b.id) AS total,
            (SELECT COUNT(DISTINCT c.control_id) FROM control c
                JOIN coverage cov ON cov.control_id = c.control_id
                    AND cov.os = b.os AND cov.framework = b.framework
                WHERE c.benchmark_id = b.id) AS covered
        FROM benchmark b
        WHERE b.framework = ?
        ORDER BY b.os`, framework)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CoverageRow
	for rows.Next() {
		var r CoverageRow
		r.Framework = framework
		if err := rows.Scan(&r.OS, &r.Version, &r.Total, &r.Covered); err != nil {
			return nil, err
		}
		r.Missing = r.Total - r.Covered
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The outer rows are fully drained and closed before the drift queries run:
	// with SetMaxOpenConns(1) a query issued while rows is still open would
	// deadlock waiting for the single connection.
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		// Drift counts distinct cited controls absent from the benchmark, not raw
		// citation rows: one renumbered control cited by many rules is one drift,
		// the same DISTINCT basis the covered count above uses.
		if err := s.db.QueryRowContext(ctx, `
            SELECT COUNT(DISTINCT cov.control_id) FROM coverage cov
            WHERE cov.framework = ? AND cov.os = ?
              AND NOT EXISTS (
                SELECT 1 FROM control c JOIN benchmark b ON c.benchmark_id = b.id
                WHERE b.framework = cov.framework AND b.os = cov.os AND c.control_id = cov.control_id)`,
			framework, out[i].OS).Scan(&out[i].Drifted); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func sqlNullInt(v int, valid bool) interface{} {
	if !valid {
		return nil
	}
	return v
}
