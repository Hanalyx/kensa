package catalog

import (
	"context"
	"database/sql"
	"errors"
)

// VerifiedRule is a functional-verification fact: a rule proven to work on an OS,
// with whether that (rule, os) also carries a benchmark mapping in coverage.
// Mapped=false is the meaningful "works, awaiting a benchmark" state (e.g. a rule
// proven on Ubuntu 26.04 before DISA/CIS publish a 26.04 benchmark).
type VerifiedRule struct {
	RuleID, OS, Scope, Host, VerifiedAt, Notes string
	Mapped                                     bool
}

// VerifiedRules returns recorded functional verifications, optionally filtered to
// one OS, each flagged with whether the rule also has a benchmark citation for
// that OS. Ordered by os, rule, scope.
func (s *Store) VerifiedRules(ctx context.Context, osFilter string) ([]VerifiedRule, error) {
	q := `
        SELECT v.rule_id, v.os, v.scope, v.host, v.verified_at, v.notes,
            EXISTS(SELECT 1 FROM coverage c WHERE c.rule_id = v.rule_id AND c.os = v.os) AS mapped
        FROM verification v`
	args := []interface{}{}
	if osFilter != "" {
		q += " WHERE v.os = ?"
		args = append(args, osFilter)
	}
	q += " ORDER BY v.os, v.rule_id, v.scope"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VerifiedRule
	for rows.Next() {
		var v VerifiedRule
		var host, at, notes sql.NullString
		var mapped int
		if err := rows.Scan(&v.RuleID, &v.OS, &v.Scope, &host, &at, &notes, &mapped); err != nil {
			return nil, err
		}
		v.Host, v.VerifiedAt, v.Notes, v.Mapped = host.String, at.String, notes.String, mapped != 0
		out = append(out, v)
	}
	return out, rows.Err()
}

// CrosswalkResult classifies a benchmark's controls for one (framework, os) by
// whether the corpus can cover them: covered (a rule already cites it), extend (no
// citation, but a rule's check target matches the control's command-extracted
// target — so an existing rule could cover it with a platform/ref extension), or
// net-new (no matching rule target — genuine authoring). ExtendList names the
// matching rule per extend candidate; NetNew lists the controls needing authoring.
type CrosswalkResult struct {
	Framework, OS          string
	Total, Covered, Extend int
	NetNew                 int
	ExtendList             []ExtendCandidate
	NetNewList             []Control
}

// ExtendCandidate is a control reachable by extending an existing rule, with the
// target that matched and the rule that owns it.
type ExtendCandidate struct {
	ControlID, Title string
	Kind, Value      string
	Rule             string
}

// Crosswalk classifies every control of (framework, os) as covered / extend /
// net-new using command-aware target matching. This is the measured extend-vs-
// net-new split the gap plan needs, replacing prose-matching guesswork.
func (s *Store) Crosswalk(ctx context.Context, framework, osID string) (*CrosswalkResult, error) {
	res := &CrosswalkResult{Framework: framework, OS: osID}
	rows, err := s.db.QueryContext(ctx, `
        SELECT c.id, c.control_id, c.severity, c.title,
            EXISTS(SELECT 1 FROM coverage cov
                   WHERE cov.framework = ? AND cov.os = ? AND cov.control_id = c.control_id) AS covered
        FROM control c JOIN benchmark b ON c.benchmark_id = b.id
        WHERE b.framework = ? AND b.os = ?
        ORDER BY c.control_id`, framework, osID, framework, osID)
	if err != nil {
		return nil, err
	}
	type row struct {
		pk        int64
		controlID string
		severity  string
		title     string
		covered   bool
	}
	var all []row
	for rows.Next() {
		var r row
		var sev, title sql.NullString
		var cov int
		if err := rows.Scan(&r.pk, &r.controlID, &sev, &title, &cov); err != nil {
			_ = rows.Close()
			return nil, err
		}
		r.severity, r.title, r.covered = sev.String, title.String, cov != 0
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	res.Total = len(all)
	for _, r := range all {
		if r.covered {
			res.Covered++
			continue
		}
		// extend if any of this control's targets matches a rule_target.
		var kind, value, rule sql.NullString
		err := s.db.QueryRowContext(ctx, `
            SELECT ct.kind, ct.value, rt.rule_id
            FROM control_target ct
            JOIN rule_target rt ON rt.kind = ct.kind AND rt.value = ct.value
            WHERE ct.control_pk = ?
            ORDER BY ct.kind, ct.value, rt.rule_id
            LIMIT 1`, r.pk).Scan(&kind, &value, &rule)
		switch {
		case err == nil:
			res.Extend++
			res.ExtendList = append(res.ExtendList, ExtendCandidate{
				ControlID: r.controlID, Title: r.title,
				Kind: kind.String, Value: value.String, Rule: rule.String,
			})
		case errors.Is(err, sql.ErrNoRows):
			res.NetNew++
			res.NetNewList = append(res.NetNewList, Control{ControlID: r.controlID, Severity: r.severity, Title: r.title})
		default:
			return nil, err
		}
	}
	return res, nil
}

// Control is a benchmark control as returned by query methods. Automatable is
// 1 (yes), 0 (no), or -1 (unknown — STIG manual XCCDF marks no subset). Title is
// empty for cis-restricted benchmarks, which store no prose.
type Control struct {
	ControlID   string
	SecondaryID string // STIG id, or CIS level
	Severity    string
	Title       string
	Automatable int
}

// MissingControls returns the controls in (framework, os) that no corpus rule
// covers: the authoring backlog for that cell, ordered by control id.
func (s *Store) MissingControls(ctx context.Context, framework, osID string) ([]Control, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT c.control_id, c.secondary_id, c.severity, c.title, c.automatable
        FROM control c JOIN benchmark b ON c.benchmark_id = b.id
        WHERE b.framework = ? AND b.os = ?
          AND NOT EXISTS (
            SELECT 1 FROM coverage cov
            WHERE cov.framework = b.framework AND cov.os = b.os AND cov.control_id = c.control_id)
        ORDER BY c.control_id`, framework, osID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanControls(rows)
}

// Drift is one stale corpus citation: a control id cited by rules that does not
// exist in the current benchmark release, with the rules that cite it.
type Drift struct {
	ControlID string
	Rules     []string
}

// DriftedCitations returns the (framework, os) citations whose control id is
// absent from the benchmark — the reference re-mapping work list.
func (s *Store) DriftedCitations(ctx context.Context, framework, osID string) ([]Drift, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT cov.control_id, GROUP_CONCAT(DISTINCT cov.rule_id)
        FROM coverage cov
        WHERE cov.framework = ? AND cov.os = ?
          AND NOT EXISTS (
            SELECT 1 FROM control c JOIN benchmark b ON c.benchmark_id = b.id
            WHERE b.framework = cov.framework AND b.os = cov.os AND c.control_id = cov.control_id)
        GROUP BY cov.control_id
        ORDER BY cov.control_id`, framework, osID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Drift
	for rows.Next() {
		var d Drift
		var rules sql.NullString
		if err := rows.Scan(&d.ControlID, &rules); err != nil {
			return nil, err
		}
		d.Rules = splitConcat(rules.String)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Crosswalk is the full cross-reference for one control: its identifiers, the
// 800-53 controls reached through its CCIs, and the corpus rules that cite it.
type Crosswalk struct {
	Framework, OS, ControlID string
	SecondaryID, Severity    string
	Title                    string
	CCIs                     []string
	NIST80053                []string // derived from CCIs (STIG only)
	CoveringRules            []string
}

// ControlCrosswalk returns the cross-reference for a single control, or nil if it
// is not in the catalog for that (framework, os).
func (s *Store) ControlCrosswalk(ctx context.Context, framework, osID, controlID string) (*Crosswalk, error) {
	var pk int64
	xw := &Crosswalk{Framework: framework, OS: osID, ControlID: controlID}
	var sec, sev, title sql.NullString
	err := s.db.QueryRowContext(ctx, `
        SELECT c.id, c.secondary_id, c.severity, c.title
        FROM control c JOIN benchmark b ON c.benchmark_id = b.id
        WHERE b.framework = ? AND b.os = ? AND c.control_id = ?`,
		framework, osID, controlID).Scan(&pk, &sec, &sev, &title)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	xw.SecondaryID, xw.Severity, xw.Title = sec.String, sev.String, title.String

	xw.CCIs, err = s.stringColumn(ctx,
		`SELECT value FROM ident WHERE control_pk = ? AND system = 'cci' ORDER BY value`, pk)
	if err != nil {
		return nil, err
	}
	xw.NIST80053, err = s.stringColumn(ctx, `
        SELECT DISTINCT xr.to_id FROM ident i
        JOIN crossref xr ON xr.from_system = 'cci' AND xr.from_id = i.value
                        AND xr.to_system = 'nist_800_53_rev5'
        WHERE i.control_pk = ? ORDER BY xr.to_id`, pk)
	if err != nil {
		return nil, err
	}
	xw.CoveringRules, err = s.stringColumn(ctx,
		`SELECT DISTINCT rule_id FROM coverage WHERE framework = ? AND os = ? AND control_id = ? ORDER BY rule_id`,
		framework, osID, controlID)
	if err != nil {
		return nil, err
	}
	return xw, nil
}

func (s *Store) stringColumn(ctx context.Context, query string, args ...interface{}) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanControls(rows *sql.Rows) ([]Control, error) {
	var out []Control
	for rows.Next() {
		var c Control
		var sec, sev, title sql.NullString
		var auto sql.NullInt64
		if err := rows.Scan(&c.ControlID, &sec, &sev, &title, &auto); err != nil {
			return nil, err
		}
		c.SecondaryID, c.Severity, c.Title = sec.String, sev.String, title.String
		if auto.Valid {
			c.Automatable = int(auto.Int64)
		} else {
			c.Automatable = -1
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func splitConcat(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
