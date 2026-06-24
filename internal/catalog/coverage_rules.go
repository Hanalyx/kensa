package catalog

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Hanalyx/kensa/internal/mappings"
)

// ruleRefs is the minimal rule shape needed to extract framework citations and
// the structured target of each implementation's check.
type ruleRefs struct {
	ID              string                 `yaml:"id"`
	References      map[string]interface{} `yaml:"references"`
	Implementations []struct {
		Check map[string]interface{} `yaml:"check"`
	} `yaml:"implementations"`
}

// ruleTargetsOf extracts the distinct structured targets of a rule's checks.
func ruleTargetsOf(rr ruleRefs) []Target {
	seen := map[Target]bool{}
	for _, impl := range rr.Implementations {
		method, _ := impl.Check["method"].(string)
		params := map[string]string{}
		for _, k := range []string{"name", "key", "path"} {
			if v, ok := impl.Check[k].(string); ok {
				params[k] = v
			}
		}
		if kind, value := ruleTarget(method, params); value != "" {
			seen[Target{Kind: kind, Value: value}] = true
		}
	}
	out := make([]Target, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	return out
}

// IngestCoverageFromRules records which rule cites which CIS section and STIG vuln
// id by reading the rule corpus directly, the source of truth. It reuses the same
// internal/mappings normalization the engine uses, so coverage can never drift from
// how Kensa itself reads a rule's references. Replaces any prior stig/cis coverage.
func (s *Store) IngestCoverageFromRules(ctx context.Context, rulesDir string) (int, error) {
	var files []string
	err := filepath.WalkDir(rulesDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yml") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("catalog: walk rules %s: %w", rulesDir, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM coverage WHERE framework IN ('stig','cis')`); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rule_target`); err != nil {
		return 0, err
	}

	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return 0, fmt.Errorf("catalog: read rule %s: %w", f, err)
		}
		var rr ruleRefs
		if err := yaml.Unmarshal(data, &rr); err != nil {
			return 0, fmt.Errorf("catalog: parse rule %s: %w", f, err)
		}
		if rr.ID == "" {
			continue
		}
		for _, t := range ruleTargetsOf(rr) {
			if _, err := tx.ExecContext(ctx, `
                INSERT OR IGNORE INTO rule_target (rule_id, kind, value) VALUES (?, ?, ?)`,
				rr.ID, t.Kind, t.Value); err != nil {
				return 0, err
			}
		}
		for _, ref := range mappings.RefsFromReferences(rr.References) {
			framework, osID, ok := splitVersionedFramework(ref.FrameworkID)
			if !ok {
				continue // flat-list frameworks (nist_800_53, ...) have no per-os control join
			}
			if _, err := tx.ExecContext(ctx, `
                INSERT OR IGNORE INTO coverage (rule_id, framework, os, control_id)
                VALUES (?, ?, ?, ?)`, rr.ID, framework, osID, ref.ControlID); err != nil {
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

// splitVersionedFramework splits a versioned FrameworkID such as "cis_rhel9" into
// ("cis", "rhel9"). It returns ok=false for flat-list frameworks like
// "nist_800_53", which carry no os-version join key.
func splitVersionedFramework(frameworkID string) (framework, osID string, ok bool) {
	for _, fw := range []string{"cis", "stig"} {
		if strings.HasPrefix(frameworkID, fw+"_") {
			return fw, frameworkID[len(fw)+1:], true
		}
	}
	return "", "", false
}
