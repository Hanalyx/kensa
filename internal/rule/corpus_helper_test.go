package rule

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// repoRulesDir locates the in-repo rules/ corpus relative to this test file
// (internal/rule/ -> ../../rules), independent of the working directory.
func repoRulesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("cannot determine caller path")
	}
	dir := filepath.Join(filepath.Dir(file), "..", "..", "rules")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("rules corpus not found at %s: %v", dir, err)
	}
	return dir
}

// loadCorpus parses every rule in the in-repo corpus into a map keyed by rule ID.
func loadCorpus(t *testing.T) map[string]*api.Rule {
	t.Helper()
	dir := repoRulesDir(t)
	out := make(map[string]*api.Rule)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}
		r, perr := ParseFile(path)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		out[r.ID] = r
		return nil
	})
	if err != nil {
		t.Fatalf("walk corpus: %v", err)
	}
	return out
}

// TestCorpusConformsToParamContract is the Layer-2 corpus gate: every rule in
// the corpus must satisfy its mechanism parameter contract, except the
// documented allowlist (knownNonConformingRules). New non-conforming rules fail
// here (and in kensa-validate, which runs the same check).
//
// @spec rule-param-contract
// @ac AC-04
func TestCorpusConformsToParamContract(t *testing.T) {
	t.Run("rule-param-contract/AC-04", func(t *testing.T) {})
	for id, r := range loadCorpus(t) {
		if errs := RemediationParamErrors(r); len(errs) != 0 {
			for _, e := range errs {
				t.Errorf("%s: %s", id, e.Error())
			}
		}
	}
}
