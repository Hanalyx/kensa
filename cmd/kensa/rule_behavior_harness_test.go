package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/transport/local"
	"github.com/Hanalyx/kensa/internal/check"
)

// Full-spectrum behavioral harness (gap fix 4/5). For each fixture under
// fixtures/rules/, it materializes the case's file content to a temp file,
// points the rule's file-based check at it, runs the REAL check engine over a
// local (no-sudo) transport, and asserts the verdict. This is what proves a
// rule's check actually distinguishes compliant from non-compliant inputs and
// handles edge cases — the gap that let comparator/delimiter rules ship broken.

type fixtureCase struct {
	Name    string `yaml:"name"`
	Content string `yaml:"content"`
	Want    string `yaml:"want"` // "pass" | "fail"
}

type ruleFixture struct {
	Rule   string            `yaml:"rule"`   // corpus rule id (traceability)
	Method string            `yaml:"method"` // file-based check method
	Params map[string]string `yaml:"params"` // resolved check params (path is injected)
	Cases  []fixtureCase     `yaml:"cases"`
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "fixtures", "rules")
}

func loadFixtures(t *testing.T) []ruleFixture {
	t.Helper()
	dir := fixtureDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	var out []ruleFixture
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		var f ruleFixture
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := yaml.Unmarshal(b, &f); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		out = append(out, f)
	}
	return out
}

// TestRuleBehaviorFixtures runs every fixture's good/bad/edge cases through the
// real check engine and asserts the verdict.
//
// @spec behavior-harness
// @ac AC-01
func TestRuleBehaviorFixtures(t *testing.T) {
	t.Run("behavior-harness/AC-01", func(t *testing.T) {})
	tr := local.New() // no sudo: temp files under the test's TempDir
	ctx := context.Background()

	for _, f := range loadFixtures(t) {
		for _, c := range f.Cases {
			t.Run(f.Rule+"/"+c.Name, func(t *testing.T) {
				tmp := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(tmp, []byte(c.Content), 0o644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				params := api.Params{"path": tmp}
				for k, v := range f.Params {
					params[k] = v
				}
				res, err := check.Run(ctx, tr, api.Check{Method: f.Method, Params: params})
				if err != nil {
					t.Fatalf("check.Run: %v", err)
				}
				want := c.Want == "pass"
				if res.Passed != want {
					t.Errorf("%s/%s: got passed=%v want %v (detail=%q)", f.Rule, c.Name, res.Passed, want, res.Detail)
				}
			})
		}
	}
}

// TestRuleBehaviorFixtureCoverageRatchet enforces that the set of rules with a
// behavioral fixture only grows. coveredRulesFloor is bumped up as fixtures are
// added; it may never be lowered — so behavioral coverage cannot regress, and
// the long tail of corpus rules is driven toward full coverage.
//
// @spec behavior-harness
// @ac AC-02
func TestRuleBehaviorFixtureCoverageRatchet(t *testing.T) {
	t.Run("behavior-harness/AC-02", func(t *testing.T) {})
	const coveredRulesFloor = 3 // raise as fixtures are added; never lower

	covered := map[string]bool{}
	for _, f := range loadFixtures(t) {
		if f.Rule == "" || f.Method == "" || len(f.Cases) == 0 {
			t.Errorf("fixture for %q is incomplete (rule/method/cases required)", f.Rule)
		}
		covered[f.Rule] = true
	}
	// every fixtured rule must exist in the corpus.
	corpus := map[string]bool{}
	for _, r := range loadCorpusRules(t) {
		corpus[r.ID] = true
	}
	var missing []string
	for id := range covered {
		if !corpus[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("fixtures reference non-existent rules: %v", missing)
	}
	if len(covered) < coveredRulesFloor {
		t.Errorf("behavioral fixture coverage regressed: %d rules covered, floor is %d", len(covered), coveredRulesFloor)
	}
}
