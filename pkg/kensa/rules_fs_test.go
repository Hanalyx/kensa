package kensa

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Hanalyx/kensa/internal/varsub"
)

// corpusDir is the repository's rule corpus. The file-tree loaders are
// compared with the directory loaders over it through os.DirFS; that the
// embedded tree holds the same files is proven in package rules.
func corpusDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sortRefs orders each summary's FrameworkRefs. Their order comes from map
// iteration and is not stable between runs, so two loads of the same corpus
// can only be compared once it is normalized.
func sortRefs(t *testing.T, s []RuleSummary) []RuleSummary {
	t.Helper()
	for i := range s {
		refs := s[i].FrameworkRefs
		sort.SliceStable(refs, func(a, b int) bool {
			return mustJSON(t, refs[a]) < mustJSON(t, refs[b])
		})
	}
	return s
}

// TestFSLoadersMatchDirLoaders covers parity between the file-tree and
// directory loaders.
//
// @spec rule-public-loader
func TestFSLoadersMatchDirLoaders(t *testing.T) {
	t.Run("rule-public-loader/AC-10", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-10
		dir := corpusDir(t)
		fsys := os.DirFS(dir)

		for _, vars := range []map[string]string{nil, {"pam_faillock_deny": "7"}} {
			fromDir, err := LoadRules(dir, nil, vars)
			if err != nil {
				t.Fatal(err)
			}
			fromFS, err := LoadRulesFS(fsys, vars)
			if err != nil {
				t.Fatal(err)
			}
			if len(fromFS) == 0 || len(fromFS) != countCorpusRuleFiles(t, dir) {
				t.Fatalf("LoadRulesFS loaded %d rules, corpus has %d files", len(fromFS), countCorpusRuleFiles(t, dir))
			}
			if mustJSON(t, fromDir) != mustJSON(t, fromFS) {
				t.Errorf("LoadRules and LoadRulesFS differ (vars %v)", vars)
			}
		}

		vDir, err := RuleVariables(dir)
		if err != nil {
			t.Fatal(err)
		}
		vFS, err := RuleVariablesFS(fsys)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(vDir, vFS) {
			t.Error("RuleVariables and RuleVariablesFS differ")
		}

		sDir, err := LoadRuleSummaries(dir, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		sFS, err := LoadRuleSummariesFS(fsys, nil)
		if err != nil {
			t.Fatal(err)
		}
		if mustJSON(t, sortRefs(t, sDir)) != mustJSON(t, sortRefs(t, sFS)) {
			t.Error("LoadRuleSummaries and LoadRuleSummariesFS differ")
		}

		// Order is a sort of full paths, as in the directory walk: "a-b/"
		// sorts before "a/". Caller variables win over built-in defaults.
		tree := fstest.MapFS{
			"a/x.yml":   {Data: []byte(ruleWithID("a-x"))},
			"a-b/y.yml": {Data: []byte(ruleWithID("ab-y"))},
			"b.yml":     {Data: []byte(ruleWithID("b"))},
			"t.yml":     {Data: []byte(templatedRule)},
			"notes.txt": {Data: []byte("not a rule")},
		}
		got, err := LoadRulesFS(tree, map[string]string{"pam_faillock_deny": "9"})
		if err != nil {
			t.Fatal(err)
		}
		if ids := ruleIDs(t, got); !reflect.DeepEqual(ids, []string{"ab-y", "a-x", "b", "templated-rule"}) {
			t.Errorf("order %v", ids)
		}
		if !strings.Contains(mustJSON(t, got[3]), `"9"`) {
			t.Errorf("caller variable did not win: %s", mustJSON(t, got[3]))
		}
	})
}

// TestLoadRulesFSFailures pins each strict failure of the file-tree loaders.
//
// @spec rule-public-loader
func TestLoadRulesFSFailures(t *testing.T) {
	t.Run("rule-public-loader/AC-11", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-11
		cases := []struct {
			name      string
			fsys      fs.FS
			prefix    string
			exact     bool
			contains  []string
			undefined bool
		}{
			{"malformed YAML",
				fstest.MapFS{"t/x.yml": {Data: []byte("id: [unclosed\n")}},
				"parse t/x.yml: rule: yaml decode: ", false, nil, false},
			{"unknown variable",
				fstest.MapFS{"t/x.yml": {Data: []byte(orphanVarRule)}},
				"parse t/x.yml: rule: t/x.yml: ", false, []string{"no_such_variable_xyz"}, true},
			{"empty tree",
				fstest.MapFS{"notes.txt": {Data: []byte("not a rule")}},
				"no *.yml files found in the rule file tree", true, nil, false},
			{"nil tree", nil, "nil rule file tree", true, nil, false},
		}
		for _, c := range cases {
			for _, loader := range []struct {
				name string
				run  func() error
			}{
				{"LoadRulesFS", func() error { _, err := LoadRulesFS(c.fsys, nil); return err }},
				{"LoadRuleSummariesFS", func() error { _, err := LoadRuleSummariesFS(c.fsys, nil); return err }},
			} {
				err := loader.run()
				if err == nil {
					t.Errorf("%s/%s: no error", loader.name, c.name)
					continue
				}
				msg := err.Error()
				if c.exact && msg != c.prefix {
					t.Errorf("%s/%s: message %q, want %q", loader.name, c.name, msg, c.prefix)
				}
				if !strings.HasPrefix(msg, c.prefix) {
					t.Errorf("%s/%s: message %q, want prefix %q", loader.name, c.name, msg, c.prefix)
				}
				for _, s := range c.contains {
					if !strings.Contains(msg, s) {
						t.Errorf("%s/%s: message %q does not name %q", loader.name, c.name, msg, s)
					}
				}
				if got := errors.Is(err, varsub.ErrUndefined); got != c.undefined {
					t.Errorf("%s/%s: errors.Is ErrUndefined = %v, want %v", loader.name, c.name, got, c.undefined)
				}
				if errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s/%s: unexpected ErrNotExist", loader.name, c.name)
				}
			}
		}
		// A strict failure anywhere fails the whole load: a good file next to
		// a bad one yields no rules.
		mixed := fstest.MapFS{
			"a.yml": {Data: []byte(ruleWithID("good"))},
			"b.yml": {Data: []byte("id: [unclosed\n")},
		}
		if rules, err := LoadRulesFS(mixed, nil); err == nil || rules != nil {
			t.Errorf("mixed tree: rules %v, err %v; want nil rules and an error", rules, err)
		}
	})
}

// TestRuleVariablesFSLenient pins that RuleVariablesFS is as lenient as
// RuleVariables.
//
// @spec rule-public-loader
func TestRuleVariablesFSLenient(t *testing.T) {
	t.Run("rule-public-loader/AC-12", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-12
		tree := fstest.MapFS{
			"t/orphan.yml":      {Data: []byte(orphanVarRule)},
			"t/broken-file.yml": {Data: []byte("id: [bad {{ shared_var }}\n")},
			"t/z.yml":           {Data: []byte("id: zz-rule\nx: '{{ shared_var }}'\n")},
			"t/a.yml":           {Data: []byte("id: aa-rule\nx: '{{ shared_var }}'\n")},
			"t/plain.yml":       {Data: []byte(plainRule)},
		}
		got, err := RuleVariablesFS(tree)
		if err != nil {
			t.Fatalf("RuleVariablesFS: %v", err)
		}
		want := map[string][]string{
			"no_such_variable_xyz": {"orphan-var-rule"},
			"shared_var":           {"aa-rule", "broken-file", "zz-rule"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("RuleVariablesFS = %v, want %v", got, want)
		}
		got, err = RuleVariablesFS(fstest.MapFS{"notes.txt": {Data: []byte("x")}})
		if err != nil || len(got) != 0 {
			t.Errorf("RuleVariablesFS(empty) = %v, %v; want empty map, nil", got, err)
		}
		if _, err := RuleVariablesFS(nil); err == nil {
			t.Error("RuleVariablesFS(nil): no error")
		}
	})
}

// TestLoadRuleSummariesFSReusesLoadRulesFS covers the read-model projection
// of the file-tree loader.
//
// @spec rule-read-model
func TestLoadRuleSummariesFSReusesLoadRulesFS(t *testing.T) {
	t.Run("rule-read-model/AC-08", func(t *testing.T) {
		// @spec rule-read-model
		// @ac AC-08
		tree := fstest.MapFS{
			"b.yml": {Data: []byte(ruleWithID("second"))},
			"a.yml": {Data: []byte(ruleWithID("first"))},
		}
		rules, err := LoadRulesFS(tree, nil)
		if err != nil {
			t.Fatal(err)
		}
		sums, err := LoadRuleSummariesFS(tree, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]RuleSummary, len(rules))
		for i, r := range rules {
			want[i] = RuleToSummary(r)
		}
		if mustJSON(t, sortRefs(t, sums)) != mustJSON(t, sortRefs(t, want)) {
			t.Errorf("LoadRuleSummariesFS differs from RuleToSummary over LoadRulesFS")
		}
	})
}
