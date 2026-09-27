package kensa

import (
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/varsub"
)

// These tests pin behavior of the directory loaders that the full-corpus
// tests cannot see: how explicit paths combine with a directory walk, the
// exact failure of each strict case, and the deliberately lenient behavior of
// RuleVariables. They were recorded against the loaders as they stood before
// the file-tree variants were added, and must keep passing unchanged.

func ruleWithID(id string) string {
	return strings.Replace(plainRule, "plain-rule", id, 1)
}

func ruleIDs(t *testing.T, rules []*api.Rule) []string {
	t.Helper()
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

// TestLoadRulesInputContract covers how LoadRules orders and combines a
// directory walk with explicit paths.
//
// @spec rule-public-loader
func TestLoadRulesInputContract(t *testing.T) {
	t.Run("rule-public-loader/AC-07", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-07
		dir := t.TempDir()
		writeRule(t, dir, "a/x.yml", ruleWithID("a-x"))
		writeRule(t, dir, "a-b/y.yml", ruleWithID("ab-y"))
		writeRule(t, dir, "b.yml", ruleWithID("b"))
		extra := t.TempDir()
		p1 := writeRule(t, extra, "p1.yml", ruleWithID("p1"))
		p2 := writeRule(t, extra, "p2.yml", ruleWithID("p2"))
		inDir := filepath.Join(dir, "b.yml")

		cases := []struct {
			name  string
			dir   string
			paths []string
			want  []string
		}{
			// Order is a sort of the full path strings, not walk order:
			// "a-b/" sorts before "a/" because '-' (0x2D) < '/' (0x2F).
			{"dir only, byte-sorted", dir, nil, []string{"ab-y", "a-x", "b"}},
			// Explicit paths alone skip the walk and keep the given order.
			{"paths only, order kept", "", []string{p2, p1}, []string{"p2", "p1"}},
			// Explicit paths come after the walk, in the given order.
			{"dir then paths", dir, []string{p2, p1}, []string{"ab-y", "a-x", "b", "p2", "p1"}},
			// No de-duplication: a path also under dir loads twice.
			{"duplicate path", dir, []string{inDir}, []string{"ab-y", "a-x", "b", "b"}},
		}
		for _, c := range cases {
			rules, err := LoadRules(c.dir, c.paths, nil)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if got := ruleIDs(t, rules); !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s: order %v, want %v", c.name, got, c.want)
			}
		}
	})
}

// TestLoadRulesFailureContract pins each strict failure as it stands:
// message form, the file named where there is one, and which sentinel holds.
//
// @spec rule-public-loader
func TestLoadRulesFailureContract(t *testing.T) {
	t.Run("rule-public-loader/AC-08", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-08
		root := t.TempDir()

		malformedDir := filepath.Join(root, "malformed")
		malformed := writeRule(t, malformedDir, "t/x.yml", "id: [unclosed\n")
		unknownDir := filepath.Join(root, "unknown")
		unknown := writeRule(t, unknownDir, "t/x.yml", orphanVarRule)
		emptyDir := filepath.Join(root, "empty")
		writeRule(t, emptyDir, "notes.txt", "not a rule")
		missingPath := filepath.Join(root, "nope.yml")
		missingDir := filepath.Join(root, "nodir")

		cases := []struct {
			name      string
			dir       string
			paths     []string
			prefix    string
			contains  []string
			undefined bool
			notExist  bool
		}{
			{"malformed YAML", malformedDir, nil,
				"parse " + malformed + ": rule: yaml decode: ", nil, false, false},
			{"unknown variable", unknownDir, nil,
				"parse " + unknown + ": rule: " + unknown + ": ",
				[]string{"no_such_variable_xyz"}, true, false},
			{"empty tree", emptyDir, nil,
				"no *.yml files found in " + emptyDir, nil, false, false},
			{"missing explicit path", "", []string{missingPath},
				"parse " + missingPath + `: rule: open "` + missingPath + `": `, nil, false, true},
			{"missing dir", missingDir, nil,
				"walk " + missingDir + ": ", nil, false, true},
		}
		for _, c := range cases {
			for _, loader := range []struct {
				name string
				run  func() error
			}{
				{"LoadRules", func() error { _, err := LoadRules(c.dir, c.paths, nil); return err }},
				{"LoadRuleSummaries", func() error { _, err := LoadRuleSummaries(c.dir, c.paths, nil); return err }},
			} {
				err := loader.run()
				if err == nil {
					t.Errorf("%s/%s: no error", loader.name, c.name)
					continue
				}
				msg := err.Error()
				if !strings.HasPrefix(msg, c.prefix) {
					t.Errorf("%s/%s: message %q, want prefix %q", loader.name, c.name, msg, c.prefix)
				}
				if c.name == "empty tree" && msg != c.prefix {
					t.Errorf("%s/%s: message %q, want exactly %q", loader.name, c.name, msg, c.prefix)
				}
				for _, s := range c.contains {
					if !strings.Contains(msg, s) {
						t.Errorf("%s/%s: message %q does not name %q", loader.name, c.name, msg, s)
					}
				}
				if got := errors.Is(err, varsub.ErrUndefined); got != c.undefined {
					t.Errorf("%s/%s: errors.Is ErrUndefined = %v, want %v", loader.name, c.name, got, c.undefined)
				}
				if got := errors.Is(err, fs.ErrNotExist); got != c.notExist {
					t.Errorf("%s/%s: errors.Is ErrNotExist = %v, want %v", loader.name, c.name, got, c.notExist)
				}
			}
		}
	})
}

// TestRuleVariablesLenientContract pins that RuleVariables reads templates
// textually and never fails on rule content, unlike LoadRules.
//
// @spec rule-public-loader
func TestRuleVariablesLenientContract(t *testing.T) {
	t.Run("rule-public-loader/AC-09", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-09
		dir := t.TempDir()
		// An undefined variable is reported, not an error.
		writeRule(t, dir, "t/orphan.yml", orphanVarRule)
		// Undecodable YAML with a template falls back to the filename stem.
		writeRule(t, dir, "t/broken-file.yml", "id: [bad {{ shared_var }}\n")
		// Two decodable rules share a variable; ids come back sorted.
		writeRule(t, dir, "t/z.yml", "id: zz-rule\nx: '{{ shared_var }}'\n")
		writeRule(t, dir, "t/a.yml", "id: aa-rule\nx: '{{ shared_var }}'\n")
		// No templates: omitted.
		writeRule(t, dir, "t/plain.yml", plainRule)

		got, err := RuleVariables(dir)
		if err != nil {
			t.Fatalf("RuleVariables: %v", err)
		}
		want := map[string][]string{
			"no_such_variable_xyz": {"orphan-var-rule"},
			"shared_var":           {"aa-rule", "broken-file", "zz-rule"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("RuleVariables = %v, want %v", got, want)
		}

		// An existing directory with no rule files is an empty map, not an
		// error (LoadRules errors on the same directory).
		empty := t.TempDir()
		writeRule(t, empty, "notes.txt", "not a rule")
		got, err = RuleVariables(empty)
		if err != nil {
			t.Fatalf("RuleVariables(empty): %v", err)
		}
		if len(got) != 0 {
			t.Errorf("RuleVariables(empty) = %v, want empty", got)
		}
	})
}
