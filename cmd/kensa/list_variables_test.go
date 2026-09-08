// Tests for `kensa list variables`.
//
// The command joins two sources: which variables the corpus references, and
// what Kensa embeds for them. Every test drives the real runCLI dispatcher
// against real temporary files, because the command's external boundary is the
// filesystem and there is no transport to fake.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/varsub"
	"github.com/Hanalyx/kensa/pkg/kensa"
)

// ruleWithTemplates writes one valid rule whose check.expected carries the
// given raw text, so a template reaches the corpus through a field the parser
// accepts.
func ruleWithTemplates(t *testing.T, dir, id, expected, extra string) {
	t.Helper()
	body := "id: " + id + `
title: Test rule
description: minimal rule
rationale: minimal rule
severity: low
category: system
tags: [test]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: command
      run: "true"
      expected_exit: 0
      expected: ` + expected + extra + `

references:
  cis:
    rhel9:
      section: "5.1.1"
`
	if err := os.WriteFile(filepath.Join(dir, id+".yml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", id, err)
	}
}

// typedVariableCorpus is the shared fixture: one list variable that ships
// empty, one integer, one string whose default has a leading zero, one site
// variable Kensa knows nothing about, and one declared string whose value
// contains commas.
func typedVariableCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ruleWithTemplates(t, dir, "accounts-rule", `"{{ authorized_local_accounts }}"`, "")
	ruleWithTemplates(t, dir, "a-rule", `"{{ pam_faillock_deny }}"`, "")
	// z-rule names pam_faillock_deny twice, so dedup is exercised, and adds a
	// second distinct variable.
	ruleWithTemplates(t, dir, "z-rule", `"{{ pam_faillock_deny }}:{{ pam_faillock_deny }}:{{ root_umask }}"`, "")
	ruleWithTemplates(t, dir, "custom-rule", `"{{ site_custom_threshold }}"`, "")
	ruleWithTemplates(t, dir, "ciphers-rule", `"{{ ssh_approved_ciphers }}"`, "")
	return dir
}

func runListVars(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	t.Setenv("KENSA_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())
	return runCLICapture(t, argv...)
}

// runCLICapture drives runCLI and returns exit code plus both streams.
func runCLICapture(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	outC, errC := make(chan string), make(chan string)
	go func() { outC <- readAll(rOut) }()
	go func() { errC <- readAll(rErr) }()
	code := runCLI(argv)
	_ = wOut.Close()
	_ = wErr.Close()
	stdout, stderr := <-outC, <-errC
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, stdout, stderr
}

type varDoc struct {
	Variables []struct {
		Default      json.RawMessage `json:"default"`
		DefaultState string          `json:"default_state"`
		Name         string          `json:"name"`
		Rules        []string        `json:"rules"`
		Type         *string         `json:"type"`
	} `json:"variables"`
}

// TestListVariables_JSONJoinsCorpusAndBuiltIns locks AC-01.
// @spec cli-list-variables
// @ac AC-01
func TestListVariables_JSONJoinsCorpusAndBuiltIns(t *testing.T) {
	t.Run("cli-list-variables/AC-01", func(t *testing.T) {})
	dir := typedVariableCorpus(t)
	code, stdout, stderr := runListVars(t, "list", "variables", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit=%d stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr must be empty; got:\n%s", stderr)
	}

	// Exact top-level and item key sets, read literally so a rename fails.
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &top); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if got := sortedKeys(top); !reflect.DeepEqual(got, []string{"variables"}) {
		t.Errorf("top-level keys = %v, want [variables]", got)
	}
	var items struct {
		Variables []map[string]json.RawMessage `json:"variables"`
	}
	if err := json.Unmarshal([]byte(stdout), &items); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	wantItemKeys := []string{"default", "default_state", "name", "rules", "type"}
	for i, it := range items.Variables {
		if got := sortedKeys(it); !reflect.DeepEqual(got, wantItemKeys) {
			t.Errorf("item %d keys = %v, want %v", i, got, wantItemKeys)
		}
	}

	var doc varDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode doc: %v", err)
	}
	type want struct {
		typ, def, state string
		rules           []string
	}
	expect := map[string]want{
		"authorized_local_accounts": {"list", `[]`, "empty", []string{"accounts-rule"}},
		"pam_faillock_deny":         {"integer", `3`, "value", []string{"a-rule", "z-rule"}},
		"root_umask":                {"string", `"027"`, "value", []string{"z-rule"}},
		"site_custom_threshold":     {"", `null`, "absent", []string{"custom-rule"}},
		"ssh_approved_ciphers": {"string",
			`"aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"`,
			"value", []string{"ciphers-rule"}},
	}
	if len(doc.Variables) != len(expect) {
		t.Fatalf("got %d variables, want %d:\n%s", len(doc.Variables), len(expect), stdout)
	}
	for _, v := range doc.Variables {
		w, ok := expect[v.Name]
		if !ok {
			t.Errorf("unexpected variable %q", v.Name)
			continue
		}
		gotType := ""
		if v.Type != nil {
			gotType = *v.Type
		}
		if gotType != w.typ {
			t.Errorf("%s: type=%q want %q", v.Name, gotType, w.typ)
		}
		if string(v.Default) != w.def {
			t.Errorf("%s: default=%s want %s", v.Name, v.Default, w.def)
		}
		if v.DefaultState != w.state {
			t.Errorf("%s: state=%q want %q", v.Name, v.DefaultState, w.state)
		}
		if !reflect.DeepEqual(v.Rules, w.rules) {
			t.Errorf("%s: rules=%v want %v", v.Name, v.Rules, w.rules)
		}
		delete(expect, v.Name)
	}
	for n := range expect {
		t.Errorf("variable %s missing from output", n)
	}
	if strings.Contains(stdout, "banner_text") {
		t.Error("unreferenced built-in banner_text must not appear")
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestListVariables_TextShowsSameValues locks AC-02.
// @spec cli-list-variables
// @ac AC-02
func TestListVariables_TextShowsSameValues(t *testing.T) {
	t.Run("cli-list-variables/AC-02", func(t *testing.T) {})
	dir := typedVariableCorpus(t)
	code, stdout, stderr := runListVars(t, "list", "variables", "--rules-dir", dir)
	if code != 0 {
		t.Fatalf("exit=%d stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "kensa list variables") {
		t.Errorf("missing heading:\n%s", stdout)
	}
	if !strings.Contains(stdout, "5 variable(s)") {
		t.Errorf("missing count line:\n%s", stdout)
	}
	for _, col := range []string{"variable", "type", "default", "state", "rules"} {
		if !strings.Contains(stdout, col) {
			t.Errorf("missing column %q", col)
		}
	}
	// Values render as JSON literals, so empty, absent, numeric and quoted
	// string defaults stay distinguishable in the human output too.
	for _, want := range []string{
		`authorized_local_accounts  list     []`,
		`pam_faillock_deny          integer  3`,
		`root_umask                 string   "027"`,
		`site_custom_threshold      untyped  null`,
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(stdout) {
			t.Errorf("missing row fragment %q in:\n%s", want, stdout)
		}
	}
	// The long declared string is present whole, commas intact, unclipped.
	if !strings.Contains(stdout, `"aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"`) {
		t.Errorf("cipher default truncated or split:\n%s", stdout)
	}
	for _, marker := range []string{"...", "…", "truncated"} {
		if strings.Contains(stdout, marker) {
			t.Errorf("output contains truncation marker %q", marker)
		}
	}
	// Order is by name.
	order := []string{"authorized_local_accounts", "pam_faillock_deny", "root_umask", "site_custom_threshold", "ssh_approved_ciphers"}
	last := -1
	for _, n := range order {
		i := strings.Index(stdout, n)
		if i < last {
			t.Errorf("rows not sorted by name: %s appears out of order", n)
		}
		last = i
	}
}

// TestListVariables_MembershipAndOrderIndependentOfFiles locks AC-03.
// @spec cli-list-variables
// @ac AC-03
func TestListVariables_MembershipAndOrderIndependentOfFiles(t *testing.T) {
	t.Run("cli-list-variables/AC-03", func(t *testing.T) {})
	// Two corpora with the same rules written in opposite filename order,
	// plus a rule with no template at all.
	build := func(t *testing.T, reverse bool) string {
		t.Helper()
		dir := t.TempDir()
		type r struct{ id, expected string }
		rules := []r{
			{"accounts-rule", `"{{ authorized_local_accounts }}"`},
			{"a-rule", `"{{ pam_faillock_deny }}"`},
			{"z-rule", `"{{ pam_faillock_deny }}:{{ pam_faillock_deny }}:{{ root_umask }}"`},
			{"custom-rule", `"{{ site_custom_threshold }}"`},
			{"ciphers-rule", `"{{ ssh_approved_ciphers }}"`},
		}
		if reverse {
			for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
		for _, x := range rules {
			ruleWithTemplates(t, dir, x.id, x.expected, "")
		}
		ruleWithTemplates(t, dir, "no-template-rule", `"0"`, "")
		return dir
	}

	_, a, _ := runListVars(t, "list", "variables", "--rules-dir", build(t, false), "--format", "json")
	_, b, _ := runListVars(t, "list", "variables", "--rules-dir", build(t, true), "--format", "json")
	if a != b {
		t.Errorf("output depends on corpus file order:\n--- A ---\n%s\n--- B ---\n%s", a, b)
	}

	var doc varDoc
	if err := json.Unmarshal([]byte(a), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var names []string
	for _, v := range doc.Variables {
		names = append(names, v.Name)
		if v.Name == "pam_faillock_deny" {
			// Named twice in one rule: one entry, not two.
			if !reflect.DeepEqual(v.Rules, []string{"a-rule", "z-rule"}) {
				t.Errorf("pam_faillock_deny rules = %v, want [a-rule z-rule]", v.Rules)
			}
		}
	}
	want := []string{"authorized_local_accounts", "pam_faillock_deny", "root_umask", "site_custom_threshold", "ssh_approved_ciphers"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("variable names = %v, want %v", names, want)
	}
	if strings.Contains(a, "no-template-rule") {
		t.Error("a rule with no template must contribute no row")
	}
	if strings.Contains(a, "banner_text") {
		t.Error("unreferenced built-in must not appear")
	}
}

// TestListVariables_IgnoresOperatorConfiguration locks AC-04.
//
// The poisoned config directories declare a value under a name the fixture
// uses. If any tier were read, that value would appear in stdout, so the test
// fails loudly rather than by a subtle count difference.
// @spec cli-list-variables
// @ac AC-04
func TestListVariables_IgnoresOperatorConfiguration(t *testing.T) {
	t.Run("cli-list-variables/AC-04", func(t *testing.T) {})
	// Not a credential: a marker string the test writes into a poisoned config
	// so it can prove the value never reaches output.
	const secret = "FOUNDER_SECRET_MUST_NOT_APPEAR" // pragma: allowlist secret
	dir := typedVariableCorpus(t)
	argv := []string{"list", "variables", "--rules-dir", dir, "--format", "json"}

	_, baseline, _ := runListVars(t, argv...)
	if strings.Contains(baseline, secret) {
		t.Fatal("fixture is contaminated")
	}

	poison := func(t *testing.T, nested string) string {
		t.Helper()
		root := t.TempDir()
		cfg := filepath.Join(root, nested)
		if err := os.MkdirAll(cfg, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// Both names are chosen so the poisoned file is VALID and passes type
		// checking: root_umask is a declared string, and site_custom_threshold
		// has no built-in and so is not type checked. A poison that failed
		// validation would abort the run and the test would pass for the wrong
		// reason, never proving that a readable operator value stays hidden.
		body := "variables:\n  root_umask: \"" + secret + "\"\n  site_custom_threshold: " + secret + "\n"
		if err := os.WriteFile(filepath.Join(cfg, "defaults.yml"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return root
	}

	runs := 1
	for _, c := range []struct {
		name, nested string
		apply        func(t *testing.T, root string)
	}{
		{"KENSA_CONFIG_DIR", ".", func(t *testing.T, root string) {
			t.Setenv("KENSA_CONFIG_DIR", root)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("HOME", t.TempDir())
		}},
		{"XDG_CONFIG_HOME", "kensa", func(t *testing.T, root string) {
			t.Setenv("XDG_CONFIG_HOME", root)
			t.Setenv("KENSA_CONFIG_DIR", "")
			t.Setenv("HOME", t.TempDir())
		}},
		{"HOME", ".config/kensa", func(t *testing.T, root string) {
			t.Setenv("HOME", root)
			t.Setenv("KENSA_CONFIG_DIR", "")
			t.Setenv("XDG_CONFIG_HOME", "")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.apply(t, poison(t, c.nested))
			code, stdout, stderr := runCLICapture(t, argv...)
			if code != 0 {
				t.Fatalf("exit=%d stderr:\n%s", code, stderr)
			}
			if stdout != baseline {
				t.Errorf("stdout changed under %s; operator configuration reached a corpus description", c.name)
			}
			if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
				t.Errorf("operator value disclosed under %s", c.name)
			}
			if strings.Contains(stderr, "defaults.yml") {
				t.Errorf("stderr mentions operator config under %s:\n%s", c.name, stderr)
			}
		})
		runs++
	}
	if runs != 4 {
		t.Errorf("ran %d configurations, want 4", runs)
	}
}

// TestListVariables_DispatchAndUsage locks AC-05.
// @spec cli-list-variables
// @ac AC-05
func TestListVariables_DispatchAndUsage(t *testing.T) {
	t.Run("cli-list-variables/AC-05", func(t *testing.T) {})
	dir := typedVariableCorpus(t)

	t.Run("parent_help", func(t *testing.T) {
		code, stdout, _ := runListVars(t, "list", "--help")
		if code != 0 {
			t.Errorf("exit=%d want 0", code)
		}
		for _, s := range []string{"frameworks", "sessions", "variables"} {
			if !strings.Contains(stdout, s) {
				t.Errorf("parent help missing subject %q", s)
			}
		}
	})
	t.Run("subject_help", func(t *testing.T) {
		code, stdout, _ := runListVars(t, "list", "variables", "--help")
		if code != 0 {
			t.Errorf("exit=%d want 0", code)
		}
		for _, s := range []string{"kensa list variables", "--rules-dir", "--format", "--quiet"} {
			if !strings.Contains(stdout, s) {
				t.Errorf("subject help missing %q", s)
			}
		}
		for _, s := range []string{"--config-dir", "--var", "--host"} {
			if strings.Contains(stdout, s) {
				t.Errorf("subject help must not offer %q", s)
			}
		}
	})
	for _, c := range []struct {
		name     string
		argv     []string
		wantCode int
		stderrIn []string
	}{
		{"missing_rules_dir", []string{"list", "variables"}, 2, []string{"--rules-dir"}},
		{"invalid_format", []string{"list", "variables", "--rules-dir", dir, "--format", "yaml"}, 2, []string{"text", "json"}},
		{"forbidden_config", []string{"list", "variables", "--rules-dir", dir, "--config-dir", "x"}, 2, nil},
		{"forbidden_var", []string{"list", "variables", "--rules-dir", dir, "--var", "x=1"}, 2, nil},
		{"missing_subject", []string{"list"}, 2, []string{"frameworks", "sessions", "variables"}},
		{"unknown_subject", []string{"list", "widgets"}, 2, []string{"frameworks", "sessions", "variables"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := runListVars(t, c.argv...)
			if code != c.wantCode {
				t.Errorf("exit=%d want %d; stderr:\n%s", code, c.wantCode, stderr)
			}
			for _, s := range c.stderrIn {
				if !strings.Contains(stderr, s) {
					t.Errorf("stderr missing %q; got:\n%s", s, stderr)
				}
			}
		})
	}
	t.Run("flag_before_subject", func(t *testing.T) {
		code, _, stderr := runListVars(t, "list", "--rules-dir", dir)
		if code != 2 {
			t.Errorf("exit=%d want 2", code)
		}
		if !strings.Contains(stderr, "missing 'list' subject") {
			t.Errorf("stderr missing the subject hint:\n%s", stderr)
		}
		for _, s := range []string{"frameworks", "sessions", "variables"} {
			if !strings.Contains(stderr, s) {
				t.Errorf("stderr must list subject %q; got:\n%s", s, stderr)
			}
		}
		// The old hint guessed one subject. Several take --rules-dir now, so
		// a guess would be a coin flip.
		if strings.Contains(stderr, "did you mean 'kensa list frameworks") {
			t.Errorf("stderr still guesses a subject:\n%s", stderr)
		}
	})
	t.Run("quiet", func(t *testing.T) {
		code, stdout, _ := runListVars(t, "list", "variables", "--rules-dir", dir, "--quiet")
		if code != 0 {
			t.Errorf("exit=%d want 0", code)
		}
		if stdout != "" {
			t.Errorf("--quiet must suppress stdout; got:\n%s", stdout)
		}
	})
}

// TestListVariables_EmptyCorpus locks AC-06.
// @spec cli-list-variables
// @ac AC-06
func TestListVariables_EmptyCorpus(t *testing.T) {
	t.Run("cli-list-variables/AC-06", func(t *testing.T) {})
	dir := t.TempDir()
	ruleWithTemplates(t, dir, "no-template-rule", `"0"`, "")

	code, stdout, stderr := runListVars(t, "list", "variables", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit=%d stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr must be empty; got:\n%s", stderr)
	}
	// An empty collection, not null and not every embedded built-in.
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &top); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if got := sortedKeys(top); !reflect.DeepEqual(got, []string{"variables"}) {
		t.Errorf("top keys = %v, want [variables]", got)
	}
	var doc varDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode doc: %v", err)
	}
	if len(doc.Variables) != 0 {
		t.Errorf("want an empty collection, got %d variables", len(doc.Variables))
	}
	if strings.Contains(stdout, "null") {
		t.Errorf("variables must serialize as [], not null:\n%s", stdout)
	}

	code, stdout, _ = runListVars(t, "list", "variables", "--rules-dir", dir)
	if code != 0 {
		t.Errorf("text exit=%d want 0", code)
	}
	if !strings.Contains(stdout, "kensa list variables") ||
		!strings.Contains(stdout, "no variables referenced by the loaded corpus") {
		t.Errorf("text form missing empty-corpus message:\n%s", stdout)
	}
}

// TestListVariables_ShippedCorpusMatchesIndependentModel locks AC-07.
//
// The expected model is derived without calling RuleVariables: the corpus is
// walked here, templates are extracted with the documented syntax, and rule
// IDs are decoded from the YAML. Reusing RuleVariables would compare the
// command against itself.
// @spec cli-list-variables
// @ac AC-07
func TestListVariables_ShippedCorpusMatchesIndependentModel(t *testing.T) {
	t.Run("cli-list-variables/AC-07", func(t *testing.T) {})
	dir := repoRulesDirForVars(t)

	tmplRe := regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	idRe := regexp.MustCompile(`(?m)^id:[ \t]*["']?([A-Za-z0-9_.-]+)["']?[ \t]*$`)
	expected := map[string]map[string]struct{}{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		id := strings.TrimSuffix(filepath.Base(path), ".yml")
		if m := idRe.FindSubmatch(raw); m != nil {
			id = string(m[1])
		}
		for _, m := range tmplRe.FindAllSubmatch(raw, -1) {
			name := string(m[1])
			if expected[name] == nil {
				expected[name] = map[string]struct{}{}
			}
			expected[name][id] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(expected) == 0 {
		t.Fatal("independent model found no variables")
	}

	defaults, err := kensa.BuiltInVars()
	if err != nil {
		t.Fatalf("BuiltInVars: %v", err)
	}
	types, err := varsub.BuiltInTypes()
	if err != nil {
		t.Fatalf("BuiltInTypes: %v", err)
	}

	code, stdout, stderr := runListVars(t, "list", "variables", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit=%d stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr must be empty; got:\n%s", stderr)
	}
	var doc varDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	got := map[string]bool{}
	for _, v := range doc.Variables {
		got[v.Name] = true
		want, ok := expected[v.Name]
		if !ok {
			t.Errorf("%s is reported but no rule references it", v.Name)
			continue
		}
		wantRules := make([]string, 0, len(want))
		for r := range want {
			wantRules = append(wantRules, r)
		}
		sort.Strings(wantRules)
		if !reflect.DeepEqual(v.Rules, wantRules) {
			t.Errorf("%s rules = %v, want %v", v.Name, v.Rules, wantRules)
		}
		raw, hasDefault := defaults[v.Name]
		if !hasDefault {
			if v.Type != nil || string(v.Default) != "null" || v.DefaultState != "absent" {
				t.Errorf("%s has no built-in; want null type/default and absent state, got type=%v default=%s state=%s",
					v.Name, v.Type, v.Default, v.DefaultState)
			}
			continue
		}
		if v.Type == nil || *v.Type != string(types[v.Name]) {
			t.Errorf("%s type = %v, want %s", v.Name, v.Type, types[v.Name])
		}
		wantState := "value"
		if raw == "" {
			wantState = "empty"
		}
		if v.DefaultState != wantState {
			t.Errorf("%s state = %s, want %s (raw %q)", v.Name, v.DefaultState, wantState, raw)
		}
	}
	for name := range expected {
		if !got[name] {
			t.Errorf("%s is referenced by the corpus but missing from output", name)
		}
	}
	for b := range defaults {
		if _, referenced := expected[b]; !referenced && got[b] {
			t.Errorf("unreferenced built-in %s must not appear", b)
		}
	}
}

func repoRulesDirForVars(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("shipped corpus absent: %v", err)
	}
	return dir
}

// TestTypedDefault_ConversionContract locks AC-08 at the conversion boundary,
// including the declarations no shipped variable currently exercises.
// @spec cli-list-variables
// @ac AC-08
func TestTypedDefault_ConversionContract(t *testing.T) {
	t.Run("cli-list-variables/AC-08", func(t *testing.T) {})
	for _, c := range []struct {
		name      string
		declared  varsub.VarType
		raw       string
		wantJSON  string
		wantState string
	}{
		{"positive-int", varsub.TypeInt, "3", `3`, "value"},
		{"negative-int", varsub.TypeInt, "-1", `-1`, "value"},
		{"leading-zero-string", varsub.TypeString, "027", `"027"`, "value"},
		{"multiline-string", varsub.TypeString, "line one\nline two\n", `"line one\nline two\n"`, "value"},
		{"nonempty-list", varsub.TypeList, "alice,bob", `["alice","bob"]`, "value"},
		{"empty-list", varsub.TypeList, "", `[]`, "empty"},
		{"empty-string", varsub.TypeString, "", `""`, "empty"},
		// A declared string whose value contains commas must stay one string.
		{"comma-bearing-string", varsub.TypeString, "a,b,c", `"a,b,c"`, "value"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, state, err := typedDefault(c.name, c.declared, c.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			enc, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(enc) != c.wantJSON {
				t.Errorf("json = %s, want %s", enc, c.wantJSON)
			}
			if state != c.wantState {
				t.Errorf("state = %s, want %s", state, c.wantState)
			}
		})
	}

	// Inconsistent metadata is an error, never a guess.
	t.Run("integer-with-non-integer-default", func(t *testing.T) {
		if _, _, err := typedDefault("bad", varsub.TypeInt, "not-an-integer"); err == nil {
			t.Error("want an error for a non-integer default declared integer")
		}
	})
	t.Run("list-member-with-whitespace", func(t *testing.T) {
		if _, _, err := typedDefault("bad", varsub.TypeList, "malformed, member"); err == nil {
			t.Error("want an error for a list member carrying surrounding whitespace")
		}
	})
	t.Run("absent-row-has-null-type-and-default", func(t *testing.T) {
		rows, err := buildVariableRows(
			map[string][]string{"site_only": {"r"}},
			map[string]string{}, map[string]varsub.VarType{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rows) != 1 || rows[0].Type != nil || rows[0].Default != nil || rows[0].DefaultState != "absent" {
			t.Errorf("absent row = %+v", rows[0])
		}
	})
	t.Run("type-without-default-is-inconsistent", func(t *testing.T) {
		_, err := buildVariableRows(
			map[string][]string{"v": {"r"}},
			map[string]string{},
			map[string]varsub.VarType{"v": varsub.TypeInt})
		if err == nil {
			t.Error("want an error when a type exists with no default")
		}
	})
}

// TestListVariables_NoPartialDocumentOnConversionError locks the second half
// of AC-08: a conversion failure must produce no JSON at all, so a consumer
// cannot parse a truncated document as complete.
// @spec cli-list-variables
// @ac AC-08
func TestListVariables_NoPartialDocumentOnConversionError(t *testing.T) {
	t.Run("cli-list-variables/AC-08", func(t *testing.T) {})
	rows, err := buildVariableRows(
		map[string][]string{"aaa_first": {"r1"}, "zzz_bad": {"r2"}},
		map[string]string{"aaa_first": "1", "zzz_bad": "not-an-int"},
		map[string]varsub.VarType{"aaa_first": varsub.TypeInt, "zzz_bad": varsub.TypeInt},
	)
	if err == nil {
		t.Fatal("want an error when a later row fails conversion")
	}
	// aaa_first converts before zzz_bad fails. Returning the rows built so far
	// would let a careless caller marshal a document that looks complete and
	// silently omits the rest of the corpus, so the failure must return none.
	if rows != nil {
		t.Errorf("a conversion failure must return no rows; got %d", len(rows))
	}
	if !strings.Contains(err.Error(), "zzz_bad") {
		t.Errorf("error should name the offending variable; got %v", err)
	}
}

// TestSortedUnique_NormalizesRuleIDs covers the rule-ID normalization
// directly.
//
// It is tested here rather than through the CLI on purpose: RuleVariables
// already sorts, and varsub.Names already dedups per rule, so no corpus can
// drive an unsorted or duplicated slice into this function today. The
// normalization stays because the command's own contract promises sorted,
// deduplicated rule IDs, and that promise should not rest on an upstream
// implementation detail that is free to change.
// @spec cli-list-variables
// @ac AC-03
func TestSortedUnique_NormalizesRuleIDs(t *testing.T) {
	t.Run("cli-list-variables/AC-03", func(t *testing.T) {})
	got := sortedUnique([]string{"z-rule", "a-rule", "z-rule", "m-rule", "a-rule"})
	want := []string{"a-rule", "m-rule", "z-rule"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedUnique = %v, want %v", got, want)
	}
	if n := len(sortedUnique(nil)); n != 0 {
		t.Errorf("sortedUnique(nil) length = %d, want 0", n)
	}
}
