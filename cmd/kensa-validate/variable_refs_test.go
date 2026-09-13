package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A rule reaches the engine only after every {{ name }} in it resolves, so a
// name nobody defines makes the rule vanish at scan time rather than fail at
// authoring time. These tests hold the validator's side of that: it names the
// unresolved references while it still has the author's attention.
//
// The references are found in the raw file, comments included, because that is
// what the runtime loader substitutes over. A name mentioned only in a comment
// is a real reference to the loader and is reported as one here.

// fixture writes a schema-valid rule whose only variable content is what the
// caller supplies, so a diagnostic can only come from the reference under test.
func fixture(t *testing.T, dir, id, expected, note, trailer string) string {
	t.Helper()
	body := `id: ` + id + `
title: Fixture rule for ` + id + `
description: >
  A synthetic fixture used only by the validator tests. It is never executed.
rationale: >
  Present so the rule schema is satisfied and the variable reference below is
  the only thing under test.
severity: medium
category: access-control
transactional: false
platforms:
  - family: rhel
    min_version: 9
implementations:
  - default: true
    check:
      method: config_value
      path: "/etc/security/faillock.conf"
      key: "deny"
      expected: "` + expected + `"
    remediation:
      steps:
        - mechanism: manual
          note: "` + note + `"
` + trailer
	path := filepath.Join(dir, id+".yml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func ruleDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "access-control")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// captureCLI runs the validator and returns its exit code with whatever it
// printed, so the assertions are about observable behavior rather than
// internal state.
//
// The reader runs concurrently with the command. A pipe holds a bounded amount
// of data, 64 KiB on Linux, and the validator prints a line per file, so a
// large enough rules directory would fill the pipe and block the writer for
// ever if the test only started reading after runCLI returned. Draining in a
// goroutine keeps the size of the output irrelevant.
func captureCLI(t *testing.T, argv ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	orig := os.Stdout
	os.Stdout = w
	// Restore stdout and release both ends even if the command panics.
	defer func() {
		os.Stdout = orig
		_ = w.Close()
		_ = r.Close()
	}()

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()

	code := runCLI(argv)

	// Close the write end so the reader sees EOF, then restore stdout before
	// waiting, so a failure in the reader cannot leave stdout redirected.
	os.Stdout = orig
	if cerr := w.Close(); cerr != nil {
		t.Fatalf("closing the capture pipe: %v", cerr)
	}
	return code, <-done
}

const unknownWarningCode = "W006"

func TestVariableRefs_UnknownNameWarns(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "unknown-var", "{{ pam_faillock_denyy }}", "n", "")

	code, out := captureCLI(t, path)
	if code != 0 {
		t.Errorf("exit=%d, want 0: an unknown variable is a warning by default\n%s", code, out)
	}
	if !strings.Contains(out, unknownWarningCode) {
		t.Errorf("output carries no %s warning:\n%s", unknownWarningCode, out)
	}
	if !strings.Contains(out, "pam_faillock_denyy") {
		t.Errorf("the warning does not name the unresolved variable:\n%s", out)
	}
	if !strings.Contains(out, "1 warning(s)") {
		t.Errorf("summary does not report exactly one warning:\n%s", out)
	}
}

func TestVariableRefs_KnownNameIsSilent(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "known-var", "{{ pam_faillock_deny }}", "n", "")

	code, out := captureCLI(t, path)
	if code != 0 {
		t.Errorf("exit=%d, want 0\n%s", code, out)
	}
	if strings.Contains(out, unknownWarningCode) {
		t.Errorf("a built-in variable produced a warning:\n%s", out)
	}
}

func TestVariableRefs_CommentOnlyReferenceWarns(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "comment-var", "static", "n",
		"# a comment mentioning {{ ghost_variable }}\n")

	code, out := captureCLI(t, path)
	if code != 0 {
		t.Errorf("exit=%d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "ghost_variable") {
		t.Errorf("a comment-only reference was not reported, but the loader substitutes over comments:\n%s", out)
	}
}

func TestVariableRefs_RepeatedReferenceWarnsOnce(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "repeat-var", "{{ ghost_variable }}",
		"{{ ghost_variable }} and {{ ghost_variable }}", "")

	_, out := captureCLI(t, path)
	// Count warning lines, not name occurrences: one warning legitimately
	// mentions the name more than once, in the location, the message and the
	// suggested declaration.
	if got := strings.Count(out, "["+unknownWarningCode+"]"); got != 1 {
		t.Errorf("the same unresolved name produced %d warnings, want 1:\n%s", got, out)
	}
	if !strings.Contains(out, "1 warning(s)") {
		t.Errorf("summary does not report exactly one warning:\n%s", out)
	}
}

func TestVariableRefs_MultipleUnknownAreDeterministic(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "multi-var", "{{ zulu_missing }}", "{{ alpha_missing }}", "")

	var first string
	for i := 0; i < 3; i++ {
		_, out := captureCLI(t, path)
		if i == 0 {
			first = out
		} else if out != first {
			t.Fatalf("diagnostics are not deterministic across runs:\n%s\n---\n%s", first, out)
		}
	}
	if !strings.Contains(first, "2 warning(s)") {
		t.Errorf("two unresolved names should produce two warnings:\n%s", first)
	}
	a := strings.Index(first, "alpha_missing")
	z := strings.Index(first, "zulu_missing")
	if a < 0 || z < 0 || a > z {
		t.Errorf("warnings are not in sorted name order:\n%s", first)
	}
}

func TestVariableRefs_DeclaredSiteNameIsSilent(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "site-var", "{{ site_local_thing }}", "n", "")

	code, out := captureCLI(t, "--declare-variable", "site_local_thing", path)
	if code != 0 {
		t.Errorf("exit=%d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "site_local_thing") {
		t.Errorf("a declared site variable still warned:\n%s", out)
	}
}

func TestVariableRefs_StrictMakesUnknownFail(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "strict-var", "{{ ghost_variable }}", "n", "")

	code, out := captureCLI(t, "--strict", path)
	if code != 1 {
		t.Errorf("exit=%d under --strict, want 1\n%s", code, out)
	}
}

func TestVariableRefs_InvalidDeclarationIsUsageError(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "decl-var", "static", "n", "")

	for _, bad := range []string{"9leading-digit", "has-dash", "has space", "", "trailing$"} {
		code, _ := captureCLI(t, "--declare-variable", bad, path)
		if code != 2 {
			t.Errorf("--declare-variable %q exited %d, want 2 (usage error)", bad, code)
		}
	}
}

func TestVariableRefs_MalformedTemplateKeepsExistingBehavior(t *testing.T) {
	dir := ruleDir(t)
	for _, tc := range []struct{ id, expected string }{
		{"bad-grammar", "{{ 9bad-name }}"},
		{"incomplete", "{{ pam_faillock_deny"},
	} {
		path := fixture(t, dir, tc.id, tc.expected, "n", "")
		code, out := captureCLI(t, path)
		if code != 0 {
			t.Errorf("%s: exit=%d, want 0\n%s", tc.id, code, out)
		}
		if strings.Contains(out, unknownWarningCode) {
			t.Errorf("%s: malformed template text produced a variable warning; it is not a reference:\n%s", tc.id, out)
		}
	}
}

func TestVariableRefs_JSONStructureIntact(t *testing.T) {
	dir := ruleDir(t)
	path := fixture(t, dir, "json-var", "{{ ghost_variable }}", "n", "")

	_, out := captureCLI(t, "--format", "json", path)
	var results []map[string]any
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("output is not the documented JSON array: %v\n%s", err, out)
	}
	if len(results) != 1 {
		t.Fatalf("got %d elements, want 1", len(results))
	}
	el := results[0]
	for _, k := range []string{"file", "rule_id", "warnings"} {
		if _, ok := el[k]; !ok {
			t.Errorf("element is missing key %q: %v", k, el)
		}
	}
	if _, ok := el["errors"]; ok {
		t.Errorf("errors key must stay omitted when empty: %v", el)
	}
	warns, _ := el["warnings"].([]any)
	if len(warns) != 1 {
		t.Fatalf("got %d warnings, want 1", len(warns))
	}
	w, _ := warns[0].(map[string]any)
	for _, k := range []string{"RuleID", "ImplIndex", "Path", "Code", "Msg"} {
		if _, ok := w[k]; !ok {
			t.Errorf("warning is missing existing key %q: %v", k, w)
		}
	}
	if w["Code"] != unknownWarningCode {
		t.Errorf("warning Code is %v, want %s", w["Code"], unknownWarningCode)
	}
}

func TestVariableRefs_ShippedCorpusIsClean(t *testing.T) {
	corpus := "../../rules"
	if _, err := os.Stat(corpus); err != nil {
		t.Skip("corpus not present in this checkout")
	}
	code, out := captureCLI(t, "--rules-dir", corpus)
	if strings.Contains(out, unknownWarningCode) {
		t.Errorf("the shipped corpus produced variable warnings:\n%s", out)
	}
	if code != 0 {
		t.Errorf("exit=%d validating the shipped corpus, want 0", code)
	}
}

// TestVariableRefs_CaptureSurvivesLargeOutput proves the capture helper does
// not deadlock when the validator prints more than a pipe can hold. Without a
// concurrent reader this test hangs rather than fails, which is why it exists
// separately from the assertions that happen to use small fixtures.
func TestVariableRefs_CaptureSurvivesLargeOutput(t *testing.T) {
	dir := ruleDir(t)
	// Each file contributes an OK line plus a warning line; a few hundred is
	// comfortably past the 64 KiB pipe buffer.
	const files = 400
	for i := 0; i < files; i++ {
		fixture(t, dir, fmt.Sprintf("bulk-%03d", i), "{{ ghost_variable }}", "n", "")
	}

	done := make(chan struct{})
	var code int
	var out string
	go func() {
		defer close(done)
		code, out = captureCLI(t, "--rules-dir", filepath.Dir(dir))
	}()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("captureCLI did not return: the helper blocked on a full pipe")
	}

	if len(out) <= 65536 {
		t.Fatalf("output is %d bytes, which does not exceed the pipe buffer this test exists to cross", len(out))
	}
	if code != 0 {
		t.Errorf("exit=%d, want 0", code)
	}
	if got := strings.Count(out, "["+unknownWarningCode+"]"); got != files {
		t.Errorf("got %d warnings, want one per file (%d)", got, files)
	}
}
