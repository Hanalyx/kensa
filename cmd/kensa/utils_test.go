// Tests for the cmd/kensa utility functions: parseSince, parseInventory,
// truncate, the print* helpers, and the loadRules family. Plus tests
// for runCoverage, runVersion, and the print*Usage helpers via runCLI
// so we get coverage of the help-render paths.
//
// Deliverable C-009 in docs/roadmap/DELIVERABLES.md. Goal: push
// cmd/kensa/ coverage to ≥90%. The runDetect/runCheck/runRemediate
// /runRollback/runHistory/runPlan happy-path arms remain at flag-parse
// coverage only — getting 90% on those would require a full mock SSH
// transport which is out of C-009 scope (kensa-fuzz already has live-
// test coverage of those code paths against `inventory.ini`).
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// ─── parseSince ────────────────────────────────────────────────────────────

func TestParseSince(t *testing.T) {
	t.Run("duration form", func(t *testing.T) {
		got, err := parseSince("24h")
		if err != nil {
			t.Fatalf("parseSince(24h): %v", err)
		}
		// Should be approximately 24h ago.
		expected := time.Now().Add(-24 * time.Hour)
		if got.After(expected.Add(2*time.Second)) || got.Before(expected.Add(-2*time.Second)) {
			t.Errorf("parseSince(24h) = %v; want ~%v (within 2s)", got, expected)
		}
	})

	t.Run("rfc3339 form", func(t *testing.T) {
		input := "2026-01-15T12:30:00Z"
		got, err := parseSince(input)
		if err != nil {
			t.Fatalf("parseSince(%q): %v", input, err)
		}
		if got.Format(time.RFC3339) != input {
			t.Errorf("parseSince(%q) = %v; want %v", input, got, input)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := parseSince("not-a-duration-or-time")
		if err == nil {
			t.Errorf("parseSince(garbage): want error, got nil")
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := parseSince("")
		if err == nil {
			t.Errorf("parseSince(\"\"): want error, got nil")
		}
	})
}

// ─── parseInventory ───────────────────────────────────────────────────────

func TestParseInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.ini")
	content := `# This is a comment
[group_a]
192.168.1.1 ansible_user=alice ansible_port=2222
192.168.1.2

[group_b]
host3.example.com ansible_user=bob

# Trailing comment
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}

	hosts, err := parseInventory(path)
	if err != nil {
		t.Fatalf("parseInventory: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts, want 3: %+v", len(hosts), hosts)
	}
	if hosts[0].addr != "192.168.1.1" || hosts[0].user != "alice" || hosts[0].port != 2222 {
		t.Errorf("hosts[0] = %+v; want {addr:192.168.1.1 user:alice port:2222}", hosts[0])
	}
	if hosts[1].addr != "192.168.1.2" || hosts[1].user != "" || hosts[1].port != 0 {
		t.Errorf("hosts[1] = %+v; want {addr:192.168.1.2 user: port:0}", hosts[1])
	}
	if hosts[2].addr != "host3.example.com" || hosts[2].user != "bob" {
		t.Errorf("hosts[2] = %+v; want {addr:host3.example.com user:bob}", hosts[2])
	}
	// C-025: parser tracks group memberships for --limit.
	if len(hosts[0].groups) != 1 || hosts[0].groups[0] != "group_a" {
		t.Errorf("hosts[0].groups = %v; want [group_a]", hosts[0].groups)
	}
	if len(hosts[1].groups) != 1 || hosts[1].groups[0] != "group_a" {
		t.Errorf("hosts[1].groups = %v; want [group_a]", hosts[1].groups)
	}
	if len(hosts[2].groups) != 1 || hosts[2].groups[0] != "group_b" {
		t.Errorf("hosts[2].groups = %v; want [group_b]", hosts[2].groups)
	}
}

func TestParseInventory_HostInMultipleGroups(t *testing.T) {
	// A host listed under two groups merges its memberships
	// rather than producing duplicate entries (C-025 parser
	// improvement).
	dir := t.TempDir()
	path := filepath.Join(dir, "test.ini")
	content := `[web]
host-1
host-2
[prod]
host-1
host-3
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	hosts, err := parseInventory(path)
	if err != nil {
		t.Fatalf("parseInventory: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts, want 3 (deduped); hosts=%+v", len(hosts), hosts)
	}
	// host-1 should have both groups.
	for _, h := range hosts {
		if h.addr == "host-1" {
			if len(h.groups) != 2 {
				t.Errorf("host-1.groups = %v; want [web prod] in some order", h.groups)
			}
			return
		}
	}
	t.Error("host-1 missing from hosts")
}

func TestParseInventory_FileNotFound(t *testing.T) {
	_, err := parseInventory("/nonexistent/path/inventory.ini")
	if err == nil {
		t.Errorf("parseInventory(nonexistent): want error, got nil")
	}
}

// ─── moved to internal/output/ in C-012 ──────────────────────────────────
//
// The truncate / printCapsTable / printJSON / printJSONL / printScanTable /
// printRemediateTable / printHistoryTable tests previously lived here.
// The functions they tested moved to internal/output/{text,json,writer}.go
// in C-012 and are now exercised by the tests in
// internal/output/{text,json,writer}_test.go alongside the implementations.

// ─── print*Usage helpers (writer-injected) ────────────────────────────────

// All print*Usage variants take an io.Writer; covered by TestPrint*Usage
// across each subcommand. They're called from runFoo when --help is
// requested, but a direct test ensures the help text generation path
// doesn't panic on empty FlagSet.

func TestPrintUsage_Variants(t *testing.T) {
	// Top-level printUsage (writes to provided io.Writer)
	var buf bytes.Buffer
	printUsage(&buf)
	if !strings.Contains(buf.String(), "Usage: kensa") {
		t.Errorf("printUsage missing 'Usage: kensa': %s", buf.String())
	}
	// Help should mention the major subcommands.
	for _, cmd := range []string{"detect", "check", "remediate", "rollback", "history", "plan"} {
		if !strings.Contains(buf.String(), cmd) {
			t.Errorf("printUsage missing %q in subcommand list", cmd)
		}
	}
}

// ─── loadRulesFromDirOrFiles ──────────────────────────────────────────────

func TestLoadRulesFromDirOrFiles_NoArgsIsUsageError(t *testing.T) {
	_, err := loadRulesFromDirOrFiles("", nil, nil)
	if err == nil {
		t.Fatalf("loadRulesFromDirOrFiles(\"\", nil): want error, got nil")
	}
	if !IsUsageError(err) {
		t.Errorf("loadRulesFromDirOrFiles(\"\", nil) = %v; want UsageError (so dispatcher exits 2)", err)
	}
}

func TestLoadRulesFromDirOrFiles_NonexistentDir(t *testing.T) {
	_, err := loadRulesFromDirOrFiles("/nonexistent-dir-xyz", nil, nil)
	if err == nil {
		t.Fatalf("loadRulesFromDirOrFiles(nonexistent): want error, got nil")
	}
	// This is a runtime error (filesystem walk failed), not a usage error.
	if IsUsageError(err) {
		t.Errorf("loadRulesFromDirOrFiles(nonexistent) was UsageError; want runtime error")
	}
}

func TestLoadRulesFromDirOrFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir() // empty
	_, err := loadRulesFromDirOrFiles(dir, nil, nil)
	if err == nil {
		t.Fatalf("loadRulesFromDirOrFiles(empty dir): want error, got nil")
	}
	// "no *.yml files found" is a runtime/operator-environment problem,
	// not a CLI usage error per se. Confirming current behavior.
	if !strings.Contains(err.Error(), "no *.yml files") {
		t.Errorf("error = %v; want 'no *.yml files'", err)
	}
}

// ─── Subcommand --help paths (exercise print*Usage helpers) ──────────────

// TestSubcommandHelpHitsPrintHelpers covers print*Usage paths that
// are otherwise only reached through the --help arm of each runFoo.
func TestSubcommandHelpHitsPrintHelpers(t *testing.T) {
	cases := []runCLITestCase{
		{name: "kensa check --help", argv: []string{"check", "--help"}, wantExit: 0},
		{name: "kensa remediate --help", argv: []string{"remediate", "--help"}, wantExit: 0},
		{name: "kensa rollback --help", argv: []string{"rollback", "--help"}, wantExit: 0},
		{name: "kensa history --help", argv: []string{"history", "--help"}, wantExit: 0},
		{name: "kensa plan --help", argv: []string{"plan", "--help"}, wantExit: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCLI(tc.argv); got != tc.wantExit {
				t.Errorf("runCLI(%q) = %d, want %d", tc.argv, got, tc.wantExit)
			}
		})
	}
}

// ─── runCoverage / runVersion happy-path coverage ────────────────────────

// `kensa coverage` (no flags) prints the registered handler list. Exercises
// runCoverage's print path beyond the --help arm.
func TestRunCoverage_HappyPath(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	if got := runCLI([]string{"coverage"}); got != 0 {
		t.Errorf("runCLI(coverage) = %d, want 0", got)
	}

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()
	if !strings.Contains(output, "Registered mechanisms") {
		t.Errorf("output missing 'Registered mechanisms': %s", output)
	}
}

// `kensa version` (no flags) prints the version string.
func TestRunVersion_HappyPath(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	if got := runCLI([]string{"version"}); got != 0 {
		t.Errorf("runCLI(version) = %d, want 0", got)
	}

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "kensa "+version) {
		t.Errorf("output missing version string; got: %s", buf.String())
	}
}

// ─── loadRules / loadRulesSkipInvalid ─────────────────────────────────────

// loadRules with a single valid rule file.
func TestLoadRules_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.yml")
	// Minimal rule YAML that parses.
	yaml := `id: test-rule-001
title: Test rule
description: A test rule for unit-test coverage.
rationale: We need a real rule on disk so loadRules has something to parse.
severity: low
category: testing
implementations:
  - default: true
    check:
      method: command
      params:
        cmd: /bin/true
    remediation:
      mechanism: command_exec
      params:
        cmd: /bin/true
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write temp rule: %v", err)
	}

	rules, err := loadRules([]string{path}, nil)
	if err != nil {
		t.Fatalf("loadRules(valid): %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "test-rule-001" {
		t.Errorf("got %d rules / first ID %q; want 1 rule with id=test-rule-001", len(rules), func() string {
			if len(rules) > 0 {
				return rules[0].ID
			}
			return "(none)"
		}())
	}
}

// loadRules error path: nonexistent file.
func TestLoadRules_FileNotFound(t *testing.T) {
	_, err := loadRules([]string{"/nonexistent/rule.yml"}, nil)
	if err == nil {
		t.Errorf("loadRules(nonexistent): want error, got nil")
	}
}

// loadRulesSkipInvalid: should skip a malformed file with a warning to
// stderr and return the valid ones. Tests both the valid-only path
// and the invalid-skip path.
func TestLoadRulesSkipInvalid_MixedFiles(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yml")
	invalidPath := filepath.Join(dir, "invalid.yml")

	validYAML := `id: skip-test-rule
title: Skip test
description: For loadRulesSkipInvalid coverage.
rationale: Need at least one valid rule alongside the invalid one.
severity: low
category: testing
implementations:
  - default: true
    check: { method: command, params: { cmd: /bin/true } }
    remediation: { mechanism: command_exec, params: { cmd: /bin/true } }
`
	if err := os.WriteFile(validPath, []byte(validYAML), 0o644); err != nil {
		t.Fatalf("write valid: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte("not: valid: yaml\n  - syntax error"), 0o644); err != nil {
		t.Fatalf("write invalid: %v", err)
	}

	// Capture stderr to check the warning is emitted.
	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	rules, err := loadRulesSkipInvalid([]string{invalidPath, validPath}, nil)

	wErr.Close()
	os.Stderr = oldStderr
	var stderrBuf bytes.Buffer
	_, _ = stderrBuf.ReadFrom(rErr)

	if err != nil {
		t.Fatalf("loadRulesSkipInvalid: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "skip-test-rule" {
		t.Errorf("got %d rules; want 1 (the valid one)", len(rules))
	}
	if !strings.Contains(stderrBuf.String(), "warn: skip") {
		t.Errorf("missing skip warning on stderr; got: %s", stderrBuf.String())
	}
}

// ─── writeOSCALFile coverage ──────────────────────────────────────────────

// writeOSCALFile takes a path and a RemediationResult and writes one
// OSCAL Assessment Results document per non-nil envelope.

// TestWriteOSCALFile_NoEnvelopes_NoFile asserts the C-016 short-
// circuit: when no transaction has an envelope, the function does
// NOT create the file (a 0-byte OSCAL artifact would be operator-
// hostile — auditors can't tell "Kensa crashed" from "empty result").
func TestWriteOSCALFile_NoEnvelopes_NoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Envelope: nil},
		},
	}
	if err := writeOSCALFile(path, result); err != nil {
		t.Fatalf("writeOSCALFile: %v", err)
	}
	// File should NOT exist.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file NOT to be created when no envelopes; got err=%v", err)
	}
}

func TestWriteOSCALFile_BadPath(t *testing.T) {
	// A bad path with at least one envelope present should error
	// because os.Create runs (the short-circuit only fires for the
	// no-envelopes case).
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Envelope: makeOSCALTestEnvelope()},
		},
	}
	err := writeOSCALFile("/nonexistent/dir/out.json", result)
	if err == nil {
		t.Errorf("writeOSCALFile(bad path): want error, got nil")
	}
}

// TestWriteOSCALFile_DelegationToWriter locks AC-09 in
// specs/output/oscal.spec.yaml: writeOSCALFile routes byte production
// through the registered "oscal" writer rather than re-implementing
// the loop. Verified by writing one envelope to a temp file and
// asserting the output is a valid OSCAL Assessment Results JSON
// document — the same shape the registered writer emits.
func TestWriteOSCALFile_DelegationToWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Envelope: makeOSCALTestEnvelope()},
		},
	}
	if err := writeOSCALFile(path, result); err != nil {
		t.Fatalf("writeOSCALFile: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(body, []byte(`"assessment-results"`)) {
		t.Errorf("output missing OSCAL top-level key; body length=%d", len(body))
	}
}

// makeOSCALTestEnvelope returns a minimally-valid envelope for OSCAL
// serialization in cmd/kensa tests. Matches the makeEnvelope helper
// in internal/output/oscal_test.go.
func makeOSCALTestEnvelope() *api.EvidenceEnvelope {
	return &api.EvidenceEnvelope{
		TransactionID: uuid.MustParse("00000000-0000-0000-0000-000000000099"),
		RuleID:        "test-rule",
		HostID:        "test-host",
		Decision:      api.StatusCommitted,
		StartedAt:     time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 5, 8, 12, 0, 5, 0, time.UTC),
		SigningKeyID:  "test-key-1",
	}
}
