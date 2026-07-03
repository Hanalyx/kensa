// Tests for the remediate strict conflict gate (--allow-conflicts).
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/rule"
)

// writeConflictingRulePair writes two mutually-exclusive rules (each declaring
// conflicts_with the other) to a temp dir and returns their paths.
func writeConflictingRulePair(t *testing.T) (a, b string) {
	t.Helper()
	dir := t.TempDir()
	mk := func(id, other string) string {
		p := filepath.Join(dir, id+".yml")
		body := "id: " + id + "\n" +
			"title: Conflict gate test " + id + "\n" +
			"severity: low\n" +
			"category: test\n" +
			"conflicts_with: [" + other + "]\n" +
			"platforms:\n  - family: rhel\n    min_version: 8\n" +
			"implementations:\n" +
			"  - default: true\n" +
			"    check:\n      method: command\n      run: \"true\"\n      expected_exit: 0\n" +
			"      expected_stdout: \"\"\n" +
			"    remediation:\n      mechanism: command_exec\n      run: \"true\"\n"
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		return p
	}
	return mk("conflict-gate-a", "conflict-gate-b"), mk("conflict-gate-b", "conflict-gate-a")
}

// TestRemediate_RefusesOnConflict proves remediate refuses (exit 2) — before
// any host connection — when the selected rules declare a conflict.
//
// @spec cli-allow-conflicts
// @ac AC-01
func TestRemediate_RefusesOnConflict(t *testing.T) {
	t.Run("cli-allow-conflicts/AC-01", func(t *testing.T) {})
	t.Log("// @spec cli-allow-conflicts")
	t.Log("// @ac AC-01")

	a, b := writeConflictingRulePair(t)
	argv := []string{"remediate", "--rule", a, "--rule", b, "--host", "127.0.0.1", "--port", "1"}

	if exit := runCLI(argv); exit != 2 {
		t.Errorf("expected exit 2 (usage refusal), got %d", exit)
	}
	_, stderr := captureRunCLI(argv, t)
	if !strings.Contains(stderr, "refusing to remediate") {
		t.Errorf("expected 'refusing to remediate' on stderr; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "conflict-gate-a") || !strings.Contains(stderr, "conflict-gate-b") {
		t.Errorf("expected both conflicting rule ids listed; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--allow-conflicts") {
		t.Errorf("expected the --allow-conflicts escape hatch named; got:\n%s", stderr)
	}
}

// TestRemediate_AllowConflictsBypasses proves --allow-conflicts opts back into
// run-anyway: the gate does not fire (the run proceeds past it to the host
// connection, which then fails on the unreachable test host).
//
// @spec cli-allow-conflicts
// @ac AC-02
func TestRemediate_AllowConflictsBypasses(t *testing.T) {
	t.Run("cli-allow-conflicts/AC-02", func(t *testing.T) {})
	t.Log("// @spec cli-allow-conflicts")
	t.Log("// @ac AC-02")

	a, b := writeConflictingRulePair(t)
	db := filepath.Join(t.TempDir(), "r.db")
	argv := []string{"--db", db, "remediate", "--rule", a, "--rule", b,
		"--host", "127.0.0.1", "--port", "1", "--allow-conflicts"}

	_, stderr := captureRunCLI(argv, t)
	if strings.Contains(stderr, "refusing to remediate") {
		t.Errorf("--allow-conflicts must bypass the refusal; got:\n%s", stderr)
	}
}

// TestFormatConflictRefusal renders every pair and both escape hatches.
//
// @spec cli-allow-conflicts
// @ac AC-01
func TestFormatConflictRefusal(t *testing.T) {
	t.Run("cli-allow-conflicts/AC-01", func(t *testing.T) {})
	t.Log("// @spec cli-allow-conflicts")
	t.Log("// @ac AC-01")

	msg := formatConflictRefusal([]rule.ConflictPair{
		{RuleID: "ssh-crypto-policy", ConflictsWith: "ssh-ciphers-fips"},
		{RuleID: "ssh-crypto-policy", ConflictsWith: "ssh-macs-fips"},
	})
	if !strings.Contains(msg, "2 rule conflict(s)") {
		t.Errorf("expected the conflict count; got:\n%s", msg)
	}
	for _, want := range []string{"ssh-crypto-policy conflicts with ssh-ciphers-fips",
		"ssh-crypto-policy conflicts with ssh-macs-fips", "--allow-conflicts"} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected %q in refusal message; got:\n%s", want, msg)
		}
	}
}
