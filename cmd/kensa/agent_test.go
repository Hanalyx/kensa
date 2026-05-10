// Tests for the C-054 `kensa agent` placeholder subcommand.
package main

import (
	"strings"
	"testing"
)

// TestRunAgent_NoFlagsIsUsageError locks AC-01.
func TestRunAgent_NoFlagsIsUsageError(t *testing.T) {
	exit := runCLI([]string{"agent"})
	if exit != 2 {
		t.Errorf("kensa agent (no flags) should exit 2; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"agent"}, t)
	if !strings.Contains(stderr, "--stdio") {
		t.Errorf("error should mention --stdio; got:\n%s", stderr)
	}
}

// TestRunAgent_StdioExitsRuntime locks AC-02. Exit 1 (runtime,
// "feature not ready"), NOT exit 2 (usage error).
func TestRunAgent_StdioExitsRuntime(t *testing.T) {
	exit := runCLI([]string{"agent", "--stdio"})
	if exit != 1 {
		t.Errorf("kensa agent --stdio should exit 1 (runtime); got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"agent", "--stdio"}, t)
	for _, want := range []string{"v1.1", "Track L"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr should mention %q; got:\n%s", want, stderr)
		}
	}
	// Workaround pointer for v1.0 operators.
	if !strings.Contains(stderr, "direct-SSH") &&
		!strings.Contains(stderr, "direct SSH") {
		t.Errorf("stderr should point operators at direct-SSH transport for v1.0; got:\n%s", stderr)
	}
}

// TestRunAgent_HelpDisclosesWireProtocol locks AC-03.
func TestRunAgent_HelpDisclosesWireProtocol(t *testing.T) {
	for _, argv := range [][]string{
		{"agent", "--help"},
		{"agent", "-h"},
	} {
		exit := runCLI(argv)
		if exit != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, exit)
		}
	}
	stdout, _ := captureRunCLI([]string{"agent", "--help"}, t)
	for _, want := range []string{
		"v1.0 PLACEHOLDER",
		"stdin",
		"stdout",
		"length-prefixed",
		"Track L Phase 1",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("agent --help should disclose %q; got:\n%s", want, stdout)
		}
	}
}

// TestRunAgent_UnknownFlagRejected locks AC-04.
func TestRunAgent_UnknownFlagRejected(t *testing.T) {
	exit := runCLI([]string{"agent", "--bogus"})
	if exit != 2 {
		t.Errorf("kensa agent --bogus should exit 2; got %d", exit)
	}
}

// TestPrintUsage_ListsAgent locks AC-05.
func TestPrintUsage_ListsAgent(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"--help"}, t)
	if !strings.Contains(stdout, "agent") {
		t.Errorf("kensa --help should list 'agent'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "v1.1 placeholder") &&
		!strings.Contains(stdout, "v1.1-placeholder") {
		t.Errorf("kensa --help agent line should disclose v1.1 placeholder status; got:\n%s", stdout)
	}
}
