// Tests for the `kensa agent` subcommand. The placeholder
// behavior (cli-agent-placeholder spec, C-054) was superseded by
// L-008's live echo loop (agent-stdio-subcommand spec); the
// preserved behaviors (bare-invocation usage error, --help
// wire-protocol disclosure, --bogus rejection) are still locked
// here.
package main

import (
	"strings"
	"testing"
)

// TestRunAgent_NoFlagsIsUsageError locks
// cli-agent-placeholder AC-01: bare `kensa agent` (no mode flag)
// MUST exit 2 with a usage error. Preserved across the L-008
// transition.
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

// TestRunAgent_HelpDisclosesWireProtocol locks
// agent-stdio-subcommand C-01 + cli-agent-placeholder C-03:
// `kensa agent --help` exits 0 and discloses the wire-protocol
// surface so v1.x consumers can write integration code. The
// L-008 transition dropped "v1.0 PLACEHOLDER" language and
// replaced it with the live framing/echo description; the
// stdin / stdout / length-prefixed / Track L disclosures are
// preserved.
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
		"stdin",
		"stdout",
		"length-prefixed",
		"Track L",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("agent --help should disclose %q; got:\n%s", want, stdout)
		}
	}
}

// TestRunAgent_UnknownFlagRejected locks
// cli-agent-placeholder AC-04: unknown flags exit 2. Preserved.
func TestRunAgent_UnknownFlagRejected(t *testing.T) {
	exit := runCLI([]string{"agent", "--bogus"})
	if exit != 2 {
		t.Errorf("kensa agent --bogus should exit 2; got %d", exit)
	}
}

// TestPrintUsage_ListsAgent locks cli-agent-placeholder AC-05
// (preserved): top-level `kensa --help` lists the agent
// subcommand. The post-L-008 description no longer says "v1.1
// placeholder" since the subcommand now does real work.
func TestPrintUsage_ListsAgent(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"--help"}, t)
	if !strings.Contains(stdout, "agent") {
		t.Errorf("kensa --help should list 'agent'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "stdio agent") {
		t.Errorf("agent line should describe the stdio role; got:\n%s", stdout)
	}
}

// Note: the end-to-end echo behavior (write framed Request →
// read framed Response → verify correlation_id + payload echo →
// exit 0 on stdin close) is locked by
// TestKensaAgent_StdioEndToEnd in agent_e2e_test.go, which
// spawns a real subprocess so it can control stdin/stdout
// pipes. In-process runCLI() reads from the test runner's
// os.Stdin and can't easily inject framed bytes.
