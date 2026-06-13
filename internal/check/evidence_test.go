package check

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// TestRun_CapturesObservationEvidence covers the structured evidence captured
// on the check path: the exact command, output, exit code, method, and
// expected value — the reproducible proof behind a verdict.
//
// @spec check-observation-evidence
func TestRun_CapturesObservationEvidence(t *testing.T) {
	// AC-01: a single check yields one CheckEvidence carrying the command it
	// ran, its stdout/exit, the method, and the expected value from params.
	t.Run("check-observation-evidence/AC-01", func(t *testing.T) {
		// @spec check-observation-evidence
		// @ac AC-01
		const cmd = "sysctl -n 'net.ipv4.ip_forward'"
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
			cmd: {Stdout: "1", ExitCode: 0},
		}}
		chk := api.Check{Method: "sysctl_value", Params: api.Params{
			"key": "net.ipv4.ip_forward", "expected": "0",
		}}
		res, err := Run(context.Background(), ft, chk)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Passed {
			t.Errorf("expected fail (got 1, expected 0)")
		}
		if len(res.Evidence) != 1 {
			t.Fatalf("want 1 evidence entry, got %d", len(res.Evidence))
		}
		ev := res.Evidence[0]
		if ev.Method != "sysctl_value" {
			t.Errorf("method: want sysctl_value, got %q", ev.Method)
		}
		if ev.Command != cmd {
			t.Errorf("command: want %q, got %q", cmd, ev.Command)
		}
		if ev.Stdout != "1" {
			t.Errorf("stdout: want %q, got %q", "1", ev.Stdout)
		}
		if ev.ExitCode != 0 {
			t.Errorf("exit_code: want 0, got %d", ev.ExitCode)
		}
		if ev.Expected != "0" {
			t.Errorf("expected: want %q, got %q", "0", ev.Expected)
		}
		if ev.Truncated {
			t.Errorf("short output must not be marked truncated")
		}
	})

	// AC-02: stdout beyond the 64 KiB cap is truncated-and-marked, not dropped.
	t.Run("check-observation-evidence/AC-02", func(t *testing.T) {
		// @spec check-observation-evidence
		// @ac AC-02
		const cmd = "sysctl -n 'kernel.big'"
		big := strings.Repeat("A", maxEvidenceFieldBytes+4096)
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
			cmd: {Stdout: big, ExitCode: 0},
		}}
		chk := api.Check{Method: "sysctl_value", Params: api.Params{
			"key": "kernel.big", "expected": "x",
		}}
		res, err := Run(context.Background(), ft, chk)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		ev := res.Evidence[0]
		if len(ev.Stdout) != maxEvidenceFieldBytes {
			t.Errorf("stdout should be capped at %d, got %d", maxEvidenceFieldBytes, len(ev.Stdout))
		}
		if !ev.Truncated {
			t.Errorf("over-cap output must set Truncated")
		}
	})

	// AC-03: a multi-check (`checks:` list) aggregates one evidence entry per
	// sub-check, each carrying its own method.
	t.Run("check-observation-evidence/AC-03", func(t *testing.T) {
		// @spec check-observation-evidence
		// @ac AC-03
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
			"sysctl -n 'a.b'": {Stdout: "0", ExitCode: 0},
			"test -e /etc/foo && echo present || echo absent": {Stdout: "present", ExitCode: 0},
		}}
		chk := api.Check{Checks: []api.Check{
			{Method: "sysctl_value", Params: api.Params{"key": "a.b", "expected": "0"}},
			{Method: "file_exists", Params: api.Params{"path": "/etc/foo"}},
		}}
		res, err := Run(context.Background(), ft, chk)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(res.Evidence) != 2 {
			t.Fatalf("want 2 evidence entries (one per sub-check), got %d", len(res.Evidence))
		}
		methods := map[string]bool{}
		for _, ev := range res.Evidence {
			methods[ev.Method] = true
			if ev.Command == "" {
				t.Errorf("sub-check evidence missing command: %+v", ev)
			}
		}
		if !methods["sysctl_value"] || !methods["file_exists"] {
			t.Errorf("want both sub-check methods in evidence, got %v", methods)
		}
	})
}
