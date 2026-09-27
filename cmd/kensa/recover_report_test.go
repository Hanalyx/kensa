package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

func recoveredResult(rule string) *api.TransactionResult {
	return &api.TransactionResult{
		TransactionID: uuid.New(), Status: api.StatusRecovered, HostUnchanged: true,
		Envelope: &api.EvidenceEnvelope{RuleID: rule},
	}
}

func refusal(rule string) engine.RecoveryRefusal {
	return engine.RecoveryRefusal{TransactionID: uuid.New(), RuleID: rule, Findings: []engine.RecoveryFinding{
		{Code: engine.FindingUnknownMechanism, StepIndex: 0, Mechanism: "ghost", Detail: "no handler is registered for this mechanism"},
	}}
}

// @spec recovery-replay
// @ac AC-09
func TestRenderRecoverReport(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-09")

	t.Run("nothing to do", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if err := renderRecoverReport(&out, &errOut, &engine.RecoveryReport{}, "h"); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if !strings.Contains(out.String(), "no interrupted transactions found") {
			t.Errorf("out = %q", out.String())
		}
	})

	t.Run("results only", func(t *testing.T) {
		var out, errOut bytes.Buffer
		rep := &engine.RecoveryReport{Results: []*api.TransactionResult{recoveredResult("rule-ok")}}
		if err := renderRecoverReport(&out, &errOut, rep, "h"); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if !strings.Contains(out.String(), "recovered") || !strings.Contains(out.String(), "rule=rule-ok") {
			t.Errorf("out = %q", out.String())
		}
		if errOut.Len() != 0 {
			t.Errorf("unexpected stderr: %q", errOut.String())
		}
	})

	t.Run("refusals only", func(t *testing.T) {
		var out, errOut bytes.Buffer
		rep := &engine.RecoveryReport{Refusals: []engine.RecoveryRefusal{refusal("rule-bad")}}
		err := renderRecoverReport(&out, &errOut, rep, "h")
		if err == nil {
			t.Fatal("a refusal must make the command fail")
		}
		if IsUsageError(err) {
			t.Error("a refusal is not a usage error; it must exit 1, not 2")
		}
		// Today's wording would claim there was nothing to recover.
		if strings.Contains(out.String(), "no interrupted transactions found") {
			t.Error("a refused entry was reported as nothing to recover")
		}
		e := errOut.String()
		for _, want := range []string{"refused", "rule=rule-bad", "unknown_mechanism", `mechanism="ghost"`, "stays open", "check whether the host"} {
			if !strings.Contains(e, want) {
				t.Errorf("stderr missing %q: %q", want, e)
			}
		}
	})

	t.Run("mixed keeps the compensated results", func(t *testing.T) {
		var out, errOut bytes.Buffer
		rep := &engine.RecoveryReport{
			Results:  []*api.TransactionResult{recoveredResult("rule-ok")},
			Refusals: []engine.RecoveryRefusal{refusal("rule-bad")},
		}
		if err := renderRecoverReport(&out, &errOut, rep, "h"); err == nil {
			t.Fatal("a refusal must make the command fail")
		}
		if !strings.Contains(out.String(), "rule=rule-ok") || !strings.Contains(out.String(), "compensated 1") {
			t.Errorf("the compensated entry was dropped from the output: %q", out.String())
		}
		if !strings.Contains(errOut.String(), "rule=rule-bad") {
			t.Errorf("the refusal is missing: %q", errOut.String())
		}
	})
}
