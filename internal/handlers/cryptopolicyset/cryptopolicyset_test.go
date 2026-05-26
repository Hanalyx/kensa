package cryptopolicyset_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/cryptopolicyset"
)

// anyRunContains reports whether any recorded command contains all subs.
func anyRunContains(runs []string, subs ...string) bool {
	for _, r := range runs {
		all := true
		for _, s := range subs {
			if !strings.Contains(r, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// @spec handler-crypto-policy-set
// @ac AC-01
func TestApply_SetsPolicy(t *testing.T) {
	t.Run("handler-crypto-policy-set/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Default unmatched command → exit 0, so the --set succeeds.
	h := cryptopolicyset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"policy": "FIPS",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "update-crypto-policies --set 'FIPS'") {
		t.Errorf("expected update-crypto-policies --set; runs=%v", tp.Runs)
	}
}

// @spec handler-crypto-policy-set
// @ac AC-02
// @spec handler-interface
// @ac AC-02
func TestCapture_RecordsPriorPolicyAndIncompleteOnFailure(t *testing.T) {
	t.Run("handler-crypto-policy-set/AC-02", func(t *testing.T) {})
	t.Run("handler-interface/AC-02", func(t *testing.T) {})
	h := cryptopolicyset.New()

	// Success path: --show returns the current policy.
	tpOK := engine.NewFakeTransport()
	tpOK.Results["update-crypto-policies --show 2>/dev/null"] = &api.CommandResult{Stdout: "DEFAULT\n"}
	pre, err := h.Capture(context.Background(), tpOK, api.Params{"policy": "FIPS"})
	if err != nil {
		t.Fatalf("Capture (ok): %v", err)
	}
	if got, _ := pre.Data["prior_policy"].(string); got != "DEFAULT" {
		t.Errorf("prior_policy recorded = %q, want %q", got, "DEFAULT")
	}

	// Failure path: --show fails (non-zero exit) → ErrCaptureIncomplete.
	tpFail := engine.NewFakeTransport()
	tpFail.Results["update-crypto-policies --show 2>/dev/null"] = &api.CommandResult{ExitCode: 127, Stderr: "command not found"}
	_, err = h.Capture(context.Background(), tpFail, api.Params{"policy": "FIPS"})
	if err == nil {
		t.Fatalf("expected error when --show fails")
	}
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("expected ErrCaptureIncomplete, got %v", err)
	}
}

// @spec handler-crypto-policy-set
// @ac AC-03
// @spec handler-interface
// @ac AC-03
func TestRollback_RestoresPriorPolicy(t *testing.T) {
	t.Run("handler-crypto-policy-set/AC-03", func(t *testing.T) {})
	t.Run("handler-interface/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := cryptopolicyset.New()
	pre := &api.PreState{
		Mechanism:  "crypto_policy_set",
		Capturable: true,
		Data: map[string]interface{}{
			"prior_policy": "DEFAULT",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "update-crypto-policies --set 'DEFAULT'") {
		t.Errorf("expected restore via --set 'DEFAULT'; runs=%v", tp.Runs)
	}
}

// @spec handler-crypto-policy-set
// @ac AC-04
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-crypto-policy-set/AC-04", func(t *testing.T) {})
	h := cryptopolicyset.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing policy", api.Params{}},
		{"empty policy", api.Params{"policy": ""}},
		{"non-string policy", api.Params{"policy": 42}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Apply(context.Background(), engine.NewFakeTransport(), tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
		})
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = cryptopolicyset.New()
}
