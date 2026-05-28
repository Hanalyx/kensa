package cryptopolicysubpolicy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/cryptopolicysubpolicy"
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

// @spec handler-crypto-policy-subpolicy
// @ac AC-01
func TestApply_AppendsSubpolicyWhenAbsent(t *testing.T) {
	t.Run("handler-crypto-policy-subpolicy/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Active base policy with no subpolicies; --show reports "DEFAULT".
	tp.Results["update-crypto-policies --show"] = &api.CommandResult{Stdout: "DEFAULT\n"}
	h := cryptopolicysubpolicy.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"subpolicy": "NO-SHA1"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// Expect a --set appending the subpolicy onto the current base.
	if !anyRunContains(tp.Runs, "update-crypto-policies --set", "DEFAULT:NO-SHA1") {
		t.Errorf("expected --set with appended subpolicy; runs=%v", tp.Runs)
	}
}

// @spec handler-crypto-policy-subpolicy
// @ac AC-02
func TestApply_NoOpWhenAlreadyActive(t *testing.T) {
	t.Run("handler-crypto-policy-subpolicy/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Subpolicy already stacked on the base; case-insensitive match.
	tp.Results["update-crypto-policies --show"] = &api.CommandResult{Stdout: "DEFAULT:no-sha1\n"}
	h := cryptopolicysubpolicy.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"subpolicy": "NO-SHA1"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if anyRunContains(tp.Runs, "update-crypto-policies --set") {
		t.Errorf("expected no --set on no-op; runs=%v", tp.Runs)
	}
}

// @spec handler-crypto-policy-subpolicy
// @ac AC-03
func TestApply_ReportsFailureOnNonZeroExit(t *testing.T) {
	t.Run("handler-crypto-policy-subpolicy/AC-03", func(t *testing.T) {})

	t.Run("show fails", func(t *testing.T) {
		tp := engine.NewFakeTransport()
		tp.Results["update-crypto-policies --show"] = &api.CommandResult{ExitCode: 1, Stderr: "nope"}
		res, err := cryptopolicysubpolicy.New().Apply(context.Background(), tp, api.Params{"subpolicy": "NO-SHA1"}, nil)
		if err != nil {
			t.Fatalf("Apply returned Go error for --show failure; want StepResult: %v", err)
		}
		if res.Success {
			t.Errorf("Success=true despite --show failure; detail=%s", res.Detail)
		}
	})

	t.Run("set fails", func(t *testing.T) {
		tp := engine.NewFakeTransport()
		tp.Results["update-crypto-policies --show"] = &api.CommandResult{Stdout: "DEFAULT\n"}
		tp.Results["update-crypto-policies --set 'DEFAULT:NO-SHA1'"] = &api.CommandResult{ExitCode: 1, Stderr: "denied"}
		res, err := cryptopolicysubpolicy.New().Apply(context.Background(), tp, api.Params{"subpolicy": "NO-SHA1"}, nil)
		if err != nil {
			t.Fatalf("Apply returned Go error for --set failure; want StepResult: %v", err)
		}
		if res.Success {
			t.Errorf("Success=true despite --set failure; detail=%s", res.Detail)
		}
	})
}

// @spec handler-crypto-policy-subpolicy
// @ac AC-04
func TestApply_RejectsInvalidParams(t *testing.T) {
	t.Run("handler-crypto-policy-subpolicy/AC-04", func(t *testing.T) {})
	h := cryptopolicysubpolicy.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing subpolicy", api.Params{"other": "x"}},
		{"empty subpolicy", api.Params{"subpolicy": ""}},
		{"non-string subpolicy", api.Params{"subpolicy": 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Apply(context.Background(), engine.NewFakeTransport(), tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
		})
	}
}

// @spec handler-crypto-policy-subpolicy
// @ac AC-05
// @spec handler-interface
// @ac AC-05
func TestHandler_NonCapturable(t *testing.T) {
	t.Run("handler-crypto-policy-subpolicy/AC-05", func(t *testing.T) {})
	t.Run("handler-interface/AC-05", func(t *testing.T) {})
	h := cryptopolicysubpolicy.New()
	if h.Capturable() {
		t.Error("crypto_policy_subpolicy must report Capturable() == false")
	}
	if _, ok := interface{}(h).(api.CombinedHandler); ok {
		t.Error("non-capturable handler must not satisfy CombinedHandler")
	}
}
