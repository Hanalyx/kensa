package authselectfeatureenable_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/authselectfeatureenable"
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

// @spec handler-authselect-feature-enable
// @ac AC-01
func TestApply_EnablesFeature(t *testing.T) {
	t.Run("handler-authselect-feature-enable/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := authselectfeatureenable.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"feature": "with-faillock",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "authselect enable-feature", "with-faillock") {
		t.Errorf("expected `authselect enable-feature with-faillock`; runs=%v", tp.Runs)
	}
}

// @spec handler-authselect-feature-enable
// @ac AC-02
// @spec handler-interface
// @ac AC-02
func TestCapture_RecordsPriorOutput(t *testing.T) {
	t.Run("handler-authselect-feature-enable/AC-02", func(t *testing.T) {})
	t.Run("handler-interface/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results["authselect current --raw 2>/dev/null"] = &api.CommandResult{
		Stdout: "sssd\nwith-sudo\n",
	}
	h := authselectfeatureenable.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"feature": "with-faillock",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if got, _ := pre.Data["feature"].(string); got != "with-faillock" {
		t.Errorf("feature = %q", got)
	}
	if got, _ := pre.Data["prior_output"].(string); !strings.Contains(got, "with-sudo") {
		t.Errorf("prior_output did not record authselect output; got %q", got)
	}
}

// @spec handler-authselect-feature-enable
// @ac AC-03
// @spec handler-interface
// @ac AC-03
func TestRollback_DisablesNewlyEnabledFeature(t *testing.T) {
	t.Run("handler-authselect-feature-enable/AC-03", func(t *testing.T) {})
	t.Run("handler-interface/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := authselectfeatureenable.New()
	// Prior output did NOT contain the feature, so Apply enabled it and
	// rollback must disable it.
	pre := &api.PreState{
		Mechanism:  "authselect_feature_enable",
		Capturable: true,
		Data: map[string]interface{}{
			"feature":      "with-faillock",
			"prior_output": "sssd\nwith-sudo\n",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "authselect disable-feature", "with-faillock") {
		t.Errorf("expected `authselect disable-feature with-faillock`; runs=%v", tp.Runs)
	}
}

// @spec handler-authselect-feature-enable
// @ac AC-04
func TestRollback_NoOpWhenPreExisting(t *testing.T) {
	t.Run("handler-authselect-feature-enable/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := authselectfeatureenable.New()
	// Prior output already contained the feature, so rollback must not
	// disable it.
	pre := &api.PreState{
		Mechanism:  "authselect_feature_enable",
		Capturable: true,
		Data: map[string]interface{}{
			"feature":      "with-faillock",
			"prior_output": "sssd\nwith-faillock\nwith-sudo\n",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if anyRunContains(tp.Runs, "disable-feature") {
		t.Errorf("expected no disable on pre-existing feature; runs=%v", tp.Runs)
	}
}

// @spec handler-authselect-feature-enable
// @ac AC-05
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-authselect-feature-enable/AC-05", func(t *testing.T) {})
	h := authselectfeatureenable.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"missing feature", api.Params{}},
		{"empty feature", api.Params{"feature": ""}},
		{"non-string feature", api.Params{"feature": 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Apply(context.Background(), engine.NewFakeTransport(), tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
		})
	}
}

// @spec handler-authselect-feature-enable
// @ac AC-06
func TestRollback_RejectsNilPreState(t *testing.T) {
	t.Run("handler-authselect-feature-enable/AC-06", func(t *testing.T) {})
	h := authselectfeatureenable.New()
	if _, err := h.Rollback(context.Background(), engine.NewFakeTransport(), nil); err == nil {
		t.Errorf("expected error on nil pre-state")
	}
	// pre-state present but missing feature.
	pre := &api.PreState{Mechanism: "authselect_feature_enable", Data: map[string]interface{}{"prior_output": "x"}}
	if _, err := h.Rollback(context.Background(), engine.NewFakeTransport(), pre); err == nil {
		t.Errorf("expected error on pre-state missing feature")
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = authselectfeatureenable.New()
}
