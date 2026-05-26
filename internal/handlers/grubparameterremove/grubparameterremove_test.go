package grubparameterremove_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/grubparameterremove"
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

// @spec handler-grub-parameter-remove
// @ac AC-01
func TestApply_StripsKeyAndRegenerates(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := grubparameterremove.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"key": "audit",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// The strip sed must target both key= and bare-key forms and edit
	// /etc/default/grub, chained with a grub config regeneration.
	if !anyRunContains(tp.Runs, "sed -i -E", `audit=[^ "]*`, `audit\b`, "/etc/default/grub") {
		t.Errorf("expected a sed strip of the key; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "grub2-mkconfig", "grub-mkconfig") {
		t.Errorf("expected grub config regeneration; runs=%v", tp.Runs)
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-02
func TestApply_RejectsInvalidParams(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-02", func(t *testing.T) {})
	h := grubparameterremove.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing key", api.Params{}},
		{"empty key", api.Params{"key": ""}},
		{"non-string key", api.Params{"key": 42}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := engine.NewFakeTransport()
			if _, err := h.Apply(context.Background(), tp, tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
			if len(tp.Runs) != 0 {
				t.Errorf("expected no commands run on invalid params; runs=%v", tp.Runs)
			}
		})
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-03
func TestApply_PipelineFailureReportsUnsuccessful(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	pipeline := `sed -i -E 's/\baudit=[^ "]*//g; s/\baudit\b//g' /etc/default/grub` +
		` && grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null`
	tp.Results[pipeline] = &api.CommandResult{ExitCode: 1, Stderr: "no such file"}
	h := grubparameterremove.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"key": "audit"}, nil)
	if err != nil {
		t.Fatalf("Apply returned error (want StepResult with Success=false): %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false on non-zero exit; detail=%s", res.Detail)
	}
	if !strings.Contains(res.Detail, "no such file") {
		t.Errorf("expected stderr surfaced in detail; got %q", res.Detail)
	}
}

// @spec handler-grub-parameter-remove
// @ac AC-04
// @spec handler-interface
// @ac AC-05
func TestHandler_NonCapturable(t *testing.T) {
	t.Run("handler-grub-parameter-remove/AC-04", func(t *testing.T) {})
	t.Run("handler-interface/AC-05", func(t *testing.T) {})
	h := grubparameterremove.New()
	if h.Capturable() {
		t.Error("Capturable() must be false for grub_parameter_remove")
	}
	if _, ok := interface{}(h).(api.CombinedHandler); ok {
		t.Error("non-capturable handler must not satisfy CombinedHandler")
	}
}
