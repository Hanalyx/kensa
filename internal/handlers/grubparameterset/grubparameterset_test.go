package grubparameterset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/grubparameterset"
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

// @spec handler-grub-parameter-set
// @ac AC-01
func TestApply_StripsAndAppendsKeyValue(t *testing.T) {
	t.Run("handler-grub-parameter-set/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := grubparameterset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"key":   "audit",
		"value": "1",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// The single chained pipeline must strip the prior key, append
	// key=value before the closing quote, and regenerate grub config.
	if !anyRunContains(tp.Runs, "sed -i -E", `audit=[^ "]*`, "/etc/default/grub") {
		t.Errorf("expected a sed strip of the prior key; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, `GRUB_CMDLINE_LINUX="[^"]*`, `audit=1`) {
		t.Errorf("expected a sed append of key=value; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "grub2-mkconfig", "grub-mkconfig") {
		t.Errorf("expected grub config regeneration; runs=%v", tp.Runs)
	}
}

// @spec handler-grub-parameter-set
// @ac AC-02
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-grub-parameter-set/AC-02", func(t *testing.T) {})
	h := grubparameterset.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing key", api.Params{"value": "1"}},
		{"empty key", api.Params{"key": "", "value": "1"}},
		{"non-string key", api.Params{"key": 42, "value": "1"}},
		{"missing value", api.Params{"key": "audit"}},
		{"non-string value", api.Params{"key": "audit", "value": 1}},
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

// @spec handler-grub-parameter-set
// @ac AC-03
func TestApply_PipelineFailureReportsUnsuccessful(t *testing.T) {
	t.Run("handler-grub-parameter-set/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	stripCmd := `sed -i -E 's/\baudit=[^ "]*//g; s/\baudit\b//g' /etc/default/grub`
	appendCmd := `sed -i -E 's/(GRUB_CMDLINE_LINUX="[^"]*)/\1 audit=1/' /etc/default/grub`
	mkconfig := "grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null"
	pipeline := strings.Join([]string{stripCmd, appendCmd, mkconfig}, " && ")
	tp.Results[pipeline] = &api.CommandResult{ExitCode: 2, Stderr: "mkconfig failed"}
	h := grubparameterset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"key": "audit", "value": "1"}, nil)
	if err != nil {
		t.Fatalf("Apply returned error (want StepResult with Success=false): %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false on non-zero exit; detail=%s", res.Detail)
	}
	if !strings.Contains(res.Detail, "mkconfig failed") {
		t.Errorf("expected stderr surfaced in detail; got %q", res.Detail)
	}
}

// @spec handler-grub-parameter-set
// @ac AC-04
// @spec handler-interface
// @ac AC-05
func TestHandler_NonCapturable(t *testing.T) {
	t.Run("handler-grub-parameter-set/AC-04", func(t *testing.T) {})
	t.Run("handler-interface/AC-05", func(t *testing.T) {})
	h := grubparameterset.New()
	if h.Capturable() {
		t.Error("Capturable() must be false for grub_parameter_set")
	}
	if _, ok := interface{}(h).(api.CombinedHandler); ok {
		t.Error("non-capturable handler must not satisfy CombinedHandler")
	}
}
