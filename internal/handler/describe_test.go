package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// stubHandler is a minimal registrable handler. describe, when non-nil,
// makes it a PreStateDescriber.
type stubHandler struct {
	name     string
	describe func(*api.PreState) string
}

func (s *stubHandler) Name() string     { return s.name }
func (s *stubHandler) Capturable() bool { return true }
func (s *stubHandler) Apply(context.Context, api.Transport, api.Params, *api.PreState) (*api.StepResult, error) {
	return &api.StepResult{Success: true}, nil
}

// describingHandler implements PreStateDescriber; stubHandler alone does
// not, which is what makes the no-describer fallback testable.
type describingHandler struct {
	stubHandler
}

func (d *describingHandler) DescribePreState(pre *api.PreState) string {
	return d.describe(pre)
}

// TestDescribePreStateFallbacks covers every path that must degrade to the
// generic rendering rather than to an empty string or a panic: a mechanism
// nothing registered, a handler with no describer, a describer that returns
// nothing, and a describer that panics on data it did not expect.
//
// @spec pkg-prestate-describe
// @ac AC-05
func TestDescribePreStateFallbacks(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-05")

	r := NewRegistry()
	r.Register(&stubHandler{name: "no_describer"})
	r.Register(&describingHandler{stubHandler{name: "empty_describer"}})
	r.Register(&describingHandler{stubHandler{name: "panicking", describe: func(pre *api.PreState) string {
		// The classic version of this bug: a direct type assertion that
		// holds on a live capture and fails after a wire round-trip.
		return pre.Data["count"].(string)
	}}})
	r.Register(&describingHandler{stubHandler{name: "good", describe: func(*api.PreState) string {
		return "a real summary"
	}}})

	data := map[string]interface{}{"count": int64(3), "path": "/etc/x"}

	for _, tc := range []struct {
		name      string
		mechanism string
		want      string
	}{
		{"unregistered mechanism", "nothing_registered", "nothing_registered: "},
		{"handler without a describer", "no_describer", "no_describer: "},
		{"describer returning empty", "empty_describer", "empty_describer: "},
		{"describer that panics", "panicking", "panicking: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := r.DescribePreState(&api.PreState{
				Mechanism: tc.mechanism, Capturable: true, Data: data,
			})
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("DescribePreState = %q, want the generic rendering %q…", got, tc.want)
			}
			if !strings.Contains(got, "path=/etc/x") {
				t.Errorf("generic rendering dropped a field: %q", got)
			}
		})
	}

	t.Run("handler describer wins", func(t *testing.T) {
		got := r.DescribePreState(&api.PreState{
			Mechanism: "good", Capturable: true, Data: data,
		})
		if got != "a real summary" {
			t.Errorf("DescribePreState = %q, want the handler's own line", got)
		}
	})
}

// TestDescribePreStateNonCapturable locks the marker a consumer needs to
// tell "this mechanism cannot capture" apart from "no summary available".
//
// @spec pkg-prestate-describe
// @ac AC-06
func TestDescribePreStateNonCapturable(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-06")

	got := NewRegistry().DescribePreState(&api.PreState{
		Mechanism: "command_exec", Capturable: false,
	})
	if got == "" {
		t.Fatal("a non-capturable pre-state rendered as empty")
	}
	if !strings.Contains(got, "not capturable") {
		t.Errorf("DescribePreState = %q, want a non-capturable marker", got)
	}
}

// TestDescribePreStateNilIsEmpty keeps a nil pre-state from panicking a
// caller that is merely rendering a page.
//
// @spec pkg-prestate-describe
// @ac AC-03
func TestDescribePreStateNilIsEmpty(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-03")

	if got := NewRegistry().DescribePreState(nil); got != "" {
		t.Errorf("DescribePreState(nil) = %q, want \"\"", got)
	}
}
