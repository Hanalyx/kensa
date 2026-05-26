package manual_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/manual"
)

// @spec handler-manual
// @ac AC-01
func TestApply_NoCommandAndSucceeds(t *testing.T) {
	t.Run("handler-manual/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := manual.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"description": "rotate the root credential out of band",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 0 {
		t.Errorf("manual handler must not run any command; runs=%v", tp.Runs)
	}
	if !strings.Contains(res.Detail, "rotate the root credential out of band") {
		t.Errorf("expected the action description in detail; got %q", res.Detail)
	}
}

// @spec handler-manual
// @ac AC-02
func TestApply_ResolvesActionAndDefault(t *testing.T) {
	t.Run("handler-manual/AC-02", func(t *testing.T) {})

	t.Run("falls back to action param", func(t *testing.T) {
		tp := engine.NewFakeTransport()
		h := manual.New()
		res, err := h.Apply(context.Background(), tp, api.Params{
			"action": "physically reseat the TPM",
		}, nil)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !res.Success {
			t.Errorf("Success=false: %s", res.Detail)
		}
		if !strings.Contains(res.Detail, "physically reseat the TPM") {
			t.Errorf("expected action param in detail; got %q", res.Detail)
		}
	})

	t.Run("default when neither present", func(t *testing.T) {
		tp := engine.NewFakeTransport()
		h := manual.New()
		res, err := h.Apply(context.Background(), tp, api.Params{}, nil)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !res.Success {
			t.Errorf("Success=false: %s", res.Detail)
		}
		if !strings.Contains(res.Detail, "manual action required") {
			t.Errorf("expected default description in detail; got %q", res.Detail)
		}
		if len(tp.Runs) != 0 {
			t.Errorf("manual handler must not run any command; runs=%v", tp.Runs)
		}
	})
}

// @spec handler-manual
// @ac AC-03
func TestApply_RejectsNilParams(t *testing.T) {
	t.Run("handler-manual/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := manual.New()
	if _, err := h.Apply(context.Background(), tp, nil, nil); err == nil {
		t.Error("expected error for nil params")
	}
	if len(tp.Runs) != 0 {
		t.Errorf("expected no commands run on nil params; runs=%v", tp.Runs)
	}
}

// @spec handler-manual
// @ac AC-04
// @spec handler-interface
// @ac AC-05
func TestHandler_NonCapturable(t *testing.T) {
	t.Run("handler-manual/AC-04", func(t *testing.T) {})
	t.Run("handler-interface/AC-05", func(t *testing.T) {})
	h := manual.New()
	if h.Capturable() {
		t.Error("Capturable() must be false for manual")
	}
	if _, ok := interface{}(h).(api.CombinedHandler); ok {
		t.Error("non-capturable handler must not satisfy CombinedHandler")
	}
}
