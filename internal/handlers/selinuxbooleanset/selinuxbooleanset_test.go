package selinuxbooleanset_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/selinuxbooleanset"
)

// @spec handler-selinux-boolean-set
// @ac AC-01
func TestApply_AC01_RunsSetseboolPersistent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := selinuxbooleanset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"boolean": "httpd_can_network_connect",
		"value":   "on",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "setsebool -P") {
		t.Errorf("expected setsebool -P; got %q", tp.Runs[0])
	}
	if !strings.Contains(tp.Runs[0], "httpd_can_network_connect") {
		t.Errorf("expected boolean name in cmd; got %q", tp.Runs[0])
	}
	if !strings.Contains(tp.Runs[0], " on") {
		t.Errorf("expected value 'on' in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-selinux-boolean-set
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := selinuxbooleanset.New()
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{
			"boolean": "httpd_can_network_connect",
			"value":   "on",
		}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-selinux-boolean-set
// @ac AC-03
func TestCapture_AC03_RecordsPriorValue(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["getsebool 'httpd_can_network_connect'"] = &api.CommandResult{
		Stdout: "httpd_can_network_connect --> off\n",
	}
	h := selinuxbooleanset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"boolean": "httpd_can_network_connect",
		"value":   "on",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["prior_value"] != "off" {
		t.Errorf("prior_value=%v, want off", pre.Data["prior_value"])
	}
}

// @spec handler-selinux-boolean-set
// @ac AC-04
func TestCapture_AC04_ReturnsErrCaptureIncompleteOnFailure(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["getsebool 'unknown_boolean'"] = &api.CommandResult{
		ExitCode: 1,
		Stderr:   "getsebool: error getting active value for unknown_boolean",
	}
	h := selinuxbooleanset.New()
	_, err := h.Capture(context.Background(), tp, api.Params{
		"boolean": "unknown_boolean",
		"value":   "on",
	})
	if err == nil {
		t.Fatal("expected error for unknown boolean")
	}
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("got err=%v, want chain to ErrCaptureIncomplete", err)
	}
}

// @spec handler-selinux-boolean-set
// @ac AC-05
func TestRollback_AC05_RestoresPriorValue(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := selinuxbooleanset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"boolean":     "httpd_can_network_connect",
			"prior_value": "off",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "setsebool -P") {
		t.Errorf("expected setsebool -P; got %q", cmd)
	}
	if !strings.Contains(cmd, " off") {
		t.Errorf("expected prior value 'off'; got %q", cmd)
	}
}

// @spec handler-selinux-boolean-set
// @ac AC-06
func TestApply_AC06_InvalidValueReturnsParamsError(t *testing.T) {
	h := selinuxbooleanset.New()
	_, err := h.Apply(context.Background(), nil, api.Params{
		"boolean": "httpd_can_network_connect",
		"value":   "yes",
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid value")
	}
	if !strings.Contains(err.Error(), "on") || !strings.Contains(err.Error(), "off") {
		t.Errorf("error should mention valid values; got %q", err.Error())
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = selinuxbooleanset.New()
}
