package packageabsent_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/packageabsent"
)

// @spec handler-package-absent
// @ac AC-01
func TestApply_AC01_RunsDnfRemove(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := packageabsent.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "telnet"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "dnf remove -y 'telnet'") {
		t.Errorf("got %q, want dnf remove -y telnet", tp.Runs[0])
	}
}

// @spec handler-package-absent
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := packageabsent.New()
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"name": "telnet"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-package-absent
// @ac AC-03
func TestCapture_AC03_RecordsInstalledPackage(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["rpm -q 'telnet' 2>&1 || true"] = &api.CommandResult{
		Stdout: "telnet-0.17-85.el9.x86_64\n",
	}
	h := packageabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "telnet"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["pkg_installed"] != true {
		t.Errorf("pkg_installed=%v, want true", pre.Data["pkg_installed"])
	}
	if pre.Data["prior_version"] == "" {
		t.Error("expected non-empty prior_version")
	}
}

// @spec handler-package-absent
// @ac AC-04
func TestCapture_AC04_RecordsNotInstalledPackage(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["rpm -q 'rsh' 2>&1 || true"] = &api.CommandResult{
		Stdout: "package rsh is not installed\n",
	}
	h := packageabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "rsh"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["pkg_installed"] != false {
		t.Errorf("pkg_installed=%v, want false", pre.Data["pkg_installed"])
	}
}

// @spec handler-package-absent
// @ac AC-05
func TestRollback_AC05_ReinstallsPackageWhenPresentAtCapture(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := packageabsent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "telnet",
			"pkg_installed": true,
			"prior_version": "telnet-0.17-85.el9.x86_64",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "dnf install -y 'telnet'") {
		t.Errorf("got %q, want dnf install -y telnet", tp.Runs[0])
	}
}

// @spec handler-package-absent
// @ac AC-06
func TestRollback_AC06_NoOpWhenAbsentAtCapture(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := packageabsent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "rsh",
			"pkg_installed": false,
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 0 {
		t.Errorf("got %d Run calls, want 0 (no-op rollback)", len(tp.Runs))
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = packageabsent.New()
}
