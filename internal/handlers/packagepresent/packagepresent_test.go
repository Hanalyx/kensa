package packagepresent_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/packagepresent"
)

// @spec handler-package-present
// @ac AC-01
func TestApply_AC01_RunsDnfInstall(t *testing.T) {
	t.Log("// @spec handler-package-present")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := packagepresent.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "aide"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "dnf install -y 'aide'") {
		t.Errorf("got %q, want dnf install -y aide", tp.Runs[0])
	}
}

// @spec handler-package-present
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	t.Log("// @spec handler-package-present")
	t.Log("// @ac AC-02")
	tp := engine.NewFakeTransport()
	h := packagepresent.New()
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"name": "aide"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-package-present
// @ac AC-03
func TestCapture_AC03_RecordsInstalledPackage(t *testing.T) {
	t.Log("// @spec handler-package-present")
	t.Log("// @ac AC-03")
	tp := engine.NewFakeTransport()
	tp.Results["rpm -q 'aide' 2>&1 || true"] = &api.CommandResult{
		Stdout: "aide-0.16-14.el9.x86_64\n",
	}
	h := packagepresent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "aide"})
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

// @spec handler-package-present
// @ac AC-04
func TestCapture_AC04_RecordsNotInstalledPackage(t *testing.T) {
	t.Log("// @spec handler-package-present")
	t.Log("// @ac AC-04")
	tp := engine.NewFakeTransport()
	tp.Results["rpm -q 'telnet' 2>&1 || true"] = &api.CommandResult{
		Stdout: "package telnet is not installed\n",
	}
	h := packagepresent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "telnet"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["pkg_installed"] != false {
		t.Errorf("pkg_installed=%v, want false", pre.Data["pkg_installed"])
	}
}

// @spec handler-package-present
// @ac AC-05
func TestRollback_AC05_RemovesPackageWhenAbsentAtCapture(t *testing.T) {
	t.Log("// @spec handler-package-present")
	t.Log("// @ac AC-05")
	tp := engine.NewFakeTransport()
	h := packagepresent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "aide",
			"pkg_installed": false,
			"prior_version": "",
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
	if !strings.Contains(tp.Runs[0], "dnf remove -y 'aide'") {
		t.Errorf("got %q, want dnf remove -y aide", tp.Runs[0])
	}
}

// @spec handler-package-present
// @ac AC-06
func TestRollback_AC06_NoOpWhenPresentAtCapture(t *testing.T) {
	t.Log("// @spec handler-package-present")
	t.Log("// @ac AC-06")
	tp := engine.NewFakeTransport()
	h := packagepresent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "aide",
			"pkg_installed": true,
			"prior_version": "aide-0.16-14.el9.x86_64",
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
	var _ api.CombinedHandler = packagepresent.New()
}
