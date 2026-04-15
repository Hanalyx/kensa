package aptabsent_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/aptabsent"
)

func TestApply_RemovesPackage(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := aptabsent.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "telnet"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 || !strings.Contains(tp.Runs[0], "apt-get remove") {
		t.Errorf("expected apt-get remove; got %v", tp.Runs)
	}
	if !strings.Contains(tp.Runs[0], "telnet") {
		t.Errorf("expected package name in command; got %q", tp.Runs[0])
	}
}

func TestCapture_PackageInstalled(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["dpkg -l 'telnet' 2>/dev/null | grep '^ii' || true"] = &api.CommandResult{
		Stdout: "ii  telnet  0.17-42  amd64  basic telnet client\n",
	}
	h := aptabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "telnet"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["pkg_installed"] != true {
		t.Errorf("pkg_installed=%v, want true", pre.Data["pkg_installed"])
	}
}

func TestCapture_PackageAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["dpkg -l 'telnet' 2>/dev/null | grep '^ii' || true"] = &api.CommandResult{Stdout: ""}
	h := aptabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "telnet"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["pkg_installed"] != false {
		t.Errorf("pkg_installed=%v, want false", pre.Data["pkg_installed"])
	}
}

func TestRollback_NoOpWhenWasAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := aptabsent.New()
	pre := &api.PreState{Data: map[string]interface{}{"name": "telnet", "pkg_installed": false}}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if len(tp.Runs) != 0 {
		t.Errorf("expected no-op; got %v", tp.Runs)
	}
}

func TestRollback_ReinstallsWhenWasPresent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := aptabsent.New()
	pre := &api.PreState{Data: map[string]interface{}{"name": "telnet", "pkg_installed": true}}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if len(tp.Runs) != 1 || !strings.Contains(tp.Runs[0], "apt-get install") {
		t.Errorf("expected apt-get install; got %v", tp.Runs)
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = aptabsent.New()
}
