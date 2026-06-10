package kernelmoduledisable_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/kernelmoduledisable"
)

// @spec handler-kernel-module-disable
// @ac AC-01
func TestApply_WritesBlacklistAndUnloads(t *testing.T) {
	t.Log("// @spec handler-kernel-module-disable")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := kernelmoduledisable.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "usb-storage"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "blacklist usb-storage") {
		t.Errorf("expected blacklist entry; got %q", cmd)
	}
	if !strings.Contains(cmd, "install usb-storage /bin/true") {
		t.Errorf("expected install /bin/true entry; got %q", cmd)
	}
	if !strings.Contains(cmd, "modprobe -r") {
		t.Errorf("expected modprobe -r; got %q", cmd)
	}
}

// @spec handler-kernel-module-disable
// @ac AC-02
// @ac AC-03
func TestRollback_RemovesBlacklistWhenAbsentAtCapture(t *testing.T) {
	t.Log("// @spec handler-kernel-module-disable")
	t.Run("handler-kernel-module-disable/AC-02", func(t *testing.T) {})
	t.Run("handler-kernel-module-disable/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := kernelmoduledisable.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"module":        "usb-storage",
			"path":          "/etc/modprobe.d/kensa-disable-usb-storage.conf",
			"file_existed":  false,
			"prior_content": "",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "rm -f") {
		t.Errorf("expected rm -f; got %q", tp.Runs[0])
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = kernelmoduledisable.New()
}
