package kernelmoduledisable_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/kernelmoduledisable"
)

func TestApply_WritesBlacklistAndUnloads(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := kernelmoduledisable.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"module": "usb-storage"}, nil)
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

func TestRollback_RemovesBlacklistWhenAbsentAtCapture(t *testing.T) {
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

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = kernelmoduledisable.New()
}
