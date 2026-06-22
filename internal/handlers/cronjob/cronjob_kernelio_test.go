package cronjob_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/handlers/cronjob"
)

const kPath = "/etc/cron.d/kensa-audit"

func kParams() api.Params {
	return api.Params{"schedule": "0 2 * * *", "user": "root", "command": "/usr/sbin/aide --check", "file": kPath}
}

// Kernel-IO Apply writes the cron file through the funnel (so the recorder
// observes it).
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-cron-job
// @ac AC-04
func TestApply_Kernel_WritesViaFunnel(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-cron-job/AC-04", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	res, err := cronjob.New().Apply(context.Background(), f, kParams(), nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	got := f.Files[kPath]
	if !strings.Contains(got, "0 2 * * * root /usr/sbin/aide --check") || !strings.Contains(got, "# Managed by Kensa.") {
		t.Errorf("cron file content = %q", got)
	}
}

// Kernel-IO round trip: a file absent at capture is removed on rollback.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-cron-job
// @ac AC-04
func TestRoundTrip_Kernel_RemovesWhenAbsent(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-cron-job/AC-04", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	h := cronjob.New()
	pre, err := h.Capture(context.Background(), f, kParams())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Fatalf("want file_existed=false, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, kParams(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := f.Files[kPath]; !ok {
		t.Fatal("apply should have written the cron file")
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, ok := f.Files[kPath]; ok {
		t.Error("rollback should have removed the cron file that did not exist at capture")
	}
}

// Kernel-IO round trip: a pre-existing cron file is restored byte-perfect.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-cron-job
// @ac AC-04
func TestRoundTrip_Kernel_RestoresPrior(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-cron-job/AC-04", func(t *testing.T) {})
	const prior = "# operator job\n0 1 * * * root /opt/old\n"
	f := kernelio.NewFakeSysctl()
	f.Files[kPath] = prior
	h := cronjob.New()
	pre, err := h.Capture(context.Background(), f, kParams())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if _, err := h.Apply(context.Background(), f, kParams(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.Files[kPath] != prior {
		t.Errorf("rollback not byte-perfect: got %q, want %q", f.Files[kPath], prior)
	}
}

// cron_job declares its single captured file to the gate.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-cron-job
// @ac AC-04
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-cron-job/AC-04", func(t *testing.T) {})
	var fp footprint.Footprinter = cronjob.New()
	f, err := fp.CapturedFootprint(&api.PreState{Data: map[string]interface{}{"path": kPath, "file_existed": false}})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if !f.Has(kPath) || f.Len() != 1 {
		t.Errorf("footprint = %v, want exactly %s", f.Entries(), kPath)
	}
}
