package configappend_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/handlers/configappend"
)

// Kernel-IO Apply appends the line through the funnel (AtomicReplace), so the
// footprint recorder observes the one file it touches.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-append
// @ac AC-06
func TestApply_Kernel_AppendsViaFunnel(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-append/AC-06", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[testPath] = "# header\nexisting=1\n"
	res, err := configappend.New().Apply(context.Background(), f,
		api.Params{"path": testPath, "line": testLine}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	got := f.Files[testPath]
	if !strings.Contains(got, testLine) || !strings.HasSuffix(got, testLine+"\n") {
		t.Errorf("line not appended as a final line: %q", got)
	}
	// Idempotent: a second apply does not duplicate the line.
	if _, err := configappend.New().Apply(context.Background(), f, api.Params{"path": testPath, "line": testLine}, nil); err != nil {
		t.Fatalf("Apply (2nd): %v", err)
	}
	if strings.Count(f.Files[testPath], testLine) != 1 {
		t.Errorf("apply duplicated the line: %q", f.Files[testPath])
	}
}

// Kernel-IO round trip: Capture → Apply → Rollback restores the prior content
// byte-perfect (the appended line is gone).
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-append
// @ac AC-06
func TestRoundTrip_Kernel_RestoresPriorContent(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-append/AC-06", func(t *testing.T) {})
	const prior = "# header\nexisting=1\n"
	f := kernelio.NewFakeSysctl()
	f.Files[testPath] = prior
	h := configappend.New()
	params := api.Params{"path": testPath, "line": testLine}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["was_present"] != false {
		t.Fatalf("want was_present=false, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(f.Files[testPath], testLine) {
		t.Fatal("apply should have appended the line")
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.Files[testPath] != prior {
		t.Errorf("rollback not byte-perfect: got %q, want %q", f.Files[testPath], prior)
	}
}

// config_append declares its single captured file to the gate.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-append
// @ac AC-06
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-append/AC-06", func(t *testing.T) {})
	var fp footprint.Footprinter = configappend.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{"path": testPath, "file_existed": true},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if !f.Has(testPath) || f.Len() != 1 {
		t.Errorf("footprint = %v, want exactly %s", f.Entries(), testPath)
	}
}
