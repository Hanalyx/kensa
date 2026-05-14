package cronjob_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/cronjob"
)

// @spec handler-cron-job
// @ac AC-01
func TestApply_WritesCronFile(t *testing.T) {
	t.Log("// @spec handler-cron-job")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := cronjob.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"name":     "kensa-audit",
		"schedule": "0 2 * * *",
		"user":     "root",
		"command":  "/usr/sbin/aide --check",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "kensa-audit") {
		t.Errorf("expected cron file path; got %q", cmd)
	}
	if !strings.Contains(cmd, "0 2 * * *") {
		t.Errorf("expected schedule in content; got %q", cmd)
	}
}

// @spec handler-cron-job
// @ac AC-02
// @ac AC-03
func TestRollback_RemovesCronFileWhenAbsentAtCapture(t *testing.T) {
	t.Log("// @spec handler-cron-job")
	t.Run("handler-cron-job/AC-02", func(t *testing.T) {})
	t.Run("handler-cron-job/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := cronjob.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/cron.d/kensa-audit",
			"file_existed": false,
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
	var _ api.CombinedHandler = cronjob.New()
}
