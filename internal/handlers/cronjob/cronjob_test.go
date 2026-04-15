package cronjob_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/cronjob"
)

func TestApply_WritesCronFile(t *testing.T) {
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

func TestRollback_RemovesCronFileWhenAbsentAtCapture(t *testing.T) {
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

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = cronjob.New()
}
