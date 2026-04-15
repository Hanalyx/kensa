package configsetdropin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/configsetdropin"
)

// @spec handler-config-set-dropin
// @ac AC-01
func TestApply_AC01_WritesDropinFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"path":  "/etc/systemd/system/sshd.service.d/kensa.conf",
		"key":   "LimitNOFILE",
		"value": "65536",
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
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "mkdir -p") {
		t.Errorf("expected mkdir -p; got %q", cmd)
	}
	if !strings.Contains(cmd, "LimitNOFILE=65536") {
		t.Errorf("expected LimitNOFILE=65536 in content; got %q", cmd)
	}
	if !strings.Contains(cmd, "Managed by Kensa") {
		t.Errorf("expected Kensa header; got %q", cmd)
	}
}

// @spec handler-config-set-dropin
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	params := api.Params{
		"path": "/etc/systemd/system/sshd.service.d/kensa.conf",
		"key":  "LimitNOFILE", "value": "65536",
	}
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-config-set-dropin
// @ac AC-03
func TestCapture_AC03_RecordsExistingDropin(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/systemd/system/sshd.service.d/kensa.conf"
	qPath := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	tp.Results["test -e "+qPath+" && cat "+qPath+" || printf '__KENSA_ABSENT__'"] =
		&api.CommandResult{Stdout: "# Managed by Kensa.\nLimitNOFILE=65536\n"}

	h := configsetdropin.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"path": path, "key": "LimitNOFILE", "value": "131072",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Errorf("file_existed=%v, want true", pre.Data["file_existed"])
	}
	if !strings.Contains(pre.Data["prior_content"].(string), "LimitNOFILE=65536") {
		t.Errorf("prior_content missing expected line; got %q", pre.Data["prior_content"])
	}
}

// @spec handler-config-set-dropin
// @ac AC-04
func TestCapture_AC04_AbsentDropinRecordsFileExistedFalse(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/systemd/system/sshd.service.d/kensa.conf"
	qPath := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	tp.Results["test -e "+qPath+" && cat "+qPath+" || printf '__KENSA_ABSENT__'"] =
		&api.CommandResult{Stdout: "__KENSA_ABSENT__"}

	h := configsetdropin.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"path": path, "key": "LimitNOFILE", "value": "65536",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Errorf("file_existed=%v, want false", pre.Data["file_existed"])
	}
}

// @spec handler-config-set-dropin
// @ac AC-05
func TestRollback_AC05_RestoresPriorContent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":          "/etc/systemd/system/sshd.service.d/kensa.conf",
			"file_existed":  true,
			"prior_content": "# Managed by Kensa.\nLimitNOFILE=65536\n",
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
	if !strings.Contains(tp.Runs[0], "printf") {
		t.Errorf("expected printf restore; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set-dropin
// @ac AC-06
func TestRollback_AC06_RemovesDropinWhenPriorWasAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/systemd/system/sshd.service.d/kensa.conf",
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
	var _ api.CombinedHandler = configsetdropin.New()
}
