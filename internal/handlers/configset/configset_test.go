package configset_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/configset"
)

// @spec handler-config-set
// @ac AC-01
func TestApply_AC01_SetsKeyEqualsValue(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"file":      "/etc/selinux/config",
		"key":       "SELINUX",
		"value":     "enforcing",
		"separator": "=",
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
	// The apply pipeline should contain the target line SELINUX=enforcing.
	if !strings.Contains(tp.Runs[0], "SELINUX=enforcing") {
		t.Errorf("expected SELINUX=enforcing in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set
// @ac AC-02
func TestApply_AC02_SpacedEqualsSign(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"file":      "/etc/login.defs",
		"key":       "PASS_MAX_DAYS",
		"value":     "90",
		"separator": " = ",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "PASS_MAX_DAYS = 90") {
		t.Errorf("expected PASS_MAX_DAYS = 90 in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set
// @ac AC-03
func TestApply_AC03_SpaceSeparator(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"file":      "/etc/ssh/sshd_config",
		"key":       "PermitRootLogin",
		"value":     "no",
		"separator": " ",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "PermitRootLogin no") {
		t.Errorf("expected 'PermitRootLogin no' in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set
// @ac AC-04
func TestApply_AC04_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	params := api.Params{"file": "/etc/selinux/config", "key": "SELINUX", "value": "enforcing"}
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-config-set
// @ac AC-05
func TestCapture_AC05_RecordsExistingLine(t *testing.T) {
	tp := engine.NewFakeTransport()
	// The capture command is a multi-part pipeline; we program the result
	// by matching the key pattern the handler will send.
	pattern := "^[[:space:]]*SELINUX[[:space:]=]"
	path := "/etc/selinux/config"

	// The capture one-liner tests existence, grep, and returns the match.
	// We use a wildcard approach: FakeTransport returns the result for
	// the exact command the handler generates.
	cmd := buildCaptureCmd(path, pattern)
	tp.Results[cmd] = &api.CommandResult{Stdout: "SELINUX=disabled\n"}

	h := configset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"file": path, "key": "SELINUX", "value": "enforcing",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["line_existed"] != true {
		t.Errorf("line_existed=%v, want true", pre.Data["line_existed"])
	}
	if pre.Data["prior_line"] != "SELINUX=disabled" {
		t.Errorf("prior_line=%q, want SELINUX=disabled", pre.Data["prior_line"])
	}
}

// @spec handler-config-set
// @ac AC-06
func TestCapture_AC06_RecordsAbsentKey(t *testing.T) {
	tp := engine.NewFakeTransport()
	pattern := "^[[:space:]]*NEWKEY[[:space:]=]"
	path := "/etc/config"
	cmd := buildCaptureCmd(path, pattern)
	tp.Results[cmd] = &api.CommandResult{Stdout: "__KENSA_ABSENT__\n"}

	h := configset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"file": path, "key": "NEWKEY", "value": "yes",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["line_existed"] != false {
		t.Errorf("line_existed=%v, want false", pre.Data["line_existed"])
	}
}

// @spec handler-config-set
// @ac AC-07
func TestCapture_AC07_NonExistentFileReturnsErrCaptureIncomplete(t *testing.T) {
	tp := engine.NewFakeTransport()
	pattern := "^[[:space:]]*KEY[[:space:]=]"
	path := "/no/such/file"
	cmd := buildCaptureCmd(path, pattern)
	tp.Results[cmd] = &api.CommandResult{Stdout: "__KENSA_NOFILE__\n"}

	h := configset.New()
	_, err := h.Capture(context.Background(), tp, api.Params{
		"file": path, "key": "KEY", "value": "v",
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("got %v, want ErrCaptureIncomplete", err)
	}
}

// @spec handler-config-set
// @ac AC-08
func TestRollback_AC08_RestoresPriorLine(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"file":         "/etc/selinux/config",
			"key":          "SELINUX",
			"separator":    "=",
			"line_existed": true,
			"prior_line":   "SELINUX=disabled",
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
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "sed -i") {
		t.Errorf("expected sed -i in rollback; got %q", cmd)
	}
	if !strings.Contains(cmd, "SELINUX=disabled") {
		t.Errorf("expected prior_line in rollback sed; got %q", cmd)
	}
}

// @spec handler-config-set
// @ac AC-09
func TestRollback_AC09_RemovesAppendedLine(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"file":         "/etc/config",
			"key":          "NEWKEY",
			"separator":    "=",
			"line_existed": false,
			"prior_line":   "",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// Rollback removes the line; the command should be a sed -i delete.
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "/d") {
		t.Errorf("expected sed delete expression; got %q", tp.Runs[0])
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = configset.New()
}

// buildCaptureCmd reconstructs the exact capture command the handler
// emits for a given file and grep pattern so tests can program responses.
func buildCaptureCmd(file, pattern string) string {
	qFile := "'" + strings.ReplaceAll(file, "'", `'\''`) + "'"
	qPat := "'" + strings.ReplaceAll(pattern, "'", `'\''`) + "'"
	return fmt.Sprintf(
		`if [ ! -e %[1]s ]; then printf '__KENSA_NOFILE__\n'; elif grep -qE %[2]s %[1]s 2>/dev/null; then grep -Em1 %[2]s %[1]s; else printf '__KENSA_ABSENT__\n'; fi`,
		qFile, qPat,
	)
}
