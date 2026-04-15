package fileabsent_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/fileabsent"
)

// captureCmd returns the exact shell command the handler produces for
// a given path, keyed for FakeTransport programming.
func captureCmd(path string) string {
	q := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	return fmt.Sprintf(
		`if [ -e %[1]s ]; then printf 'EXISTS\n'; stat -c '%%a|%%U|%%G' %[1]s; ls -Zd %[1]s 2>/dev/null | awk '{print $1}'; cat %[1]s; else printf 'ABSENT\n'; fi`,
		q,
	)
}

// @spec handler-file-absent
// @ac AC-01
func TestApply_AC01_RemovesFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"path": "/etc/resolv.conf.bak"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "rm -f") {
		t.Errorf("expected rm -f; got %q", tp.Runs[0])
	}
}

// @spec handler-file-absent
// @ac AC-02
func TestApply_AC02_IsIdempotentForAbsentFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	// FakeTransport returns exit 0 by default; rm -f of absent file = 0.
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"path": "/etc/gone"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-file-absent
// @ac AC-03
func TestCapture_AC03_RecordsExistingFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/resolv.conf.bak"
	tp.Results[captureCmd(path)] = &api.CommandResult{
		Stdout: "EXISTS\n0600|root|root\nsystem_u:object_r:net_conf_t:s0\nnameserver 1.1.1.1\n",
	}
	h := fileabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Errorf("file_existed=%v, want true", pre.Data["file_existed"])
	}
	if pre.Data["content"] != "nameserver 1.1.1.1\n" {
		t.Errorf("content=%q, want nameserver line", pre.Data["content"])
	}
	if pre.Data["mode"] != "0600" {
		t.Errorf("mode=%v, want 0600", pre.Data["mode"])
	}
}

// @spec handler-file-absent
// @ac AC-04
func TestCapture_AC04_AbsentFileReturnsFileExistedFalse(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/gone"
	tp.Results[captureCmd(path)] = &api.CommandResult{Stdout: "ABSENT\n"}
	h := fileabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path})
	if err != nil {
		t.Fatalf("Capture returned unexpected error: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Errorf("file_existed=%v, want false", pre.Data["file_existed"])
	}
}

// @spec handler-file-absent
// @ac AC-05
func TestRollback_AC05_RecreatesFileWithAttrs(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/resolv.conf.bak",
			"file_existed": true,
			"content":      "nameserver 1.1.1.1\n",
			"mode":         "0644",
			"owner":        "root",
			"group":        "root",
			"selinux":      "system_u:object_r:net_conf_t:s0",
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
	if !strings.Contains(cmd, "printf") {
		t.Errorf("expected printf write; got %q", cmd)
	}
	if !strings.Contains(cmd, "chmod 0644") {
		t.Errorf("expected chmod; got %q", cmd)
	}
}

// @spec handler-file-absent
// @ac AC-06
func TestRollback_AC06_NoOpWhenFileWasAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/gone",
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
	if len(tp.Runs) != 0 {
		t.Errorf("got %d Run calls, want 0 (no-op rollback)", len(tp.Runs))
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = fileabsent.New()
}
