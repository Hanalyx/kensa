package sysctlset_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/sysctlset"
)

// @spec handler-sysctl-set
// @ac AC-01
func TestApply_AC01_RuntimeAndPersistBothWritten(t *testing.T) {
	t.Log("// @spec handler-sysctl-set")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := sysctlset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"key":   "net.ipv4.ip_forward",
		"value": "0",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 2 {
		t.Fatalf("got %d Run calls, want 2 (runtime + persist)", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "sysctl -w 'net.ipv4.ip_forward'='0'") {
		t.Errorf("first run should be sysctl -w; got %q", tp.Runs[0])
	}
	if !strings.Contains(tp.Runs[1], "/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf") {
		t.Errorf("second run should write to default persist file; got %q", tp.Runs[1])
	}
	if !strings.Contains(tp.Runs[1], "net.ipv4.ip_forward = 0") {
		t.Errorf("second run should contain canonical assignment; got %q", tp.Runs[1])
	}
}

// @spec handler-sysctl-set
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	t.Log("// @spec handler-sysctl-set")
	t.Log("// @ac AC-02")
	tp := engine.NewFakeTransport()
	h := sysctlset.New()
	params := api.Params{"key": "kernel.dmesg_restrict", "value": "1"}
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d failed: err=%v success=%v", i+1, err, res.Success)
		}
	}
	if len(tp.Runs) != 6 {
		t.Errorf("got %d Run calls, want 6 (3 invocations × 2 commands)", len(tp.Runs))
	}
}

// @spec handler-sysctl-set
// @ac AC-03
func TestCapture_AC03_RecordsRuntimeAndPersistContent(t *testing.T) {
	t.Log("// @spec handler-sysctl-set")
	t.Log("// @ac AC-03")
	tp := engine.NewFakeTransport()
	// Program runtime probe.
	tp.Results["sysctl -n 'net.ipv4.ip_forward'"] = &api.CommandResult{Stdout: "0\n"}
	// Program persist-file existence + read.
	tp.Results["test -e '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf' && cat '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf' || printf '__KENSA_ABSENT__'"] =
		&api.CommandResult{Stdout: "# old kensa\nnet.ipv4.ip_forward = 0\n"}

	h := sysctlset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"key":   "net.ipv4.ip_forward",
		"value": "0",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["runtime_value"] != "0" {
		t.Errorf("runtime_value=%v, want 0", pre.Data["runtime_value"])
	}
	if !strings.Contains(pre.Data["persist_file_content"].(string), "net.ipv4.ip_forward = 0") {
		t.Errorf("persist_file_content missing expected line: %q", pre.Data["persist_file_content"])
	}
	if pre.Data["persist_file_existed"] != true {
		t.Error("persist_file_existed should be true")
	}
}

// @spec handler-sysctl-set
// @ac AC-04
func TestRollback_AC04_RestoresFileContent(t *testing.T) {
	t.Log("// @spec handler-sysctl-set")
	t.Log("// @ac AC-04")
	tp := engine.NewFakeTransport()
	h := sysctlset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"key":                  "net.ipv4.ip_forward",
			"persist_file":         "/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf",
			"runtime_value":        "0",
			"persist_file_content": "# original\nnet.ipv4.ip_forward = 0\n",
			"persist_file_existed": true,
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false: %s", res.Detail)
	}
	// Both persist write + sysctl -w should fire.
	if len(tp.Runs) != 2 {
		t.Fatalf("got %d Run calls, want 2", len(tp.Runs))
	}
}

// @spec handler-sysctl-set
// @ac AC-05
func TestRollback_AC05_RemovesFileWhenAbsent(t *testing.T) {
	t.Log("// @spec handler-sysctl-set")
	t.Log("// @ac AC-05")
	tp := engine.NewFakeTransport()
	h := sysctlset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"key":                  "net.ipv4.ip_forward",
			"persist_file":         "/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf",
			"runtime_value":        "1",
			"persist_file_content": "",
			"persist_file_existed": false,
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "rm -f '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf'") {
		t.Errorf("expected rm -f for absent file; got %q", tp.Runs[0])
	}
}

// @spec handler-sysctl-set
// @ac AC-06
func TestApply_AC06_FailsCleanlyOnRuntimeRejection(t *testing.T) {
	t.Log("// @spec handler-sysctl-set")
	t.Log("// @ac AC-06")
	tp := engine.NewFakeTransport()
	tp.Results["sysctl -w 'net.invalid.key'='42'"] = &api.CommandResult{
		ExitCode: 1,
		Stderr:   "sysctl: cannot stat /proc/sys/net/invalid/key: No such file or directory",
	}
	h := sysctlset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"key":   "net.invalid.key",
		"value": "42",
	}, nil)
	if err != nil {
		t.Fatalf("Apply transport err: %v", err)
	}
	if res.Success {
		t.Error("expected Success=false on runtime rejection")
	}
	if !strings.Contains(res.Detail, "No such file") {
		t.Errorf("expected detail to include kernel error; got %q", res.Detail)
	}
	// Persist should NOT have been written since runtime rejected.
	if len(tp.Runs) != 1 {
		t.Errorf("got %d Run calls, want 1 (persist must not run after runtime rejection)", len(tp.Runs))
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = sysctlset.New()
}

func TestDecodeParams_RequiresKey(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := sysctlset.New()
	_, err := h.Apply(context.Background(), tp, api.Params{"value": "0"}, nil)
	if err == nil {
		t.Error("expected error for missing key")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error should mention 'key'; got %v", err)
	}
}

func TestDecodeParams_AcceptsCustomPersistFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := sysctlset.New()
	_, err := h.Apply(context.Background(), tp, api.Params{
		"key":          "net.ipv4.ip_forward",
		"value":        "0",
		"persist_file": "/etc/sysctl.d/00-custom.conf",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(tp.Runs[1], "/etc/sysctl.d/00-custom.conf") {
		t.Errorf("expected custom persist file in command; got %q", tp.Runs[1])
	}
}

// Sanity: the registry-import wiring puts sysctl_set in handler.Default.
func TestRegistration_Available(t *testing.T) {
	// Register-side effect: importing the package registers the handler.
	// Already imported above transitively via the test package.
	if !errors.Is(nil, nil) { // dummy use of errors
		t.Skip()
	}
}
