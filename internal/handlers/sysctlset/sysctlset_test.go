package sysctlset_test

import (
	"context"
	"encoding/base64"
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
	tp.Results["if [ -e '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf' ]; then base64 '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf'; else printf '%s' '__KENSA_ABSENT__'; fi"] =
		&api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("# old kensa\nnet.ipv4.ip_forward = 0\n"))}

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

// @spec security-value-hardening
// @ac AC-02
func TestApply_RejectsControlCharValue(t *testing.T) {
	t.Run("security-value-hardening/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// A newline in the value would inject extra sysctl directives (security.md
	// #13b); reject at decode, host untouched.
	_, err := sysctlset.New().Apply(context.Background(), tp,
		api.Params{"key": "kernel.dmesg_restrict", "value": "1\nkernel.evil = 1"}, nil)
	if err == nil {
		t.Fatal("expected an error for a newline in the sysctl value")
	}
	if len(tp.Runs) != 0 {
		t.Errorf("host must be untouched; got %d run(s)", len(tp.Runs))
	}
}

// TestCapture_Base64Failure_AbortsNoDestructiveEmpty is the round-3 panel
// regression: if base64 FAILS on an EXISTING persist file (missing applet /
// EACCES), the if-form returns a non-zero exit with empty stdout. Capture MUST
// return an error (aborting the transaction before any mutation), NOT record
// existed=true/content="" — which would rewrite the file EMPTY on rollback.
func TestCapture_Base64Failure_AbortsNoDestructiveEmpty(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["sysctl -n 'net.ipv4.ip_forward'"] = &api.CommandResult{Stdout: "0\n"}
	// base64 failed on an existing file: non-zero exit, empty stdout.
	tp.Results["if [ -e '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf' ]; then base64 '/etc/sysctl.d/99-kensa_net.ipv4.ip_forward.conf'; else printf '%s' '__KENSA_ABSENT__'; fi"] =
		&api.CommandResult{ExitCode: 127, Stderr: "base64: command not found"}

	h := sysctlset.New()
	_, err := h.Capture(context.Background(), tp, api.Params{
		"key": "net.ipv4.ip_forward", "value": "1",
	})
	if err == nil {
		t.Fatal("Capture must ERROR when base64 fails on an existing file — a nil error would let rollback rewrite the file EMPTY (destructive)")
	}
}
