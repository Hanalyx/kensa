package sysctlset_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/sysctlset"
)

// persistPathFor mirrors the handler's per-key default drop-in path. Each
// sysctl key gets its own file so multiple rules never share (and clobber) one.
func persistPathFor(key string) string { return "/etc/sysctl.d/99-kensa-" + key + ".conf" }

// Kernel-IO Apply writes the runtime value to the proc layer and the
// drop-in to the persist layer (no shell).
//
// @spec kernelio-sysctl
// @ac AC-04
func TestApply_Kernel(t *testing.T) {
	t.Run("kernelio-sysctl/AC-04", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	res, err := sysctlset.New().Apply(context.Background(), f,
		api.Params{"key": "net.ipv4.ip_forward", "value": "0"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	if f.Runtime["net.ipv4.ip_forward"] != "0" {
		t.Errorf("runtime = %q, want 0", f.Runtime["net.ipv4.ip_forward"])
	}
	if got := f.Files[persistPathFor("net.ipv4.ip_forward")]; !strings.Contains(got, "net.ipv4.ip_forward = 0") {
		t.Errorf("persist file = %q, want the canonical assignment", got)
	}
}

// A kernel-rejected value (EINVAL on the proc write) is a failed step,
// not a Go error, and the persist file is NOT touched.
//
// @spec kernelio-sysctl
// @ac AC-04
func TestApply_Kernel_RejectedValue(t *testing.T) {
	t.Run("kernelio-sysctl/AC-04", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.WriteErr["vm.bad"] = errors.New("invalid argument")
	res, err := sysctlset.New().Apply(context.Background(), f,
		api.Params{"key": "vm.bad", "value": "x"}, nil)
	if err != nil {
		t.Fatalf("rejected value must not be a Go error; got %v", err)
	}
	if res.Success {
		t.Error("want Success:false on kernel rejection")
	}
	if _, ok := f.Files[persistPathFor("vm.bad")]; ok {
		t.Error("persist file must not be written when runtime apply fails")
	}
}

// Kernel-IO Capture → Apply → Rollback restores both layers when the
// drop-in existed before.
//
// @spec kernelio-sysctl
// @ac AC-05
func TestRoundTrip_Kernel_RewritesExistingPersist(t *testing.T) {
	t.Run("kernelio-sysctl/AC-05", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Runtime["net.ipv4.ip_forward"] = "1"
	f.Files[persistPathFor("net.ipv4.ip_forward")] = "# prior\nnet.ipv4.ip_forward = 1\n"
	h := sysctlset.New()
	params := api.Params{"key": "net.ipv4.ip_forward", "value": "0"}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["runtime_value"] != "1" || pre.Data["persist_file_existed"] != true {
		t.Fatalf("capture data = %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.Runtime["net.ipv4.ip_forward"] != "0" {
		t.Fatalf("post-apply runtime = %q, want 0", f.Runtime["net.ipv4.ip_forward"])
	}
	rb, err := h.Rollback(context.Background(), f, pre)
	if err != nil || !rb.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, rb.Success)
	}
	if f.Runtime["net.ipv4.ip_forward"] != "1" {
		t.Errorf("rolled-back runtime = %q, want 1", f.Runtime["net.ipv4.ip_forward"])
	}
	if f.Files[persistPathFor("net.ipv4.ip_forward")] != "# prior\nnet.ipv4.ip_forward = 1\n" {
		t.Errorf("rolled-back persist = %q, want prior content", f.Files[persistPathFor("net.ipv4.ip_forward")])
	}
}

// When the drop-in did not exist at capture, rollback removes it.
//
// @spec kernelio-sysctl
// @ac AC-05
func TestRoundTrip_Kernel_RemovesAbsentPersist(t *testing.T) {
	t.Run("kernelio-sysctl/AC-05", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Runtime["kernel.randomize_va_space"] = "2"
	// No persist file present.
	h := sysctlset.New()
	params := api.Params{"key": "kernel.randomize_va_space", "value": "1"}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["persist_file_existed"] != false {
		t.Fatalf("want persist_file_existed=false, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := f.Files[persistPathFor("kernel.randomize_va_space")]; !ok {
		t.Fatal("apply should have created the persist file")
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, ok := f.Files[persistPathFor("kernel.randomize_va_space")]; ok {
		t.Error("rollback should have removed the persist file that did not exist at capture")
	}
	if f.Runtime["kernel.randomize_va_space"] != "2" {
		t.Errorf("rolled-back runtime = %q, want 2", f.Runtime["kernel.randomize_va_space"])
	}
}

// TestDefaultPersistFile_PerKey_NoClobber locks the fix for the shared-persist-
// file clobber: two different sysctl keys must resolve to DIFFERENT default
// drop-in files, each containing only its own key. Before the fix all keys
// shared /etc/sysctl.d/99-kensa.conf and each whole-file Apply overwrote the
// previous — so remediating several sysctl rules persisted only the LAST key
// (the others set at runtime but lost on reboot) and rollback was not
// byte-perfect.
//
// @spec kernelio-sysctl
// @ac AC-05
func TestDefaultPersistFile_PerKey_NoClobber(t *testing.T) {
	t.Run("kernelio-sysctl/AC-05", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	h := sysctlset.New()
	for _, kv := range [][2]string{
		{"fs.suid_dumpable", "0"},
		{"net.ipv4.conf.all.secure_redirects", "0"},
	} {
		if _, err := h.Apply(context.Background(), f, api.Params{"key": kv[0], "value": kv[1]}, nil); err != nil {
			t.Fatalf("Apply %s: %v", kv[0], err)
		}
	}
	fa := f.Files[persistPathFor("fs.suid_dumpable")]
	fb := f.Files[persistPathFor("net.ipv4.conf.all.secure_redirects")]
	if fa == "" || fb == "" {
		t.Fatalf("each key must own a drop-in file; got fa=%q fb=%q", fa, fb)
	}
	if strings.Contains(fa, "secure_redirects") || strings.Contains(fb, "suid_dumpable") {
		t.Errorf("keys must not share a file (clobber class); fa=%q fb=%q", fa, fb)
	}
	if len(f.Files) != 2 {
		t.Errorf("expected 2 distinct drop-in files (one per key), got %d: %v", len(f.Files), f.Files)
	}
}

// Fallback: a transport without the kernelio capability uses the shell
// path (sysctl -w).
//
// @spec kernelio-sysctl
// @ac AC-06
func TestApply_FallsBackToShell(t *testing.T) {
	t.Run("kernelio-sysctl/AC-06", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	res, err := sysctlset.New().Apply(context.Background(), tp,
		api.Params{"key": "net.ipv4.ip_forward", "value": "0"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("shell Apply: err=%v success=%v", err, res.Success)
	}
	var sawSysctl bool
	for _, c := range tp.Runs {
		if strings.Contains(c, "sysctl -w 'net.ipv4.ip_forward'='0'") {
			sawSysctl = true
		}
	}
	if !sawSysctl {
		t.Errorf("expected shell `sysctl -w`; Runs=%v", tp.Runs)
	}
}
