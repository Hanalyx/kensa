package kernelmoduledisable_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/kernelmoduledisable"
)

const blPath = "/etc/modprobe.d/kensa-disable-usb-storage.conf"

// Kernel-IO Apply writes the blacklist drop-in atomically and unloads the
// module via delete_module(2).
//
// @spec kernelio-module
// @ac AC-02
func TestApply_Kernel(t *testing.T) {
	t.Run("kernelio-module/AC-02", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	res, err := kernelmoduledisable.New().Apply(context.Background(), f,
		api.Params{"name": "usb-storage"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	if got := f.Files[blPath]; !strings.Contains(got, "blacklist usb-storage") || !strings.Contains(got, "install usb-storage /bin/true") {
		t.Errorf("blacklist file = %q", got)
	}
	if len(f.DeletedModules) != 1 || f.DeletedModules[0] != "usb-storage" {
		t.Errorf("DeletedModules = %v, want [usb-storage]", f.DeletedModules)
	}
}

// The runtime unload is best-effort: an in-use / not-loaded module does
// not fail Apply (the persistent blacklist is the load-bearing change).
//
// @spec kernelio-module
// @ac AC-02
func TestApply_Kernel_UnloadBestEffort(t *testing.T) {
	t.Run("kernelio-module/AC-02", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.DeleteModuleErr["usb-storage"] = errors.New("module in use")
	res, err := kernelmoduledisable.New().Apply(context.Background(), f,
		api.Params{"name": "usb-storage"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("unload failure must not fail Apply; err=%v success=%v", err, res.Success)
	}
	if _, ok := f.Files[blPath]; !ok {
		t.Error("blacklist file must still be written when unload fails")
	}
}

// Kernel-IO round trip: a drop-in that did not exist at capture is removed
// on rollback.
//
// @spec kernelio-module
// @ac AC-03
func TestRoundTrip_Kernel_RemovesWhenAbsent(t *testing.T) {
	t.Run("kernelio-module/AC-03", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	h := kernelmoduledisable.New()
	params := api.Params{"name": "usb-storage"}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Fatalf("want file_existed=false, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := f.Files[blPath]; !ok {
		t.Fatal("apply should have created the blacklist file")
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, ok := f.Files[blPath]; ok {
		t.Error("rollback should have removed the file that did not exist at capture")
	}
}

// Kernel-IO round trip: a pre-existing drop-in is restored to its prior
// content on rollback.
//
// @spec kernelio-module
// @ac AC-03
func TestRoundTrip_Kernel_RestoresPrior(t *testing.T) {
	t.Run("kernelio-module/AC-03", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[blPath] = "# pre-existing\nblacklist usb-storage\n"
	h := kernelmoduledisable.New()
	params := api.Params{"name": "usb-storage"}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Fatalf("want file_existed=true, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.Files[blPath] != "# pre-existing\nblacklist usb-storage\n" {
		t.Errorf("rolled-back content = %q, want prior", f.Files[blPath])
	}
}

// Fallback: a transport without the kernelio capability uses the shell path.
//
// @spec kernelio-module
// @ac AC-04
func TestApply_FallsBackToShell(t *testing.T) {
	t.Run("kernelio-module/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	res, err := kernelmoduledisable.New().Apply(context.Background(), tp,
		api.Params{"name": "usb-storage"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("shell Apply: err=%v success=%v", err, res.Success)
	}
	var sawModprobe bool
	for _, c := range tp.Runs {
		if strings.Contains(c, "modprobe -r 'usb-storage'") {
			sawModprobe = true
		}
	}
	if !sawModprobe {
		t.Errorf("expected modprobe shell path; Runs=%v", tp.Runs)
	}
}
