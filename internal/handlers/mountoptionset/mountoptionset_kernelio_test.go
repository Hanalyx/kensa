package mountoptionset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/mountoptionset"
)

const fstabBefore = "UUID=aaaa / ext4 defaults 0 1\nUUID=bbbb /tmp ext4 defaults 0 2\n"

// newFstabFake returns a kernelio file-transport fake pre-seeded with an
// /etc/fstab. (FakeSysctlTransport implements kernelio.FileTransport.)
func newFstabFake(fstab string) *kernelio.FakeSysctlTransport {
	f := kernelio.NewFakeSysctl()
	f.Files["/etc/fstab"] = fstab
	return f
}

// Kernel-IO Apply edits fstab in place (atomic) and remounts via mount(8).
//
// @spec kernelio-mount
// @ac AC-02
func TestApply_Kernel(t *testing.T) {
	t.Run("kernelio-mount/AC-02", func(t *testing.T) {})
	f := newFstabFake(fstabBefore)
	res, err := mountoptionset.New().Apply(context.Background(), f,
		api.Params{"mount_point": "/tmp", "options": []interface{}{"nodev", "nosuid"}}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	if !strings.Contains(f.Files["/etc/fstab"], "UUID=bbbb /tmp ext4 defaults,nodev,nosuid 0 2") {
		t.Errorf("fstab not edited as expected:\n%s", f.Files["/etc/fstab"])
	}
	// Remount stays on mount(8).
	if len(f.Runs) != 1 || !strings.Contains(f.Runs[0], "mount -o remount '/tmp'") {
		t.Errorf("expected one mount -o remount; Runs=%v", f.Runs)
	}
}

// Apply on a mount point with no fstab entry is a failed step, not an error.
//
// @spec kernelio-mount
// @ac AC-02
func TestApply_Kernel_NoEntry(t *testing.T) {
	t.Run("kernelio-mount/AC-02", func(t *testing.T) {})
	f := newFstabFake(fstabBefore)
	res, err := mountoptionset.New().Apply(context.Background(), f,
		api.Params{"mount_point": "/var", "options": []interface{}{"nodev"}}, nil)
	if err != nil {
		t.Fatalf("no-entry must not be a Go error; got %v", err)
	}
	if res.Success {
		t.Error("want Success:false when no fstab entry matches")
	}
	if len(f.Runs) != 0 {
		t.Errorf("must not remount when fstab edit found no entry; Runs=%v", f.Runs)
	}
}

// Kernel-IO Capture → Apply → Rollback restores the prior fstab line.
//
// @spec kernelio-mount
// @ac AC-03
func TestRoundTrip_Kernel(t *testing.T) {
	t.Run("kernelio-mount/AC-03", func(t *testing.T) {})
	f := newFstabFake(fstabBefore)
	h := mountoptionset.New()
	params := api.Params{"mount_point": "/tmp", "options": []interface{}{"nodev"}}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["prior_line"] != "UUID=bbbb /tmp ext4 defaults 0 2" {
		t.Fatalf("captured prior_line = %q", pre.Data["prior_line"])
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(f.Files["/etc/fstab"], "defaults,nodev") {
		t.Fatalf("apply did not add the option:\n%s", f.Files["/etc/fstab"])
	}
	rb, err := h.Rollback(context.Background(), f, pre)
	if err != nil || !rb.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, rb.Success)
	}
	if l, _ := kernelio.FstabFindLine(f.Files["/etc/fstab"], "/tmp"); l != "UUID=bbbb /tmp ext4 defaults 0 2" {
		t.Errorf("rolled-back /tmp line = %q, want the prior line", l)
	}
}

// Capture on a missing fstab entry surfaces ErrCaptureIncomplete.
//
// @spec kernelio-mount
// @ac AC-03
func TestCapture_Kernel_NoEntry(t *testing.T) {
	t.Run("kernelio-mount/AC-03", func(t *testing.T) {})
	f := newFstabFake(fstabBefore)
	_, err := mountoptionset.New().Capture(context.Background(), f,
		api.Params{"mount_point": "/var", "options": []interface{}{"nodev"}})
	if err == nil {
		t.Fatal("expected an error for a missing fstab entry")
	}
}

// Fallback: a transport without the kernelio capability uses the awk shell path.
//
// @spec kernelio-mount
// @ac AC-04
func TestApply_FallsBackToShell(t *testing.T) {
	t.Run("kernelio-mount/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	res, err := mountoptionset.New().Apply(context.Background(), tp,
		api.Params{"mount_point": "/tmp", "options": []interface{}{"nodev"}}, nil)
	if err != nil || !res.Success {
		t.Fatalf("shell Apply: err=%v success=%v", err, res.Success)
	}
	var sawAwk bool
	for _, c := range tp.Runs {
		if strings.Contains(c, "awk") && strings.Contains(c, "/etc/fstab") {
			sawAwk = true
		}
	}
	if !sawAwk {
		t.Errorf("expected awk shell path; Runs=%v", tp.Runs)
	}
}
