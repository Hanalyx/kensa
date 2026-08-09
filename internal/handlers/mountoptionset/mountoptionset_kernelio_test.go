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

// Apply on a mount point with no fstab entry AND no live mount is a failed
// step, not an error: nothing can be created from nothing.
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
	// Probing the live mount is expected — that is how a missing entry gets
	// created when the filesystem IS mounted. The invariant is narrower: do not
	// remount a mount point that was never edited.
	for _, r := range f.Runs {
		if strings.Contains(r, "remount") {
			t.Errorf("must not remount when nothing was edited; Runs=%v", f.Runs)
		}
	}
	if !strings.Contains(f.Files["/etc/fstab"], fstabBefore) {
		t.Errorf("fstab must be untouched; got:\n%s", f.Files["/etc/fstab"])
	}
}

// A mount point with no fstab entry but a live mount is the /dev/shm case
// (KN-KN-026): systemd mounts it, fstab does not mention it, and persisting an
// option means creating the entry from what the kernel reports.
//
// @spec handler-mount-option-set
// @ac AC-05
func TestApply_Kernel_NoEntry_CreatesFromLiveMount(t *testing.T) {
	t.Run("handler-mount-option-set/AC-05", func(t *testing.T) {})
	f := newFstabFake(fstabBefore)
	f.RunResults = map[string]*api.CommandResult{
		"findmnt --kernel -n -o SOURCE,FSTYPE,OPTIONS '/dev/shm'": {
			Stdout: "tmpfs tmpfs rw,nosuid,nodev,seclabel,inode64\n",
		},
	}
	res, err := mountoptionset.New().Apply(context.Background(), f,
		api.Params{"mount_point": "/dev/shm", "options": []interface{}{"noexec"}}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got: %s", res.Detail)
	}
	line, found := kernelio.FstabFindLine(f.Files["/etc/fstab"], "/dev/shm")
	if !found {
		t.Fatalf("no entry was created:\n%s", f.Files["/etc/fstab"])
	}
	// The source and fstype come from the host, never from a guess.
	if !strings.HasPrefix(line, "tmpfs /dev/shm tmpfs ") {
		t.Errorf("source or fstype guessed rather than read from findmnt: %s", line)
	}
	if !strings.Contains(line, "noexec") {
		t.Errorf("the requested option is missing: %s", line)
	}
	// The regression this guards: a line of "defaults,noexec" REPLACES the
	// options systemd set, so the next remount drops nosuid and nodev. Adding
	// one security option must never remove two. Measured on the fleet before
	// this was fixed: /dev/shm went from rw,nosuid,nodev to rw,noexec.
	for _, carried := range []string{"nosuid", "nodev"} {
		if !strings.Contains(line, carried) {
			t.Errorf("live option %q was dropped from the synthesized line: %s", carried, line)
		}
	}
	// seclabel is reported by the kernel but rejected by mount(8) as input.
	if strings.Contains(line, "seclabel") {
		t.Errorf("seclabel must not be written to fstab: %s", line)
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
	// The rollback read-back verify must observe /tmp with nodev gone.
	f.RunResults = map[string]*api.CommandResult{
		"findmnt -rno OPTIONS '/tmp'": {Stdout: "rw,relatime\n"},
	}
	rb, err := h.Rollback(context.Background(), f, pre)
	if err != nil || !rb.Success {
		t.Fatalf("Rollback: err=%v success=%v detail=%s", err, rb.Success, rb.Detail)
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

// Kernel-IO rollback reports a verified-partial restore when the remount
// runs but the live mount still carries the option that was removed from
// fstab — the runtime did not reconcile.
//
// @spec kernelio-mount
// @ac AC-03
// @spec handler-mount-option-set
// @ac AC-04
func TestRollback_Kernel_PartialWhenRuntimeNotReconciled(t *testing.T) {
	t.Run("kernelio-mount/AC-03", func(t *testing.T) {})
	t.Run("handler-mount-option-set/AC-04", func(t *testing.T) {})
	// fstab currently carries noexec; the prior line dropped it, so the
	// rewrite changes fstab (not the early-return path) and a remount runs.
	f := newFstabFake("UUID=bbbb /tmp ext4 defaults,noexec 0 2\n")
	// The live mount still shows noexec → the runtime did not reconcile.
	f.RunResults = map[string]*api.CommandResult{
		"findmnt -rno OPTIONS '/tmp'": {Stdout: "rw,relatime,noexec\n"},
	}
	pre := &api.PreState{Data: map[string]interface{}{
		"mount_point": "/tmp", "option": "noexec",
		"prior_line": "UUID=bbbb /tmp ext4 defaults 0 2",
	}}
	rb, err := mountoptionset.New().Rollback(context.Background(), f, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rb.Success || !rb.PartialRestore {
		t.Errorf("want Success=false, PartialRestore=true; got Success=%v Partial=%v detail=%q",
			rb.Success, rb.PartialRestore, rb.Detail)
	}
}

// Kernel-IO rollback verifies the live mount even when fstab already holds
// the prior line (the no-rewrite early-return): a live divergence is caught
// and reported, not assumed clean.
//
// @spec kernelio-mount
// @ac AC-03
// @spec handler-mount-option-set
// @ac AC-04
func TestRollback_Kernel_VerifiesOnNoRewrite(t *testing.T) {
	t.Run("kernelio-mount/AC-03", func(t *testing.T) {})
	t.Run("handler-mount-option-set/AC-04", func(t *testing.T) {})
	// fstab already equals the prior line → no rewrite, no remount, but the
	// live mount still shows the applied option, so the verify must catch it.
	f := newFstabFake("UUID=bbbb /tmp ext4 defaults 0 2\n")
	f.RunResults = map[string]*api.CommandResult{
		"findmnt -rno OPTIONS '/tmp'": {Stdout: "rw,relatime,noexec\n"},
	}
	pre := &api.PreState{Data: map[string]interface{}{
		"mount_point": "/tmp", "option": "noexec",
		"prior_line": "UUID=bbbb /tmp ext4 defaults 0 2",
	}}
	rb, err := mountoptionset.New().Rollback(context.Background(), f, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rb.Success || !rb.PartialRestore {
		t.Errorf("no-rewrite path must still verify; got Success=%v Partial=%v detail=%q",
			rb.Success, rb.PartialRestore, rb.Detail)
	}
	// No remount should have been issued (only the findmnt read-back).
	for _, c := range f.Runs {
		if strings.Contains(c, "remount") {
			t.Errorf("must not remount on the no-rewrite path; Runs=%v", f.Runs)
		}
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
