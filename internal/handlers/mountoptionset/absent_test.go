package mountoptionset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/handlers/mountoptionset"
)

// KN-KN-026. A mount point that systemd mounts with no /etc/fstab line —
// /dev/shm on every current EL and Ubuntu — used to be unremediable, because
// Capture read "no fstab line" as "cannot describe the prior state".

const shmFindmnt = "findmnt --kernel -n -o SOURCE,FSTYPE,OPTIONS '/dev/shm'"

func shmFake(fstab, liveOptions string) *kernelio.FakeSysctlTransport {
	f := newFstabFake(fstab)
	f.RunResults = map[string]*api.CommandResult{
		shmFindmnt: {Stdout: "tmpfs tmpfs " + liveOptions + "\n"},
	}
	return f
}

// @spec handler-mount-option-set
// @ac AC-06
func TestCapture_NoFstabEntry_IsCapturable(t *testing.T) {
	t.Run("handler-mount-option-set/AC-06", func(t *testing.T) {})
	f := shmFake(fstabBefore, "rw,nosuid,nodev,seclabel,inode64")

	pre, err := mountoptionset.New().Capture(context.Background(), f,
		api.Params{"mount_point": "/dev/shm", "options": []interface{}{"noexec"}})
	if err != nil {
		t.Fatalf("Capture must succeed when the mount can be read: %v", err)
	}
	if !pre.Capturable {
		t.Error("a describable prior state must be marked capturable")
	}
	if absent, _ := pre.Data["prior_absent"].(bool); !absent {
		t.Error("prior_absent not recorded")
	}
	// The live options are the restoration target. Without them rollback cannot
	// tell which options it introduced and which were already there.
	if got, _ := pre.Data["prior_options"].(string); got != "rw,nosuid,nodev,seclabel,inode64" {
		t.Errorf("prior_options = %q, want the live option set", got)
	}
	if got, _ := pre.Data["prior_source"].(string); got != "tmpfs" {
		t.Errorf("prior_source = %q, want tmpfs", got)
	}
}

// A mount point that is neither in fstab nor mounted genuinely cannot be
// described, and there the refusal is still correct.
//
// @spec handler-mount-option-set
// @ac AC-06
func TestCapture_NoFstabEntry_NotMounted_StillRefuses(t *testing.T) {
	f := newFstabFake(fstabBefore) // no findmnt result programmed
	_, err := mountoptionset.New().Capture(context.Background(), f,
		api.Params{"mount_point": "/dev/shm", "options": []interface{}{"noexec"}})
	if err == nil {
		t.Fatal("want a refusal when the path is neither in fstab nor mounted")
	}
	if !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("the reason should say what was missing; got %v", err)
	}
}

// Rolling back an entry this engine created must remove the line AND take the
// option off the live mount. Removing the line alone leaves the option applied,
// because `mount -o remount` rereads fstab only for a mount point that is IN
// fstab — measured on a live host, and the reason this test exists.
//
// @spec handler-mount-option-set
// @ac AC-07
func TestRollback_Absent_RemovesLineAndNegatesOption(t *testing.T) {
	t.Run("handler-mount-option-set/AC-07", func(t *testing.T) {})
	// The line Apply would really have written: the live options carried
	// forward, plus ours.
	created := fstabBefore + "tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64,noexec 0 0\n"
	f := shmFake(created, "rw,nosuid,nodev,seclabel,inode64")

	res, err := mountoptionset.New().Rollback(context.Background(), f, &api.PreState{
		Mechanism:  "mount_option_set",
		Capturable: true,
		Data: map[string]interface{}{
			"mount_point":   "/dev/shm",
			"option":        "noexec",
			"prior_line":    "",
			"prior_absent":  true,
			"prior_options": "rw,nosuid,nodev,seclabel,inode64",
		},
	})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got: %s", res.Detail)
	}
	if strings.Contains(f.Files["/etc/fstab"], "/dev/shm") {
		t.Errorf("the created entry should be gone:\n%s", f.Files["/etc/fstab"])
	}
	var negated bool
	for _, r := range f.Runs {
		if strings.Contains(r, "remount,exec") {
			negated = true
		}
	}
	if !negated {
		t.Errorf("noexec must be negated explicitly; Runs=%v", f.Runs)
	}
}

// The sibling case, and the reason this is not simply "delete the line again".
// /dev/shm has three rules and /tmp, /home and /var/tmp have three each.
// Whichever runs first creates the entry; the others add to it. Rolling back
// the first must not throw away the other two rules' work.
//
// @spec handler-mount-option-set
// @ac AC-08
func TestRollback_Absent_KeepsSiblingOptions(t *testing.T) {
	t.Run("handler-mount-option-set/AC-08", func(t *testing.T) {})
	// noexec created the line carrying the live options; a sibling rule then
	// added relatime, which was NOT on the mount at capture.
	shared := fstabBefore + "tmpfs /dev/shm tmpfs rw,inode64,noexec,relatime 0 0\n"
	f := shmFake(shared, "rw,seclabel,inode64")

	res, err := mountoptionset.New().Rollback(context.Background(), f, &api.PreState{
		Mechanism:  "mount_option_set",
		Capturable: true,
		Data: map[string]interface{}{
			"mount_point":   "/dev/shm",
			"option":        "noexec",
			"prior_line":    "",
			"prior_absent":  true,
			"prior_options": "rw,seclabel,inode64",
		},
	})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got: %s", res.Detail)
	}
	line, found := kernelio.FstabFindLine(f.Files["/etc/fstab"], "/dev/shm")
	if !found {
		t.Fatalf("the entry must survive; two other rules still need it:\n%s", f.Files["/etc/fstab"])
	}
	if strings.Contains(line, "noexec") {
		t.Errorf("our own option should be gone: %s", line)
	}
	if !strings.Contains(line, "relatime") {
		t.Errorf("the sibling transaction's option was destroyed: %s", line)
	}
	// The options that were live at capture ride along on the line and are not
	// evidence of a sibling; they must not keep the entry alive on their own.
	for _, carried := range []string{"rw", "inode64"} {
		if !strings.Contains(line, carried) {
			t.Errorf("carried option %s should still be on the line: %s", carried, line)
		}
	}
}

// An option the mount already carried is not ours to undo. Negating it would
// change state this transaction never touched.
//
// @spec handler-mount-option-set
// @ac AC-07
func TestRollback_Absent_DoesNotNegateAPreexistingOption(t *testing.T) {
	created := fstabBefore + "tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0\n"
	f := shmFake(created, "rw,nosuid,nodev,seclabel,inode64") // nodev was already live

	res, err := mountoptionset.New().Rollback(context.Background(), f, &api.PreState{
		Mechanism:  "mount_option_set",
		Capturable: true,
		Data: map[string]interface{}{
			"mount_point":   "/dev/shm",
			"option":        "nodev",
			"prior_line":    "",
			"prior_absent":  true,
			"prior_options": "rw,nosuid,nodev,seclabel,inode64",
		},
	})
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v detail=%s", err, res.Detail)
	}
	for _, r := range f.Runs {
		if strings.Contains(r, "remount,dev") {
			t.Errorf("must not negate an option the mount already had; Runs=%v", f.Runs)
		}
	}
}
