package bootguard_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
)

// TestArmHappyPath_RealHost arms the Option-B one-shot trial on a real host with
// a BENIGN, inert kernel param (kensa_selftest=1) and installs the confirm unit,
// then verifies the staging read-only. It deliberately does NOT reboot — the
// reboot + post-boot promote verification is driven externally (the operator
// reboots, then inspects). A benign param carries no brick risk: either the
// trial boots (param is inert) and gets promoted, or a malformed trial auto-
// falls back to the untouched saved default. The saved default is never touched
// by arm, so this cannot brick a host.
//
// Gated on KENSA_TEST_SSH_HOST + KENSA_BOOTGUARD_ARM=1 so it never arms a host
// during an ordinary real-host test run. Carries no @spec annotations (skipped
// in CI; unit tests own AC coverage).
func TestArmHappyPath_RealHost(t *testing.T) {
	host := os.Getenv("KENSA_TEST_SSH_HOST")
	if host == "" || os.Getenv("KENSA_BOOTGUARD_ARM") == "" {
		t.Skip("set KENSA_TEST_SSH_HOST and KENSA_BOOTGUARD_ARM=1 to arm the bootguard happy-path trial")
	}
	port := 22
	if v := os.Getenv("KENSA_TEST_SSH_PORT"); v != "" {
		port, _ = strconv.Atoi(v)
	}
	const param = "kensa_selftest=1"

	ctx := context.Background()
	tp, err := ssh.Connect(ctx, ssh.Config{
		Host:    host,
		User:    os.Getenv("KENSA_TEST_SSH_USER"),
		Port:    port,
		KeyPath: os.Getenv("KENSA_TEST_SSH_KEY"),
		Sudo:    true,
	})
	if err != nil {
		t.Fatalf("ssh.Connect: %v", err)
	}
	defer tp.Close()

	flavor, err := bootguard.DetectFlavor(ctx, tp)
	if err != nil {
		t.Fatalf("DetectFlavor: %v", err)
	}
	t.Logf("flavor=%s", flavor)

	dec, err := bootguard.CheckArmable(ctx, tp)
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	if !dec.Armable {
		t.Fatalf("host reports NOT armable: %v", dec.Refusals)
	}
	t.Logf("armable=%t refusals=%v", dec.Armable, dec.Refusals)

	// Baseline: the default entry's args BEFORE arm (promote must add the param
	// here, post-boot — it must NOT be present yet).
	if r, err := tp.Run(ctx, "grubby --info=DEFAULT 2>/dev/null | grep -E '^(args|kernel|title)='"); err == nil {
		t.Logf("DEFAULT before arm:\n%s", strings.TrimSpace(r.Stdout))
		if strings.Contains(r.Stdout, param) {
			t.Fatalf("param %q already present on default before arm — pick a clean host", param)
		}
	}

	if _, err := bootguard.Capture(ctx, tp); err != nil {
		t.Fatalf("Capture baseline: %v", err)
	}

	title, err := bootguard.ArmOneshot(ctx, tp, flavor, param)
	if err != nil {
		t.Fatalf("ArmOneshot: %v", err)
	}
	t.Logf("armed trial title=%q param=%q", title, param)

	if err := bootguard.InstallConfirmUnit(ctx, tp, flavor); err != nil {
		t.Fatalf("InstallConfirmUnit: %v", err)
	}

	// --- read-only staging verification (no reboot) ---
	checks := []struct {
		label string
		cmd   string
	}{
		{"trial entry file(s) carrying the sentinel", "grep -l kensa_bootguard_trial /boot/loader/entries/*.conf 2>/dev/null || echo NONE"},
		{"recorded trial_entry", "cat /var/lib/kensa/bootguard/trial_entry 2>/dev/null || echo MISSING"},
		{"recorded param_applied", "cat /var/lib/kensa/bootguard/param_applied 2>/dev/null || echo MISSING"},
		{"confirm unit enabled", "systemctl is-enabled kensa-bootguard-confirm.service 2>&1 || true"},
		{"one-shot next_entry armed", "grub2-editenv list 2>/dev/null | grep -i next_entry || echo NO_NEXT_ENTRY"},
		{"DEFAULT args AFTER arm (param must still be ABSENT — promote is post-boot)", "grubby --info=DEFAULT 2>/dev/null | grep '^args='"},
	}
	for _, c := range checks {
		r, err := tp.Run(ctx, c.cmd)
		if err != nil {
			t.Errorf("%s: transport error: %v", c.label, err)
			continue
		}
		t.Logf("[%s]\n%s", c.label, strings.TrimSpace(r.Stdout))
	}

	// Hard assertions on the staging.
	if r, _ := tp.Run(ctx, "grep -lc kensa_bootguard_trial /boot/loader/entries/*.conf 2>/dev/null | head -1"); strings.TrimSpace(r.Stdout) == "" {
		t.Errorf("no BLS entry carries the trial sentinel — arm did not create the trial entry")
	}
	if r, _ := tp.Run(ctx, "grubby --info=DEFAULT 2>/dev/null | grep '^args='"); strings.Contains(r.Stdout, param) {
		t.Errorf("DEFAULT already carries %q after arm — arm must NOT touch the default; only promote (post-boot) may", param)
	}
	t.Logf("ARM STAGED OK — host is armed for a one-shot trial boot. Reboot to exercise promote.")
}
