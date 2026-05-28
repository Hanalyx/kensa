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

// TestArmHappyPath_RealHost arms the one-shot trial on a real host with
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
	param := "kensa_selftest=1"
	if p := os.Getenv("KENSA_BOOTGUARD_PARAM"); p != "" {
		param = p // e.g. fatal-fallback "init=/bin/false panic=10"; for op=remove, the key alone (e.g. "audit_backlog_limit").
	}
	op := "set"
	if v := os.Getenv("KENSA_BOOTGUARD_OP"); v != "" {
		op = v // "set" (default, calls ArmOneshot) or "remove" (calls ArmOneshotRemove).
	}

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

	// Baseline: the default entry's args BEFORE arm. For op=set, the param must
	// NOT yet be on the default (promote will add it post-boot). For op=remove,
	// the key SHOULD be present (else there is nothing to test removing — we
	// still proceed, but log it).
	if r, err := tp.Run(ctx, "grubby --info=DEFAULT 2>/dev/null | grep -E '^(args|kernel|title)='"); err == nil {
		t.Logf("DEFAULT before arm:\n%s", strings.TrimSpace(r.Stdout))
		switch op {
		case "remove":
			if !strings.Contains(r.Stdout, param) {
				t.Logf("WARN op=remove but key %q is NOT on the default — test will exercise the mechanism but the promote is a no-op", param)
			}
		default:
			if strings.Contains(r.Stdout, param) {
				t.Fatalf("op=set: param %q already present on default before arm — pick a clean host", param)
			}
		}
	}

	if _, err := bootguard.Capture(ctx, tp); err != nil {
		t.Fatalf("Capture baseline: %v", err)
	}

	var (
		title   string
		armErr  error
	)
	switch op {
	case "remove":
		title, armErr = bootguard.ArmOneshotRemove(ctx, tp, flavor, param)
	default:
		title, armErr = bootguard.ArmOneshot(ctx, tp, flavor, param)
	}
	if armErr != nil {
		t.Fatalf("Arm (op=%s): %v", op, armErr)
	}
	t.Logf("armed trial title=%q op=%s param=%q", title, op, param)

	if err := bootguard.InstallConfirmUnit(ctx, tp, flavor); err != nil {
		t.Fatalf("InstallConfirmUnit: %v", err)
	}

	// --- read-only staging verification (no reboot) ---
	// Flavor-generic state.
	for _, c := range []struct{ label, cmd string }{
		{"recorded trial_entry", "cat /var/lib/kensa/bootguard/trial_entry 2>/dev/null || echo MISSING"},
		{"recorded param_applied", "cat /var/lib/kensa/bootguard/param_applied 2>/dev/null || echo MISSING"},
		{"confirm unit enabled", "systemctl is-enabled kensa-bootguard-confirm.service 2>&1 || true"},
	} {
		if r, err := tp.Run(ctx, c.cmd); err == nil {
			t.Logf("[%s] %s", c.label, strings.TrimSpace(r.Stdout))
		}
	}

	switch flavor {
	case bootguard.FlavorBLS:
		if r, _ := tp.Run(ctx, "grep -lc kensa_bootguard_trial /boot/loader/entries/*.conf 2>/dev/null | head -1"); strings.TrimSpace(r.Stdout) == "" {
			t.Errorf("no BLS entry carries the trial sentinel — arm did not create the trial entry")
		}
		// The saved default's args must be UNCHANGED by arm: for op=set the
		// param must still be absent; for op=remove the key must still be
		// present. Either way the trial (not the default) holds the change.
		r, _ := tp.Run(ctx, "grubby --info=DEFAULT 2>/dev/null | grep '^args='")
		has := strings.Contains(r.Stdout, param)
		switch op {
		case "remove":
			if !has {
				t.Errorf("op=remove: DEFAULT lost key %q after arm — arm must NOT modify the default", param)
			} else {
				t.Logf("DEFAULT args after arm (key still present — good):\n%s", strings.TrimSpace(r.Stdout))
			}
		default:
			if has {
				t.Errorf("op=set: DEFAULT already carries %q after arm — arm must NOT modify the default", param)
			} else {
				t.Logf("DEFAULT args after arm (param absent — good):\n%s", strings.TrimSpace(r.Stdout))
			}
		}
	case bootguard.FlavorLegacy:
		if r, _ := tp.Run(ctx, "test -f /etc/grub.d/11_kensa_bootguard && echo present || echo MISSING"); strings.TrimSpace(r.Stdout) != "present" {
			t.Errorf("trial /etc/grub.d/11_kensa_bootguard not written")
		}
		if r, _ := tp.Run(ctx, "grep -c kensa-bootguard-trial /boot/grub/grub.cfg"); strings.TrimSpace(r.Stdout) == "0" {
			t.Errorf("trial menuentry not present in grub.cfg after update-grub")
		}
		// The trial must NOT be menu index 0 — the real default must stay first.
		if r, _ := tp.Run(ctx, "awk '/^menuentry |^submenu /{print NR\": \"$0}' /boot/grub/grub.cfg | head -3"); true {
			t.Logf("first menuentries after arm (index 0 must be the real default, NOT the trial):\n%s", strings.TrimSpace(r.Stdout))
		}
	}
	t.Logf("ARM STAGED OK — host is armed for a one-shot trial boot. Reboot to exercise promote.")
}
