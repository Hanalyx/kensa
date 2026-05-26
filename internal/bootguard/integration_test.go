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

// TestCapture_RealHost validates the compiled Capture over a real,
// privileged (Sudo) SSH transport. It is read-only — it snapshots boot
// state and mutates nothing — and skips unless KENSA_TEST_SSH_HOST is set,
// keeping the unit-test pass fast on machines without a RHEL/Ubuntu target.
//
// This test carries no @spec/@ac annotations on purpose: it is skipped in
// CI (no KENSA_TEST_SSH_HOST), so the unit tests own the AC coverage.
//
//	KENSA_TEST_SSH_HOST  host or IP (required to run)
//	KENSA_TEST_SSH_USER  ssh user (optional)
//	KENSA_TEST_SSH_PORT  port (optional; default 22)
//	KENSA_TEST_SSH_KEY   identity file (optional; defaults to agent)
func TestCapture_RealHost(t *testing.T) {
	host := os.Getenv("KENSA_TEST_SSH_HOST")
	if host == "" {
		t.Skip("KENSA_TEST_SSH_HOST not set; skipping real-host capture test")
	}
	port := 22
	if v := os.Getenv("KENSA_TEST_SSH_PORT"); v != "" {
		port, _ = strconv.Atoi(v)
	}

	ctx := context.Background()
	tp, err := ssh.Connect(ctx, ssh.Config{
		Host:    host,
		User:    os.Getenv("KENSA_TEST_SSH_USER"),
		Port:    port,
		KeyPath: os.Getenv("KENSA_TEST_SSH_KEY"),
		Sudo:    true, // boot directories are 0700 root on hardened hosts
	})
	if err != nil {
		t.Fatalf("ssh.Connect: %v", err)
	}
	defer tp.Close()

	snap, err := bootguard.Capture(ctx, tp)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	t.Logf("flavor=%s grubcfg=%q bls_entries=%d", snap.Flavor, snap.GrubCfgPath, len(snap.BLSEntries))

	if !strings.Contains(snap.DefaultGrub, "GRUB_CMDLINE_LINUX") {
		t.Errorf("DefaultGrub missing GRUB_CMDLINE_LINUX: %q", snap.DefaultGrub)
	}
	switch snap.Flavor {
	case bootguard.FlavorBLS:
		if len(snap.BLSEntries) == 0 {
			t.Error("BLS host: expected >=1 captured entry (privileged transport should read /boot/loader/entries)")
		}
		if snap.GrubCfgPath == "" {
			t.Error("BLS host: expected a grub.cfg path to be found")
		}
	case bootguard.FlavorLegacy:
		if snap.GrubCfgPath == "" {
			t.Error("legacy host: expected a grub.cfg path to be found")
		}
	}
}
