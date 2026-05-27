package bootguard_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
)

// TestCheckArmable_RealHost validates the refuse-to-arm gate over a real
// privileged SSH transport. Read-only. Skipped unless KENSA_TEST_SSH_HOST is
// set. The tested fleet is BIOS GRUB (not ostree, not encrypted /boot), so the
// gate is expected to report Armable=true; the test logs the decision either
// way so an out-of-envelope host is visible rather than a hard failure.
func TestCheckArmable_RealHost(t *testing.T) {
	host := os.Getenv("KENSA_TEST_SSH_HOST")
	if host == "" {
		t.Skip("KENSA_TEST_SSH_HOST not set; skipping real-host gate test")
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
		Sudo:    true,
	})
	if err != nil {
		t.Fatalf("ssh.Connect: %v", err)
	}
	defer tp.Close()

	d, err := bootguard.CheckArmable(ctx, tp)
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	t.Logf("armable=%v flavor=%s refusals=%v", d.Armable, d.Flavor, d.Refusals)
	if !d.Armable {
		t.Logf("host is OUTSIDE the validated envelope (expected for UEFI/ostree/encrypted/non-GRUB): %v", d.Refusals)
	}
}
