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

// TestRestore_RealHost validates the compiled Restore over a real, privileged
// SSH transport with a boot-SAFE round-trip:
//
//	Capture baseline → inject a harmless COMMENT marker into
//	/etc/default/grub → Restore(baseline) → assert the marker is gone.
//
// The marker is a comment, so it cannot affect boot even if the test aborts
// mid-run; and it should be run only against a snapshotted/disposable host.
// Skipped unless KENSA_TEST_SSH_HOST is set. Carries no @spec annotations
// (skipped in CI, so unit tests own AC coverage).
func TestRestore_RealHost(t *testing.T) {
	host := os.Getenv("KENSA_TEST_SSH_HOST")
	if host == "" {
		t.Skip("KENSA_TEST_SSH_HOST not set; skipping real-host restore test")
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

	const marker = "kensa-bootguard-restore-test-marker"
	grepCmd := "grep -c " + marker + " /etc/default/grub || true"

	base, err := bootguard.Capture(ctx, tp)
	if err != nil {
		t.Fatalf("baseline Capture: %v", err)
	}

	// Inject a harmless comment marker into /etc/default/grub.
	if _, err := tp.Run(ctx, "echo '# "+marker+"' >> /etc/default/grub"); err != nil {
		t.Fatalf("inject marker: %v", err)
	}
	pre, err := tp.Run(ctx, grepCmd)
	if err != nil {
		t.Fatalf("pre grep: %v", err)
	}
	if strings.TrimSpace(pre.Stdout) == "0" {
		t.Fatalf("marker not injected (count=%q)", pre.Stdout)
	}

	// Restore the captured baseline — should remove the marker.
	if err := bootguard.Restore(ctx, tp, base); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	post, err := tp.Run(ctx, grepCmd)
	if err != nil {
		t.Fatalf("post grep: %v", err)
	}
	if strings.TrimSpace(post.Stdout) != "0" {
		t.Errorf("Restore did not revert /etc/default/grub: marker count=%q", post.Stdout)
	}
	t.Logf("flavor=%s entries=%d — restore round-trip OK (marker removed)", base.Flavor, len(base.BLSEntries))
}
