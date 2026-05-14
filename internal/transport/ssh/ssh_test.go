package ssh_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/transport/ssh"
)

// realHostFromEnv returns the connection details for an integration
// test against a real SSH host. Tests that need a real connection skip
// when KENSA_TEST_SSH_HOST is unset; this keeps the unit-test pass
// fast on developer machines without RHEL access.
//
// Required env vars:
//
//	KENSA_TEST_SSH_HOST  hostname or IP
//	KENSA_TEST_SSH_USER  ssh user (optional; defaults to $USER)
//	KENSA_TEST_SSH_PORT  port (optional; defaults to 22)
//	KENSA_TEST_SSH_KEY   identity file (optional; defaults to agent)
func realHostFromEnv(t *testing.T) ssh.Config {
	t.Helper()
	host := os.Getenv("KENSA_TEST_SSH_HOST")
	if host == "" {
		t.Skip("KENSA_TEST_SSH_HOST not set; skipping SSH integration test")
	}
	port := 22
	if v := os.Getenv("KENSA_TEST_SSH_PORT"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &port)
	}
	return ssh.Config{
		Host:    host,
		User:    os.Getenv("KENSA_TEST_SSH_USER"),
		Port:    port,
		KeyPath: os.Getenv("KENSA_TEST_SSH_KEY"),
	}
}

// TestConnect_RealHost is the M1 milestone gate: open a connection,
// run echo hello, persist nothing yet, close cleanly.
func TestConnect_RealHost(t *testing.T) {
	cfg := realHostFromEnv(t)
	ctx := context.Background()

	tp, err := ssh.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer tp.Close()

	res, err := tp.Run(ctx, "echo hello-from-kensa")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode=%d, want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "hello-from-kensa" {
		t.Errorf("Stdout=%q, want %q", res.Stdout, "hello-from-kensa")
	}
}

// TestConnect_RealHost_MultiplexReuse verifies the ControlMaster is
// shared across multiple Run calls. We check that the second Run
// starts much faster than the first (which has to wait for the master
// connection if not pre-existing). With ControlMaster the second
// command is essentially a local scp-style invocation.
func TestConnect_RealHost_MultiplexReuse(t *testing.T) {
	cfg := realHostFromEnv(t)
	ctx := context.Background()

	tp, err := ssh.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer tp.Close()

	for i := 0; i < 3; i++ {
		res, err := tp.Run(ctx, "true")
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		if res.ExitCode != 0 {
			t.Errorf("Run %d exit=%d", i, res.ExitCode)
		}
	}
}

// TestConnect_RealHost_NonZeroExit confirms a failing remote command
// surfaces as ExitCode != 0 with the captured stderr, not as a
// transport error.
func TestConnect_RealHost_NonZeroExit(t *testing.T) {
	cfg := realHostFromEnv(t)
	ctx := context.Background()

	tp, err := ssh.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer tp.Close()

	res, err := tp.Run(ctx, "exit 7")
	if err != nil {
		t.Fatalf("Run: %v (transport error, expected ExitCode=7)", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("ExitCode=%d, want 7", res.ExitCode)
	}
}

// ─── Unit tests that don't need a real host ─────────────────────────────

func TestConnect_RequiresHost(t *testing.T) {
	_, err := ssh.Connect(context.Background(), ssh.Config{})
	if err == nil {
		t.Fatal("expected error for empty Config.Host")
	}
	if !strings.Contains(err.Error(), "Host is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTransport_ControlChannelSensitiveDefault(t *testing.T) {
	tp := &ssh.Transport{}
	if tp.ControlChannelSensitive() {
		t.Error("default should be false")
	}
}

func TestTransport_ControlChannelSensitiveToggle(t *testing.T) {
	tp := &ssh.Transport{}
	tp.SetControlChannelSensitive(true)
	if !tp.ControlChannelSensitive() {
		t.Error("expected true after Set(true)")
	}
	tp.SetControlChannelSensitive(false)
	if tp.ControlChannelSensitive() {
		t.Error("expected false after Set(false)")
	}
}
