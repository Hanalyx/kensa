package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLocalTransport_Run locks AC-01: Run executes via
// sh -c locally, populates CommandResult fields, captures
// stdout cleanly.
//
// @spec agent-handler-port-filepermissions
// @ac AC-01
func TestLocalTransport_Run(t *testing.T) {
	t.Log("// @spec agent-handler-port-filepermissions")
	t.Log("// @ac AC-01")
	tr := New()
	defer tr.Close()

	t.Run("happy_path", func(t *testing.T) {
		res, err := tr.Run(context.Background(), "echo hello")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.ExitCode != 0 {
			t.Errorf("ExitCode: got %d, want 0", res.ExitCode)
		}
		if res.Stdout != "hello" {
			t.Errorf("Stdout: got %q, want %q", res.Stdout, "hello")
		}
		if res.Duration == 0 {
			t.Error("Duration is zero; should be measurable")
		}
	})

	t.Run("nonzero_exit", func(t *testing.T) {
		res, err := tr.Run(context.Background(), "false")
		// `false` exits 1 but isn't a Go-side error per
		// the spec — exec.ExitError is unwrapped to the
		// ExitCode field.
		if err != nil {
			t.Fatalf("Run(false) Go error should be nil; got: %v", err)
		}
		if res.ExitCode != 1 {
			t.Errorf("ExitCode: got %d, want 1", res.ExitCode)
		}
	})

	t.Run("stderr_captured", func(t *testing.T) {
		res, err := tr.Run(context.Background(), "echo oops >&2; exit 2")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.ExitCode != 2 {
			t.Errorf("ExitCode: got %d, want 2", res.ExitCode)
		}
		if res.Stderr != "oops" {
			t.Errorf("Stderr: got %q, want %q", res.Stderr, "oops")
		}
	})

	t.Run("ctx_cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-canceled
		_, err := tr.Run(ctx, "sleep 10")
		// exec.CommandContext kills the command and returns
		// an error; we surface as Go error.
		if err == nil {
			t.Error("expected ctx-cancel error, got nil")
		}
	})
}

// TestLocalTransport_Put locks AC-02: Put copies the bytes
// and sets the file mode.
//
// @spec agent-handler-port-filepermissions
// @ac AC-02
func TestLocalTransport_Put(t *testing.T) {
	t.Log("// @spec agent-handler-port-filepermissions")
	t.Log("// @ac AC-02")
	tr := New()
	defer tr.Close()

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src")
	dstPath := filepath.Join(dir, "dst")
	content := []byte("kensa-fixture-content")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := tr.Put(context.Background(), srcPath, dstPath, 0o755); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("content: got %q, want %q", got, content)
	}

	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode: got %o, want 0755", info.Mode().Perm())
	}
}

// TestLocalTransport_Get: Get copies bytes back local-to-local.
func TestLocalTransport_Get(t *testing.T) {
	tr := New()
	defer tr.Close()

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "remote-src")
	dstPath := filepath.Join(dir, "local-dst")
	if err := os.WriteFile(srcPath, []byte("xyz"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := tr.Get(context.Background(), srcPath, dstPath); err != nil {
		t.Fatalf("Get: %v", err)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "xyz" {
		t.Errorf("content: got %q, want %q", got, "xyz")
	}
}

// TestLocalTransport_ControlChannelSensitive always false.
// The agent IS the target.
func TestLocalTransport_ControlChannelSensitive(t *testing.T) {
	tr := New()
	if tr.ControlChannelSensitive() {
		t.Error("LocalTransport.ControlChannelSensitive should always be false")
	}
}

// TestLocalTransport_Close no-op.
func TestLocalTransport_Close(t *testing.T) {
	tr := New()
	if err := tr.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Idempotent.
	if err := tr.Close(); err != nil {
		t.Errorf("Close (2nd): %v", err)
	}
}

// TestLocalTransport_WithSudo locks the sudo-wrap behavior
// in command construction. We can't actually invoke sudo
// in a unit test without privileges, but we can verify
// the command shape by intercepting via a non-sudo-locking
// command that echoes its argv.
//
// Skipped if sudo isn't available — locks the option
// plumbing rather than the actual privilege escalation.
func TestLocalTransport_WithSudo_OptionWiring(t *testing.T) {
	tr := New(WithSudo(true))
	if !tr.useSudo {
		t.Error("WithSudo(true) didn't set useSudo")
	}
	tr2 := New(WithSudo(false))
	if tr2.useSudo {
		t.Error("WithSudo(false) set useSudo")
	}
}
