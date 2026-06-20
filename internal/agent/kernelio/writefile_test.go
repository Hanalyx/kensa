package kernelio_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// WriteFile is create-OR-replace: it succeeds whether or not the target
// exists (the live-caught bug was AtomicReplace failing on a new file).
//
// @spec kernelio-sysctl
// @ac AC-03
func TestWriteFile_CreateOrReplace(t *testing.T) {
	t.Run("kernelio-sysctl/AC-03", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	const p = "/etc/sysctl.d/99-kensa.conf"

	// Create (absent → must succeed; the bug was an ErrNotExist here).
	if err := kernelio.WriteFile(context.Background(), f, p, 0o644, []byte("a\n")); err != nil {
		t.Fatalf("WriteFile create: %v", err)
	}
	if f.Files[p] != "a\n" {
		t.Errorf("after create = %q, want a\\n", f.Files[p])
	}
	// Replace (present → must also succeed).
	if err := kernelio.WriteFile(context.Background(), f, p, 0o644, []byte("b\n")); err != nil {
		t.Fatalf("WriteFile replace: %v", err)
	}
	if f.Files[p] != "b\n" {
		t.Errorf("after replace = %q, want b\\n", f.Files[p])
	}
}

// RemoveFile treats an already-absent file as success (the live-caught
// rollback bug was AtomicRemove failing ErrNotExist on a never-created
// drop-in, which aborted rollback and left the runtime value unrestored).
//
// @spec kernelio-sysctl
// @ac AC-03
func TestRemoveFile_AbsentIsNoop(t *testing.T) {
	t.Run("kernelio-sysctl/AC-03", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	const p = "/etc/sysctl.d/99-kensa.conf"

	// Remove an absent file → no error (the fix).
	if err := kernelio.RemoveFile(context.Background(), f, p); err != nil {
		t.Errorf("RemoveFile(absent) = %v, want nil", err)
	}
	// Remove a present file → gone.
	f.Files[p] = "x"
	if err := kernelio.RemoveFile(context.Background(), f, p); err != nil {
		t.Fatalf("RemoveFile(present): %v", err)
	}
	if _, ok := f.Files[p]; ok {
		t.Error("file should be gone after RemoveFile")
	}
}
