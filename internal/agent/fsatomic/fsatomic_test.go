package fsatomic

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAtomicWrite_HappyPath locks the basic publish:
// new file with the requested content + mode appears in
// the directory.
func TestAtomicWrite_HappyPath(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello, atomic world")
	if err := AtomicWrite(context.Background(), dir, "testfile", 0o644, content); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "testfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content: got %q, want %q", got, content)
	}
	info, err := os.Stat(filepath.Join(dir, "testfile"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode: got %o, want 0644", info.Mode().Perm())
	}
}

// TestAtomicWrite_RejectsExisting locks the
// ErrAlreadyExists contract.
func TestAtomicWrite_RejectsExisting(t *testing.T) {
	dir := t.TempDir()
	preexisting := filepath.Join(dir, "preexisting")
	if err := os.WriteFile(preexisting, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := AtomicWrite(context.Background(), dir, "preexisting", 0o644, []byte("new"))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists; got: %v", err)
	}
	// Pre-existing bytes must be intact.
	got, _ := os.ReadFile(preexisting)
	if string(got) != "old" {
		t.Errorf("pre-existing content corrupted: %q", got)
	}
}

// TestAtomicWrite_RejectsPathInName locks the
// name-must-be-basename contract.
func TestAtomicWrite_RejectsPathInName(t *testing.T) {
	dir := t.TempDir()
	err := AtomicWrite(context.Background(), dir, "subdir/file", 0o644, []byte("x"))
	if err == nil {
		t.Error("expected error for name containing path separator")
	}
}

// TestAtomicReplace_HappyPath: existing file gets new
// content with the requested mode.
func TestAtomicReplace_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	if err := os.WriteFile(path, []byte("old content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicReplace(context.Background(), path, 0o600, []byte("new content")); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new content" {
		t.Errorf("content: got %q, want %q", got, "new content")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode: got %o, want 0600", info.Mode().Perm())
	}
}

// TestAtomicReplace_NotExist locks the ErrNotExist
// contract.
func TestAtomicReplace_NotExist(t *testing.T) {
	dir := t.TempDir()
	err := AtomicReplace(context.Background(), filepath.Join(dir, "nope"), 0o644, []byte("x"))
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("expected ErrNotExist; got: %v", err)
	}
}

// TestAtomicReplace_FollowsSymlinks locks the
// symlink-following contract (founder Q2 ratified rec).
// The symlink is preserved; the target file gets new
// content.
func TestAtomicReplace_FollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "symlink")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := AtomicReplace(context.Background(), link, 0o644, []byte("new")); err != nil {
		t.Fatalf("AtomicReplace via symlink: %v", err)
	}
	// Symlink still a symlink.
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink converted to regular file — should remain a symlink")
	}
	// Target has new content.
	got, _ := os.ReadFile(target)
	if string(got) != "new" {
		t.Errorf("target content: got %q, want %q", got, "new")
	}
}

// TestAtomicRemove_HappyPath + ErrNotExist.
func TestAtomicRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "toremove")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicRemove(context.Background(), path); err != nil {
		t.Fatalf("AtomicRemove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should be gone; stat err: %v", err)
	}

	// Removing a non-existent path returns ErrNotExist.
	err := AtomicRemove(context.Background(), filepath.Join(dir, "nope"))
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("expected ErrNotExist; got: %v", err)
	}
}

// TestAtomicReplace_AtomicityProperty is the load-bearing
// test: a reader concurrently observing the target during
// AtomicReplace MUST see either old-complete or
// new-complete, never partial. This locks the entire
// point of fsatomic.
//
// Implementation: writer goroutine performs N
// AtomicReplaces. Reader goroutine spins on os.ReadFile
// in parallel. After joining, assert every read returned
// either ALL-OLD-BYTES or ALL-NEW-BYTES bytes (no torn
// reads, no partial content).
func TestAtomicReplace_AtomicityProperty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic-target")

	// Distinct old/new content with NO shared prefix so
	// any torn read would be obviously detectable.
	oldContent := bytes.Repeat([]byte("AAAA"), 256) // 1024 A's
	newContent := bytes.Repeat([]byte("BBBB"), 256) // 1024 B's

	if err := os.WriteFile(path, oldContent, 0o644); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var readOps atomic.Int64
	var tornReads atomic.Int64

	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for !stop.Load() {
			b, err := os.ReadFile(path)
			if err != nil {
				// EOF/ENOENT during the rename window is
				// not a torn read — it's the filesystem
				// briefly returning before the new entry
				// is established. We're testing for
				// PARTIAL CONTENT, not transient
				// errors. Skip and continue.
				continue
			}
			readOps.Add(1)
			if !bytes.Equal(b, oldContent) && !bytes.Equal(b, newContent) {
				tornReads.Add(1)
				t.Errorf("torn read detected: len=%d, prefix=%q ...", len(b), b[:min(len(b), 20)])
			}
		}
	}()

	// Writer: AtomicReplace alternating old/new for ~100ms.
	deadline := time.Now().Add(100 * time.Millisecond)
	writeCount := 0
	for time.Now().Before(deadline) {
		want := oldContent
		if writeCount%2 == 1 {
			want = newContent
		}
		if err := AtomicReplace(context.Background(), path, 0o644, want); err != nil {
			t.Errorf("AtomicReplace: %v", err)
			break
		}
		writeCount++
	}

	stop.Store(true)
	readerWG.Wait()

	if tornReads.Load() > 0 {
		t.Errorf("ATOMICITY VIOLATED: %d torn reads out of %d total", tornReads.Load(), readOps.Load())
	}
	t.Logf("performed %d AtomicReplace writes, %d concurrent reads, %d torn reads (must be 0)",
		writeCount, readOps.Load(), tornReads.Load())
}

// TestAtomicWrite_FsyncDoesNotPanic — sanity check that
// fsync on a tmpfs directory works (tmpfs DOES support
// fsync as a no-op).
func TestAtomicWrite_FsyncDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		name := "f" + string(rune('A'+i))
		if err := AtomicWrite(context.Background(), dir, name, 0o644, []byte{byte(i)}); err != nil {
			t.Errorf("AtomicWrite(%s): %v", name, err)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
