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

// TestAtomicWrite_RejectsParentDirMissing locks the
// ErrParentDirMissing contract.
func TestAtomicWrite_RejectsParentDirMissing(t *testing.T) {
	root := t.TempDir()
	err := AtomicWrite(context.Background(), filepath.Join(root, "no-such-dir"), "f", 0o644, []byte("x"))
	if !errors.Is(err, ErrParentDirMissing) {
		t.Errorf("expected ErrParentDirMissing; got: %v", err)
	}
}

// TestAtomicReplace_HappyPath: existing file gets new content
// with the requested mode.
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

// TestAtomicReplace_NotExist locks the ErrNotExist contract.
func TestAtomicReplace_NotExist(t *testing.T) {
	dir := t.TempDir()
	err := AtomicReplace(context.Background(), filepath.Join(dir, "nope"), 0o644, []byte("x"))
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("expected ErrNotExist; got: %v", err)
	}
}

// TestAtomicReplace_RefusesSymlinkBase locks the
// symlink-refusal contract for a symlink AT THE TARGET
// position. Founder D2 ratification (2026-05-11): O_NOFOLLOW
// traversal, hard refusal — reverses the prior Q2 follow-
// symlinks decision after the post-merge security review
// identified a local-root primitive.
func TestAtomicReplace_RefusesSymlinkBase(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "symlink")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := AtomicReplace(context.Background(), link, 0o644, []byte("new"))
	if !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("expected ErrSymlinkInPath; got: %v", err)
	}
	// Target must remain unchanged.
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Errorf("target was modified despite symlink refusal: %q", got)
	}
}

// TestAtomicReplace_RefusesSymlinkInPath plants a symlink
// at an INTERMEDIATE component of the path. fsatomic must
// refuse to traverse it. This is the load-bearing security
// test: an attacker planting /etc/sudoers.d → /etc cannot
// use fsatomic to rewrite /etc/passwd.
func TestAtomicReplace_RefusesSymlinkInPath(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real-dir")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "sensitive"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(root, "link-dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	// fullPath traverses the symlink at link-dir.
	err := AtomicReplace(context.Background(), filepath.Join(linkDir, "sensitive"), 0o644, []byte("attacker"))
	if !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("expected ErrSymlinkInPath; got: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(realDir, "sensitive"))
	if string(got) != "secret" {
		t.Errorf("file was modified through symlink path: %q", got)
	}
}

// TestAtomicReplace_RefusesRelativePath locks the
// absolute-path requirement.
func TestAtomicReplace_RefusesRelativePath(t *testing.T) {
	err := AtomicReplace(context.Background(), "relative/path", 0o644, []byte("x"))
	if err == nil || !contains(err.Error(), "must be absolute") {
		t.Errorf("expected absolute-path error; got: %v", err)
	}
}

// TestAtomicReplace_RefusesDirectory locks the regular-file
// requirement.
func TestAtomicReplace_RefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := AtomicReplace(context.Background(), subdir, 0o644, []byte("x"))
	if err == nil || !contains(err.Error(), "not a regular file") {
		t.Errorf("expected regular-file rejection; got: %v", err)
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

	err := AtomicRemove(context.Background(), filepath.Join(dir, "nope"))
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("expected ErrNotExist; got: %v", err)
	}
}

// TestAtomicRemove_RefusesSymlink locks the symlink-refusal
// contract for AtomicRemove.
func TestAtomicRemove_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := AtomicRemove(context.Background(), link)
	if !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("expected ErrSymlinkInPath; got: %v", err)
	}
	// Target must still exist.
	if _, statErr := os.Stat(target); statErr != nil {
		t.Errorf("target should still exist: %v", statErr)
	}
}

// TestAtomicReplace_AtomicityProperty is the load-bearing
// concurrency test: a reader concurrently observing the
// target during AtomicReplace MUST see either old-complete
// or new-complete, never partial.
func TestAtomicReplace_AtomicityProperty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic-target")

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
				continue
			}
			readOps.Add(1)
			if !bytes.Equal(b, oldContent) && !bytes.Equal(b, newContent) {
				tornReads.Add(1)
				t.Errorf("torn read detected: len=%d, prefix=%q ...", len(b), b[:minInt(len(b), 20)])
			}
		}
	}()

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

// TestAtomicReplace_ConcurrentSameTarget locks the per-
// goroutine random-suffix contract: two goroutines replacing
// the same target in the same process must both succeed
// without temp-file collision.
func TestAtomicReplace_ConcurrentSameTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	if err := os.WriteFile(path, []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}

	const goroutines = 8
	const iterations = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var failures atomic.Int64
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			content := []byte{byte('A' + g)}
			for i := 0; i < iterations; i++ {
				if err := AtomicReplace(context.Background(), path, 0o644, content); err != nil {
					failures.Add(1)
					t.Errorf("goroutine %d iteration %d: %v", g, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if failures.Load() > 0 {
		t.Errorf("%d concurrent-replace failures (expected 0)", failures.Load())
	}
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
