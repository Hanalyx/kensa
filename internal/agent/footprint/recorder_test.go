package footprint

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// fakeInspector returns canonical=path and a pre-image looked up from a map;
// any path not in the map is reported absent.
func fakeInspector(images map[string]PreImage) Inspector {
	return func(path string) (string, PreImage, error) {
		if p, ok := images[path]; ok {
			return path, p, nil
		}
		return path, PreImage{Absent: true}, nil
	}
}

// newRecorderWith wraps a kernelio fake and injects a fake inspector.
func newRecorderWith(images map[string]PreImage) (*Recorder, *kernelio.FakeSysctlTransport) {
	inner := kernelio.NewFakeSysctl()
	r := NewRecorder(inner)
	r.inspect = fakeInspector(images)
	return r, inner
}

// AtomicReplace records OpModify with the prior pre-image and delegates.
//
// @spec footprint-funnel
// @ac AC-03
func TestRecorder_AtomicReplace_RecordsModify(t *testing.T) {
	t.Run("footprint-funnel/AC-03", func(t *testing.T) {})
	path := "/etc/dconf/db/local.d/00-login"
	r, inner := newRecorderWith(map[string]PreImage{
		path: {Mode: 0o644, Size: 5, SHA256: "old"},
	})
	inner.Files[path] = "old"
	if err := r.AtomicReplace(context.Background(), path, 0o644, []byte("new content")); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	if inner.Files[path] != "new content" {
		t.Errorf("delegate did not write: %q", inner.Files[path])
	}
	es := r.Footprint().Entries()
	if len(es) != 1 || es[0].Path != path || es[0].Op != OpModify || es[0].PreImage.SHA256 != "old" {
		t.Errorf("footprint = %+v, want one OpModify with prior pre-image", es)
	}
}

// AtomicWrite records OpCreate (absent pre-image) and delegates.
//
// @spec footprint-funnel
// @ac AC-03
func TestRecorder_AtomicWrite_RecordsCreate(t *testing.T) {
	t.Run("footprint-funnel/AC-03", func(t *testing.T) {})
	r, inner := newRecorderWith(nil) // all absent
	if err := r.AtomicWrite(context.Background(), "/etc/modprobe.d", "kensa.conf", 0o644, []byte("x")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	want := "/etc/modprobe.d/kensa.conf"
	if inner.Files[want] != "x" {
		t.Errorf("delegate did not create: %q", inner.Files[want])
	}
	es := r.Footprint().Entries()
	if len(es) != 1 || es[0].Path != want || es[0].Op != OpCreate || !es[0].PreImage.Absent {
		t.Errorf("footprint = %+v, want one OpCreate absent", es)
	}
}

// AtomicRemove records OpDelete with the prior pre-image and delegates.
//
// @spec footprint-funnel
// @ac AC-03
func TestRecorder_AtomicRemove_RecordsDelete(t *testing.T) {
	t.Run("footprint-funnel/AC-03", func(t *testing.T) {})
	path := "/etc/audit/rules.d/99-kensa.rules"
	r, inner := newRecorderWith(map[string]PreImage{path: {Mode: 0o640, Size: 3, SHA256: "abc"}})
	inner.Files[path] = "abc"
	if err := r.AtomicRemove(context.Background(), path); err != nil {
		t.Fatalf("AtomicRemove: %v", err)
	}
	if _, ok := inner.Files[path]; ok {
		t.Error("delegate did not remove the file")
	}
	es := r.Footprint().Entries()
	if len(es) != 1 || es[0].Op != OpDelete || es[0].PreImage.SHA256 != "abc" {
		t.Errorf("footprint = %+v, want one OpDelete with prior pre-image", es)
	}
}

// MkdirAll records only the directory levels it creates (absent ones), not
// pre-existing levels.
//
// @spec footprint-funnel
// @ac AC-03
func TestRecorder_MkdirAll_RecordsMissingLevels(t *testing.T) {
	t.Run("footprint-funnel/AC-03", func(t *testing.T) {})
	// /etc and /etc/dconf exist; /etc/dconf/db and below are absent.
	r, _ := newRecorderWith(map[string]PreImage{
		"/etc":       {IsDir: true, Mode: 0o755},
		"/etc/dconf": {IsDir: true, Mode: 0o755},
	})
	if err := r.MkdirAll("/etc/dconf/db/local.d/locks", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	got := map[string]bool{}
	for _, e := range r.Footprint().Entries() {
		if e.Op != OpCreate || !e.PreImage.IsDir || !e.PreImage.Absent {
			t.Errorf("level %s not recorded as absent-dir create: %+v", e.Path, e)
		}
		got[e.Path] = true
	}
	for _, want := range []string{"/etc/dconf/db", "/etc/dconf/db/local.d", "/etc/dconf/db/local.d/locks"} {
		if !got[want] {
			t.Errorf("missing recorded level %s; got %v", want, got)
		}
	}
	if got["/etc"] || got["/etc/dconf"] {
		t.Errorf("pre-existing levels must not be recorded; got %v", got)
	}
}

// Reads and runtime forwards are NOT recorded.
//
// @spec footprint-funnel
// @ac AC-03
func TestRecorder_ReadsAndRuntimeNotRecorded(t *testing.T) {
	t.Run("footprint-funnel/AC-03", func(t *testing.T) {})
	r, inner := newRecorderWith(nil)
	inner.Files["/etc/x"] = "y"
	if _, _, err := r.ReadFileIfExists("/etc/x"); err != nil {
		t.Fatalf("ReadFileIfExists: %v", err)
	}
	if err := r.WriteSysctl("kernel.randomize_va_space", "2"); err != nil {
		t.Fatalf("WriteSysctl: %v", err)
	}
	if err := r.DeleteModule("usb-storage"); err != nil {
		t.Fatalf("DeleteModule: %v", err)
	}
	if n := r.Footprint().Len(); n != 0 {
		t.Errorf("reads/runtime ops must not be recorded; footprint len=%d", n)
	}
}

// realInspect reads a true pre-image from the filesystem: absent, a file
// (mode + size + hash), a directory, and a refused symlink.
//
// @spec footprint-funnel
// @ac AC-03
func TestRealInspect(t *testing.T) {
	t.Run("footprint-funnel/AC-03", func(t *testing.T) {})
	dir := t.TempDir()

	// Absent.
	if _, pre, err := realInspect(filepath.Join(dir, "nope")); err != nil || !pre.Absent {
		t.Errorf("absent: pre=%+v err=%v", pre, err)
	}

	// File with known content.
	fp := filepath.Join(dir, "f")
	if err := os.WriteFile(fp, []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, pre, err := realInspect(fp)
	if err != nil || pre.Absent || pre.IsDir || pre.Size != 5 || pre.SHA256 == "" {
		t.Errorf("file: pre=%+v err=%v", pre, err)
	}

	// Directory.
	_, dpre, err := realInspect(dir)
	if err != nil || !dpre.IsDir || dpre.SHA256 != "" {
		t.Errorf("dir: pre=%+v err=%v", dpre, err)
	}

	// Symlink is refused.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(fp, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := realInspect(link); err == nil {
		t.Error("expected symlink to be refused")
	}
}
