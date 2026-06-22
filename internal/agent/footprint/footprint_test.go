package footprint

import (
	"io/fs"
	"testing"
)

func modEntry(path string) Entry {
	return Entry{Path: path, Op: OpModify, PreImage: PreImage{Mode: 0o644, Size: 3, SHA256: "abc"}}
}

func createEntry(path string) Entry {
	return Entry{Path: path, Op: OpCreate, PreImage: PreImage{Absent: true}}
}

// Add keys by path, Entries is sorted and deterministic.
//
// @spec footprint-funnel
// @ac AC-01
func TestAdd_KeysByPathDeterministic(t *testing.T) {
	t.Run("footprint-funnel/AC-01", func(t *testing.T) {})
	f := New()
	f.Add(modEntry("/etc/b"))
	f.Add(modEntry("/etc/a"))
	f.Add(createEntry("/etc/c"))
	got := f.Entries()
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3", len(got))
	}
	if got[0].Path != "/etc/a" || got[1].Path != "/etc/b" || got[2].Path != "/etc/c" {
		t.Errorf("not sorted: %v", []string{got[0].Path, got[1].Path, got[2].Path})
	}
}

// The FIRST pre-image is retained when a path is touched twice (it reverses
// the whole transaction); the op advances to the latest mutation.
//
// @spec footprint-funnel
// @ac AC-01
func TestAdd_KeepsFirstPreImageAdvancesOp(t *testing.T) {
	t.Run("footprint-funnel/AC-01", func(t *testing.T) {})
	f := New()
	f.Add(Entry{Path: "/etc/x", Op: OpModify, PreImage: PreImage{Mode: 0o600, SHA256: "first"}})
	f.Add(Entry{Path: "/etc/x", Op: OpDelete, PreImage: PreImage{Mode: 0o644, SHA256: "second"}})
	es := f.Entries()
	if len(es) != 1 {
		t.Fatalf("len=%d, want 1", len(es))
	}
	if es[0].PreImage.SHA256 != "first" {
		t.Errorf("kept pre-image = %q, want the first (%q)", es[0].PreImage.SHA256, "first")
	}
	if es[0].Op != OpDelete {
		t.Errorf("op = %v, want advanced to delete", es[0].Op)
	}
}

// create-then-delete nets back to untouched (nothing to roll back).
//
// @spec footprint-funnel
// @ac AC-01
func TestAdd_CreateThenDeleteNetsToUntouched(t *testing.T) {
	t.Run("footprint-funnel/AC-01", func(t *testing.T) {})
	f := New()
	f.Add(createEntry("/etc/tmp"))
	f.Add(Entry{Path: "/etc/tmp", Op: OpDelete, PreImage: PreImage{Absent: true}})
	if f.Len() != 0 {
		t.Errorf("create-then-delete should net to empty; len=%d", f.Len())
	}
}

// Uncovered returns observed paths missing from captured, sorted; empty when
// observed ⊆ captured.
//
// @spec footprint-funnel
// @ac AC-02
func TestUncovered_SubsetGate(t *testing.T) {
	t.Run("footprint-funnel/AC-02", func(t *testing.T) {})
	captured := New()
	captured.Add(modEntry("/etc/snippet"))
	captured.Add(modEntry("/etc/lock"))

	// observed ⊆ captured → no miss.
	observed := New()
	observed.Add(modEntry("/etc/snippet"))
	if miss := Uncovered(observed, captured); len(miss) != 0 {
		t.Errorf("expected no uncovered, got %v", miss)
	}

	// observed touches an uncaptured parent dir → miss.
	observed.Add(Entry{Path: "/etc/parent-dir", Op: OpCreate, PreImage: PreImage{Absent: true, IsDir: true}})
	observed.Add(modEntry("/etc/another"))
	miss := Uncovered(observed, captured)
	if len(miss) != 2 || miss[0] != "/etc/another" || miss[1] != "/etc/parent-dir" {
		t.Errorf("uncovered = %v, want [/etc/another /etc/parent-dir]", miss)
	}
}

// Op.String renders each op.
//
// @spec footprint-funnel
// @ac AC-01
func TestOpString(t *testing.T) {
	t.Run("footprint-funnel/AC-01", func(t *testing.T) {})
	for op, want := range map[Op]string{OpCreate: "create", OpModify: "modify", OpDelete: "delete", Op(9): "unknown"} {
		if got := op.String(); got != want {
			t.Errorf("Op(%d).String()=%q, want %q", op, got, want)
		}
	}
}

// PreImage carries the fields a rollback needs (compile/shape guard).
//
// @spec footprint-funnel
// @ac AC-01
func TestPreImageShape(t *testing.T) {
	t.Run("footprint-funnel/AC-01", func(t *testing.T) {})
	p := PreImage{Absent: false, IsDir: false, Mode: fs.FileMode(0o640), Size: 12, SHA256: "deadbeef", UID: 0, GID: 0}
	if p.Mode != 0o640 || p.Size != 12 || p.SHA256 != "deadbeef" {
		t.Errorf("pre-image fields not retained: %+v", p)
	}
}
