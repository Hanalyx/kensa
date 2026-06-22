package footprint

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// End-to-end: the recorder observes every write; Gate catches the one the
// handler did not capture (rollback would be incomplete for it).
//
// @spec footprint-funnel
// @ac AC-04
func TestGate_CatchesUncapturedWrite(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	r, inner := newRecorderWith(map[string]PreImage{
		"/etc/declared": {Mode: 0o644, Size: 1, SHA256: "d"},
	})
	inner.Files["/etc/declared"] = "d" // AtomicReplace requires existence
	ctx := context.Background()
	if err := r.AtomicReplace(ctx, "/etc/declared", 0o644, []byte("x")); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	if err := r.AtomicWrite(ctx, "/etc", "undeclared", 0o644, []byte("y")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	captured := New()
	captured.Add(Entry{Path: "/etc/declared", Op: OpModify})

	miss := Gate(r.Footprint(), captured)
	if len(miss) != 1 || miss[0] != "/etc/undeclared" {
		t.Errorf("gate = %v, want [/etc/undeclared]", miss)
	}
}

// A handler that touches only what it declared passes the gate.
//
// @spec footprint-funnel
// @ac AC-04
func TestGate_PassesWhenSubset(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	r, inner := newRecorderWith(map[string]PreImage{
		"/etc/declared": {Mode: 0o644, Size: 1, SHA256: "d"},
	})
	inner.Files["/etc/declared"] = "d"
	if err := r.AtomicReplace(context.Background(), "/etc/declared", 0o644, []byte("x")); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	captured := New()
	captured.Add(Entry{Path: "/etc/declared", Op: OpModify})
	captured.Add(Entry{Path: "/etc/also-allowed", Op: OpCreate}) // captured ⊋ observed is fine

	if miss := Gate(r.Footprint(), captured); len(miss) != 0 {
		t.Errorf("gate should pass when observed ⊆ captured; got %v", miss)
	}
}

// SingleFile builds a one-path footprint from the pre-state, and errors when
// the path key is missing.
//
// @spec footprint-funnel
// @ac AC-04
func TestSingleFile(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	pre := &api.PreState{Data: map[string]interface{}{"path": "/etc/thing", "file_existed": true}}
	f, err := SingleFile(pre, "path")
	if err != nil {
		t.Fatalf("SingleFile: %v", err)
	}
	if !f.Has("/etc/thing") {
		t.Errorf("footprint missing the captured path: %v", f.Entries())
	}
	if _, err := SingleFile(pre, "nonexistent"); err == nil {
		t.Error("expected error for a missing path key")
	}
}
