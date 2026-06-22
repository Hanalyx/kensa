// Package footprint records the concrete set of resources an agent-mode
// transaction touches, so the engine can enforce that a handler captured
// (and can therefore roll back) everything its apply actually mutated.
//
// Two footprints exist per transaction:
//
//   - the CAPTURED footprint — what a handler declared it intends to touch,
//     derived from its Capture pre-state;
//   - the OBSERVED footprint — what the recording layer (see the recorder in
//     this package) saw the apply actually touch, one entry per mutating
//     syscall, each with the pre-image read synchronously BEFORE the
//     mutation.
//
// The engine's pre-commit gate asserts observed ⊆ captured: a handler that
// touched a resource it did not capture cannot reach committed, because its
// rollback would be incomplete. This converts capture-completeness from a
// human-review promise (CONTRIBUTING.md) into a code-enforced precondition.
//
// Paths are canonical (resolved by the recorder via the touched fd/inode,
// not the caller's string) so a symlink or a `..` cannot let an apply touch
// one path while declaring another.
package footprint

import (
	"io/fs"
	"sort"
)

// Op is the kind of mutation applied to a resource — which determines how
// rollback reverses it.
type Op uint8

const (
	// OpCreate: the resource did not exist before; rollback removes it
	// (unlink for a file, rmdir for a directory).
	OpCreate Op = iota
	// OpModify: the resource existed; rollback restores its pre-image
	// (content + mode + owner).
	OpModify
	// OpDelete: the resource existed and was removed; rollback recreates it
	// from the pre-image.
	OpDelete
)

// String renders the op for logs and gate messages.
func (o Op) String() string {
	switch o {
	case OpCreate:
		return "create"
	case OpModify:
		return "modify"
	case OpDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// PreImage is the restorable prior state of one resource, captured
// synchronously BEFORE the mutating syscall. Absent==true means the resource
// did not exist (so the matching Op is OpCreate and rollback is an
// unlink/rmdir); the remaining fields are then zero.
type PreImage struct {
	// Absent is true when the resource did not exist before the mutation.
	Absent bool
	// IsDir distinguishes a directory pre-image from a file's.
	IsDir bool
	// Mode is the prior file mode (permission + type bits).
	Mode fs.FileMode
	// Size is the prior content size in bytes (0 for a directory).
	Size int64
	// SHA256 is the hex content hash of the prior file (empty for a
	// directory or an absent resource) — the integrity anchor a rollback
	// restore can be checked against.
	SHA256 string
	// UID/GID are the prior owner ids.
	UID uint32
	GID uint32
}

// Entry is one touched resource: its canonical path, the operation applied,
// and the pre-image needed to reverse it.
type Entry struct {
	// Path is the canonical (symlink- and dot-resolved) absolute path.
	Path string
	// Op is the mutation kind.
	Op Op
	// PreImage is the prior state for rollback.
	PreImage PreImage
}

// Footprint is a set of touched resources keyed by canonical path. The
// zero value is not usable; call New.
type Footprint struct {
	entries map[string]Entry
}

// New returns an empty Footprint.
func New() *Footprint {
	return &Footprint{entries: make(map[string]Entry)}
}

// Add records a touched resource. If the same canonical path is touched more
// than once in a transaction, the FIRST pre-image is retained (it is the one
// that reverses the whole transaction's effect on that path), while the Op is
// widened toward the net effect: a create followed by a delete nets to the
// original absent state and the entry is dropped; otherwise the earliest
// pre-image with the latest op is kept.
func (f *Footprint) Add(e Entry) {
	prev, seen := f.entries[e.Path]
	if !seen {
		f.entries[e.Path] = e
		return
	}
	// Net a create-then-delete back to "untouched": the resource was absent
	// before and is absent after, so there is nothing to roll back.
	if prev.Op == OpCreate && e.Op == OpDelete {
		delete(f.entries, e.Path)
		return
	}
	// Otherwise keep the earliest pre-image (prev) but advance the op to the
	// latest mutation, so rollback reverses to the true prior state.
	prev.Op = e.Op
	f.entries[e.Path] = prev
}

// Has reports whether the path is in the footprint.
func (f *Footprint) Has(path string) bool {
	_, ok := f.entries[path]
	return ok
}

// Len returns the number of distinct resources.
func (f *Footprint) Len() int { return len(f.entries) }

// Entries returns the recorded entries sorted by path, for deterministic
// output (gate messages, wire encoding, tests).
func (f *Footprint) Entries() []Entry {
	out := make([]Entry, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Uncovered returns the canonical paths present in observed but NOT in
// captured — the gate's failure set. An empty result means observed ⊆
// captured: every resource the apply touched was captured for rollback. The
// result is sorted for deterministic gate messages.
func Uncovered(observed, captured *Footprint) []string {
	var miss []string
	for path := range observed.entries {
		if !captured.Has(path) {
			miss = append(miss, path)
		}
	}
	sort.Strings(miss)
	return miss
}
