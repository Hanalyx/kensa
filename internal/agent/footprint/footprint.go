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
	"fmt"
	"io/fs"
	"sort"

	"github.com/Hanalyx/kensa/api"
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
	// A resource this transaction CREATED stays a create no matter what is
	// done to it afterward: its net reversal is still removal (the prior
	// state was absent). Keeping OpCreate keeps the op coherent with the
	// retained absent pre-image — a later modify/create must not relabel it
	// "restore prior content" when there was no prior content.
	if prev.Op == OpCreate {
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

// Gate canonicalizes both footprints and returns the observed paths not
// covered by captured. Canonicalizing both sides means a handler may declare
// its captured footprint with raw paths: a symlinked parent (which the
// recorder already resolved on the observed side) cannot cause a spurious
// gate failure. An empty result means the apply touched nothing it did not
// capture.
func Gate(observed, captured *Footprint) []string {
	return Uncovered(canonicalized(observed), canonicalized(captured))
}

// canonicalized returns a copy of f re-keyed by canonical path. Idempotent
// on a footprint whose paths are already canonical (the observed side).
func canonicalized(f *Footprint) *Footprint {
	out := New()
	for _, e := range f.Entries() {
		e.Path = Canonicalize(e.Path)
		out.Add(e)
	}
	return out
}

// Footprinter is the optional capability a capturable handler implements to
// opt into the pre-commit footprint gate: given the pre-state it recorded,
// it declares the CAPTURED footprint — the set of resources it intends to
// touch, each with the pre-image its rollback can restore. The agent asserts
// it after Apply and fails the step if the observed footprint is not a
// subset (apply touched something the handler did not capture, so rollback
// would be incomplete). A handler that does not implement it is not gated —
// capture-completeness stays a review promise for it until it opts in, so
// the gate rolls out per-handler with no flip-everything-at-once regression.
type Footprinter interface {
	CapturedFootprint(pre *api.PreState) (*Footprint, error)
}

// SingleFile builds a captured footprint for a handler that touches exactly
// one file, whose path is recorded at pre.Data[pathKey]. The op is derived
// from a "file_existed" flag when present (absent → create, else modify) and
// is informational — the gate compares paths. It returns an error if the
// path key is missing, so a handler opting into the gate cannot silently
// declare an empty footprint.
func SingleFile(pre *api.PreState, pathKey string) (*Footprint, error) {
	if pre == nil || pre.Data == nil {
		return nil, fmt.Errorf("footprint: nil pre-state")
	}
	path, _ := pre.Data[pathKey].(string)
	if path == "" {
		return nil, fmt.Errorf("footprint: pre-state missing %q", pathKey)
	}
	op := OpModify
	if existed, ok := pre.Data["file_existed"].(bool); ok && !existed {
		op = OpCreate
	}
	f := New()
	f.Add(Entry{Path: path, Op: op})
	return f, nil
}
