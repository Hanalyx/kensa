package footprint

import "sort"

// Unrestorable returns the captured paths that cannot be restored on rollback
// right now. The only check today is the immutable inode flag (chattr +i): a
// file a rollback would rewrite or remove, but which the kernel will refuse to
// modify, means the transaction cannot be reversed — so it should be refused
// before any mutation rather than committed unrollbackable. Coverage
// (observed ⊆ captured) is necessary but insufficient; this is the "is it
// restorable now" complement.
//
// The immutable check is injected so the agent supplies the real ioctl probe
// (kernelio.IsImmutable) and tests supply a fake. A check that errors is
// treated as "not known-unrestorable" (best-effort): the probe never turns a
// transient probe error into a refusal. The result is sorted for
// deterministic messages.
func Unrestorable(captured *Footprint, immutable func(path string) (bool, error)) []string {
	var bad []string
	for _, e := range captured.Entries() {
		if imm, err := immutable(e.Path); err == nil && imm {
			bad = append(bad, e.Path)
		}
	}
	sort.Strings(bad)
	return bad
}
