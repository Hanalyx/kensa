package fsatomic

import (
	"context"
	"io/fs"
)

// Transport is the capability interface for transports that
// can perform kernel-atomic file operations on the target
// host. The agent's LocalTransport implements it by
// delegating to the package-level AtomicWrite / AtomicReplace
// / AtomicRemove primitives.
//
// **Where this interface lives.** Originally introduced in
// `api/` as `api.AtomicTransport`, moved here as part of the
// fix/phase-2-rework drop after the post-merge architecture
// review observed:
//
//   - Atomicity is an agent-side capability; OpenWatch and
//     other consumers of `api.Transport` are not expected to
//     implement it themselves.
//   - Phases 4-7 will introduce sibling capabilities
//     (SystemdDBus, AuditNetlink, SysctlDirect,
//     SELinuxRuntime, DconfDBus); growing `api/` to six
//     interfaces would be a public-surface mistake.
//   - The local transport already depends on this package
//     for the primitives, so the layering bullet is already
//     crossed.
//
// **Handler use.** Each file-touching handler type-asserts:
//
//	if afs, ok := transport.(fsatomic.Transport); ok {
//	    // agent-mode: kernel-atomic path
//	} else {
//	    // direct-SSH: shell-pipeline best-effort
//	}
//
// **Contract.** Methods on this interface deliver the
// guarantees documented at the package level: mid-write
// crashes leave either OLD bytes intact or NEW bytes
// complete; symlinks are refused; per-filesystem
// RENAME_EXCHANGE probe with rename-into-place fallback.
//
// **Direct-SSH does NOT implement this interface.** That is
// the intended split — direct-SSH retains shell-pipeline
// best-effort atomicity for v1.x.
type Transport interface {
	AtomicWrite(ctx context.Context, dir, name string, mode fs.FileMode, content []byte) error
	AtomicReplace(ctx context.Context, fullPath string, mode fs.FileMode, content []byte) error
	AtomicRemove(ctx context.Context, fullPath string) error
}
