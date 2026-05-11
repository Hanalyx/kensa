# Phase 2 deliverable breakdown — file atomicity primitives

**Status**: Draft, awaiting founder review before deliverables enter DELIVERABLES.md.
**Date**: 2026-05-11.
**Companion**: `docs/roadmap/LOW_LEVEL_MIGRATION_V1.md` §3 Phase 2; `docs/roadmap/DELIVERABLES.md`.

---

## What Phase 2 is

The first phase where kensa's atomicity claim becomes **literally true** for any handler. Today (post-Phase-1) `file_*` and `config_*` handlers Apply via shell commands (`echo > /tmp/x && mv /tmp/x /etc/whatever`) over either SSH or the agent's `sh -c`. The mid-write window is real: a crash between `echo` completing and `mv` succeeding leaves the destination in an indeterminate state, and the controller has no kernel-level guarantee that `fsync` flushed the new bytes before the file system reports success.

Phase 2 replaces the shell pipeline with **`O_TMPFILE` + `Linkat` (publish path) or `Renameat2(RENAME_EXCHANGE)` (replace path) + `Fsync(parent_dir_fd)`**. Mid-write crashes leave either the old bytes intact or the new bytes complete; readers never observe a half-written file.

**Five handlers in scope** (every file-touching capturable handler):

| Handler | Today | After Phase 2 |
|---|---|---|
| `file_content` | `echo > tmp && mv` | `O_TMPFILE` + `Linkat` / `Renameat2` |
| `file_permissions` | `chmod` | Unchanged (chmod is atomic at syscall level) |
| `config_set` | `sed` in-place | `O_TMPFILE` rewrite + atomic publish |
| `config_set_dropin` | `echo >` (new file) | `O_TMPFILE` + `Linkat` |
| `file_absent` | `rm -f` | `Unlinkat` (parent-dir-fd-relative) |

Only `file_permissions` is unchanged — `chmod` is already a single kernel syscall with no mid-state.

---

## Why break it down

The 2-week single-deliverable plan in `LOW_LEVEL_MIGRATION_V1.md` §3 is the right scope but the wrong unit. Reasoning:

1. **fsatomic is foundational.** Every handler in scope uses the same package. Shipping the package alone (zero handler edits) lets reviewer evaluate the primitive design before any handler migrates.
2. **Each handler migration is a CONTRIBUTING-flagged path.** Every `Apply` rewrite needs a failure-mode-analysis commit body per `CONTRIBUTING.md`. Five handlers × per-PR-review-with-founder-attention = 5 separate reviewable units.
3. **One handler at a time validates the primitive.** If the fsatomic API has a flaw (e.g., O_TMPFILE not supported on btrfs subvolumes — there are real edge cases), we discover it at handler #1, fix the package, retry. Per-handler granularity makes this iterative.
4. **Rollback path needs fsatomic too.** The handlers' Rollback functions currently reverse the Apply via shell. After Phase 2 they need fsatomic primitives too (Capture stashes the bytes; Rollback writes them back atomically). Splitting the Apply rewrite from the Rollback rewrite lets each be reviewed independently.

---

## Proposed breakdown — six deliverables

### P-001 — `internal/agent/fsatomic/` primitive package

**Phase**: LL Phase 2
**Deps**: L-032 (LL Phase 1 complete — agent runs all capturable handlers)
**Size**: ~2 days
**Scope**:
- `AtomicWrite(ctx, dirPath, fileName, mode, content) error` — publish-new-file via `O_TMPFILE` + `Linkat`. Errors if file already exists.
- `AtomicReplace(ctx, fullPath, mode, content) error` — replace-existing via `O_TMPFILE` + `Renameat2(RENAME_EXCHANGE)`. Errors if file doesn't exist. Falls back to AtomicWrite if RENAME_EXCHANGE isn't supported.
- `AtomicRemove(ctx, fullPath) error` — `Unlinkat(parent_dir_fd, basename, 0)`. Atomic remove.
- `Fsync` of the file fd before publish; `Fsync` of the parent dir fd after publish. Per `LOW_LEVEL_MIGRATION_V1.md` §3.
- Unit tests on tmpfs: write/replace/remove + verify side effects + verify atomicity property (read concurrent with write never sees torn state).
- Filesystem capability detection: cached check at package init — does this kernel support `RENAME_EXCHANGE`? If not, AtomicReplace silently falls back to `AtomicWrite` (publish to tempname then rename via plain `Renameat`).

**Acceptance**:
- Round-trip tests for the three operations.
- Concurrent-read-while-write test: spawn a reader goroutine that opens+reads the target in a tight loop; AtomicReplace from another goroutine; reader observes either old-complete or new-complete, never partial. Locks the atomicity property.
- Fsync verification: tests on tmpfs use `O_DSYNC`-armed reads to confirm parent-dir-fd fsync persisted the new directory entry.

**Risk**: Low. The Linux primitives are decade-stable.

**No handler edits.** P-001 ships the package alone. P-002..P-006 migrate handlers.

---

### P-002 — Migrate `file_content` to fsatomic

**Phase**: LL Phase 2
**Deps**: P-001
**Size**: ~3 days (handler rewrite + Rollback path + per-PR failure-mode analysis)
**Scope**:
- `internal/handlers/filecontent/filecontent.go` Apply: replace the `echo > tmp && mv` shell pipeline with `fsatomic.AtomicReplace` (if file exists) or `fsatomic.AtomicWrite` (if new). The transport.Run-based shell path is preserved behind a build tag for fallback testing, removed after Phase 2 ships.
- Capture: unchanged (already reads bytes; no atomicity issue on the read path).
- Rollback: writes the captured bytes back via `fsatomic.AtomicReplace`.
- Unit tests update to verify atomicity property (concurrent reader sees old-complete-or-new-complete).
- Failure-mode analysis in commit body per CONTRIBUTING.md.

**Acceptance**:
- All existing file_content tests pass.
- New atomicity test: writer + reader in concurrent goroutines, no torn-state observed.
- Live-host test (gated on KENSA_TEST_SSH_HOST) verifies Apply + Capture + Rollback against a real target.

**Risk**: Medium. file_content is the most-used file handler; regression here breaks rules touching `/etc/ssh/sshd_config`, `/etc/login.defs`, etc.

---

### P-003 — Migrate `file_absent` to fsatomic

**Phase**: LL Phase 2
**Deps**: P-001
**Size**: ~1 day (simpler — single Unlinkat)
**Scope**:
- Apply: `fsatomic.AtomicRemove(parent_dir, basename)`.
- Capture: unchanged (reads file bytes for rollback).
- Rollback: re-creates via `fsatomic.AtomicWrite` with the captured bytes.
- Tests + failure-mode analysis.

**Risk**: Low. Simpler than P-002.

---

### P-004 — Migrate `config_set` to fsatomic

**Phase**: LL Phase 2
**Deps**: P-001
**Size**: ~4 days (most complex handler — line-oriented in-place rewrite)
**Scope**:
- Apply today uses `sed -i` to set a key=value. After Phase 2:
  1. Read the file contents (Capture already does this — reuse).
  2. Compute the new contents in-process (Go string manipulation, not sed).
  3. `fsatomic.AtomicReplace` with the new content.
- The line-rewrite logic is the substantive work. Today's sed pipeline is N regex+substitution steps; Go re-implementation must match exactly.
- Capture: unchanged.
- Rollback: `fsatomic.AtomicReplace` with the captured original.
- Tests: existing config_set tests + new Go-rewrite-matches-sed-pipeline fixture.

**Risk**: Medium-high. config_set is used by ~half the corpus rules. Behavioral parity between the Go rewrite and the current sed pipeline is the load-bearing assertion.

---

### P-005 — Migrate `config_set_dropin` to fsatomic

**Phase**: LL Phase 2
**Deps**: P-001
**Size**: ~2 days
**Scope**:
- Apply: build dropin content in-process, `fsatomic.AtomicWrite` to the drop-in path.
- Capture: unchanged.
- Rollback: `fsatomic.AtomicRemove`.
- Tests + failure-mode analysis.

**Risk**: Low-medium. Simpler than config_set (no in-place rewrite).

---

### P-006 — `TRANSACTION_CONTRACT_V1.md` amendment + Phase-2 close

**Phase**: LL Phase 2 close
**Deps**: P-001..P-005
**Size**: ~1 day
**Scope**:
- Update `docs/TRANSACTION_CONTRACT_V1.md` to scope the literal atomicity commitment to the five Phase 2 file handlers. Other handlers retain their current best-effort wording.
- Update `docs/test_docs/security.md`'s atomicity section.
- Add a "atomicity basis" tag to the handler list in `CLAUDE.md`:
  - `kernel-atomic` for the five Phase 2 handlers
  - `kernel-runtime + file-persistence` for sysctl/mount/selinux-boolean (Phase 6)
  - `daemon-atomic` for service_* (Phase 4 — D-Bus)
  - `cli-best-effort` for package_*, GRUB, cron, PAM, etc.
- Operator-facing release note in CHANGELOG.

**Risk**: Documentation-only.

---

## Sequencing

```
P-001 (fsatomic package, no handlers)
  │
  ├──► P-002 (file_content)        ┐
  ├──► P-003 (file_absent)         │
  ├──► P-004 (config_set)          ├── parallel after P-001
  └──► P-005 (config_set_dropin)   ┘
                  │
                  ▼
              P-006 (close + docs)
```

P-002..P-005 can ship in parallel — they touch disjoint handlers. The bulk of risk concentrates in P-002 (file_content's regression surface) and P-004 (config_set's behavioral-parity requirement).

**Total**: ~2 weeks single-engineer sequential, ~10 days with parallelization. Matches the `LOW_LEVEL_MIGRATION_V1.md` §3 estimate.

---

## Open questions for founder

1. **Build-tag fallback during migration window?** When P-002 ships, do we want a `--no-fsatomic` build tag (or runtime flag) that reverts to the shell pipeline? Pros: instant rollback if a regression is discovered post-deploy. Cons: doubled test surface; the shell path lingers until Phase-2 close. **Recommendation**: NO build tag. P-002's tests + live-host validation are sufficient; rollback via `git revert` is the escape hatch. Adding a flag locks us into maintaining the shell path for the entire Phase 2 window.

2. **AtomicReplace semantics for symlinks?** `Renameat2(RENAME_EXCHANGE)` on a symlinked target swaps the symlink, not the underlying file. Existing handlers don't explicitly handle symlinks; sed in-place follows them. Decision: AtomicReplace **follows symlinks** (resolves target with `Realpath` before operating) to preserve existing handler semantics. Documented in fsatomic package doc.

3. **Filesystem-capability detection**: probe RENAME_EXCHANGE support at agent startup, or per-call? **Recommendation**: at startup, cached on the LocalTransport. Fallback to plain Renameat is silent (logged once). Operators on legacy filesystems get a stderr warning at the first AtomicReplace call.

4. **What about non-agent-mode (direct-SSH)?** Phase 2's fsatomic primitives are LOCAL — they need the agent process running on the target. Direct-SSH operators don't get atomicity. **Recommendation**: That's correct — Phase 1's whole point was making fsatomic reachable. Direct-SSH remains the v1.0 path with shell-best-effort atomicity. Document this in the release notes for v1.1: "Atomic file operations require KENSA_USE_AGENT=1; direct-SSH retains best-effort semantics."

5. **Coexistence with Phase 6 (sysctl/mount/kernel-module)?** Phase 6's `/proc/sys/<key>` writes also benefit from fsatomic for the persistence-file path (e.g., `/etc/sysctl.d/99-kensa.conf`). Recommendation: Phase 2 ships fsatomic; Phase 6 reuses it. No separate "Phase 6 atomicity primitives" deliverable needed.

---

## Decision

If you ratify the breakdown above, I add P-001..P-006 to `DELIVERABLES.md` and `STATUS.md` updates the Phase 2 row to "ready for loop pickup." The loop discipline picks them up in dep order. P-001 ships first; P-002..P-005 in parallel after.

If any deliverable should be split further (e.g., config_set's sed-to-Go behavioral parity work is large enough to warrant its own iteration), say so and I'll re-partition.
