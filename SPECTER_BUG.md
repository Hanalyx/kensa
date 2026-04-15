# Specter Bug Reports

Bugs discovered while integrating Specter into kensa-go.

---

## BUG-001: Multi-AC annotation on a single `@ac` line only registers the first AC

**Severity:** High
**Discovered:** 2026-04-15
**Affects:** `specter coverage`, `specter doctor`, `specter sync`

### Description

When a test function carries a single `@ac` annotation with multiple AC IDs separated
by spaces (e.g. `@ac AC-02 AC-03 AC-04`), Specter only registers coverage for the
**first** AC in the list. Subsequent ACs on the same line are silently ignored.

### Reproduction

```go
// @spec deadman-timer
// @ac AC-02 AC-03 AC-04
func TestArm_UploadAndSchedule(t *testing.T) { ... }
```

Running `specter coverage` reports AC-03 and AC-04 as uncovered even though the
annotation intends to cover them.

### Observed behaviour

```
deadman-timer: 40% coverage (T1 requires 100%)
  uncovered: AC-04, AC-06, AC-07, AC-08, AC-09, AC-10
```

AC-03 was covered (from `@ac AC-03` on another line), but AC-04 was not, despite
appearing in the `@ac AC-02 AC-03 AC-04` annotation.

### Expected behaviour

All AC IDs listed on a single `@ac` line should be registered. Both of the following
forms should produce identical coverage:

```go
// Single-line form (desired)
// @ac AC-02 AC-03 AC-04

// Multi-line form (workaround currently required)
// @ac AC-02
// @ac AC-03
// @ac AC-04
```

### Workaround

Use one `@ac` line per AC ID. All kensa-go tests have been updated to use this form.

### Impact

Any project using the space-separated form will have silently under-reported coverage.
The gap only becomes visible when the first AC passes threshold but a later AC in the
same line is the spec's last uncovered AC.

---

## BUG-002: `specter.yaml` `exclude` list does not filter subdirectory paths

**Severity:** Medium
**Discovered:** 2026-04-15
**Affects:** `specter resolve`, `specter sync`

### Description

Adding a directory name (e.g. `.claude`) to the `settings.exclude` list in
`specter.yaml` does not prevent Specter from scanning `.spec.yaml` files inside
subdirectories of that name. Specter discovers all `.spec.yaml` files project-wide
regardless of the exclude configuration, leading to `duplicate_id` errors when a git
worktree under `.claude/worktrees/` contains copies of the spec files.

### Reproduction

```yaml
# specter.yaml
settings:
  exclude:
    - .claude   # expected to skip .claude/worktrees/agent-*/specs/
```

`specter resolve` still reports:

```
error [duplicate_id] Duplicate spec ID "deadman-timer" found in
  .claude/worktrees/agent-ab7a8b9a/specs/deadman/timer.spec.yaml and
  specs/deadman/timer.spec.yaml
```

### Workaround

Remove the stale worktree with `git worktree remove --force <path>` before running
`specter sync`. Long-term, the exclude list should support glob patterns
(see SPECTER_FEATURE_REQUEST.md FR-002).
