# Specter Feature Requests

Feature requests for the Specter tool itself. Kensa-go implementation gaps
that surfaced during Specter integration are tracked in BACKLOG.md.

---

## FR-002: `specter.yaml` exclude list should support glob patterns

**Status:** Added to Specter Phase 3 roadmap
**Discovered:** 2026-04-15

The current `settings.exclude` list does not filter subdirectory paths, causing
`duplicate_id` errors when git worktrees or similar tooling directories contain
copies of spec files. Support glob patterns such as `- .claude/**` so that entire
subtree hierarchies can be excluded without needing to remove the physical directory.

**Workaround until fixed:** Remove stale worktrees with `git worktree remove --force`
before running `specter sync`.
