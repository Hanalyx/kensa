# CLI Testing Documentation

Per-subcommand verification state for `kensa`, `kensa-fuzz`, and `kensa-validate`. Each subcommand's document follows the same shape:

1. **Purpose** — what the operator uses it for.
2. **Current state** — what works end-to-end as of 2026-05-09.
3. **Flags** — the full flag inventory grouped by category, with current state per flag.
4. **Verification protocol** — exact commands to run.
5. **Known limits** — deliberate exclusions a founder must sign off on.

## Subcommands

| Subcommand | Document | Status |
|---|---|---|
| `kensa detect` | [`detect.md`](detect.md) | DONE — full Phase 3 flag surface |
| `kensa check` | [`check.md`](check.md) | DONE — full Phase 3.6 flag surface incl. inventory mode (5-tier vars in single-host; 3-tier in inventory pending Phase 3.7) |
| `kensa remediate` | [`remediate.md`](remediate.md) | DONE — full Phase 3.6 flag surface (single-host only) |
| `kensa plan` | [`plan.md`](plan.md) | DONE — kensa-go addition; capability-gated selection deferred |
| `kensa rollback` | [`rollback.md`](rollback.md) | PARTIAL — `--txn UUID` form done; session-list workflow Phase 4 |
| `kensa history` | [`history.md`](history.md) | DONE — transaction log query |
| `kensa coverage` | [`coverage.md`](coverage.md) | DONE — handler mechanism listing (rename to `mechanisms` Phase 4) |
| `kensa version` | [`version.md`](version.md) | DONE |
| `kensa-fuzz` | [`kensa-fuzz.md`](kensa-fuzz.md) | DONE — failure injection harness, requires real host |
| `kensa-validate` | [`kensa-validate.md`](kensa-validate.md) | DONE — rule + spec validator |

## Cross-cutting concerns

- **Exit codes**: per GNU/POSIX, kensa returns 0 (success), 1 (runtime error), or 2 (usage error). Verified by `cli-smoke.sh` (`assert_exit` matrix).
- **Help text**: every SSH-using subcommand groups flags by category (Target / Rule / Output / General) per migration doc §5. C-038 added 45 smoke checks asserting this.
- **Short letters**: reserved in `cmd/kensa/flags.go`. Conflict-free as of 2026-05-09; the comment block documents the reservations and any future-deliverable-affecting tensions (e.g., `ShortRule = "R"` is reserved for filter-by-ID, not the C-037 file-loader form).
- **Deprecation warnings**: `--format`, `--oscal`, and the legacy single-dash long forms emit a warning to stderr the first time they're used unless `KENSA_NO_DEPRECATION_WARNINGS=1` is set (CI noise control).

## Smoke-harness counts

| Phase | Total smoke scenarios |
|---|---|
| End of M6 (pre-CLI) | ~30 |
| CLI Phase 1 close | 41 |
| CLI Phase 2 close | 54 |
| CLI Phase 2.5 close | 54 |
| CLI Phase 3.5 close | 99 |
| **CLI Phase 3.6 close (current)** | **99** (no smoke additions; new behavior covered by Go unit tests) |
