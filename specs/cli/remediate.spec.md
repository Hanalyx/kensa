# Spec: remediate CLI Command

## Context
- **Module:** `runner/cli.py` → `remediate()`
- **Click decorators:** `@main.command()`, `@target_options`, `@rule_options`, `@output_options`, plus `--dry-run`, `--rollback-on-failure`, `--allow-conflicts`, `--no-snapshot`
- **Option groups:** target_options, rule_options, output_options (same as check)
- **Dependencies:** Same as check plus `runner.conflicts`, `runner.storage` (unconditional)

## Objective
Check rules and remediate failures on target hosts. Always persists results to SQLite (unlike check). Supports dry-run preview, inline rollback-on-failure, conflict detection, and pre-state snapshot capture.

### Input Contract

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| (target_options) | | | | See detect spec |
| (rule_options) | | | | See check spec |
| (output_options) | | | | See check spec |
| `--dry-run` | `bool` | No | `False` | Preview without making changes |
| `--rollback-on-failure` | `bool` | No | `False` | Auto-rollback on failure |
| `--allow-conflicts` | `bool` | No | `False` | Proceed despite detected conflicts |
| `--no-snapshot` | `bool` | No | `False` | Disable pre-state snapshot capture |

### Behavior

1. Resolve targets and load rules (same as check).
2. Prune expired pre-state snapshots from SQLite (failure must not block remediation).
3. Run preliminary conflict detection with empty capabilities.
4. If conflicts found and `--allow-conflicts` not set: print conflicts and exit 1.
5. If conflicts found and `--allow-conflicts` set: print warning and continue.
6. For each host (sequential or parallel):
   a. Same SSH setup as check (connect, detect, override, auto-framework).
   b. Per-host variable resolution.
   c. Run `run_remediation()` with dry_run, rollback_on_failure, snapshot flags.
   d. Collect results: pass, fail, fixed, skip, rolled_back counts.
7. Print per-host summary (rules | pass | fixed | fail | skip | rolled back).
8. Print multi-host summary if >1 host.
9. Sort results by framework section if active.
10. Write output files.
11. **Always** persist results via `_store_remediation_results()` (unconditional).

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Normal completion — even with remediation failures or connection errors |
| 1 | Target resolution error, rule loading error, unresolved conflicts (without --allow-conflicts), output format error |

### Output Contract

**Terminal (default):**
- "DRY RUN — no changes will be made" banner when `--dry-run`.
- Conflict warning when `--allow-conflicts` and conflicts detected.
- Per-host: rules | pass | fixed | fail | skip | rolled back.
- Multi-host: Grand summary with totals.
- "Stored remediation results in session N" confirmation.

**`--quiet`:** Suppresses terminal output except storage confirmation.

**`-o` formats:** Same as check.

### Side Effects

- **SQLite (always):** Creates session, remediation_session, remediations, steps, pre_states records.
- **Snapshot pruning:** Deletes expired pre-state data older than `snapshot_archive_days` (default 90).
- **File writes:** Via `-o fmt:path`.

### Acceptance Criteria

- **AC-1:** Remediate with one passing rule exits 0, shows "1 pass", no remediation occurs.
- **AC-2:** Remediate with one failing rule shows "fixed" or "fail" count.
- **AC-3:** `--dry-run` prints "DRY RUN" banner and does not execute remediation steps.
- **AC-4:** No target hosts exits 1.
- **AC-5:** No rules exits 1.
- **AC-6:** Unresolved conflicts (without `--allow-conflicts`) exits 1.
- **AC-7:** `--allow-conflicts` prints warning and proceeds despite conflicts.
- **AC-8:** Results are **always** stored to SQLite (no `--store` flag needed).
- **AC-9:** `--no-snapshot` sets snapshot_mode to "none" in stored session.
- **AC-10:** `--rollback-on-failure` enables inline rollback; rolled-back count appears in summary.
- **AC-11:** `--quiet` suppresses terminal output.
- **AC-12:** Connection failure prints error and continues; exit 0.
- **AC-13:** Multi-host run prints summary with totals.
- **AC-14:** `--framework` sorts results by section order.
- **AC-15:** Parallel execution (`--workers 2`) produces results for all hosts.
- **AC-16:** `-o json` writes JSON to stdout.
- **AC-17:** Snapshot pruning runs before processing hosts.
- **AC-18:** Snapshot pruning failure does not block remediation.
- **AC-19:** `--var KEY=VALUE` overrides rule variables.
- **AC-20:** `--control` filters to rules for a specific framework control.

## Constraints

- MUST always persist remediation results to SQLite (unlike check which requires `--store`).
- MUST exit 1 on unresolved conflicts unless `--allow-conflicts` is set.
- MUST NOT let snapshot pruning failures block remediation.
- MUST show "DRY RUN" banner when `--dry-run` is active.
- MUST capture pre-state snapshots by default (opt out with `--no-snapshot`).
