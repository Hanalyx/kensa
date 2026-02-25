# Spec: rollback CLI Command

## Context
- **Module:** `runner/cli.py` → `rollback()`
- **Click decorators:** `@main.command()`, individual options (no shared option groups)
- **Three sub-modes:** `--list`, `--info ID`, `--start ID` (mutually exclusive)
- **Dependencies:** `runner.storage.ResultStore`, `runner.inventory` (for --start), `runner._host_runner` (for --start SSH), `runner._orchestration.rollback_from_stored`

## Objective
Inspect past remediation sessions and optionally execute rollback from stored pre-state snapshots. Three mutually exclusive modes: list sessions, show session details, or execute rollback.

### Input Contract

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--list` | `bool` | No* | `False` | List recent remediation sessions |
| `--info` | `int` | No* | `None` | Show details for a remediation session |
| `--start` | `int` | No* | `None` | Execute rollback from stored snapshots |
| `--detail` | `bool` | No | `False` | Show per-step pre-state data (with --info) |
| `--rule` | `str` | No | `None` | Filter to a specific rule |
| `--host / -h` | `str` | No | `None` | Target host (--start) or filter (--list/--info) |
| `--inventory / -i` | `str` | No | `None` | Inventory file for SSH credentials |
| `--limit / -l` | `str` | No | `None` | Host glob pattern |
| `--max / -n` | `int` | No | `20` | Max sessions to list |
| `--json` | `bool` | No | `False` | Output as JSON |
| `--user / -u` | `str` | No | `None` | SSH username |
| `--key / -k` | `str` | No | `None` | SSH private key path |
| `--password / -p` | `str` | No | `None` | SSH password |
| `--port / -P` | `int` | No | `22` | SSH port |
| `--sudo` | `bool` | No | `False` | Run commands via sudo |
| `--strict-host-keys / --no-strict-host-keys` | `bool` | No | `False` | Verify SSH host keys |
| `--dry-run` | `bool` | No | `False` | Show what would be rolled back (--start) |
| `--force` | `bool` | No | `False` | Override stale/already-rolled-back warnings |

\* Exactly one of `--list`, `--info`, `--start` is required.

### Behavior

1. Validate exactly one mode flag is set; exit 1 if zero or >1.
2. **--list mode:** Query `ResultStore.list_remediation_sessions()`, display table or JSON.
3. **--info mode:** Query session by ID, display detailed remediation info or JSON.
4. **--start mode:**
   a. Require `--host` or `--limit`; exit 1 if missing.
   b. Validate session exists and has remediations for the target host.
   c. Check for stale snapshots (>7 days); exit 1 unless `--force`.
   d. Check for already-rolled-back steps; skip unless `--force`.
   e. Connect via SSH and execute rollback from stored pre-state data.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Successful list/info/start |
| 1 | No mode specified, multiple modes, session not found, host not found in session, host mismatch, stale snapshot (without --force), SSH failure |

### Output Contract

**--list (terminal):** Rich table with columns: ID, Timestamp, Host(s), Rules, Fixed, Fail, Rolled Back.
**--list --json:** JSON array of session objects.
**--info (terminal):** Session metadata, counts, remediated rules summary, non-rollbackable steps, optional step details.
**--info --json:** JSON object with session data, summary, remediations array.
**--start (terminal):** Per-step rollback progress, success/fail summary.

### Side Effects

- **SQLite reads:** All modes read from `.kensa/results.db`.
- **SQLite writes:** `--start` records rollback events.
- **Remote changes:** `--start` executes rollback commands over SSH.

### Acceptance Criteria

- **AC-1:** No mode flag exits 1 with "Specify --list, --info ID, or --start ID".
- **AC-2:** Multiple mode flags exits 1 with "Only one of" error.
- **AC-3:** `--list` with no sessions prints "No remediation sessions found".
- **AC-4:** `--list` with sessions exits 0 and displays table.
- **AC-5:** `--list --json` outputs valid JSON array.
- **AC-6:** `--info` with valid session exits 0 and displays session metadata.
- **AC-7:** `--info` with nonexistent session exits 1 with "not found".
- **AC-8:** `--info --json` outputs valid JSON object.
- **AC-9:** `--info --detail` includes per-step pre-state data.
- **AC-10:** `--start` without `--host`/`--limit` exits 1.
- **AC-11:** `--start` with host not in session exits 1 with stored hosts listed.
- **AC-12:** `--start` with stale snapshot (>7 days) without `--force` exits 1.
- **AC-13:** `--start --force` overrides stale snapshot warning.
- **AC-14:** `--start --dry-run` shows what would be rolled back without executing.
- **AC-15:** `--list --host` filters sessions by host.
- **AC-16:** `--info --rule` filters to a specific rule.
- **AC-17:** Already-rolled-back steps are skipped unless `--force`.
- **AC-18:** `--start` with nonexistent session exits 1.

## Constraints

- MUST require exactly one of `--list`, `--info`, `--start`.
- MUST require `--host` or `--limit` for `--start` mode.
- MUST check stale snapshot age (>7 days) and require `--force` to proceed.
- MUST report non-rollbackable (non-capturable) steps in `--info` output.
