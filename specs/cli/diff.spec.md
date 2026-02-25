# Spec: diff CLI Command

## Context
- **Module:** `runner/cli.py` → `diff()`
- **Click decorators:** `@main.command()`, `@click.argument("session1")`, `@click.argument("session2")`
- **Dependencies:** `runner.storage.ResultStore`, `runner.storage.diff_sessions`

## Objective
Compare two scan sessions to show compliance drift. Categorizes each rule result as regression, resolved, new failure, new pass, or unchanged.

### Input Contract

| Argument/Flag | Type | Required | Default | Description |
|---------------|------|----------|---------|-------------|
| `SESSION1` | `int` | Yes | — | Older session ID (positional) |
| `SESSION2` | `int` | Yes | — | Newer session ID (positional) |
| `--host / -h` | `str` | No | `None` | Filter by host |
| `--show-unchanged` | `bool` | No | `False` | Include unchanged results |
| `--json` | `bool` | No | `False` | Output as JSON |

### Behavior

1. Open `ResultStore` and call `diff_sessions(store, session1, session2)`.
2. If `--json`: output JSON with session metadata, summary, and changes array.
3. If terminal:
   a. Print diff header with session IDs and timestamps.
   b. Print summary counts (regressions, resolved, new failures, new passes, unchanged).
   c. Filter by `--host` if specified.
   d. Filter out unchanged unless `--show-unchanged`.
   e. Display changes table grouped by status.
4. On `ValueError` from `diff_sessions`: print error, exit 1.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Normal completion (even with no changes) |
| 1 | Invalid session IDs (ValueError from diff_sessions) |

### Output Contract

**Terminal:** Diff header, summary section, changes table with columns: Status, Host, Rule, Old, New.
**Status categories:** REGRESSION (red), NEW FAIL (red), RESOLVED (green), NEW PASS (green), UNCHANGED (dim).
**--json:** JSON object with `session1`, `session2`, `summary`, and `changes` array.

### Side Effects

- **SQLite reads only.** No writes.

### Acceptance Criteria

- **AC-1:** Diff of two valid sessions exits 0 with summary and changes.
- **AC-2:** `--json` outputs valid JSON with session metadata and changes.
- **AC-3:** `--show-unchanged` includes unchanged results in output.
- **AC-4:** `--host` filters changes to specified host only.
- **AC-5:** No changes between sessions prints "No changes between sessions".
- **AC-6:** Invalid session ID exits 1 with error.
- **AC-7:** Regressions (pass → fail) appear as REGRESSION status.
- **AC-8:** Resolved (fail → pass) appear as RESOLVED status.
- **AC-9:** `--json` `--show-unchanged` includes unchanged entries in JSON.
- **AC-10:** Missing positional arguments shows Click usage error.

## Constraints

- MUST use positional arguments for session IDs (not flags).
- MUST group changes by status in terminal output.
- MUST filter unchanged results by default (opt-in with `--show-unchanged`).
- MUST exit 1 only for invalid session references.
