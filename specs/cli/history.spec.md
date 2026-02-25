# Spec: history CLI Command

## Context
- **Module:** `runner/cli.py` → `history()`
- **Click decorators:** `@main.command()`, individual options
- **Five modes:** `--stats`, `--prune DAYS`, `--session-id ID`, `--sessions`, default (result history)
- **Dependencies:** `runner.storage.ResultStore`

## Objective
Query compliance scan history from the local SQLite database. Supports listing sessions, viewing session details, showing database statistics, pruning old data, and querying per-host result history.

### Input Contract

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--host / -h` | `str` | No* | `None` | Filter by host |
| `--rule / -r` | `str` | No | `None` | Filter by rule ID |
| `--sessions / -s` | `bool` | No | `False` | List sessions |
| `--session-id / -S` | `int` | No | `None` | Show specific session results |
| `--limit / -n` | `int` | No | `20` | Max entries to show |
| `--stats` | `bool` | No | `False` | Show database statistics |
| `--prune` | `int` | No | `None` | Remove results older than N days |

\* `--host` is required for default mode (result history).

### Behavior

1. **--stats:** Display database statistics table (session count, result count, oldest/newest, path). Return immediately.
2. **--prune DAYS:** Delete sessions older than N days, print count. Return immediately.
3. **--session-id ID:** Look up session, display header + results table. Exit 1 if not found.
4. **--sessions:** List sessions with optional `--host` filter.
5. **Default (no mode flag):** Require `--host`. Query per-host result history. Show "No history" if empty.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Successful query (including empty results) |
| 1 | `--session-id` not found, default mode without `--host` |

### Output Contract

**--stats:** Rich table with Metric/Value columns.
**--prune:** "Deleted N sessions older than N days".
**--session-id:** Session header + results table (Host, Rule, Status, Remediated, Detail).
**--sessions:** Sessions table (ID, Timestamp, Hosts, Rules Path).
**Default:** History table (Session, Timestamp, Rule, Status, Remediated).

### Side Effects

- **SQLite reads:** All modes except `--prune`.
- **SQLite deletes:** `--prune` removes old sessions and associated data.

### Acceptance Criteria

- **AC-1:** `--stats` exits 0 and displays database statistics table.
- **AC-2:** `--prune 30` exits 0 and prints deletion count.
- **AC-3:** `--session-id` with valid session exits 0 and shows session header + results.
- **AC-4:** `--session-id` with nonexistent session exits 1 with "not found".
- **AC-5:** `--sessions` exits 0 and lists sessions.
- **AC-6:** `--sessions --host` filters sessions by host.
- **AC-7:** `--sessions` with no sessions prints "No sessions found".
- **AC-8:** Default mode without `--host` exits 1 with error message.
- **AC-9:** Default mode with `--host` exits 0 and shows history table.
- **AC-10:** Default mode with `--host` and no history prints "No history for host".
- **AC-11:** `--session-id` with no results for session prints "No results".
- **AC-12:** Default mode with `--host` and `--rule` filters by both.

## Constraints

- MUST require `--host` for default result history mode.
- MUST handle empty result sets gracefully (informational message, exit 0).
- MUST exit 1 only for session-not-found or missing required flags.
