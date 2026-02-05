# P2-1: Result Persistence

## Status: Scoping

## Problem
V0 results are ephemeral — printed to the terminal and lost. Compliance requires historical records: what was the state at a given time, what changed, who remediated.

## Scope
- Store results in a local SQLite database (no server dependencies)
- Each run creates a session with timestamp, host list, rule set
- Each result row: session_id, host, rule_id, passed, detail, remediated, timestamp
- Query interface: `aegis history --host <ip>` shows past runs
- `aegis diff --session <id1> <id2>` shows changes between runs

## Open Questions
- SQLite per-project or global `~/.aegis/results.db`?
- Retention policy? Auto-prune after N days?
- Should results include the rule YAML hash to detect rule changes?
