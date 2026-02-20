# P2-1: Result Persistence

## Status: Complete

## Problem
V0 results are ephemeral — printed to the terminal and lost. Compliance requires historical records: what was the state at a given time, what changed, who remediated.

## Solution Implemented
- SQLite database at `.kensa/results.db` (per-project)
- `runner/storage.py` module with `ResultStore` class
- Schema: sessions table + results table with foreign key
- 90-day default retention with `--prune` option

## Features
- `kensa check --store` - Save results to database
- `kensa history --host <ip>` - Show result history for a host
- `kensa history --sessions` - List all scan sessions
- `kensa history --session-id N` - Show results for specific session
- `kensa history --stats` - Show database statistics
- `kensa history --prune N` - Remove results older than N days

## Design Decisions
- Per-project database (`.kensa/results.db`) for isolation
- 90-day default retention, configurable via `--prune`
- Rule hash stored for change detection (optional)
- Sessions linked to results via foreign key with CASCADE delete
