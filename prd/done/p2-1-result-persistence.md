# P2-1: Result Persistence

## Status: Complete

## Problem
V0 results are ephemeral — printed to the terminal and lost. Compliance requires historical records: what was the state at a given time, what changed, who remediated.

## Solution Implemented
- SQLite database at `.aegis/results.db` (per-project)
- `runner/storage.py` module with `ResultStore` class
- Schema: sessions table + results table with foreign key
- 90-day default retention with `--prune` option

## Features
- `aegis check --store` - Save results to database
- `aegis history --host <ip>` - Show result history for a host
- `aegis history --sessions` - List all scan sessions
- `aegis history --session-id N` - Show results for specific session
- `aegis history --stats` - Show database statistics
- `aegis history --prune N` - Remove results older than N days

## Design Decisions
- Per-project database (`.aegis/results.db`) for isolation
- 90-day default retention, configurable via `--prune`
- Rule hash stored for change detection (optional)
- Sessions linked to results via foreign key with CASCADE delete
