# P2-2: Diff Reporting

## Status: Complete

## Problem
Compliance teams need to track drift: what changed between two scans? Which hosts regressed? Which improved?

## Solution Implemented
- `kensa diff SESSION1 SESSION2` command compares two stored sessions
- Shows regressions (was passing, now failing), resolved (was failing, now passing), new failures/passes
- Per-host filtering with `--host` option
- Output formats: terminal table (default) or JSON (`--json`)
- `--show-unchanged` flag to include unchanged rules in output

## Features
- `kensa diff 1 2` - Compare session 1 (older) to session 2 (newer)
- `kensa diff 1 2 --host 192.168.1.100` - Filter diff to specific host
- `kensa diff 1 2 --json` - JSON output for automation
- `kensa diff 1 2 --show-unchanged` - Include unchanged rules

## Implementation
- `DiffEntry` dataclass: captures status (regression, resolved, new_failure, new_pass, unchanged)
- `DiffReport` dataclass: holds entries with properties for filtering by status
- `diff_sessions()` function: compares two sessions, returns DiffReport
- CLI `diff` command: renders report with color-coded output

## Dependencies
- Requires P2-1 (result persistence) — can't diff without stored results
