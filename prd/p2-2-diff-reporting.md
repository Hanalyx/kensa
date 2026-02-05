# P2-2: Diff Reporting

## Status: Scoping

## Problem
Compliance teams need to track drift: what changed between two scans? Which hosts regressed? Which improved?

## Scope
- Compare two result sets (by session ID or by timestamp range)
- Show: new failures, resolved failures, new passes, unchanged
- Per-host and aggregate views
- Output as terminal table, JSON, or HTML report

## Dependencies
- Requires P2-1 (result persistence) — can't diff without stored results
