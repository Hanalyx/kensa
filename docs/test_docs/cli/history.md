# `kensa history`

## Purpose

Query the local SQLite transaction log. Each remediate / rollback action writes a record; history reads them back, optionally filtered by host, time range, status, severity, or rule.

Used to:
- Audit "what did kensa do on this host last week"
- Drive rollback discovery (until Phase 4's session model lands)
- Generate compliance evidence chains

## Current state

DONE for the basic query forms. Output is text/json. The store's schema is defined by `internal/store/`; the public query surface is `api.LogQuery` (see `api/log_query.go`).

## Flags

| Flag | Status | Note |
|---|---|---|
| `-H, --host` | DONE | Filter by hostname |
| `-S, --since` | DONE | Filter by min timestamp; accepts duration ("24h", "7d") or ISO timestamp |
| `--until` | DONE | Filter by max timestamp |
| `-n, --max` | DONE | Limit result count |
| `--status` | DONE | Filter by transaction status |
| `--severity` | PARTIAL | Server-side filter not wired through; client-side post-filter |
| `--rule` | DONE | Filter by rule ID (NOTE: this is the C-037 collision case — `--rule` here means "filter by rule ID", in check/remediate it means "load this file") |
| `-o, --output` | DONE | text, json |
| `-q, --quiet` | DONE | |

## Verification protocol

```bash
# 1. Help text.
./bin/kensa history --help

# 2. Negative-path validation.
./bin/kensa history --since not-a-duration                # exit 2

# 3. Live query (requires existing SQLite store with records).
./bin/kensa history --host 192.168.1.211 --since 24h --max 20

# 4. JSON for programmatic consumption.
./bin/kensa history --host 192.168.1.211 --since 7d -o json | \
    jq '.[] | {id, status, rule_id, finished_at}'
```

## Known limits

- **`--rule` semantic collides with check/remediate's `--rule`.** In history it filters by rule ID; in check/remediate it loads a file. This collision is acknowledged in `cmd/kensa/flags.go` post-C-037: the long-form `--rule` is now bound to file-loading on rule-loading subcommands, but history's existing semantic predates that and stays. Operators must read context. A future Phase 4 cleanup may rename history's `--rule` to `--rule-id` for consistency.
- **Severity filter is client-side.** The store doesn't yet index by severity; querying for "critical only" loads all records then filters in memory. Acceptable at current scale; flag for indexing work if logs grow.
- **No multi-host aggregation.** History is single-host or all-hosts. No grouping by host with per-host summaries; downstream ops would do that with jq.
- **No retention / pruning.** A long-running operator's store grows without bound. The migration doc Phase 4 reserves `--prune` for this.
- **Records are signed at write time (M-012 + C-060, 2026-05-10).** Each persisted envelope carries a real Ed25519 signature; auditors extract the JSON via store query and run `kensa verify` against a trust dir. See [`../security.md`](../security.md).
