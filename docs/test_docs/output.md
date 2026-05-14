# Output Formats

## Purpose

`kensa check` and `kensa remediate` emit results in multiple formats. The canonical surface is `--output FORMAT[:PATH]` (C-019), repeatable. Operators can fan out a single scan to text/stdout + json/file + evidence/file in one run.

## Current state

DONE for: `table`, `json`, `jsonl`, `csv`, `pdf`, `evidence`, `oscal`, `markdown`. See [`cli/check.md`](cli/check.md) and [`cli/remediate.md`](cli/remediate.md) for the per-subcommand wiring.

## Formats

| Format | Producer | File / stdout | Schema |
|---|---|---|---|
| `table` | `internal/output/text` | stdout-only by default | Operator-facing text (C-022 rewrite for failure-first layout, severity badges, fix-line synthesis, glob-compacted PASSED) |
| `json` | `internal/output/json` | both | `api.ScanResult` / `api.RemediationResult` |
| `jsonl` | `internal/output/jsonl` | both | One JSON object per line, suitable for streaming consumers |
| `csv` | `internal/output/csv` | both | Per-rule columns: ID, severity, status, host, fix-line |
| `pdf` | `internal/output/pdf` (maroto v2) | file-only | Operator-facing report; PDF-specific layout |
| `evidence` | `internal/output/evidence` | both | Hanalyx evidence-envelope schema; Ed25519-signed (M-012 + C-060, 2026-05-10) |
| `oscal` | `internal/output/oscal` | both | OSCAL Assessment Results JSON v1.0.0 |
| `markdown` | `internal/output/markdown` | both | Operator-facing report (similar shape to PDF) |

## Verification protocol

```bash
# 1. Per-format unit tests (no network).
go test ./internal/output/...

# 2. Live multi-format fan-out.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical \
    -o json -o csv:/tmp/results.csv -o evidence:/tmp/evidence.json \
    -o pdf:/tmp/results.pdf -o oscal:/tmp/oscal.json

# 3. Verify the fan-out wrote each file.
ls -la /tmp/results.csv /tmp/evidence.json /tmp/results.pdf /tmp/oscal.json

# 4. Inspect a few format-specific shapes.
jq '.host_id, (.transactions | length)' /tmp/evidence.json
jq '."assessment-results".results[0].observations | length' /tmp/oscal.json
file /tmp/results.pdf      # should report "PDF document"

# 5. Inventory + stdout sinks (file sinks rejected per C-019 data-loss guard).
./bin/kensa check --inventory inventory.ini --no-strict-host-keys -w 4 \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -o json   # ok — stdout sink
./bin/kensa check --inventory inventory.ini --no-strict-host-keys -w 4 \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -o csv:/tmp/results.csv   # exit 2 — file sink rejected with --inventory
```

## Inventory mode rules

Per C-019, file-output sinks are rejected when `--inventory` is set:

> "--inventory + --output FORMAT:PATH: file outputs not yet supported in inventory mode (would overwrite the file per-host with silent data loss). Use one path per host (run kensa check per-host), omit Path to write to stdout, or wait for streaming-writer integration."

Stdout sinks (no `:PATH`) are allowed; each host's result is concatenated.

## Deprecation chain

Pre-C-019 single-output flags (`--format` and `--oscal`) emit a stderr warning the first time they're used unless `KENSA_NO_DEPRECATION_WARNINGS=1`:

```
kensa: warning: --format is deprecated; use --output FORMAT[:PATH]
```

Operators upgrading existing scripts see one warning per run; CI consumers can suppress.

## Remediate text-output summary semantics (B6 fix, 2026-05-13)

The text writer's `kensa remediate` summary now distinguishes:

- **`applied`** — the engine ran a transaction: capture → apply → commit (or rollback on validate failure). A persisted record is written to the transaction log. `kensa history` will show this transaction.
- **`already-compliant`** — the scanner's pre-check found the host already in desired state; no apply ran, no transaction was created. These do NOT appear in `kensa history` (no engine work, no persisted record).
- **`rolled_back`** / **`errors`** / **`skipped`** — unchanged semantics.

Pre-fix, both `applied` and `already-compliant` rolled into a single `committed` count, which created a 433-vs-36 discrepancy between the remediate summary and the history table observed during the 2026-05-13 live test. The split makes the actual work kensa did legible without consulting history.

Per-row STATUS column also shows `applied` or `already-compliant` instead of the generic `committed`.

The JSON/CSV/OSCAL/Evidence output formats are unchanged — the underlying TransactionResult shape is preserved (Status=Committed for both cases; the in-memory synthetic record's `Steps[0].Mechanism == "check"` is the discriminator). Programmatic consumers can replicate the split by checking that marker.

## Known limits

- **Evidence envelopes carry real Ed25519 signatures (M-012 + C-060, 2026-05-10).** `kensa verify <evidence-file>` validates against a trust dir of kensa-keygen-produced `.pub` files; persistent operator keys via `KENSA_SIGNING_KEY=/path/to/key.priv`.
- **No streaming output for inventory.** Per-host results are collected then rendered. A 100-host fleet pays the latency penalty; the `-o csv:PATH` data-loss guard exists because of this.
- **PDF format embeds maroto v2.** The PDF builder is a heavy dependency. Operators not needing PDF can build with `-tags=nopdf` (future build-tag, not yet wired) to drop the dependency. Today the binary always includes maroto.
- **No `markdown:PATH` smoke check.** The markdown writer is exercised by unit tests but not the cli-smoke matrix; format-specific smoke gates are queued.
- **`kensa diff` shipped in CLI Phase 4 (`c0b58a3`, 2026-05-09).** Compares two stored sessions by ID; rule-by-rule drift report.
- **OSCAL output is Assessment Results only, not Plan or Profile.** Operators wanting OSCAL-Profile-aligned input must use Python kensa.
