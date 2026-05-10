# `kensa rollback`

## Purpose

Roll back a past transaction by UUID. Reads the transaction record from the SQLite store, replays its captured pre-state via the engine's rollback path, and writes a result record to the store.

This is the operator-facing recovery flow. It exercises the same capture-replay machinery the engine uses internally on validation failure during remediate.

## Current state

PARTIAL.
- DONE: `kensa rollback --txn UUID --host HOST` form.
- NOT DONE: session-list workflow (Python kensa has `--list`, `--info`, `--start`). Phase 4.

## Flags

### Target options

| Flag | Status | Note |
|---|---|---|
| `-H, --host` | DONE | Required |
| `-u, --user` | DONE | |
| `-k, --key` | DONE | |
| `-P, --port` | DONE | |
| `--sudo` | DONE | |
| `--strict-host-keys` / `--no-strict-host-keys` | DONE (C-027) | |

### Subcommand-specific

| Flag | Status | Note |
|---|---|---|
| `--txn` (or `-T`) | DONE | UUID of the transaction to roll back. Required |

### Output options

| Flag | Status |
|---|---|
| `-q, --quiet` | DONE |

NOT YET WIRED (Phase 4): `--list`, `--info`, `--start`, `--rule`, `--password`, `--inventory`, `--limit`, `--max`, `--output`, `--dry-run`, `--force`. The Python rollback CLI has these; kensa-go's surface is intentionally a strict subset until session model lands.

## Verification protocol

```bash
# 1. Help text.
./bin/kensa rollback --help

# 2. Negative-path validation.
./bin/kensa rollback                                          # exit 2 (--host required)
./bin/kensa rollback -H foo                                   # exit 2 (--txn required)
./bin/kensa rollback -H foo --txn not-a-uuid                  # exit 2 (UUID parse error)
./bin/kensa rollback -H foo --txn 00000000-0000-0000-0000-000000000000 \
    --strict-host-keys --no-strict-host-keys                  # exit 2 (mutex)

# 3. Round-trip atomicity test (kensa-fuzz).
# kensa-fuzz produces a remediation, then deliberately fails validation, then
# verifies rollback restores pre-state. Drives the same code path operators
# would invoke via `kensa rollback`.
KENSA_TEST_SSH_HOST=<throwaway> KENSA_TEST_SSH_USER=root \
    go test ./cmd/kensa-fuzz/... -v -timeout 10m

# 4. Manual round-trip:
#    a. Run a remediate that succeeds. Note the transaction UUID from the result.
#    b. Run `kensa history --host HOST --max 1` to confirm.
#    c. Run `kensa rollback --host HOST --txn UUID`.
#    d. Re-run the original `kensa check` against the same rule set; expected
#       changes have been undone.
```

## Known limits

- **No session-list workflow yet.** An operator running rollback without knowing the UUID has no in-CLI way to discover recent transactions. Workaround: `kensa history` (basic transaction log query). Phase 4 lands the `--list` / `--info` / `--start` surface.
- **No `--password` flag on rollback.** Operators using password auth must set `SSHPASS` env. (C-026 wired `--password` on detect/check/remediate/plan but explicitly not on rollback because rollback's invocation pattern usually pre-dates a successful auth.)
- **Rollback uses persisted PreState, not capability gating.** A rule whose handler implementation has changed since the original transaction may roll back via the *new* code path against the *old* PreState. The engine's PreState shape includes the mechanism name, so handler-internal changes are usually compatible; cross-handler changes are not. Documented in `engine-transaction.spec.yaml`.
- **Non-capturable handlers cannot roll back.** Rules with `transactional: false` (the 10 stub handlers — see [`../engine.md`](../engine.md)) are marked `StatusSkipped` for rollback. Operators see "rule was non-transactional; no captured state" and must manually undo.
- **Rollback output is signed (M-012 + C-060, 2026-05-10).** The rollback finalize path emits a real Ed25519 signature on the resulting envelope; auditors validate via `kensa verify <evidence-file>` against a trust dir of `.pub` files.
