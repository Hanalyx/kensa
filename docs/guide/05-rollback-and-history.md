# 05 · Rollback and history

_Applies to: Kensa v0.7.4 — last updated 2026-07-10._

Every `kensa remediate` writes what it did to a durable transaction log
(SQLite). That log is what makes a remediation reversible, what crash
recovery replays, and what you query to audit a host over time. This
chapter covers the four commands built on it:

- [`rollback`](#rollback-undo-a-remediation): undo committed transactions
- [`recover`](#recover-crash-recovery): repair an interrupted run
- [`history`](#history-query-the-transaction-log): query the log
- [`diff`](#diff-drift-between-two-sessions): compare two scans

It also explains [how a transaction reaches its terminal
status](#how-a-transaction-reaches-its-terminal-status).

---

## How a transaction reaches its terminal status

A `remediate` runs each rule as one **transaction**, the four-phase Kensa
operation (capture, apply, validate, then commit or roll back). The
terminal status the transaction lands in is what the log records:

| Status | How it gets there |
|---|---|
| `committed` | Every apply step succeeded and every validator passed. The host is in the target state; the signed evidence envelope (the Ed25519-signed record of what the transaction did) is persisted. This is the status `rollback` reverses. |
| `rolled_back` | Apply or validate failed, and the engine reversed every applied capturable step using the captured pre-state, in the **same run**. The host is back in its exact pre-change state. |
| `partially_applied` | A `transactional: false` rule ran at least one non-capturable step before failing. Those steps are not reversed; per-step `Stranded` flags say which. |
| `errored` | A phase could not complete within the deadline, or a terminal step (signing or persistence) failed. `HostUnchanged` distinguishes an abort that never mutated the host. |
| `rollback_failed` | Apply/validate failed and the engine tried to reverse, but the restoration could not be machine-verified (a rollback step failed or reported a partial restore). The host is in an unconfirmed state. |
| `recovered` | An interrupted transaction (the process died after pre-state was persisted but before any terminal record) was reversed out-of-band by [`kensa recover`](#recover-crash-recovery). |

The key distinction: **`rolled_back`** is the engine undoing a failure
*within the same remediate run*; **`kensa rollback`** is you reversing a
*committed* transaction later; **`recovered`** is `kensa recover`
cleaning up a *crash*.

A capturable mechanism writes its pre-state to durable storage **before**
any host change, which is what lets rollback and recovery restore the
host. A `transactional: false` rule captures nothing, so it is outside
the reversal guarantee (see [10 · Mechanisms](10-mechanisms.md)).

---

## `rollback`: undo a remediation

`kensa rollback` reverses already-**committed** transactions using their
captured pre-state. Pick exactly one mode.

### Read-only modes (no host needed)

```bash
kensa rollback --list
kensa rollback --info <session-id> --detail
```

| Flag | Meaning |
|---|---|
| `--list` | List rollback-able sessions (those with committed transactions). |
| `--info SESSION_ID` | Show a session's detail (its transactions and their statuses). |
| `--detail` | Modifier: add a per-step breakdown. Composes with `--list` and `--info` (not with `--start`/`--txn`). |

Both `kensa remediate` and `kensa check --store` group their transactions into
a rollback-able session. To roll back a remediation you ran on the CLI, find
its session ID with `kensa list sessions` (the `session_id` column) and use
`rollback --start` (below); `rollback --list` shows the sessions that have
committed transactions to reverse. The per-transaction mode `--txn` remains as
a fallback for reversing a single transaction by UUID (from `kensa history`).

### Executing a rollback (host required)

```bash
# Reverse every committed transaction in a session:
kensa rollback --start <session-id> -H rhel9-host.example.com -u admin --sudo

# Legacy: reverse a single transaction by UUID:
kensa rollback --txn <txn-uuid> -H rhel9-host.example.com -u admin --sudo
```

| Flag | Meaning |
|---|---|
| `--start SESSION_ID` | Execute rollback for **every** committed transaction in the session. Needs `--host`. |
| `-T, --txn TXN_UUID` | Legacy: roll back a single transaction by UUID. Needs `--host`. |

`--start` reverses a whole **session** and is the primary path — including for
a `kensa remediate` you ran on the CLI, which records a session you can find
with `kensa list sessions`. The binary's help labels `--txn` as *legacy*: it
reverses a single transaction by UUID (from `kensa history`), a fallback for
undoing one transaction rather than the whole session. Both connect to the host,
so they take the
same target flags as `check`/`remediate`: `-H/--host` (required here),
`-u/--user`, `-k/--key`, `-P/--port`, `--sudo`, `--sudo-password`
(and `KENSA_SUDO_PASSWORD`), `--strict-host-keys`/`--no-strict-host-keys`.

Output: `--format text` (default) or `json`; `-q/--quiet` suppresses it.

> What rollback restores depends on the mechanism. File mechanisms
> restore byte-for-byte; reversible mechanisms restore the captured state
> and verify it (a runtime aspect may need a restart or reboot, reported
> as a partial restore); best-effort mechanisms restore through the
> host's own tool. See the reversal-level table in
> [10 · Mechanisms](10-mechanisms.md).

---

## `recover`: crash recovery

If a `kensa` process is interrupted mid-transaction (killed, host lost,
power failure) **after** pre-state was persisted but **before** a
terminal record was written, the transaction is left open. `kensa
recover` compensates those open transactions from the durable
crash-recovery journal: each is rolled back from its captured pre-state
and recorded as `recovered`.

```bash
kensa recover -H rhel9-host.example.com -u admin --sudo
```

| Flag | Meaning |
|---|---|
| `-H, --host` | Scope recovery to this host (also the SSH target). **Required.** |
| `-u, --user` | SSH user (default: current user). |
| `-P, --port` | SSH port (default 22). |
| `--key` | SSH private-key path. |
| `--sudo` | Wrap commands in sudo. |
| `--sudo-password` | Sudo password for non-NOPASSWD hosts. |
| `--strict-host-keys` | Verify SSH host keys; reject unknown. |
| `-q, --quiet` | Suppress default output. |
| `-D, --db` | SQLite transaction-log path (default `.kensa/results.db`). |

Run it **after a crash, when no live `kensa` is operating the host.**
`recover` reverses every captured mechanism (Atomic, Reversible, or
Best-effort); it cannot reverse a `transactional: false` step, because
none was captured.

### `recover.lock` fencing

`recover` takes an **exclusive** cross-process advisory lock (`flock`) at
`<db>.recover.lock` (`RecoverLockPath` is the store path plus
`.recover.lock`), so it can never race a second recovery run or a live
engine on the same store. A live engine takes the same lock **shared**;
the exclusive acquisition blocks while any engine holds it. If the lock
is already held, `recover` refuses to proceed rather than racing
(`ErrRecoverLocked`). The lock is released automatically if the process
dies (it is per-open-file-description).

The `-H/--host` scope is what keeps recovery surgical: only that host's
open transactions are compensated.

---

## `history`: query the transaction log

`kensa history` queries the log. With no filters it lists the most recent
transactions.

```bash
kensa history                                  # 50 most recent
kensa history -H rhel9-host.example.com -S 24h          # one host, last 24h
kensa history -T <txn-uuid>                    # one transaction by UUID
kensa history -a by_host -S 168h               # 7-day posture per host (168h)
kensa history --stats                          # summary counts, then exit
```

| Flag | Meaning |
|---|---|
| `-H, --host` | Filter by host ID. |
| `-R, --rule` | Filter by rule ID. |
| `-S, --since` | Since a duration or an RFC3339 time. The duration uses Go units (`s`, `m`, `h`); there is no day (`d`) unit, so write seven days as `168h`. |
| `-n, --limit` | Max rows (default 50). |
| `-T, --txn` | Fetch a single transaction by UUID. |
| `-a, --aggregate` | Aggregate key: `by_host`, `by_rule`, or `by_framework_control`. |
| `--stats` | Print summary stats (sessions, transactions, by status / severity / host) and exit. |
| `--format` | `table` (default), `json`, or `jsonl` (jsonl is transaction-list only). |
| `--prune N` | Delete sessions (and cascade) older than N days. **Destructive**; long-only. |
| `--force` | Skip the `--prune` confirmation prompt (required in non-interactive runs). |
| `-q, --quiet` | Suppress default output. |

```bash
# Stream the last 200 to a log aggregator as JSON Lines:
kensa history -n 200 --format jsonl | jq -c .

# Prune in CI/cron without a prompt:
kensa history --prune 30 --force
```

`--prune` cascades: deleting a session removes its transactions too. The
interactive form prompts for confirmation; add `--force` for cron and CI.

---

## `diff`: drift between two sessions

`kensa diff` compares two **stored** sessions and emits the per-rule
drift between them: status changes, rules added (in the second session
only), and rules removed (in the first only).

```bash
kensa list sessions                          # find the session IDs first
kensa diff <id1> <id2>                        # compact drift report
kensa diff <id1> <id2> --show-unchanged       # include unchanged rules
kensa diff <id1> <id2> --format json          # programmatic output
```

| Flag | Meaning |
|---|---|
| `--show-unchanged` | Also list rules whose status is identical between the two sessions. |
| `--format` | `text` (default) or `json`. |
| `-q, --quiet` | Suppress default output. |

The direction follows git's convention: `SESSION_ID_1` is the earlier
("before") snapshot and `SESSION_ID_2` is the later ("after") one;
reversing the arguments inverts the report. Comparing across hostnames is
allowed; a stderr note discloses the cross-host scope.

To populate sessions for `diff`, run `check --store` (a persisted scan)
or `remediate` (always persisted), then find the UUIDs with `kensa list
sessions`.

---

## Finding session IDs

Most of these commands key off a session UUID. List them with:

```bash
kensa list sessions                          # 20 most recent
kensa list sessions -H rhel9-host.example.com         # one hostname
kensa list sessions --format json -n 5       # last 5 as JSON
```

The `session_id` column is the UUID that `rollback --info` / `--start`
and both `diff` arguments expect.

## Next

[06 · Rule authoring](06-rule-authoring.md) covers writing your own
rules; [10 · Mechanisms](10-mechanisms.md) details the reversal level you
get from each mechanism.
