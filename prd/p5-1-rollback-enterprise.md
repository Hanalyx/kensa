# P5-1: Enterprise Rollback — Implementation Plan

**Project:** Kensa
**Date:** 2026-02-22
**Status:** Draft
**Companion:** TECHNICAL_REMEDIATION_MP_V0.md (Sections 3.4, 3.7),
CANONICAL_RULE_SCHEMA_V0.md (Section 3.5), RULE_REVIEW_GUIDE_V0.md (Section 4)

---

## 1. Motivation

### 1.1 Current State

Kensa's rollback system has the right architecture — symmetric capture/rollback
handlers mirroring all 23 remediation mechanisms, reverse-order execution, and
capability-gated skipping for inherently non-reversible operations. But the
implementation has gaps that prevent it from being an enterprise-grade,
marketable feature:

- **Ephemeral state.** Pre-remediation snapshots exist only in memory. If the
  admin doesn't pass `--rollback-on-failure`, the capture data is never created.
  If the process exits, the data is gone. There is no post-hoc rollback.

- **No persistence.** The `remediate` command does not write to SQLite at all.
  The `_store_results()` function (cli.py:684) is only called from `check`.
  There is no historical record of remediations, snapshots, or rollback events.

- **Missing handlers.** `pam_module_configure` has no capture or rollback
  handler despite being one of the most dangerous remediation mechanisms — a
  PAM misconfiguration can lock users out of a system entirely.

- **No exception safety.** `_execute_rollback` does not wrap handler calls in
  try/except. A single handler failure (SSH timeout, missing dict key) aborts
  all remaining rollback steps.

- **Silent lies.** Service rollback handlers (`_rollback_service_enabled`,
  `_rollback_service_disabled`, `_rollback_service_masked`) discard `systemctl`
  return codes and always report success.

- **Correctness bug.** `_rollback_service_enabled` routes previously-masked
  services through `systemctl disable` instead of `systemctl mask` due to a
  dead-code branch.

- **60% untested.** Only 8 of 20 rollback handlers have unit tests. 12 handlers
  — including complex ones like `audit_rule_set`, `selinux_boolean_set`, and
  `mount_option_set` — have zero test coverage.

- **No standalone rollback.** Users cannot inspect or reverse a past remediation.
  The only rollback path is the inline `--rollback-on-failure` flag, which is
  opt-in and fire-and-forget.

### 1.2 Alignment with Core Vision

The Technical Remediation Master Plan (Section 3.4) states:

> "Each mechanism is also reversible — the prior state is captured before
> modification for rollback support."

And the execution model (Section 3.7, Phase 3) defines:

> "Record pre-state (for rollback) → Apply the change → Verify the change →
> Record result"

The canonical schema (Section 3.5) explicitly calls out:

> "Rollback is handled at the execution engine level, not the schema level."

This plan fulfills the vision already stated in the founding documents. The
architecture assumed persistent snapshots and reliable rollback. The
implementation needs to catch up.

The Rule Review Guide (Section 4.1) emphasizes round-trip consistency and
reboot awareness. A persistent rollback system gives admins a safety net when
remediation produces an unexpected effective state — exactly the scenario the
review guide warns about.

### 1.3 Design Principles for This Work

These principles derive directly from the six in TECHNICAL_REMEDIATION_MP_V0.md:

1. **Snapshots are evidence.** Pre-state captures serve the same
   evidence-first philosophy as check evidence. "Here is what the system
   looked like before we touched it" is an audit artifact regardless of
   whether rollback is ever executed.

2. **Safe by default.** Snapshot capture should be the default mode. An admin
   who forgets a flag should get more safety, not less.

3. **Declarative rollback.** Rollback should be derived from the mechanism
   type and captured data, not from per-rule configuration. This matches the
   schema principle that rollback lives at the engine level.

4. **Honest about limits.** Mechanisms that cannot be rolled back (GRUB,
   `command_exec`, `manual`) must be clearly surfaced, not silently skipped.

---

## 2. Scope

### 2.1 In Scope

Nine build phases, ordered by dependency:

| Phase | Description | Dependency |
|-------|-------------|------------|
| 1 | Schema v3 migration — remediation and snapshot tables | None |
| 2 | Persist remediation results and pre-state data | Phase 1 |
| 3 | Harden existing rollback handlers (6 bug fixes) | None |
| 4 | `kensa rollback --info` command | Phase 2 |
| 5 | `kensa rollback --start` command | Phase 4 |
| 6 | Flip default — snapshot always, add `--no-snapshot` | Phase 2 |
| 7 | Risk classification for snapshot policy | Phase 6 |
| 8 | Backfill empty severity values | None |
| 9 | Snapshot retention policy | Phase 2 |

### 2.2 Out of Scope

- **Per-rule rollback configuration in YAML.** The canonical schema keeps
  rollback at the engine level. This plan does not add rollback fields to rules.
- **Remote snapshot storage.** Snapshots are stored in the local SQLite database.
  Central aggregation is a future phase.
- **Automatic rollback scheduling.** No cron-based or timer-based rollback.
  Rollback is always operator-initiated or failure-triggered.
- **Rollback across hosts.** Each `kensa rollback --start` targets one host.
  Multi-host rollback is a wrapper, not a new primitive.

---

## 3. Phase 1: Schema v3 Migration

### 3.1 Problem

The current SQLite schema (v2) has no concept of remediations, steps, or
pre-state. It stores only session/result/evidence/framework_refs. The
`remediate` command does not persist anything.

### 3.2 New Tables

```sql
-- Remediation session (one per kensa remediate invocation)
CREATE TABLE IF NOT EXISTS remediation_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,          -- FK to sessions table
    dry_run INTEGER NOT NULL DEFAULT 0,
    rollback_on_failure INTEGER NOT NULL DEFAULT 0,
    snapshot_mode TEXT NOT NULL DEFAULT 'all',  -- all | risk_based | none
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- One row per rule remediated on a host
CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    remediation_session_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT,
    passed_before INTEGER NOT NULL,       -- check result before remediation
    passed_after INTEGER,                 -- check result after (NULL if not re-checked)
    remediated INTEGER NOT NULL DEFAULT 0,
    rolled_back INTEGER NOT NULL DEFAULT 0,
    detail TEXT DEFAULT '',
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (remediation_session_id) REFERENCES remediation_sessions(id) ON DELETE CASCADE
);

-- One row per remediation step
CREATE TABLE IF NOT EXISTS remediation_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    remediation_id INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    mechanism TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail TEXT DEFAULT '',
    FOREIGN KEY (remediation_id) REFERENCES remediations(id) ON DELETE CASCADE
);

-- Pre-state snapshot for a step (the rollback payload)
CREATE TABLE IF NOT EXISTS pre_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    step_id INTEGER NOT NULL,              -- FK to remediation_steps
    mechanism TEXT NOT NULL,
    data_json TEXT NOT NULL,               -- JSON-serialized PreState.data dict
    capturable INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (step_id) REFERENCES remediation_steps(id) ON DELETE CASCADE
);

-- Rollback event log (populated when rollback is executed)
CREATE TABLE IF NOT EXISTS rollback_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    step_id INTEGER NOT NULL,              -- FK to remediation_steps
    mechanism TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail TEXT DEFAULT '',
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source TEXT NOT NULL DEFAULT 'inline', -- inline | manual
    FOREIGN KEY (step_id) REFERENCES remediation_steps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_remediations_session ON remediations(remediation_session_id);
CREATE INDEX IF NOT EXISTS idx_remediations_host_rule ON remediations(host, rule_id);
CREATE INDEX IF NOT EXISTS idx_remediation_steps_remediation ON remediation_steps(remediation_id);
CREATE INDEX IF NOT EXISTS idx_pre_states_step ON pre_states(step_id);
CREATE INDEX IF NOT EXISTS idx_rollback_events_step ON rollback_events(step_id);
```

### 3.3 Migration Strategy

Add `_migrate_to_v3()` in `runner/storage.py`, following the existing
`_migrate_to_v2()` pattern. The migration is additive — no existing tables or
columns are modified. Bump `SCHEMA_VERSION` to 3.

### 3.4 Data Types

`PreState.data` contains only simple types: `str`, `bool`, `None`,
`list[dict[str, str]]`. JSON serialization via `json.dumps()` / `json.loads()`
is sufficient. No custom encoder needed.

### 3.5 Files Modified

| File | Change |
|------|--------|
| `runner/storage.py` | Add `_migrate_to_v3()`, new `record_remediation()`, `record_step()`, `record_pre_state()`, `record_rollback_event()`, `get_remediation()`, `get_remediation_steps()`, `get_pre_states()`, `list_remediations()` methods. Bump `SCHEMA_VERSION` to 3. |
| `runner/_types.py` | No change — existing `PreState`, `StepResult`, `RollbackResult`, `RuleResult` types are sufficient. |

### 3.6 Tests

- `tests/test_storage.py`: Add `TestSchemaV3Migration` (upgrade from v2),
  `TestRemediationPersistence` (round-trip write/read of remediation + steps +
  pre_states + rollback_events), `TestPreStateJsonSerialization` (all
  mechanism data dicts serialize/deserialize correctly).

### 3.7 Acceptance Criteria

- [ ] `_migrate_to_v3()` creates all new tables and indexes
- [ ] Existing v2 databases upgrade cleanly without data loss
- [ ] `record_remediation()` persists a full remediation with steps and pre-states
- [ ] `get_remediation()` returns a complete remediation record including steps
- [ ] All new methods have unit tests
- [ ] `SCHEMA_VERSION = 3`

---

## 4. Phase 2: Persist Remediation Results

### 4.1 Problem

The `remediate` command does not call `_store_results()` or any storage method.
Remediation outcomes exist only in terminal output and ephemeral JSON exports.

### 4.2 Approach

Wire the `remediate` command to persist results after each host completes,
mirroring how `check` calls `_store_results()`. The remediation-specific data
flows through new storage methods from Phase 1.

### 4.3 Integration Points

**`runner/cli.py`:**

Add `_store_remediation_results()` function, called after each host completes in
the `remediate` command. This function:

1. Creates a `remediation_session` linked to the scan session.
2. For each `RuleResult` with `remediated=True`:
   a. Calls `store.record_remediation()` with host, rule_id, severity,
      pass/fail before/after, rolled_back status.
   b. For each `StepResult`, calls `store.record_step()` with mechanism,
      success, detail.
   c. For each `StepResult.pre_state` (where not None and capturable=True),
      calls `store.record_pre_state()` with JSON-serialized data.
   d. For each `RollbackResult`, calls `store.record_rollback_event()` with
      source='inline'.

**`runner/_host_runner.py`:**

No changes. The `RuleResult` objects already carry all needed data
(`step_results`, `rollback_results`, `rolled_back`). Persistence is handled
at the CLI layer.

### 4.4 Session Linking

Every `kensa remediate` invocation first creates a `sessions` row (reusing the
existing `create_session()`) for host/rules/options tracking. Then it creates a
`remediation_sessions` row linked to that session, recording `dry_run`,
`rollback_on_failure`, and `snapshot_mode`.

This means `kensa history` and `kensa diff` continue to work for remediation
runs, and the new `kensa rollback` command can query the remediation-specific
tables.

### 4.5 Files Modified

| File | Change |
|------|--------|
| `runner/cli.py` | Add `_store_remediation_results()`, call it from `remediate` command after each host. |
| `runner/storage.py` | Ensure `record_remediation()` returns the remediation ID for step/pre_state linking. |

### 4.6 Tests

- `tests/test_cli.py`: Add `TestRemediationPersistence` — mock SSH, run
  `remediate` via CliRunner, verify SQLite contains remediation + step +
  pre_state rows.
- `tests/test_storage.py`: Integration test — write a remediation, read it
  back, verify all fields including JSON-deserialized pre_state data.

### 4.7 Acceptance Criteria

- [ ] Every `kensa remediate` run persists remediation results to SQLite
- [ ] Pre-state snapshots are JSON-serialized and recoverable
- [ ] `kensa history` shows remediation sessions alongside check sessions
- [ ] Dry-run remediations are persisted (with `dry_run=1`) but without pre-states
- [ ] Rollback events from `--rollback-on-failure` are persisted with source='inline'

---

## 5. Phase 3: Harden Existing Rollback Handlers

### 5.1 Problem

Six known defects in the current rollback implementation undermine reliability.

### 5.2 Fix 1: Exception Safety in `_execute_rollback`

**File:** `runner/handlers/rollback/__init__.py`

Wrap each handler call in try/except to ensure best-effort rollback of all
steps. A single handler failure must not abort remaining steps.

```python
# Current (unsafe):
ok, detail = handler(ssh, sr.pre_state)

# Fixed:
try:
    ok, detail = handler(ssh, sr.pre_state)
except Exception as exc:
    ok, detail = False, f"Exception: {exc}"
```

### 5.3 Fix 2: PAM Capture and Rollback Handlers

**Files:** `runner/handlers/capture/_security.py`,
`runner/handlers/rollback/_security.py`

Add `_capture_pam_module_configure()` and `_rollback_pam_module_configure()`.

**Capture strategy:** Snapshot the relevant PAM file content (e.g.,
`/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`) and the authselect
profile state (`authselect current`). PAM files are small text files — full
content capture is safe and fast.

**Rollback strategy:** Restore the captured file content. If authselect was
active, restore the authselect profile. This is conservative but correct — it
restores exactly what was there before.

Register both handlers in `CAPTURE_HANDLERS` and `ROLLBACK_HANDLERS` with key
`pam_module_configure`.

PAM is called out explicitly in the Technical Remediation Master Plan (Section
5, Risks): "Isolate PAM into a dedicated mechanism with conservative change
semantics. Always verify PAM state after modification. Provide rollback." This
fix fulfills that stated requirement.

### 5.4 Fix 3: Service Rollback Return Code Checking

**File:** `runner/handlers/rollback/_service.py`

All three service handlers (`_rollback_service_enabled`,
`_rollback_service_disabled`, `_rollback_service_masked`) discard `ssh.run()`
results. Fix to check exit codes and return `(False, detail)` on failure.

### 5.5 Fix 4: Masked Service Dead-Code Bug

**File:** `runner/handlers/rollback/_service.py`

`_rollback_service_enabled` has a dead branch: `was_enabled == "masked"` is
caught by the first condition (`"disabled"` or `"masked"`) but routes to
`systemctl disable` instead of `systemctl mask`. Fix:

```python
if was_enabled == "masked":
    ssh.run(f"systemctl mask {name}")
elif was_enabled == "disabled":
    ssh.run(f"systemctl disable {name}")
```

### 5.6 Fix 5: File Permission Rollback Return Code Checking

**File:** `runner/handlers/rollback/_file.py`

`_rollback_file_permissions` discards `chown`/`chmod` results and always
returns True. Fix to check exit codes.

### 5.7 Fix 6: Missing `systemd` Mechanism Handler

The mechanism distribution across rules includes `mechanism: systemd` (1 rule),
but no `systemd` entry exists in `CAPTURE_HANDLERS`, `ROLLBACK_HANDLERS`, or
`REMEDIATION_HANDLERS`. Either:
- Add a `systemd` handler set if the mechanism is intentional, or
- Fix the one rule to use the correct mechanism name (likely `service_enabled`
  or `service_disabled`)

Investigation of the rule will determine which path.

### 5.8 Tests for All 20 Handlers

Write unit tests for the 12 untested rollback handlers and their corresponding
capture handlers:

| Handler | Test Class |
|---------|-----------|
| `_rollback_config_remove` | `TestRollbackConfigRemove` |
| `_rollback_config_block` | `TestRollbackConfigBlock` |
| `_rollback_file_content` | `TestRollbackFileContent` |
| `_rollback_file_absent` | `TestRollbackFileAbsent` |
| `_rollback_package_absent` | `TestRollbackPackageAbsent` |
| `_rollback_service_enabled` | `TestRollbackServiceEnabled` |
| `_rollback_service_disabled` | `TestRollbackServiceDisabled` |
| `_rollback_service_masked` | `TestRollbackServiceMasked` |
| `_rollback_mount_option_set` | `TestRollbackMountOptionSet` |
| `_rollback_grub_parameter_set` | `TestRollbackGrubParameterSet` |
| `_rollback_cron_job` | `TestRollbackCronJob` |
| `_rollback_selinux_boolean_set` | `TestRollbackSELinuxBooleanSet` |
| `_rollback_audit_rule_set` | `TestRollbackAuditRuleSet` |
| `_rollback_pam_module_configure` | `TestRollbackPamModuleConfigure` |

Plus an integration test: `TestRollbackExceptionSafety` — verify that when one
handler throws, remaining steps are still attempted.

### 5.9 Files Modified

| File | Change |
|------|--------|
| `runner/handlers/rollback/__init__.py` | try/except in `_execute_rollback` |
| `runner/handlers/rollback/_service.py` | Return code checks, masked-service fix |
| `runner/handlers/rollback/_file.py` | Return code checks for chown/chmod |
| `runner/handlers/capture/_security.py` | Add `_capture_pam_module_configure` |
| `runner/handlers/rollback/_security.py` | Add `_rollback_pam_module_configure` |
| `runner/handlers/capture/__init__.py` | Register `pam_module_configure` in `CAPTURE_HANDLERS` |
| `runner/handlers/rollback/__init__.py` | Register `pam_module_configure` in `ROLLBACK_HANDLERS` |
| `tests/test_engine_remediation.py` | 14 new test classes |

### 5.10 Acceptance Criteria

- [ ] `_execute_rollback` continues through all steps even when one handler throws
- [ ] `pam_module_configure` has capture and rollback handlers
- [ ] Service rollback handlers check systemctl return codes
- [ ] Masked services are correctly restored via `systemctl mask`
- [ ] File permission rollback checks chown/chmod return codes
- [ ] The `systemd` mechanism rule is fixed or handler is added
- [ ] All 20+1 rollback handlers have unit tests
- [ ] All 20+1 capture handlers have unit tests
- [ ] `pytest tests/test_engine_remediation.py` passes

---

## 6. Phase 4: `kensa rollback --info` Command

### 6.1 Problem

There is no way to inspect what a past remediation changed or what the
pre-state looked like. Admins must either have captured terminal output or
re-examine the system manually.

### 6.2 User Experience

```bash
# List recent remediation sessions
kensa rollback --list
kensa rollback --list --host 10.0.0.5

# Show summary of a specific remediation
kensa rollback --info 42

# Show detailed pre-state for a specific remediation
kensa rollback --info 42 --detail

# Filter to a specific rule
kensa rollback --info 42 --rule ssh-disable-root-login
```

### 6.3 Output Format: `--list`

```
Remediation Sessions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ID   Timestamp             Host(s)        Rules  Fixed  Fail  Rolled Back
  42   2026-02-22 14:30:01   10.0.0.5       120    95     5     3
  41   2026-02-22 10:15:44   10.0.0.5       120    88     12    0
  40   2026-02-21 09:00:22   10.0.0.6,..    240    210    10    0
```

### 6.4 Output Format: `--info 42`

```
Remediation Session #42
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Timestamp:   2026-02-22 14:30:01
  Host:        10.0.0.5
  Mode:        live (not dry-run)
  Snapshot:    all
  Rollback:    on-failure (enabled)

  Rules remediated: 100
  Rules rolled back: 3

  Rolled-back rules:
    FAIL  ssh-disable-root-login        (rolled back — 2 steps, 2 reversed)
    FAIL  sysctl-net-ipv4-ip-forward    (rolled back — 1 step, 1 reversed)
    FAIL  svc-disable-rpcbind           (rolled back — 1 step, 1 reversed)

  Non-rollbackable steps encountered:
    crypto-policy-no-sha1  step 2: command_exec  (not capturable)
    grub-audit              step 1: grub_parameter_set  (GRUB — not reversible)
```

### 6.5 Output Format: `--info 42 --detail`

Appends per-step pre-state data:

```
  ssh-disable-root-login
    Step 0: config_set_dropin
      Pre-state:
        path: /etc/ssh/sshd_config.d/00-kensa-permit-root-login.conf
        existed: false
      Rollback: ok — removed new file
    Step 1: command_exec
      Pre-state: not capturable (command_exec)
      Rollback: skipped
```

### 6.6 JSON Output

`kensa rollback --info 42 -o json` outputs a machine-readable JSON blob with
the full remediation record including pre-state data. This enables integration
with external SIEM/SOAR systems.

### 6.7 Files Modified

| File | Change |
|------|--------|
| `runner/cli.py` | Add `rollback` command group with `--list`, `--info` subcommands |
| `runner/storage.py` | Add `list_remediations()`, `get_remediation_detail()` query methods |

### 6.8 Tests

- `tests/test_cli.py`: `TestRollbackList` (output format, host filter),
  `TestRollbackInfo` (summary format, detail format, rule filter, JSON output).

### 6.9 Acceptance Criteria

- [ ] `kensa rollback --list` shows recent remediation sessions
- [ ] `kensa rollback --list --host X` filters by host
- [ ] `kensa rollback --info N` shows summary with rolled-back rules and non-rollbackable warnings
- [ ] `kensa rollback --info N --detail` shows per-step pre-state data
- [ ] `kensa rollback --info N --rule X` filters to a single rule
- [ ] `kensa rollback --info N -o json` outputs machine-readable JSON
- [ ] Output clearly identifies non-rollbackable steps and why

---

## 7. Phase 5: `kensa rollback --start` Command

### 7.1 Problem

There is no way to reverse a past remediation. If an admin runs `remediate`
without `--rollback-on-failure` and something breaks, their only option is
manual recovery.

### 7.2 User Experience

```bash
# Preview what would be rolled back (dry run)
kensa rollback --start 42 --host 10.0.0.5 --sudo --dry-run

# Execute rollback
kensa rollback --start 42 --host 10.0.0.5 --sudo

# Rollback a specific rule only
kensa rollback --start 42 --host 10.0.0.5 --sudo --rule ssh-disable-root-login
```

### 7.3 Execution Flow

1. Load the remediation record from SQLite (remediation ID 42).
2. Validate the target host matches the stored host.
3. Load all `pre_states` for the remediation's steps.
4. Filter steps: only capturable steps with stored pre-state data. Skip
   steps that were not successful (nothing to undo). Skip steps that were
   already rolled back (inline rollback already executed).
5. Reconstruct `PreState` objects from the stored JSON data.
6. Connect to host via SSH.
7. Execute `_execute_rollback()` with the reconstructed step results.
8. Persist `rollback_events` with `source='manual'`.
9. Report results.

### 7.4 Safety Checks

- **Host mismatch.** If `--host` doesn't match the stored host, abort with
  error. The pre-state data is host-specific.
- **Already rolled back.** If all steps already have rollback_events, warn
  and abort unless `--force` is passed.
- **Stale snapshot.** If the remediation is older than a configurable
  threshold (default: 7 days), warn that the system may have changed since
  the snapshot. Proceed with `--force` or user confirmation.
- **Dry run.** `--dry-run` shows what would be executed without connecting
  to the host.

### 7.5 Connection Parameters

The `rollback --start` command accepts the same SSH options as `remediate`:
`--host`, `--user`, `--key`, `--password`, `--port`, `--sudo`,
`--strict-host-keys`. The stored remediation record includes the original
hostname but not credentials (never store credentials).

### 7.6 Files Modified

| File | Change |
|------|--------|
| `runner/cli.py` | Add `--start` subcommand to `rollback` group |
| `runner/storage.py` | Add `get_pre_states_for_remediation()`, `mark_steps_rolled_back()` |
| `runner/_orchestration.py` | Add `rollback_from_stored()` function that reconstructs StepResults from stored pre-states and calls `_execute_rollback()` |

### 7.7 Tests

- `tests/test_cli.py`: `TestRollbackStart` — mock SSH, store a remediation with
  pre-states, invoke `rollback --start`, verify SSH commands executed in
  reverse order, verify rollback_events persisted.
- `tests/test_cli.py`: `TestRollbackStartSafety` — host mismatch abort,
  already-rolled-back warning, stale snapshot warning.
- `tests/test_engine_remediation.py`: `TestRollbackFromStored` — unit test for
  `rollback_from_stored()` with reconstructed PreState objects.

### 7.8 Acceptance Criteria

- [ ] `kensa rollback --start N --host X --sudo` executes rollback from stored pre-states
- [ ] Steps execute in reverse order (last-applied, first-undone)
- [ ] `--dry-run` shows what would be reversed without executing
- [ ] `--rule X` limits rollback to a specific rule
- [ ] Host mismatch aborts with clear error
- [ ] Already-rolled-back steps are skipped with warning
- [ ] Rollback events are persisted with `source='manual'`
- [ ] `--force` overrides stale-snapshot and already-rolled-back warnings

---

## 8. Phase 6: Default Snapshot Mode

### 8.1 Problem

`--rollback-on-failure` is opt-in. The safe behavior requires the admin to
remember a flag. The unsafe behavior is the default.

### 8.2 Approach

Make snapshot capture the default. Pre-state data is always captured and
persisted to SQLite during remediation, regardless of whether
`--rollback-on-failure` is passed. This ensures `kensa rollback --start` is
always available after any remediation.

The `--rollback-on-failure` flag continues to control whether inline
automatic rollback happens on failure. But the snapshot capture is
decoupled from it.

Add `--no-snapshot` flag to disable capture for performance-sensitive runs.

### 8.3 Performance Impact

The performance cost of snapshot capture is modest. Most capture handlers
execute a single SSH command:

| Mechanism | Capture Cost | Rule Count |
|-----------|-------------|------------|
| config_set | 1 grep | 84 |
| audit_rule_set | 1 auditctl + 1 cat | 79 |
| sysctl_set | 1 sysctl + 1 cat | 56 |
| command_exec | None (capturable=false) | 49 |
| file_permissions | 1 stat | 47 |
| manual | None (capturable=false) | 86 |
| package_absent | 1 rpm -q | 39 |
| config_set_dropin | 1 test + 1 cat | 34 |
| package_present | 1 rpm -q | 31 |
| service_masked | 2 systemctl | 28 |
| Others | 1-2 commands each | ~75 |

For a full 508-rule run, roughly 380 rules need capture (128 are
`command_exec` or `manual` with `capturable=false`). At ~1.5 SSH commands
per capture, that is ~570 additional SSH round-trips. At ~50ms per
round-trip over LAN, this adds ~28 seconds to a full run. Over WAN
(~150ms RTT), it adds ~85 seconds.

This is acceptable for the default mode. Admins running time-critical
bulk remediations can opt out with `--no-snapshot`.

### 8.4 Files Modified

| File | Change |
|------|--------|
| `runner/cli.py` | Add `--no-snapshot` flag to `remediate`. Remove snapshot gating from `--rollback-on-failure`. |
| `runner/_orchestration.py` | Decouple capture from `rollback_on_failure`. Add `snapshot` parameter to `remediate_rule()`. |
| `runner/_host_runner.py` | Thread `snapshot` parameter through host execution. |

### 8.5 Backward Compatibility

The `--rollback-on-failure` flag is preserved with the same semantics: it
controls whether failed remediations are automatically reversed inline. The
only change is that snapshot capture happens by default even without it.

Existing scripts that pass `--rollback-on-failure` continue to work
identically.

### 8.6 Acceptance Criteria

- [ ] `kensa remediate` captures pre-state by default (no flag needed)
- [ ] `kensa remediate --no-snapshot` disables capture
- [ ] `--rollback-on-failure` still controls inline auto-rollback
- [ ] Pre-state data appears in SQLite after a default remediation run
- [ ] `kensa rollback --info N` works after a run without `--rollback-on-failure`

---

## 9. Phase 7: Risk Classification

### 9.1 Problem

Some mechanisms carry higher risk than others. A `file_permissions` change on
`/etc/passwd` is narrow and easily reversed. A `grub_parameter_set` or
`pam_module_configure` can brick a system or lock out all users. Admins who
want faster runs should be able to skip low-risk snapshots while keeping
high-risk ones.

### 9.2 Risk Taxonomy

Risk is determined by **mechanism type** and **target path**. Both dimensions
matter: `config_set` on `/etc/ssh/sshd_config` is medium risk, but `config_set`
on `/etc/pam.d/system-auth` is high risk.

#### Mechanism Risk (base level)

| Risk | Mechanisms | Rationale |
|------|-----------|-----------|
| High | `grub_parameter_set`, `grub_parameter_remove`, `mount_option_set`, `pam_module_configure`, `kernel_module_disable` | Can brick boot, break mounts, lock out users, or make modules unavailable |
| Medium | `config_set`, `config_set_dropin`, `config_block`, `config_remove`, `sysctl_set`, `service_masked`, `service_disabled`, `audit_rule_set`, `selinux_boolean_set`, `file_content` | Can break services, change security posture, or alter system behavior |
| Low | `file_permissions`, `package_present`, `package_absent`, `service_enabled`, `cron_job`, `file_absent` | Narrow blast radius, easily manually reversed |
| N/A | `command_exec`, `manual` | Not capturable |

#### Path Escalation

Certain paths elevate the risk regardless of mechanism:

| Path Pattern | Escalates To | Rationale |
|-------------|-------------|-----------|
| `/etc/pam.d/*` | High | PAM misconfiguration locks out users |
| `/etc/fstab` | High | Mount errors can prevent boot |
| `/etc/crypttab` | High | Encryption errors can prevent boot |
| `/etc/default/grub` | High | GRUB errors can prevent boot |
| `/etc/selinux/config` | High | SELinux errors can prevent boot or block all services |
| `/etc/ssh/sshd_config` | Medium (min) | SSH config errors lock out remote access |
| `/etc/security/*` | Medium (min) | Security subsystem configuration |

The effective risk is `max(mechanism_risk, path_risk)`.

### 9.3 Configuration

Add to `config/defaults.yml`:

```yaml
rollback:
  # Snapshot mode: all (default) | risk_based | none
  snapshot: all

  # When snapshot=risk_based, minimum risk level to capture
  # Options: high | medium | low
  risk_threshold: medium

  # Additional paths that elevate risk to 'high'
  # (merged with built-in high-risk paths above)
  high_risk_paths: []
```

Overridable via the existing variable precedence chain (CLI > host > group >
conf.d > defaults).

### 9.4 Implementation

Add `runner/risk.py` module:

```python
def classify_step_risk(mechanism: str, remediation: dict) -> str:
    """Return 'high', 'medium', 'low', or 'na' for a remediation step."""
```

This function is called in the capture dispatch path. When `snapshot=risk_based`,
steps with risk below the threshold skip capture.

### 9.5 Files Modified

| File | Change |
|------|--------|
| `runner/risk.py` | New module — `classify_step_risk()`, `MECHANISM_RISK`, `HIGH_RISK_PATHS` |
| `config/defaults.yml` | Add `rollback:` section |
| `runner/_orchestration.py` | Call `classify_step_risk()` in capture dispatch |
| `runner/handlers/capture/__init__.py` | Accept `risk_threshold` parameter, skip capture for low-risk steps |

### 9.6 Tests

- `tests/test_risk.py`: Test risk classification for all mechanisms, path
  escalation, config override.
- `tests/test_engine_remediation.py`: `TestRiskBasedCapture` — verify low-risk
  steps are skipped when threshold is medium, high-risk steps are always
  captured.

### 9.7 Acceptance Criteria

- [ ] `classify_step_risk()` returns correct risk for all 23 mechanisms
- [ ] Path escalation overrides base mechanism risk
- [ ] `snapshot: risk_based` with `risk_threshold: high` captures only high-risk steps
- [ ] `snapshot: all` captures everything (default, existing behavior)
- [ ] `snapshot: none` is equivalent to `--no-snapshot`
- [ ] Custom `high_risk_paths` in config are respected

---

## 10. Phase 8: Backfill Empty Severity Values

### 10.1 Problem

281 of 508 rules (55%) have empty `severity` fields. The risk classification
in Phase 7 does not depend on severity, but empty severities undermine
reporting, filtering (`kensa check -s high`), and the remediation record's
usefulness.

The Rule Review Guide (Section 5.2) defines clear severity criteria. The
category-level reviews (Section 9.3) have been completed for all 8 categories,
but severity was not systematically backfilled during those reviews.

### 10.2 Approach

Systematic pass through all 508 rules to assign severity using the criteria
from RULE_REVIEW_GUIDE_V0.md Section 5.2:

| Severity | Criteria |
|----------|----------|
| `critical` | Immediate, complete system compromise |
| `high` | Significant privilege escalation or unauthorized access |
| `medium` | Weakens security posture, requires additional conditions |
| `low` | Defense-in-depth, does not directly enable compromise |

### 10.3 Methodology

Process rules by category. For each rule:

1. Read the rule's `description` and `rationale`.
2. Consider the attack scenario if the control is absent.
3. Cross-reference STIG CAT (I/II/III) and CIS Level (L1/L2) as input
   signals, but assign Kensa's independent assessment per Section 5.2.
4. When in doubt, align with the higher-impact framework rating.

### 10.4 Distribution Target

Based on typical compliance rule distributions and the criteria in the review
guide, the expected outcome is approximately:

| Severity | Expected Count | Expected % |
|----------|---------------|------------|
| critical | 5-10 | 1-2% |
| high | 60-80 | 12-16% |
| medium | 300-350 | 59-69% |
| low | 80-120 | 16-24% |

### 10.5 Execution

This is a bulk YAML edit operation, not a code change. It can be done in
batches by category, with each batch validated by `pre-commit run --all-files`
and submitted as a PR.

| Category | Rules with Empty Severity | Estimated Effort |
|----------|--------------------------|-----------------|
| access-control | ~60 | 1 PR |
| audit | ~50 | 1 PR |
| services | ~50 | 1 PR |
| system | ~30 | 1 PR |
| filesystem | ~30 | 1 PR |
| network | ~25 | 1 PR |
| kernel | ~15 | 1 PR |
| logging | ~10 | 1 PR |

### 10.6 Acceptance Criteria

- [ ] Zero rules have empty `severity` field
- [ ] All severity values are one of: `critical`, `high`, `medium`, `low`
- [ ] `pre-commit run --all-files` passes
- [ ] Distribution approximately matches the target range

---

## 11. Phase 9: Snapshot Retention Policy

### 11.1 Problem

Pre-state data is larger than check results. A `file_content` capture stores
the entire file contents. A `config_block` capture stores the full file.
Across 508 rules, multiple hosts, and daily runs, the SQLite database will
grow significantly.

The existing `prune_old_results()` method (storage.py:617) prunes sessions
older than `retention_days` (default 90). But snapshot data has different
retention characteristics: it's most valuable in the first 7 days (when you
might need to rollback) and decreases in value as the system drifts further
from the captured state.

### 11.2 Approach

Add a separate retention policy for snapshot data with a shorter default
retention period. Implement as a two-tier strategy:

1. **Active snapshots** (0-7 days): Full pre-state data retained. Rollback
   is available via `kensa rollback --start`.
2. **Archived snapshots** (7-90 days): Pre-state data available for
   inspection (`kensa rollback --info`) but rollback requires `--force`
   with a staleness warning.
3. **Pruned** (>90 days): Pre-state data deleted. Remediation metadata
   (what was changed, when, success/failure) retained per the existing
   90-day session retention.

### 11.3 Configuration

Add to `config/defaults.yml` under the `rollback:` section:

```yaml
rollback:
  snapshot: all
  risk_threshold: medium
  # Retention
  snapshot_active_days: 7        # Full rollback available
  snapshot_archive_days: 90      # Info only, rollback requires --force
```

### 11.4 Implementation

Add `prune_snapshots()` method to `ResultStore`:

- Delete `pre_states` rows where the linked `remediation_sessions.timestamp`
  is older than `snapshot_archive_days`.
- The `remediations`, `remediation_steps`, and `rollback_events` tables are
  retained per the existing session retention policy.

Pruning runs automatically at the start of each `kensa remediate` invocation,
same as the existing `prune_old_results()` behavior.

### 11.5 Files Modified

| File | Change |
|------|--------|
| `runner/storage.py` | Add `prune_snapshots()` method |
| `config/defaults.yml` | Add retention config under `rollback:` |
| `runner/cli.py` | Call `prune_snapshots()` at remediate startup |

### 11.6 Tests

- `tests/test_storage.py`: `TestSnapshotRetention` — create remediations at
  various ages, prune, verify correct rows deleted/retained.

### 11.7 Acceptance Criteria

- [ ] `prune_snapshots()` deletes pre_states older than `snapshot_archive_days`
- [ ] Remediation metadata survives snapshot pruning
- [ ] `kensa rollback --start` warns about stale snapshots (>active_days)
- [ ] `kensa rollback --info` works on archived snapshots (no pre-state data)
- [ ] Retention values are configurable via `config/defaults.yml`

---

## 12. Dependency Graph

```
Phase 1 (Schema v3)
  │
  ├──▶ Phase 2 (Persist remediations)
  │      │
  │      ├──▶ Phase 4 (rollback --info)
  │      │      │
  │      │      └──▶ Phase 5 (rollback --start)
  │      │
  │      ├──▶ Phase 6 (Default snapshot)
  │      │      │
  │      │      └──▶ Phase 7 (Risk classification)
  │      │
  │      └──▶ Phase 9 (Retention policy)
  │
  Phase 3 (Harden handlers) ◀── independent, can parallel with 1-2
  │
  Phase 8 (Backfill severity) ◀── independent, can parallel with anything
```

Phases 3 and 8 have no dependencies and can be executed in parallel with
any other phase.

---

## 13. CLI Command Summary

After all phases, the `rollback` command group:

```
kensa rollback [OPTIONS]

  Inspect and reverse past remediations.

Subcommands:
  --list                          List recent remediation sessions
  --info ID                       Show remediation details and pre-state data
  --start ID                      Execute rollback from stored snapshots

List Options:
  --host TEXT                     Filter by host

Info Options:
  --detail                        Show per-step pre-state data
  --rule TEXT                     Filter to a specific rule
  -o, --output FORMAT             Output format (json)

Start Options:
  -h, --host TEXT                 Target host (required, must match stored host)
  -u, --user TEXT                 SSH username
  -k, --key TEXT                  SSH private key path
  -p, --password TEXT             SSH password
  -P, --port INTEGER              SSH port (default: 22)
  --sudo                          Run commands via sudo
  --dry-run                       Preview without executing
  --rule TEXT                     Rollback a specific rule only
  --force                         Override staleness and already-rolled-back warnings
  --strict-host-keys / --no-strict-host-keys
                                  Verify SSH host keys

Examples:
  kensa rollback --list
  kensa rollback --list --host 10.0.0.5
  kensa rollback --info 42
  kensa rollback --info 42 --detail --rule ssh-disable-root-login
  kensa rollback --start 42 --host 10.0.0.5 --sudo --dry-run
  kensa rollback --start 42 --host 10.0.0.5 --sudo
  kensa rollback --start 42 --host 10.0.0.5 --sudo --rule ssh-disable-root-login
```

The `remediate` command gains:

```
  --no-snapshot                   Disable pre-state capture (faster, no rollback)
```

And `--rollback-on-failure` remains as-is (controls inline auto-rollback).

---

## 14. Success Criteria

The rollback feature is enterprise-ready and marketable when:

1. Every `kensa remediate` run persists pre-state snapshots by default.
2. `kensa rollback --info N` shows exactly what the system looked like before
   remediation — usable as a compliance artifact.
3. `kensa rollback --start N` can reverse a past remediation days after the
   fact, with clear safety warnings about staleness.
4. All 21 remediation mechanisms have capture and rollback handlers (or are
   explicitly marked non-capturable with user-visible warnings).
5. Rollback handlers have 100% unit test coverage.
6. Rollback handler failures are caught and logged without aborting remaining
   steps.
7. Risk classification is available for admins who need faster runs.
8. All 508 rules have severity values.

At that point, the marketing claim becomes:

> "Kensa captures pre-remediation state for every change. Inspect past changes
> with `kensa rollback --info`. Reverse any remediation with
> `kensa rollback --start`. Risk-classified snapshots ensure safety without
> sacrificing speed."

---

## 15. References

- **TECHNICAL_REMEDIATION_MP_V0.md** — Section 3.4 (mechanism reversibility),
  Section 3.7 Phase 3 (record pre-state), Section 5 (PAM risk)
- **CANONICAL_RULE_SCHEMA_V0.md** — Section 3.5 (rollback at engine level,
  not schema level)
- **RULE_REVIEW_GUIDE_V0.md** — Section 4 (remediation effectiveness),
  Section 5.2 (severity criteria)
- **runner/storage.py** — Current schema v2, migration pattern
- **runner/handlers/rollback/** — Current 20 rollback handlers
- **runner/handlers/capture/** — Current 20 capture handlers
- **runner/_orchestration.py** — Current remediate_rule() flow

---

*This document defines the implementation plan for enterprise-grade rollback
in Kensa. It builds on the architectural foundation established in the
Technical Remediation Master Plan and fulfills the rollback capabilities
assumed but not yet fully implemented in V0.*
