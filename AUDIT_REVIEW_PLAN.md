# Audit Rule Review — Findings & Fix Plan

**Scope:** All 92 rules in `rules/audit/`
**Date:** 2026-02-18
**Guide:** RULE_REVIEW_GUIDE_V0.md

---

## Executive Summary

Reviewed 92 audit rules against the 5-dimension criteria in
RULE_REVIEW_GUIDE_V0.md. Found **~146 findings** across 80+ rules, organized
into 8 fix phases. The most critical findings are:

1. **5 runtime-critical field/schema bugs** — `state: "running"` silently
   ignored by the `service_state` handler (2 rules), invalid `systemd_timer`
   capability, invalid `reload:` format, unrecognized `start:` field.

2. **14 duplicate rule pairs** (28 rules) — same control implemented by two
   rules with neither declaring `supersedes` or `conflicts_with`.

3. **17 weak/imprecise checks** — overly broad grep patterns on `auditctl -l`
   that should use `audit_rule_exists`, plus 2 logic bugs (string-vs-numeric
   comparison, checking `-e 2` via `auditctl -l` which never outputs it).

---

## Table of Contents

1. [FIX-01: Runtime-Critical Field/Schema Bugs (P0)](#fix-01)
2. [FIX-02: Check Logic Bugs (P1)](#fix-02)
3. [FIX-03: Duplicate Rule Resolution (P1)](#fix-03)
4. [FIX-04: Weak Grep → audit_rule_exists Migration (P2)](#fix-04)
5. [FIX-05: Incomplete Multi-Condition Checks & Remediations (P2)](#fix-05)
6. [FIX-06: Config/Remediation Quality (P2)](#fix-06)
7. [FIX-07: Missing Dependencies & Platform Scope (P2)](#fix-07)
8. [FIX-08: Missing Framework References (P3)](#fix-08)

---

## FIX-01: Runtime-Critical Field/Schema Bugs (P0) {#fix-01}

### Problem

These defects cause incorrect behavior at runtime — either fields are silently
ignored or the engine cannot match the value to a handler.

### Findings

#### 1a. `state: "running"` silently ignored by `service_state` handler

The `service_state` check handler (`runner/handlers/checks/_service.py`) only
reads `enabled` and `active` keys. `state: "running"` is not a recognized field
and is silently ignored, meaning these rules do NOT verify the service is running.

| Rule File | Fix |
|-----------|-----|
| `auditd-service-enabled.yml` | Replace `state: "running"` with `active: true` |
| `auditd-enabled.yml` | Replace `state: "running"` with `active: true` |

#### 1b. Invalid capability `systemd_timer`

| Rule File | Fix |
|-----------|-----|
| `aide-cron-check.yml` | `when: systemd_timer` — not in `CAPABILITY_PROBES`. Remove this implementation block or add the probe to `runner/detect.py`. |

#### 1c. Invalid `reload:` value (expects service name, not full command)

| Rule File | Current | Fix |
|-----------|---------|-----|
| `auditd-space-low-warning.yml` | `reload: "systemctl restart auditd"` | Change to `restart: "auditd"` |

#### 1d. Unrecognized `start:` field on `service_enabled` mechanism

| Rule File | Fix |
|-----------|-----|
| `auditd-enabled.yml` | Remove `start: true` — `service_enabled` implicitly starts the service |

### Verification

```bash
pytest tests/ -v -k "service"
./aegis check --inventory inventory.ini --sudo --limit <host> --rule auditd-service-enabled
```

---

## FIX-02: Check Logic Bugs (P1) {#fix-02}

### Problem

Checks that produce incorrect pass/fail results due to logic errors.

### Findings

#### 2a. `audit-immutable.yml` — `-e 2` not in `auditctl -l` output

`auditctl -l` lists rules, not control commands. `-e 2` is a control command
that appears in rules files but is NOT reported by `auditctl -l`. The check
`grep -qE '^-e 2'` on `auditctl -l` output will **always fail**.

**Fix:** Check effective state via `auditctl -s | grep 'enabled 2'` or check
the rules file directly.

#### 2b. `audit-tools-permissions.yml` — string vs numeric comparison

The check uses `awk '{if ($1 > 755) exit 1}'` but `$1` is a string. String
comparison means "1000" < "755" (compares character by character), so
permissions like 1755 would incorrectly pass.

**Fix:** Use numeric comparison: `awk '{if ($1+0 > 755) exit 1}'` or better,
use `stat -c '%a'` with a proper numeric test.

#### 2c. `audit-rules-immutable.yml` — checks static file only

Checks `grep -E '^\s*-e\s+2\s*$' /etc/audit/rules.d/*.rules` but does not
verify the effective running state (`auditctl -s | grep 'enabled 2'`).

**Fix:** Add effective state check alongside the static file check, or convert
to `multi_check`.

### Verification

```bash
pytest tests/ -v -k "audit"
```

---

## FIX-03: Duplicate Rule Resolution (P1) {#fix-03}

### Problem

14 pairs of rules implement the same control. Some are "old CIS" vs "new CIS"
(chapter 4.1.x → 6.3.x renumbering), some are CIS vs STIG. Neither member of
any pair declares `supersedes` or `conflicts_with`.

### Duplicate Pairs

| # | Older Rule | Newer Rule | Control |
|---|-----------|------------|---------|
| 1 | `audit-network-changes` | `audit-network-change` | Network environment changes |
| 2 | `audit-login-logout` | `audit-logins` | Login/logout events |
| 3 | `audit-session-initiation` | `audit-session` | Session initiation |
| 4 | `audit-permission-changes` | `audit-perm-mod` | DAC permission changes |
| 5 | `audit-sudoers-changes` | `audit-sudoers` | Sudoers file changes |
| 6 | `audit-file-deletion` | `audit-delete` | File deletion events |
| 7 | `audit-rules-immutable` | `audit-immutable` | Immutable audit config |
| 8 | `audit-mount-operations` | `audit-mounts` | Mount operations |
| 9 | `audit-unsuccessful-access` | `audit-file-access-failed` | Failed file access |
| 10 | `auditd-service-enabled` | `auditd-enabled` | Auditd service |
| 11 | `auditd-space-action` | `auditd-space-left-action` | Space left action |
| 12 | `aide-cron-check` | `aide-scheduled` | AIDE periodic check |
| 13 | `audit-binary-permissions` | `audit-tools-permissions`+owner+group | Audit tool perms |
| 14 | `aide-audit-tools` | `auditd-tools-integrity` | Audit tool integrity |

### Fix Strategy

For each pair, determine which rule is "canonical" (preferred) based on:
- Which one has more complete checks/remediation
- Which one the current CIS v2.0.0 / STIG v2r7 mappings reference

Then:
- Add `supersedes: [older-rule-id]` to the canonical rule
- Add `superseded_by: newer-rule-id` to the deprecated rule (or delete it if
  nothing references it)
- Merge any unique framework references from the deprecated rule into the
  canonical rule

### Verification

```bash
pytest tests/ -v
./aegis coverage --framework cis-rhel9-v2.0.0
```

---

## FIX-04: Weak Grep → `audit_rule_exists` Migration (P2) {#fix-04}

### Problem

13+ rules use `command` checks with `auditctl -l | grep -qE 'keyword'` to
verify audit rules exist. These grep patterns match keywords (e.g., `'delete'`,
`'session'`, `'mounts'`) that could produce false positives or miss rules with
different key names.

The `audit_rule_exists` check method provides precise matching.

### Affected Rules

| Rule File | Current Pattern | Migration Target |
|-----------|----------------|------------------|
| `audit-mounts.yml` | `grep -qE 'mounts'` | `audit_rule_exists` |
| `audit-session.yml` | `grep -qE 'session'` | `audit_rule_exists` |
| `audit-network-change.yml` | `grep -qE 'system-locale'` | `audit_rule_exists` |
| `audit-perm-mod.yml` | `grep -qE 'perm_mod'` | `audit_rule_exists` |
| `audit-identity-change.yml` | `grep -qE 'identity'` | `audit_rule_exists` |
| `audit-logins.yml` | `grep -qE 'logins'` | `audit_rule_exists` |
| `audit-file-access-failed.yml` | `grep -qE 'access'` | `audit_rule_exists` |
| `audit-sudo-log.yml` | `grep -qE 'sudo.log'` (`.` is wildcard) | `audit_rule_exists` |
| `audit-mac-policy.yml` | `grep -qE 'MAC-policy'` | `audit_rule_exists` |
| `audit-delete.yml` | `grep -qE 'delete'` | `audit_rule_exists` |
| `audit-user-emulation.yml` | `grep -qE 'user_emulation'` | `audit_rule_exists` |
| `audit-sudoers.yml` | `grep -qE 'sudoers.*scope'` | `audit_rule_exists` |
| `audit-privileged-commands.yml` | `grep -E 'execve.*auid>=1000.*euid=0'` | `audit_rule_exists` |

### Fix

Convert each to `audit_rule_exists` with the exact rule specification. Need to
read the `audit_rule_exists` handler to understand its expected fields first.

### Verification

```bash
pytest tests/ -v -k "audit_rule"
```

---

## FIX-05: Incomplete Multi-Condition Checks & Remediations (P2) {#fix-05}

### Problem

Rules where the check verifies only one of several required audit rules, or the
remediation only sets one of several required rules.

### Affected Rules

| Rule File | Issue | Fix |
|-----------|-------|-----|
| `audit-sudoers-changes.yml` | Check only verifies `/etc/sudoers` but CIS also requires `/etc/sudoers.d` | Add multi-check |
| `audit-session-initiation.yml` | Check only verifies `utmp` but CIS requires `wtmp` + `btmp` | Add multi-check |
| `audit-login-logout.yml` | Check only verifies `lastlog` but CIS requires `faillock` | Add multi-check |
| `audit-session.yml` | Remediation only sets `utmp`, CIS 6.3.3.11 requires `wtmp` + `btmp` | Add multi-step remediation |
| `audit-logins.yml` | Remediation only sets `lastlog`, CIS 6.3.3.12 requires `faillock` | Add multi-step remediation |
| `audit-identity-change.yml` | Remediation only sets `/etc/group`, CIS 6.3.3.8 requires passwd/shadow/gshadow | Add multi-step remediation |
| `audit-sudoers.yml` | Remediation only sets `/etc/sudoers`, CIS 6.3.3.1 requires `/etc/sudoers.d` | Add multi-step remediation |
| `audit-mac-policy.yml` | Remediation only sets `/etc/selinux`, CIS 6.3.3.14 requires `/usr/share/selinux` | Add remediation step |
| `audit-permission-changes.yml` | Check only verifies chmod but title says "ownership changes" too | Expand check or narrow title |

**Note:** Several of these are in duplicate pairs (Category D). If the "older"
rule in the pair has a more complete check, the fix may be to consolidate rather
than expand the "newer" rule.

### Verification

```bash
pytest tests/ -v
```

---

## FIX-06: Config/Remediation Quality (P2) {#fix-06}

### Problem

Multiple issues with remediation blocks: missing `separator:` on `config_set`
for `auditd.conf`, missing `restart:` after config changes, error-swallowing
`2>/dev/null`, and a missing `persist_file` on `audit_rule_set`.

### Findings

#### 6a. Missing `separator: " = "` on auditd.conf `config_set`

`auditd.conf` uses ` = ` (space-equals-space) as separator. Without specifying
it, the handler defaults to space, producing `key value` instead of `key = value`.

| Rule File | Fix |
|-----------|-----|
| `auditd-max-log-file-action.yml` | Add `separator: " = "` |
| `auditd-max-log-file.yml` | Add `separator: " = "` |
| `auditd-action-mail-acct.yml` | Add `separator: " = "` |

#### 6b. Missing `restart:` after auditd.conf change

| Rule File | Fix |
|-----------|-----|
| `auditd-space-left-action.yml` | Add `restart: "auditd"` |

#### 6c. Error-swallowing `2>/dev/null` in remediation commands

| Rule File | Fix |
|-----------|-----|
| `audit-binary-permissions.yml` | Remove `2>/dev/null` from chmod/chown |
| `audit-tools-owner.yml` | Remove `2>/dev/null` |
| `audit-tools-group.yml` | Remove `2>/dev/null` |
| `audit-tools-permissions.yml` | Remove `2>/dev/null` |

#### 6d. Missing `persist_file` on `audit_rule_set`

| Rule File | Fix |
|-----------|-----|
| `audit-rules-immutable.yml` | Add `persist_file: "/etc/audit/rules.d/99-finalize.rules"` |

### Verification

```bash
pytest tests/ -v -k "config_set or audit_rule"
```

---

## FIX-07: Missing Dependencies & Platform Scope (P2) {#fix-07}

### Problem

Rules that should declare `depends_on` for prerequisite rules, and rules with
`min_version: 9` that could also apply to RHEL 8.

### 7a. Missing `depends_on`

| Rule File | Fix |
|-----------|-----|
| `audit-config-owner.yml` | Add `depends_on: [auditd-service-enabled]` |
| `audit-config-group.yml` | Add `depends_on: [auditd-service-enabled]` |
| `audit-log-owner.yml` | Add `depends_on: [auditd-service-enabled]` |
| `audit-log-group.yml` | Add `depends_on: [auditd-service-enabled]` |
| `audit-tools-owner.yml` | Add `depends_on: [auditd-service-enabled]` |
| `audit-tools-group.yml` | Add `depends_on: [auditd-service-enabled]` |
| `audit-tools-permissions.yml` | Add `depends_on: [auditd-service-enabled]` |
| `auditd-enabled.yml` | Add `depends_on: [auditd-installed]` |
| `auditd-space-left-action.yml` | Add `depends_on: [auditd-service-enabled]` |
| `aide-scheduled.yml` | Add `depends_on: [aide-installed]` |

### 7b. Overly narrow `min_version: 9`

~18 rules (all `audit-cmd-*.yml` plus a few others) use `min_version: 9` but
the audit syscalls/commands exist on RHEL 8. These may be intentionally scoped
to match STIG RHEL 9 only. **Defer decision** — flag for review but don't
change without confirming the intent.

### Verification

```bash
pytest tests/ -v
./aegis check --inventory inventory.ini --sudo --limit <host> --rule aide-scheduled
```

---

## FIX-08: Missing Framework References (P3) {#fix-08}

### Problem

Multiple rules are missing CIS RHEL 8, STIG, or NIST references that exist in
the mapping files. Also 3 CIS section number mismatches between rules and
mappings.

### 8a. Missing CIS RHEL 8 references (~14 rules)

Cross-reference the CIS RHEL 8 v4.0.0 mapping against rule `references.cis`
blocks and add missing `rhel8_v4` entries.

### 8b. Missing STIG references (~9 rules)

Cross-reference the STIG RHEL 9 v2r7 mapping against rule `references.stig`
blocks and add missing entries.

### 8c. CIS section mismatches (3 rules)

| Rule File | Issue |
|-----------|-------|
| `auditd-space-low-warning.yml` | Claims CIS 6.3.2.4 but `auditd-action-mail-acct.yml` also claims it — section collision |
| `aide-audit-tools.yml` | Claims CIS 6.3.4.8 but mapping says that's `audit-tools-permissions` |
| `audit-binary-permissions.yml` | Claims CIS 6.3.4.10 but mapping says that's `audit-tools-group` |

### Fix

Use the same scripted approach as PR #20 — write a temporary script to
cross-reference mappings and add missing references.

### Verification

```bash
python scripts/cis_validate.py --mapping cis-rhel9-v2.0.0
./aegis coverage --framework cis-rhel9-v2.0.0
```

---

## Phase Execution Order

| Phase | Fix | Priority | Est. Rules | Depends On |
|-------|-----|----------|-----------|------------|
| 1 | FIX-01: Runtime field/schema bugs | P0 | 5 rules | — |
| 2 | FIX-02: Check logic bugs | P1 | 3 rules | — |
| 3 | FIX-03: Duplicate rule resolution | P1 | 28 rules | — |
| 4 | FIX-04: Grep → audit_rule_exists | P2 | 13 rules | Phase 3 (some are in duplicate pairs) |
| 5 | FIX-05: Incomplete multi-condition | P2 | 9 rules | Phase 3 (some are in duplicate pairs) |
| 6 | FIX-06: Config/remediation quality | P2 | 8 rules | Phase 1 |
| 7 | FIX-07: Dependencies & platform | P2 | 11 rules | — |
| 8 | FIX-08: Framework references | P3 | ~26 rules | Phase 3 (refs merge from deprecated rules) |

**Deferred (not in scope):**
- Category M: Description/rationale quality improvements (P4, 23 rules) — cosmetic
- Category N: Platform scope expansion `min_version: 9` → `8` (P4, 18 rules) — needs intent confirmation
