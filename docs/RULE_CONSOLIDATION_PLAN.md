# Rule Consolidation Plan

**Date:** 2026-03-14
**Status:** Draft — Awaiting Review
**Related:** TECHNICAL_REMEDIATION_MP_V0.md, RULE_REVIEW_GUIDE_V0.md, CANONICAL_RULE_SCHEMA_V0.md

---

## 1. Problem Statement

A thorough review of all 508 rules against Kensa's foundational design documents revealed
systematic violations of the project's core philosophy. Approximately 110 rules (21%) have
`conflicts_with` fields pointing at another rule that implements the same security control.
Instead of **one rule per control** with framework references as metadata (Principle 1 and
Principle 4 from TECHNICAL_REMEDIATION_MP_V0.md), rules were created per-benchmark-version
— one for CIS RHEL 8's numbering, another for CIS RHEL 9's.

### Root Cause

Rules were written against specific benchmark versions. CIS RHEL 8 and CIS RHEL 9 use
different section numbering and sometimes different control names. Rules were created
per-benchmark rather than per-control, and `conflicts_with` was added as a band-aid to
prevent both from running on the same host. This does not solve the architectural violation.

### Violated Principles

- **Principle 1:** "Separate the rule from its implementation. The rule is the stable core."
- **Principle 3:** "One canonical rule set. Thin overlays for genuine differences."
- **Principle 4:** "Framework identifiers are cross-references attached to rules as metadata.
  They do not define the structure of the rule set. Adding a new framework means adding a
  new column of labels, not a new set of rules."

### Impact

- ~55 duplicate pairs exist, inflating the rule count from ~508 to what should be ~450-460
- Some pairs have inconsistent remediation quality (one typed, one manual)
- Mapping files reference different rule IDs for the same control across RHEL versions
- Framework coverage reports are misleading — the same control appears as two separate rules

---

## 2. Findings by Category

### Category 1: True Duplicates — Same ID, Different Directories (4 pairs)

These rules exist with identical filenames in two category directories simultaneously. This
violates the schema requirement that `category` matches the parent directory and that `id` is
globally unique.

| Rule ID | Location 1 | Location 2 |
|---------|-----------|-----------|
| `gdm-disable-user-list` | `rules/services/` | `rules/system/` |
| `issue-permissions` | `rules/filesystem/` | `rules/system/` |
| `issue-net-permissions` | `rules/filesystem/` | `rules/system/` |
| `motd-permissions` | `rules/filesystem/` | `rules/system/` |

**Action:** Determine the correct category for each. Delete the duplicate. Update any mapping
references.

---

### Category 2: OS-Split Duplicates — Same Control, One Rule per RHEL Version (~55 pairs)

These are pairs where the same security control was written as two separate rules — typically
one named for CIS RHEL 8's convention and one for CIS RHEL 9's. They have `conflicts_with`
pointing at each other, but should be a single rule carrying both CIS section references.

#### 2a. Filesystem Permissions (12 pairs)

| RHEL 8 Rule | RHEL 9 Rule | Control |
|-------------|-------------|---------|
| `fs-permissions-etc-passwd` | `etc-passwd-permissions` | /etc/passwd permissions |
| `fs-permissions-etc-passwd-backup` | `etc-passwd-backup-permissions` | /etc/passwd- permissions |
| `fs-permissions-etc-shadow` | `etc-shadow-permissions` | /etc/shadow permissions |
| `fs-permissions-etc-shadow-backup` | `etc-shadow-backup-permissions` | /etc/shadow- permissions |
| `fs-permissions-etc-group` | `etc-group-permissions` | /etc/group permissions |
| `fs-permissions-etc-group-backup` | `etc-group-backup-permissions` | /etc/group- permissions |
| `fs-permissions-etc-gshadow` | `etc-gshadow-permissions` | /etc/gshadow permissions |
| `fs-permissions-etc-gshadow-backup` | `etc-gshadow-backup-permissions` | /etc/gshadow- permissions |
| `fs-permissions-etc-shells` | `shells-permissions` | /etc/shells permissions |
| `fs-permissions-opasswd` | `opasswd-permissions` | opasswd permissions |
| `no-world-writable-files` | `no-world-writable` | world-writable file audit |
| `no-ungrouped-files` | `no-unowned-files` | unowned/ungrouped file audit |

**Notes:**
- Some RHEL 8 variants use `command` checks; RHEL 9 variants use typed `file_permission`
- The consolidated rule should use the typed handler (better remediation quality)
- `no-world-writable-files` has `file_permissions` remediation; `no-world-writable` has `manual` — keep the typed one

#### 2b. Sysctl Network Parameters (18+ rules → ~8 consolidated)

CIS RHEL 8 had separate controls per interface (`conf.all` + `conf.default`). CIS RHEL 9
consolidated them into single controls. Instead of merging into one rule with a multi-check,
separate rules were created for each naming convention.

| RHEL 8 Rules (per-interface) | RHEL 9 Rule (consolidated) |
|---|---|
| `sysctl-net-ipv4-conf-all-send-redirects` + `sysctl-net-ipv4-conf-default-send-redirects` | `sysctl-send-redirects-disabled` |
| `sysctl-net-ipv4-conf-all-accept-redirects` + `...-default-...` + ipv6 variants | `sysctl-icmp-redirects-disabled` |
| `sysctl-net-ipv4-conf-all-accept-source-route` + `...-default-...` + ipv6 variants | `sysctl-source-route-disabled` |
| `sysctl-net-ipv4-conf-all-secure-redirects` + `...-default-...` | `sysctl-secure-redirects-disabled` |
| `sysctl-net-ipv4-conf-all-rp-filter` + `...-default-...` | `sysctl-rp-filter` |
| `sysctl-net-ipv6-conf-all-accept-ra` + `...-default-...` | `sysctl-ipv6-ra-disabled` |
| `sysctl-net-ipv4-conf-all-log-martians` + `...-default-...` | `sysctl-log-martians` |
| `sysctl-net-ipv4-icmp-echo-ignore-broadcasts` | `sysctl-ignore-broadcast-icmp` |
| `sysctl-net-ipv4-icmp-ignore-bogus-error-responses` | `sysctl-ignore-bogus-icmp` |
| `sysctl-net-ipv4-tcp-syncookies` | `sysctl-tcp-syncookies` |
| `sysctl-net-ipv6-conf-all-forwarding` | `sysctl-ip-forward-disabled` |

**Notes:**
- The RHEL 8 per-interface rules check individual sysctl keys; the RHEL 9 consolidated rules
  check both `conf.all` and `conf.default` in a `multi_check`
- Consolidation means the surviving rule carries CIS RHEL 8 section refs for each individual
  key AND the CIS RHEL 9 consolidated section ref
- Some per-interface rules also have STIG references that must be preserved

#### 2c. Services (3 pairs)

| RHEL 8 Name | RHEL 9 Name | Actual Service |
|---|---|---|
| `service-disable-avahi-daemon` | `service-disable-avahi` | avahi-daemon |
| `service-disable-samba` | `service-disable-smb` | smb |
| `service-disable-rsync` | `service-disable-rsyncd` | rsyncd |

**Notes:**
- Both rules in each pair check the exact same systemd service
- The service name didn't change between RHEL 8 and 9 — only the CIS section name changed

#### 2d. Audit Rules (8 pairs)

| Old Rule | New Rule | Has `supersedes`? |
|---|---|---|
| `audit-login-logout` | `audit-logins` | Yes |
| `audit-session-initiation` | `audit-session` | Yes |
| `audit-network-changes` | `audit-network-change` | Yes |
| `audit-permission-changes` | `audit-perm-mod` | No (conflicts_with only) |
| `audit-file-deletion` | `audit-delete` | No (conflicts_with only) |
| `audit-sudoers-changes` | `audit-sudoers` | No (conflicts_with only) |
| `audit-user-group-changes` | `audit-identity-change` | No (conflicts_with only) |
| `auditd-service-enabled` | `auditd-enabled` | No (conflicts_with only) |

**Notes:**
- Some newer rules correctly use `supersedes:` — these are partially addressed
- The old rules should be deleted after merging references into the new rule

#### 2e. Logging (3 pairs)

| RHEL 8 Rule | RHEL 9 Rule |
|---|---|
| `rsyslog-default-permissions` | `rsyslog-file-permissions` |
| `journald-storage` | `journald-storage-persistent` |
| `journald-forward-syslog` | `journald-no-forward-syslog` |

#### 2f. Access Control (8 pairs)

| RHEL 8 Rule | RHEL 9 Rule |
|---|---|
| `accounts-no-uid-zero` | `root-only-uid0` |
| `root-gid` | `root-only-gid0` |
| `su-require-wheel` | `pam-wheel-su` |
| `inactive-password-lock` | `password-inactive` |
| `login-defs-pass-min-days` | `password-min-age` |
| `login-defs-pass-warn-age` | `password-warn-age` |
| `login-defs-encrypt-method` | `password-hashing-algorithm` |
| `login-defs-umask` | `umask-default` |

#### 2g. Other Pairs

| RHEL 8 Rule | RHEL 9 Rule |
|---|---|
| `service-enable-firewalld` | `nftables-installed` |
| `service-disable-debug-shell` | `debug-shell-disabled` |
| `service-disable-kdump` | `kdump-disabled` |
| `package-ypserv-removed` | `pkg-ypserv-absent` |
| `package-xorg-x11-server-common-removed` | `xorg-removed` |
| `aide-cron-check` | `aide-scheduled` |
| `ssh-ciphers-fips` / `ssh-macs-fips` / `ssh-kex-fips` | `ssh-crypto-policy` |
| `audit-rules-immutable` | `audit-immutable` |
| `auditd-space-action` | `auditd-space-left-action` |
| `pam-pwquality-ucredit` | (correct rule at RHEL 9 target) |
| `pam-faillock-fail-interval` | `pam-faillock-deny` |
| `password-remember` | `pam-pwhistory-remember` |

---

### Category 3: One-Sided CIS References (228 rules)

65 rules have CIS references for RHEL 8 only. 163 rules have CIS references for RHEL 9 only.
Many are the "other half" of Category 2 pairs — the RHEL 8 rule doesn't carry RHEL 9's section
number because a separate rule was created for RHEL 9.

After Category 2 consolidation, the surviving rules should carry both RHEL 8 and RHEL 9 CIS
section numbers where the control exists in both benchmarks.

---

### Category 4: Remediation Quality Inconsistencies

Some duplicate pairs have different remediation quality:

| Pair | Better Mechanism | Weaker Mechanism |
|---|---|---|
| `no-world-writable-files` / `no-world-writable` | `file_permissions` (typed) | `manual` |
| `motd-permissions` (filesystem) / `motd-permissions` (system) | `file_permissions` (typed) | `command` |
| Several `fs-permissions-*` / `etc-*-permissions` pairs | varies | varies |

The consolidated rule must use the better (typed) mechanism.

---

## 3. Consolidation Strategy

### For each duplicate pair

1. **Choose the surviving rule** — prefer the better-named rule (usually RHEL 9 naming is cleaner)
2. **Merge CIS/STIG/NIST references** from the deleted rule into the surviving rule
3. **Use the better remediation mechanism** (typed over manual/command_exec)
4. **Update mapping files** — all `mappings/cis/`, `mappings/stig/` entries must point to the surviving rule ID
5. **Delete the superseded rule** file
6. **Remove `conflicts_with`** from the surviving rule (no longer needed)
7. **Run validation** — `schema/validate.py`, `scripts/cis_validate.py`, `pytest`

### Naming decisions

For each pair, decide which name survives. General principles:
- Prefer descriptive, control-focused names over implementation-focused names
- Prefer shorter names when equally descriptive
- Prefer names that don't embed framework-specific terminology

Suggested survivors for each subgroup:

| Pair | Survivor | Rationale |
|---|---|---|
| `fs-permissions-etc-passwd` / `etc-passwd-permissions` | `etc-passwd-permissions` | Shorter, cleaner |
| `no-world-writable-files` / `no-world-writable` | `no-world-writable` | Shorter, but take the typed remediation from the other |
| `service-disable-avahi-daemon` / `service-disable-avahi` | `service-disable-avahi` | Cleaner (avahi is the project name) |
| `service-disable-samba` / `service-disable-smb` | `service-disable-smb` | Matches systemd unit name |
| `audit-login-logout` / `audit-logins` | `audit-logins` | Already has `supersedes` |
| `accounts-no-uid-zero` / `root-only-uid0` | `root-only-uid0` | Describes the desired state |
| `rsyslog-default-permissions` / `rsyslog-file-permissions` | `rsyslog-file-permissions` | More descriptive |
| Sysctl per-interface rules | RHEL 9 consolidated names | Multi-check covers both interfaces |

---

## 4. Phased Execution

### Phase 1: True Duplicates (4 pairs) — Low risk

Remove the 4 cross-directory duplicates. These are clear-cut — same ID, two locations.

- Determine correct category
- Delete the wrong-category copy
- Verify no mapping references break

**Estimated scope:** 4 file deletions, mapping file updates

### Phase 2: Filesystem Permissions (12 pairs) — Low risk

These are straightforward `file_permission` checks. Merge references, keep the better rule,
delete the duplicate.

**Estimated scope:** 12 file deletions, 12 rule reference merges, mapping file updates

### Phase 3: Services + Access Control + Logging + Other (17 pairs) — Medium risk

Merge service disable, access control, logging, and misc pairs.

**Estimated scope:** ~17 file deletions, reference merges, mapping updates

### Phase 4: Audit Rules (8 pairs) — Medium risk

Some already have `supersedes:`. Merge references, delete old rules.

**Estimated scope:** ~8 file deletions, reference merges

### Phase 5: Sysctl Consolidation (18+ rules → ~8) — Higher complexity

CIS RHEL 8's per-interface controls vs RHEL 9's consolidated controls require careful
multi-check merging. The surviving rule needs to check both `conf.all` and `conf.default`
variants while carrying both RHEL 8 per-interface section refs and RHEL 9 consolidated refs.

**Estimated scope:** ~18 rules consolidated into ~8, complex reference merging

### Phase 6: SSH Crypto Pairs (3→1) — Needs review

`ssh-ciphers-fips`, `ssh-macs-fips`, `ssh-kex-fips` vs `ssh-crypto-policy`. These may be
genuinely different controls (individual algorithm checks vs system-wide crypto policy). Needs
careful review before consolidation.

**Estimated scope:** Review, possible consolidation of 3→1

---

## 5. Validation Checklist

After each phase:

- [ ] `python3 -m schema.validate rules/` — 0 failures
- [ ] `python3 scripts/cis_validate.py` — 0 gaps introduced
- [ ] `python3 scripts/cis_validate.py --mapping cis-rhel8-v4.0.0` — 0 gaps introduced
- [ ] `grep -r 'conflicts_with' rules/ | wc -l` — count should decrease
- [ ] All mapping files reference only existing rule IDs
- [ ] `pytest tests/` — all tests pass
- [ ] Coverage percentages unchanged (same controls, fewer rules)

---

## 6. Expected Outcome

| Metric | Before | After |
|---|---|---|
| Total rules | ~508 | ~450-460 |
| Rules with `conflicts_with` | ~110 | ~15-20 (only genuine conflicts like GDM rules vs gdm-removed) |
| Duplicate pairs | ~55 | 0 |
| Rules with single-version CIS refs | ~228 | Significantly reduced |
| Philosophy violations | Systemic | Resolved |

After consolidation, the rule set will properly embody the canonical rule model: one rule per
security control, framework references as metadata, no per-OS-version duplication.
