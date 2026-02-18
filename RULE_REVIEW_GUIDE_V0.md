# Rule Review Guide — Version 0

**Project:** Aegis
**Date:** 2026-02-17
**Status:** Draft
**Companion:** CANONICAL_RULE_SCHEMA_V0.md, TECHNICAL_REMEDIATION_MP_V0.md

---

## 1. Purpose

This document defines the criteria for reviewing Aegis canonical rules. Every rule
in `rules/` should be evaluated against these criteria to ensure correctness,
completeness, and alignment with the project's design philosophy.

A rule review is not a checkbox exercise. It requires understanding the control's
security intent, the system behavior it targets, and the difference between what a
static configuration file says and what the system actually enforces.

### When to Use This Guide

- **New rule creation.** Before a rule enters the canonical set.
- **Periodic rule audit.** Systematic review of existing rules for accuracy.
- **Post-incident review.** When a rule produces a false positive or false negative
  in production.
- **Framework update.** When a new benchmark version publishes and reference
  mappings need verification.

---

## 2. Review Dimensions

A rule review covers five dimensions, ordered by impact:

| #  | Dimension                  | Priority | Description                                        |
|----|----------------------------|----------|----------------------------------------------------|
| 1  | Check Accuracy             | Critical | Does the check measure what it claims to measure?  |
| 2  | Remediation Effectiveness  | Critical | Does the remediation produce the desired state?    |
| 3  | Schema Compliance          | High     | Does the rule conform to the canonical schema?     |
| 4  | Framework References       | Medium   | Are all applicable framework mappings present?     |
| 5  | Forward Compatibility      | Medium   | Will this rule work on future OS versions?         |

Check accuracy is listed first because an incorrect check undermines everything
downstream — the remediation, the report, and the auditor's trust in the tool.

---

## 3. Dimension 1: Check Accuracy

### 3.1 Effective vs. Static Configuration

**This is the single most important review criterion.**

Many system settings have two truths: the static configuration (what the file says)
and the effective configuration (what the system enforces). These can differ due to
include directives, drop-in overrides, runtime changes, or default values not
explicitly set in any file.

A check that reads only the static file can produce both false positives (file says
compliant, effective config is not) and false negatives (file says non-compliant, but
a drop-in overrides it to the correct value).

**Review question:** Does this check verify what the system actually enforces, or
only what a file contains?

#### Domain-Specific Guidance

| Domain | Static Source | Effective Source | How to Check Effective |
|--------|-------------|-----------------|----------------------|
| SSH | `/etc/ssh/sshd_config` | Resolved config after all includes | `sshd -T` (test mode) |
| SSH (user-specific) | `sshd_config` + `Match` blocks | Per-user resolved config | `sshd -T -C user=<user>,host=<host>` |
| Sysctl | `/etc/sysctl.conf`, `/etc/sysctl.d/*.conf` | Runtime kernel parameters | `sysctl -n <key>` |
| PAM | `/etc/pam.d/*` files | Authselect-managed stack | `authselect current`, then verify stack |
| Audit rules | `/etc/audit/rules.d/*.rules` | Loaded audit rules | `auditctl -l` |
| Firewall | Zone XML files, direct rules | Active firewall state | `firewall-cmd --list-all` |
| Crypto policy | `/etc/crypto-policies/config` | Active policy + submodules | `update-crypto-policies --show` |
| GRUB parameters | `/etc/default/grub`, BLS entries | Running kernel cmdline | `cat /proc/cmdline` |
| Mount options | `/etc/fstab` | Currently mounted options | `findmnt -n -o OPTIONS <mount>` |
| Systemd units | Unit files in `/etc/systemd/` | Effective unit config | `systemctl show <unit>` |
| SELinux | `/etc/selinux/config` | Runtime enforcement | `getenforce` |
| Login.defs | `/etc/login.defs` | Effective defaults | Direct file read (no override mechanism) |
| Limits | `/etc/security/limits.conf`, `/etc/security/limits.d/*.conf` | Effective limits | `ulimit` or `/proc/<pid>/limits` |

#### What Good Looks Like

**Ideal check pattern — verify both persistent and effective state:**

```yaml
check:
  checks:
    # Persistent: will survive reboot
    - method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "PermitRootLogin"
      expected: "no"
      scan_pattern: "*.conf"
    # Effective: what's enforced right now
    - method: command
      run: "sshd -T | grep -i '^permitrootlogin'"
      expected_stdout: "permitrootlogin no"
```

**Acceptable pattern — verify effective state only (when persistent config is
implied by the effective state):**

```yaml
check:
  method: sysctl_value
  key: "net.ipv4.ip_forward"
  expected: "0"
```

This works because `sysctl_value` reads from the kernel's runtime state. However,
a runtime-only check misses the case where the persistent config is wrong but the
runtime was manually corrected — the finding would return on reboot.

**Unacceptable pattern — static file only when overrides are possible:**

```yaml
# BAD: sshd_config may be overridden by sshd_config.d drop-ins
check:
  method: config_value
  path: "/etc/ssh/sshd_config"
  key: "PermitRootLogin"
  expected: "no"
```

#### Override Precedence Rules

When reviewing checks that read configuration files with include/drop-in
mechanisms, understand the precedence:

- **SSH:** Last match wins. A drop-in in `sshd_config.d/` loaded after the main
  `sshd_config` overrides it. Files in `sshd_config.d/` are processed in
  lexicographic order.
- **Sysctl:** Last value wins across all files in `/etc/sysctl.d/`, `/run/sysctl.d/`,
  `/usr/lib/sysctl.d/`, and `/etc/sysctl.conf`. Processed in lexicographic order
  within each directory.
- **PAM:** Stack order matters. Modules are evaluated top-to-bottom within each
  management group (auth, account, password, session).
- **Audit:** Rules are additive. Later rules do not override earlier ones — they
  add to the set. Immutable flag (`-e 2`) locks the set until reboot.
- **Systemd:** Drop-ins in `<unit>.d/` override the base unit file. Later drop-ins
  (lexicographic order) override earlier ones.

### 3.2 Check Method Selection

**Review question:** Is the check method the most appropriate for this control?

The `command` method is an escape hatch. Before accepting a `command` check, verify
that no typed method covers the case:

| If the check does this...                | Use this method instead of `command` |
|------------------------------------------|--------------------------------------|
| Reads a key=value from a config file     | `config_value`                       |
| Verifies a key is absent from config     | `config_absent`                      |
| Checks file ownership/permissions        | `file_permission`                    |
| Checks if a file exists                  | `file_exists` / `file_not_exists`    |
| Checks file content against a pattern    | `file_content_match`                 |
| Checks a systemd service state           | `service_state`                      |
| Checks if a package is installed         | `package_state`                      |
| Checks a sysctl kernel parameter         | `sysctl_value`                       |
| Checks a kernel module state             | `kernel_module_state`                |
| Checks mount options                     | `mount_option`                       |
| Checks an audit rule exists              | `audit_rule_exists`                  |
| Checks a GRUB boot parameter            | `grub_parameter`                     |
| Checks an SELinux boolean                | `selinux_boolean`                    |
| Checks SELinux enforcement mode          | `selinux_state`                      |

If `command` is genuinely necessary, document why in the rule's description or as
a YAML comment.

### 3.3 Evidence Quality

**Review question:** Does the check capture enough raw output for an auditor to
independently verify the result?

Good evidence is:
- **Unambiguous.** The output clearly shows the setting and its value.
- **Complete.** An auditor can confirm compliance without re-running the check.
- **Unforgeable.** The evidence comes from the system, not from Aegis's interpretation.

Watch for:
- `grep` patterns that match false positives (e.g., matching a comment line)
- Checks that report pass/fail without capturing the actual value
- Checks that only verify presence/absence without showing the current state

### 3.4 Multi-Condition Completeness

**Review question:** Does the check verify all conditions required for compliance?

Some controls have compound requirements. Examples:

- "Ensure auditd is installed AND enabled AND running" — needs `package_state` +
  `service_state`, not just one.
- "Ensure /tmp is a separate partition with nodev,nosuid,noexec" — needs
  `mount_option` for all three options, not just one.
- "Ensure PAM faillock is configured with deny=3 AND unlock_time=900" — needs
  checks for both parameters.

Use `checks:` (list with AND semantics) when multiple conditions must all be true.

---

## 4. Dimension 2: Remediation Effectiveness

### 4.1 Round-Trip Consistency

**Review question:** After remediation runs, will the check pass?

This is the fundamental contract. If the remediation sets `PermitRootLogin no` in
`sshd_config` but the check reads from `sshd -T` (effective config), they must
agree. If the remediation writes to the wrong file, uses the wrong separator, or
targets the wrong path, the check will still fail after remediation.

Verify:
- The `path`/`key`/`value` in remediation matches what the check reads.
- The `separator` matches the config file's format (space for sshd, `=` for sysctl,
  ` = ` for faillock.conf).
- After remediation, `reload`/`restart` triggers so the effective state reflects
  the change.

### 4.2 Mechanism Durability

**Review question:** Will this remediation survive package updates, authselect
changes, and reboots?

From Principle 5: "Prefer remediations that are durable, idempotent, and minimally
invasive."

Durability hierarchy (most durable first):

| Mechanism | Durability | Use When |
|-----------|-----------|----------|
| Drop-in file in `.d/` directory | Survives package updates (package restores main config, drop-in persists) | System supports `.d/` includes |
| Authselect feature | Survives authselect profile switches | PAM configuration on authselect systems |
| Dedicated config file (`/etc/sysctl.d/99-aegis.conf`) | Survives package updates | Sysctl, modprobe, audit rules |
| Direct edit to main config file | Overwritten by package updates | No `.d/` alternative exists |
| Runtime-only command | Lost on reboot | Never (unless paired with persistent change) |

**Red flags in remediation:**
- Editing `/etc/ssh/sshd_config` directly when `sshd_config_d` capability is true.
- Editing `/etc/sysctl.conf` instead of `/etc/sysctl.d/<name>.conf`.
- Editing PAM files directly when `authselect` capability is true.
- Setting a runtime value without persisting it to disk.

### 4.3 Idempotency

**Review question:** Is this remediation safe to run twice?

Every mechanism must be idempotent — running it N times produces the same result as
running it once. For declarative mechanisms (`config_set`, `file_permissions`,
`service_enabled`), idempotency is built in. For `command_exec`, idempotency must
be explicit:

```yaml
# GOOD: idempotent via unless guard
remediation:
  mechanism: command_exec
  run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
  unless: "test -f /var/lib/aide/aide.db.gz"

# BAD: no idempotency guard — runs every time
remediation:
  mechanism: command_exec
  run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
```

Every `command_exec` must have an `unless` or `onlyif` guard. If neither is
possible, the command must be inherently idempotent (e.g., `chmod 0644 /etc/passwd`).

### 4.4 Reboot Awareness

**Review question:** Does this remediation require a reboot to take effect?

Some changes are not effective until reboot:

| Change Type | Effective Immediately? | Notes |
|-------------|----------------------|-------|
| Config file edit + service reload | Yes (after reload) | Most common case |
| Sysctl set via `sysctl -w` | Yes (runtime) | Persistent file also needed |
| Kernel module blacklist | No | Module may be loaded; unload requires reboot if in use |
| GRUB boot parameter | No | Takes effect on next boot |
| Mount option in fstab | Partial | `mount -o remount` for mounted fs; new mounts need reboot |
| SELinux mode change | Partial | `setenforce` for runtime; `/etc/selinux/config` for persistent |
| Audit immutable flag (`-e 2`) | Lock takes effect immediately | New rules require reboot when locked |
| PAM changes | Yes | Affects next authentication attempt |
| Firewall rule changes | Yes | Via `firewall-cmd --permanent` + `--reload` |

Rules for controls that require reboot should:
1. Set the persistent configuration (so it takes effect on next boot).
2. Attempt to set the runtime state if possible (e.g., `sysctl -w` for sysctl,
   `setenforce` for SELinux).
3. Note the reboot requirement — the check may still report a mismatch between
   persistent and runtime state until reboot occurs.

### 4.5 Multi-Step Ordering

**Review question:** Are multi-step remediations in the correct order?

Steps execute sequentially and fail-fast. Common ordering requirements:

- Package install before configuration (can't configure what isn't installed).
- Configuration before service enable (don't start with bad config).
- Service reload/restart after configuration change.
- `aide --init` after AIDE package install.
- `authselect enable-feature` after verifying authselect is active.

### 4.6 Conflict and Dependency Awareness

**Review question:** Does this rule declare its dependencies and conflicts?

- If remediation depends on another rule (e.g., `aide-periodic-check` needs
  `aide-installed`), `depends_on` must be set.
- If two rules are mutually exclusive (e.g., direct PAM edit vs. authselect
  management), `conflicts_with` must be set.
- If a rule replaces an older rule, `supersedes` must be set.

The execution engine uses `depends_on` for ordering. Missing dependencies cause
remediation failures that are hard to diagnose.

---

## 5. Dimension 3: Schema Compliance

### 5.1 Required Fields

Every rule must have all required fields per CANONICAL_RULE_SCHEMA_V0.md:

| Field | Type | Requirement |
|-------|------|-------------|
| `id` | string | Globally unique, kebab-case, matches filename |
| `title` | string | Imperative voice, under 100 characters |
| `description` | string | 2-4 sentences: what the rule enforces and security context |
| `rationale` | string | Security justification: why an attacker exploits absence |
| `severity` | enum | `critical`, `high`, `medium`, `low` — Aegis's own assessment |
| `category` | string | Must match parent directory name |
| `tags` | list | Free-form labels including primary service/subsystem |
| `references` | object | Framework cross-references (see Dimension 4) |
| `platforms` | list | OS family and version scope |
| `implementations` | list | At least one, exactly one with `default: true` |

### 5.2 Severity Assessment

**Review question:** Is the severity Aegis's own assessment, not a copy of a
framework's rating?

Aegis severity is independent of CIS Level (L1/L2) and STIG Category (CAT I/II/III).
A control may be CIS L2 but Aegis `high` if the security impact warrants it.

| Severity | Criteria |
|----------|----------|
| `critical` | Exploitation leads to immediate, complete system compromise. No root password, world-writable `/etc/shadow`. |
| `high` | Exploitation leads to significant privilege escalation or unauthorized access. SSH root login, no audit logging. |
| `medium` | Exploitation weakens security posture but requires additional conditions. Weak password policy, missing mount options. |
| `low` | Defense-in-depth measure. Absence does not directly enable compromise. Banner text, log compression. |

### 5.3 Naming Conventions

- **`id`:** `{scope}-{action}-{target}` or `{scope}-{target}-{property}`.
  Examples: `ssh-disable-root-login`, `sysctl-net-ipv4-ip-forward`.
- **`title`:** Imperative voice. "Disable SSH root login", not "SSH root login
  is disabled" or "Ensuring SSH root login is disabled".
- **Filename:** `{id}.yml` — must match the `id` field exactly.

### 5.4 Description and Rationale Quality

The `description` explains what the rule enforces for a system administrator. The
`rationale` explains why for an auditor. They serve different audiences and should
not duplicate each other.

**Description pattern:** "The [component] must [desired state]. [Context for why
this matters operationally]."

**Rationale pattern:** "Without this control, an attacker could [attack vector].
This [consequence] because [mechanism]."

---

## 6. Dimension 4: Framework References

### 6.1 Completeness

**Review question:** Does this rule reference every framework that includes this
control?

A rule that disables SSH root login should map to CIS, STIG, NIST 800-53, and
PCI-DSS — not just the framework it was originally written for.

Cross-reference sources:
- `mappings/cis/rhel9_v2.0.0.yaml` and `mappings/cis/rhel8_v4.0.0.yaml`
- `mappings/stig/rhel9_v2r7.yaml` and `mappings/stig/rhel8_v2r6.yaml`
- `mappings/nist/800-53_r5.yaml`
- `mappings/pci-dss/v4.0.yaml`
- `mappings/fedramp/moderate.yaml`

### 6.2 Accuracy

**Review question:** Are the framework identifiers correct?

- CIS section numbers change between benchmark versions. Verify against the mapping
  files, not from memory.
- STIG vuln_ids and stig_ids must match the published STIG.
- NIST control identifiers are stable but enhancement numbering (e.g., `AC-7(a)`)
  must be exact.

### 6.3 Consistency with Mapping Files

The rule's `references` section and the mapping files (`mappings/`) are two
representations of the same relationship. They must agree. If a mapping file says
section `5.2.3` maps to rule `ssh-disable-root-login`, then the rule's CIS
reference must list section `5.2.3`.

Use `scripts/sync_cis_mappings.py` and `scripts/cis_validate.py` to detect
discrepancies programmatically.

---

## 7. Dimension 5: Forward Compatibility

### 7.1 Platform Scope

**Review question:** Is the platform scope as broad as it can be?

From Principle 6: "A new OS version should require only its genuinely new
exceptions."

- Prefer `min_version: 8` with no `max_version` (open-ended forward compatibility).
- Set `max_version` only when a feature is genuinely removed in a later version
  (e.g., `pam_tally2` removed in RHEL 9).
- Never set `max_version` based on "we haven't tested on RHEL 10 yet."

### 7.2 Implementation Gating

**Review question:** Are implementation variants gated by capabilities, not version
numbers?

From Principle 2: "Target capabilities, not version strings."

- `when: sshd_config_d` is correct.
- `when: rhel9` is wrong (and not a valid capability).

If a rule needs behavior that genuinely differs by OS version, the difference should
be expressed through a capability that captures the behavioral difference, not the
version number.

### 7.3 RHEL Derivative Coverage

**Review question:** Will this rule work on Rocky Linux, AlmaLinux, CentOS Stream,
and Oracle Linux?

Rules targeting `family: rhel` automatically include derivatives (the `derivatives`
field defaults to `true`). The capability detection system normalizes these
distributions to `family: rhel`. No rule should contain distribution-specific logic
unless it addresses a genuine behavioral difference in a derivative.

---

## 8. Common Defects

Patterns frequently found during rule review, ordered by frequency:

### 8.1 Static-Only SSH Checks

**Defect:** Check reads `/etc/ssh/sshd_config` without accounting for
`sshd_config.d/` drop-in overrides.

**Impact:** False negatives when a drop-in overrides the main config. False
positives when the main config appears compliant but a drop-in changes it.

**Fix:** Use `sshd -T` for effective config verification, or ensure the
capability-gated implementation reads the correct source.

### 8.2 Missing Idempotency Guards

**Defect:** `command_exec` remediation without `unless` or `onlyif`.

**Impact:** Remediation runs every time, potentially causing side effects (e.g.,
reinitializing an AIDE database, regenerating GRUB config unnecessarily).

**Fix:** Add appropriate guard condition.

### 8.3 Incomplete Multi-Condition Checks

**Defect:** A control requires multiple conditions but the check verifies only one.

**Impact:** Partial compliance reported as full compliance.

**Fix:** Add `checks:` list with all required conditions.

### 8.4 Wrong Separator in Config Set

**Defect:** Remediation uses `separator: " "` (space) but the config file uses `=`
or ` = `.

**Impact:** Remediation writes syntactically incorrect config, potentially breaking
the service.

**Fix:** Verify the separator matches the target config file format.

### 8.5 Missing Service Reload After Config Change

**Defect:** Config file is modified but no `reload` or `restart` triggers.

**Impact:** Change is persisted but not effective until the next service restart
(which may be never, or may be at an unexpected time).

**Fix:** Add `reload` (preferred) or `restart` to the remediation.

### 8.6 Severity Copied from Framework

**Defect:** Aegis `severity` is set to match CIS Level or STIG Category rather
than Aegis's own assessment.

**Impact:** Misleading severity when frameworks disagree. CIS L2 does not
automatically mean Aegis `medium`.

**Fix:** Assess severity independently using the criteria in Section 5.2.

### 8.7 Missing Framework References

**Defect:** Rule maps to CIS but not STIG, NIST, or PCI-DSS even though the
control exists in those frameworks.

**Impact:** Coverage gaps in framework reports. The rule runs, but the result
doesn't appear in the STIG or NIST report.

**Fix:** Cross-reference all mapping files and add missing references.

### 8.8 Overly Narrow Platform Scope

**Defect:** Rule sets `max_version: 9` without justification.

**Impact:** Rule excluded from RHEL 10+ runs even though the control is still
applicable.

**Fix:** Remove `max_version` unless the controlled feature was genuinely removed.

---

## 9. Review Workflow

### 9.1 Per-Rule Review

For each rule file, work through the five dimensions in order:

1. **Check accuracy.** Read the check(s). For each one, ask: does this verify the
   effective system state? Refer to the domain-specific guidance in Section 3.1.

2. **Remediation effectiveness.** Trace the remediation to the check. After
   remediation runs, will the check pass? Is the mechanism durable? Is it
   idempotent? Does it need a reboot?

3. **Schema compliance.** Verify required fields, naming conventions, severity
   assessment, description and rationale quality.

4. **Framework references.** Cross-check against mapping files. Are all applicable
   frameworks referenced? Are identifiers correct?

5. **Forward compatibility.** Is the platform scope appropriately broad? Are
   capability gates used instead of version checks?

### 9.2 Category-Level Review

When reviewing a full category (e.g., all rules in `rules/access-control/`):

- Check for missing `depends_on` relationships between related rules.
- Check for missing `conflicts_with` between mutually exclusive approaches.
- Verify consistent use of capabilities across similar rules (e.g., all SSH rules
  should gate on `sshd_config_d` the same way).
- Look for rules that should exist but don't (coverage gaps).

### 9.3 Tracking Review Status

Track review progress per category. A rule has been reviewed when all five
dimensions have been evaluated and any defects have been either fixed or documented.

| Category | Rules | Reviewed | Defects Found | Defects Fixed |
|----------|-------|----------|---------------|---------------|
| access-control | 114 | 114 | 78 | 78 (PRs #13-#20) |
| audit | 92 | 92 | ~146 | ~146 (PRs #21-#28) |
| services | 92 | | | |
| system | 56 | | | |
| filesystem | 51 | | | |
| network | 42 | | | |
| kernel | 19 | | | |
| logging | 18 | | | |

---

## 10. References

- **CANONICAL_RULE_SCHEMA_V0.md** — Rule schema specification (field definitions,
  check methods, remediation mechanisms, capability reference)
- **TECHNICAL_REMEDIATION_MP_V0.md** — Design philosophy (six principles, three-layer
  architecture, capability detection model)
- **schema/rule.schema.json** — Machine-validatable JSON Schema for rule files
- **scripts/cis_validate.py** — Automated CIS reference validation
- **scripts/sync_cis_mappings.py** — Automated mapping consistency checks

---

*This document defines the review criteria for Aegis canonical rules. It is the
quality gate between authored rules and the canonical set. Every rule should meet
these criteria before being considered production-ready.*
