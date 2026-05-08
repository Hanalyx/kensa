# Canonical Rule Schema Specification — Version 1

**Project:** Kensa
**Date:** 2026-04-13
**Status:** Draft
**Supersedes:** `CANONICAL_RULE_SCHEMA_V0.md` (retained for historical reference)
**Companion:** `TECHNICAL_REMEDIATION_MP_V1.md`, `RULE_REVIEW_GUIDE_V1.md`, `TRANSACTION_CONTRACT_V1.md`

---

## 0. What Changed from V0

V0 defined the canonical rule as the atomic unit of compliance automation: a
framework-independent YAML declaration of desired system state, with its own check,
remediation, framework references, and capability-gated implementations. V1 preserves all
of that.

V1 adds three things:

1. **An `atomicity` declaration on every rule.** A new optional top-level field,
   `transactional`, that defaults to `true`. It declares whether the rule's remediation
   can be applied as an all-or-nothing transaction. Rules that include non-capturable
   mechanisms (`command_exec`, `manual`, `grub_parameter_*`) must set this to `false`.

2. **Cross-step atomicity as the default contract.** V0 stated that in multi-step
   remediations, "earlier steps are not rolled back automatically." V1 flips this: all
   steps within a rule execute atomically, and failure of any step triggers rollback of
   all prior successful steps using captured pre-state. Rules that cannot honor this —
   those with `transactional: false` — declare the boundary explicitly.

3. **Mechanism capturability classification.** Every mechanism in the reference tables is
   now classified as capturable or non-capturable. A capturable mechanism has a defined,
   tested procedure for recording pre-state and restoring it. The engine uses this
   classification to determine whether a rule's claimed `transactional: true` is
   structurally achievable.

No existing rule file is invalidated by these changes. The `transactional` field defaults
to `true`, which is correct for the majority of rules. Rules that already use
`command_exec` or `manual` must have `transactional: false` added as part of the V1
migration — a mechanical change, and one that surfaces existing escape hatches explicitly
rather than hiding them.

---

## 1. Overview

This document defines the schema for Kensa canonical rules — the atomic unit of
compliance automation described in the Technical Remediation Master Plan.

A canonical rule is a single, framework-independent statement of desired system state. It
carries its own check logic, remediation logic, framework cross-references, and
capability-gated implementation variants. It is written once and applies across all
supported OS versions and compliance frameworks.

Rules are authored in YAML. Each rule lives in its own file under the `rules/` directory,
organized by category.

Rules are **inputs to the transaction engine.** The rule declares desired state and the
remediation mechanisms that produce it. The engine wraps every remediation in a
transaction (capture → apply → validate → commit-or-rollback) and guarantees that the
rule either commits completely or rolls back to the pre-change state. The rule YAML does
not express capture, validation, or rollback — those are engine concerns. The rule
expresses *what*. The engine provides *how* and *guarantees*.

### Design Principles

1. **Human-readable first.** A compliance engineer who has never seen this schema should
   be able to read a rule file and understand what it enforces, how it checks, and how
   it remediates. YAML was chosen for this reason.

2. **Declarative, not procedural.** Rules declare desired state and the mechanism to
   achieve it. They do not contain imperative scripts. The `command_exec` mechanism
   exists as an escape hatch; its use forfeits the atomicity guarantee and is tracked
   and minimized.

3. **The common case should be simple.** A rule that sets a single config value on all
   platforms should be ~20 lines of YAML. The schema should not impose ceremony on
   straightforward controls.

4. **The complex case should be possible.** Capability-gated variants, multi-step
   remediations, and cross-rule dependencies must be expressible without breaking the
   schema.

5. **Machine-validatable.** A JSON Schema (`schema/rule.schema.json`) provides formal
   validation. Every rule file must pass schema validation before it enters the
   canonical set.

6. **Atomic by construction.** A rule's remediation steps execute as a single
   transaction unless the rule explicitly declares `transactional: false`. The schema
   surfaces the atomicity boundary — it does not hide it. A reviewer can tell, from the
   rule YAML alone, whether the rule will run atomically.

---

## 2. File Organization

```
rules/
├── access-control/
├── audit/
├── filesystem/
├── kernel/
├── logging/
├── network/
├── services/
└── system/
```

**Naming convention:** `{category-prefix}-{descriptive-kebab-case}.yml`

The category prefix is a short mnemonic, not the directory name repeated. This keeps
filenames scannable when listed flat (e.g., in search results or git logs).

---

## 3. Schema Reference

### 3.1 Top-Level Structure

```yaml
# Required metadata
id: string                    # Unique rule identifier (kebab-case)
title: string                 # Human-readable title (imperative: "Disable X")
description: string           # What this rule enforces and why (2-4 sentences)
rationale: string             # Security justification for this control

# Classification
severity: enum                # critical | high | medium | low
category: string              # Top-level category (matches directory)
tags: [string]                # Additional classification labels

# Atomicity declaration (new in V1)
transactional: bool           # Optional. Default: true.
                              # Set to false if any step uses a non-capturable mechanism.

# Framework cross-references
references: object            # Framework mappings (see 3.3)

# Platform scope
platforms: [object]           # Which OS families/versions this applies to (see 3.4)

# Capability-gated implementations
implementations: [object]     # Check + remediation variants (see 3.5)

# Inter-rule relationships (optional)
depends_on: [string]          # Rule IDs that must be satisfied first
conflicts_with: [string]      # Rule IDs that are mutually exclusive
supersedes: [string]          # Rule IDs this rule replaces (for evolution)
```

### 3.2 Field Definitions — Metadata

#### `id` (string, required)

Globally unique identifier. Kebab-case. Stable across versions — once assigned, an ID
never changes. IDs are never reused.

Format: `{scope}-{action}-{target}` or `{scope}-{target}-{property}`.

#### `title` (string, required)

Concise, imperative description. "Disable SSH root login", not "SSH root login is
disabled". Maximum 100 characters.

#### `description` (string, required)

2-4 sentence explanation of what the rule enforces and its security context.

#### `rationale` (string, required)

Security justification. Why would an attacker exploit the absence of this control? What
risk does the control mitigate?

#### `severity` (enum, required)

Kensa's own assessment, independent of framework ratings.

| Value      | Meaning                                                        |
|------------|----------------------------------------------------------------|
| `critical` | Immediate, complete system compromise.                         |
| `high`     | Significant privilege escalation or unauthorized access.       |
| `medium`   | Weakens security posture; requires additional conditions.      |
| `low`      | Defense-in-depth measure.                                       |

#### `category` (string, required)

Must match one of the directory names under `rules/` (`access-control`, `audit`,
`filesystem`, `kernel`, `logging`, `network`, `services`, `system`).

#### `tags` (list of strings, optional)

Free-form labels. Recommended tags include the primary service or subsystem.

#### `transactional` (boolean, optional — NEW IN V1)

Declares whether this rule's remediation can be applied as an atomic transaction.

| Value   | Meaning                                                                   |
|---------|---------------------------------------------------------------------------|
| `true`  | (Default.) All steps execute atomically. If any step fails, prior steps  |
|         | are rolled back using captured pre-state. System ends in the target      |
|         | state or the exact pre-change state.                                      |
| `false` | At least one step uses a non-capturable mechanism. Atomicity cannot be   |
|         | guaranteed. The rule is still useful, but operators running it accept    |
|         | that a mid-rule failure may leave earlier successful steps applied.      |

**When to set `transactional: false`:**

The field **must** be set to `false` if any step uses:

- `command_exec` (arbitrary command — pre-state cannot be inferred)
- `manual` (requires human intervention — no machine pre-state)
- `grub_parameter_set` or `grub_parameter_remove` (bootloader state is not
  reliably reversible mid-boot)

The field **may** remain `true` (or be omitted, defaulting to `true`) only if every step
in every implementation uses a capturable mechanism. See Section 3.5.3 for the full
classification.

**Why this field is explicit rather than inferred:** The engine could compute this from
the mechanism table, and it does — the RESOLVE phase flags any mismatch between the
declared `transactional` value and the structural capturability of the rule's steps. But
the declaration in the YAML serves two purposes: (1) it forces the rule author to
consciously decide whether they are writing an atomic rule or an escape-hatch rule, and
(2) it makes the atomicity scope visible to reviewers without requiring them to look up
every mechanism.

A rule that declares `transactional: true` but contains a non-capturable step is a
schema violation. The validator rejects it.

### 3.3 Field Definitions — References

The `references` section maps this rule to external framework identifiers. The V0
structure carries forward unchanged:

```yaml
references:
  cis:
    rhel8: { section: "5.2.10", level: "L1", type: "Automated", profile: "..." }
    rhel9: { section: "5.2.3",  level: "L1", type: "Automated", profile: "..." }
  stig:
    rhel8: { vuln_id: "V-230296", rule_id: "...", stig_id: "...", severity: "CAT II", cci: ["CCI-000770"] }
    rhel9: { vuln_id: "V-257947", rule_id: "...", stig_id: "...", severity: "CAT II", cci: ["CCI-000770"] }
  nist_800_53: ["AC-6(2)", "AC-17(2)", "IA-2(5)"]
  pci_dss_4:   ["2.2.6", "8.6.1"]
  iso27001_2022: ["A.8.9"]
  cmmc_l2:     ["AC.L2-3.1.12"]
  hipaa:       ["164.312(a)(1)"]
  srg:         ["SRG-OS-000109-GPOS-00056"]
```

**Key design decisions** (unchanged from V0):

- CIS and STIG references are objects because they carry version-specific metadata.
- Other frameworks use flat lists because their identifiers are stable across OS
  versions.
- CIS/STIG keys use a `{os}{version}` pattern. Each key tracks the current benchmark
  version for that OS.

### 3.4 Field Definitions — Platforms

```yaml
platforms:
  - family: rhel
    min_version: 8
    # max_version: 10          # Optional. Omit for open-ended forward compatibility.
    # derivatives: true        # Default: true.
```

| Field         | Type    | Required | Description                               |
|---------------|---------|----------|-------------------------------------------|
| `family`      | enum    | yes      | `rhel`, `debian`, `suse` (V1: rhel only)  |
| `min_version` | integer | yes      | Minimum major version (inclusive)          |
| `max_version` | integer | no       | Maximum major version (inclusive)          |
| `derivatives` | boolean | no       | Default: `true`                            |

### 3.5 Field Definitions — Implementations

The `implementations` section contains one or more check+remediation pairs, each
optionally gated by a capability condition.

```yaml
implementations:
  - when: sshd_config_d              # Capability gate (optional)
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "PermitRootLogin"
      expected: "no"
      scan_pattern: "*.conf"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-kensa-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"

  - default: true                     # Default implementation
    check:
      method: config_value
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      expected: "no"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"
```

#### 3.5.1 Implementation Selection

Implementations are evaluated top-to-bottom. The first whose `when` condition is
satisfied by the target system's capability set is selected. Every rule must have
exactly one `default: true` implementation.

#### 3.5.2 `when` — Capability Gates

`when` may be a single capability, an `all:` list (AND), an `any:` list (OR), or a `not:`
expression. Most rules use a single capability or none at all.

```yaml
when: sshd_config_d                          # Single capability

when:
  all: [authselect, pam_faillock]            # All must be true

when:
  any: [crypto_policy_modules, fips_mode]    # Any must be true

when:
  not: systemd_resolved                      # Negation
```

#### 3.5.3 Check Methods

The V0 check method table carries forward unchanged. Check methods are read-only — they
do not participate in the atomicity model because they do not mutate system state.

| Method                 | Purpose                                    | Key Fields                              |
|------------------------|--------------------------------------------|-----------------------------------------|
| `config_value`         | Key=value in a config file                 | `path`, `key`, `expected`               |
| `config_absent`        | Key must NOT exist in config               | `path`, `key`                           |
| `file_permission`      | File/directory ownership and mode          | `path`, `owner`, `group`, `mode`        |
| `file_exists`          | File must exist                            | `path`                                  |
| `file_not_exists`      | File must not exist                        | `path`                                  |
| `file_content_match`   | File content matches pattern               | `path`, `pattern` (regex)               |
| `file_content_no_match`| File content must NOT match pattern        | `path`, `pattern` (regex)               |
| `service_state`        | Systemd service state                      | `name`, `enabled`, `active`             |
| `package_state`        | Package installed or absent                | `name`, `state`                         |
| `sysctl_value`         | Kernel parameter value                     | `key`, `expected`                       |
| `kernel_module_state`  | Kernel module loaded/blacklisted           | `name`, `state`                         |
| `mount_option`         | Mount point has required options           | `mount_point`, `options` (list)         |
| `audit_rule_exists`    | Audit rule is present                      | `rule` (string or pattern)              |
| `grub_parameter`       | Kernel boot parameter set                  | `key`, `expected` (optional)            |
| `selinux_boolean`      | SELinux boolean value                      | `name`, `expected`                      |
| `selinux_state`        | SELinux enforcement mode                   | `expected`                              |
| `pam_module`           | PAM module configured in stack             | `service`, `type`, `module`, `args`     |
| `command`              | Arbitrary command (escape hatch)           | `run`, `expected_exit`, `expected_stdout`|

Multi-condition checks use a `checks:` list with AND semantics.

#### 3.5.4 Remediation Mechanisms

Every mechanism is classified as **capturable** or **non-capturable**. The engine uses
this classification to enforce the `transactional` declaration.

**Capturable mechanisms.** These have defined capture and rollback handlers. A rule
composed entirely of capturable mechanisms can be `transactional: true`.

| Mechanism              | Purpose                                      | Key Fields                              |
|------------------------|----------------------------------------------|-----------------------------------------|
| `config_set`           | Set key=value in a config file               | `path`, `key`, `value`, `separator`     |
| `config_set_dropin`    | Set key=value in a .d drop-in file           | `dir`, `file`, `key`, `value`           |
| `config_remove`        | Remove or comment out a key                  | `path`, `key`                           |
| `config_block`         | Ensure a multiline block exists              | `path`, `block`, `marker`               |
| `file_permissions`     | Set owner, group, mode                       | `path`, `owner`, `group`, `mode`        |
| `file_absent`          | Delete a file                                | `path`                                  |
| `file_content`         | Write specific content to a file             | `path`, `content`, `owner`, `group`, `mode` |
| `service_enabled`      | Enable and start a service                   | `name`                                  |
| `service_disabled`     | Disable and stop a service                   | `name`                                  |
| `service_masked`       | Mask a service                               | `name`                                  |
| `package_present`      | Install a package                            | `name`                                  |
| `package_absent`       | Remove a package                             | `name`                                  |
| `sysctl_set`           | Set a kernel parameter (persisted)           | `key`, `value`, `persist_file`          |
| `kernel_module_disable`| Blacklist a kernel module                    | `name`                                  |
| `mount_option_set`     | Set mount options in fstab                   | `mount_point`, `options` (list)         |
| `pam_module_configure` | Configure PAM via authselect or direct edit  | `module`, `type`, `control`, `args`     |
| `audit_rule_set`       | Add an audit rule                            | `rule`, `persist_file`                  |
| `selinux_boolean_set`  | Set an SELinux boolean                       | `name`, `value`, `persistent`           |
| `cron_job`             | Create a cron job or systemd timer           | `schedule`, `command`, `user`           |

**Non-capturable mechanisms (escape hatches).** A rule that uses any of these must
declare `transactional: false`.

| Mechanism               | Purpose                                     | Why Non-Capturable                        |
|-------------------------|---------------------------------------------|-------------------------------------------|
| `command_exec`          | Run an arbitrary command                    | Pre-state cannot be inferred from command |
| `manual`                | No automated remediation                    | Requires human intervention               |
| `grub_parameter_set`    | Set a kernel boot parameter                 | Bootloader state not reliably reversible  |
| `grub_parameter_remove` | Remove a kernel boot parameter              | Bootloader state not reliably reversible  |

#### 3.5.5 Multi-Step Remediations — Atomicity Semantics (CHANGED FROM V0)

Some rules require ordered steps:

```yaml
remediation:
  steps:
    - mechanism: package_present
      name: "aide"
    - mechanism: file_permissions
      path: "/var/lib/aide/aide.db.gz"
      owner: "root"
      group: "root"
      mode: "0600"
```

**Steps execute as a single transaction.** The engine captures pre-state for every step
before any step runs. Steps then execute in order. If any step fails, the transaction
halts and every prior successful step is rolled back using its captured pre-state, in
reverse order. The rule is recorded as rolled-back.

**This is a change from V0.** V0 stated that earlier steps were not rolled back
automatically. V1 makes cross-step atomicity the default contract for rules declared
`transactional: true`.

**Rules that cannot honor atomicity** (those containing `command_exec`, `manual`, or
bootloader mechanisms) must declare `transactional: false`. For these rules:

- Capture still runs for any capturable steps.
- If a capturable step fails, prior capturable steps are rolled back.
- Non-capturable steps that have already run are not reversed. The rule is marked
  partially-applied in the transaction log.

The schema's contract with the operator is: *what you see is what you get.* A rule
declaring `transactional: true` is atomic. A rule declaring `transactional: false`
surfaces the escape hatch. There is no hidden third case.

#### 3.5.6 Mechanism Field Reference

The V0 field reference tables for each mechanism (`config_set`, `config_set_dropin`,
`sysctl_set`, `audit_rule_set`, `command_exec`, etc.) carry forward unchanged. See
`CANONICAL_RULE_SCHEMA_V0.md` §3.5 for the per-mechanism field tables; they are not
duplicated here.

### 3.6 Field Definitions — Relationships

`depends_on`, `conflicts_with`, and `supersedes` carry forward from V0 unchanged.

```yaml
depends_on:     [aide-installed]                 # Must be satisfied first
conflicts_with: [pam-faillock-direct]            # Mutually exclusive
supersedes:     [ssh-crypto-policy]              # Replaces older rule
```

---

## 4. Capabilities Reference

Capabilities are boolean facts about the target system, detected at runtime. They are
the controlled vocabulary that `when` gates reference.

The capability table (`sshd_config_d`, `authselect`, `crypto_policies`, `fips_mode`,
`firewalld_nftables`, `pam_faillock`, `grub_bls`, `selinux`, `aide`, `fapolicyd`, etc.)
carries forward from V0 Section 4 unchanged. See `CANONICAL_RULE_SCHEMA_V0.md` §4 for
the full table and detection logic.

Capabilities should be observable (single command or file check), stable during a run,
and binary (true or false).

---

## 5. Complete Examples

### 5.1 Category A — Identical Across All Versions (Atomic)

```yaml
# rules/kernel/sysctl-net-ipv4-ip-forward.yml

id: sysctl-net-ipv4-ip-forward
title: Disable IPv4 forwarding
description: >
  IP forwarding allows the system to act as a router, forwarding packets between
  network interfaces. On systems that are not designated routers, this must be
  disabled to prevent the system from being used to redirect network traffic.
rationale: >
  An attacker could use a compromised host with IP forwarding enabled to route
  traffic between otherwise segmented networks, bypassing firewall controls and
  enabling lateral movement.
severity: medium
category: kernel
tags: [sysctl, networking, ipv4, routing]

# transactional: true  (default — sysctl_set is capturable)

references:
  cis:
    rhel8:  { section: "3.3.1", level: "L1", type: "Automated" }
    rhel9:  { section: "3.3.1", level: "L1", type: "Automated" }
    rhel10: { section: "3.3.1", level: "L1", type: "Automated" }
  stig:
    rhel8: { vuln_id: "V-230537", stig_id: "RHEL-08-040259", severity: "CAT II" }
    rhel9: { vuln_id: "V-257963", stig_id: "RHEL-09-253010", severity: "CAT II" }
  nist_800_53: ["CM-7", "SC-5"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: sysctl_value
      key: "net.ipv4.ip_forward"
      expected: "0"
    remediation:
      mechanism: sysctl_set
      key: "net.ipv4.ip_forward"
      value: "0"
```

### 5.2 Category B — Capability-Gated (Atomic)

```yaml
# rules/access-control/ssh-disable-root-login.yml

id: ssh-disable-root-login
title: Disable SSH root login
description: >
  The SSH daemon must not permit direct login as the root account.
rationale: >
  Direct root login over SSH exposes the highest-privilege account to network
  brute-force attacks and eliminates the ability to attribute administrative
  actions to individual users.
severity: high
category: access-control
tags: [ssh, authentication, remote-access, privileged-access]

# transactional: true  (default — config_set and config_set_dropin are capturable)

references:
  cis:
    rhel8:  { section: "5.1.22", level: "L1", type: "Automated" }
    rhel9:  { section: "5.1.20", level: "L1", type: "Automated" }
  stig:
    rhel8: { vuln_id: "V-230296", stig_id: "RHEL-08-010550", severity: "CAT II" }
    rhel9: { vuln_id: "V-257947", stig_id: "RHEL-09-255045", severity: "CAT II" }
  nist_800_53: ["AC-6(2)", "AC-17(2)", "IA-2(5)"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - when: sshd_config_d
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "PermitRootLogin"
      expected: "no"
      scan_pattern: "*.conf"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-kensa-permit-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"

  - default: true
    check:
      method: config_value
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      expected: "no"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      value: "no"
      separator: " "
      reload: "sshd"
```

### 5.3 Multi-Step Remediation — Atomic

Every step uses a capturable mechanism. The rule remains `transactional: true`. If
step 2 fails, step 1 is rolled back automatically.

```yaml
# rules/access-control/faillock-configure-atomic.yml

id: faillock-configure
title: Configure faillock with deny threshold
description: >
  The faillock module must be configured with deny=3 and unlock_time=900.
severity: high
category: access-control
tags: [pam, faillock, account-lockout]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      checks:
        - method: config_value
          path: "/etc/security/faillock.conf"
          key: "deny"
          expected: "3"
        - method: config_value
          path: "/etc/security/faillock.conf"
          key: "unlock_time"
          expected: "900"
    remediation:
      steps:
        - mechanism: config_set
          path: "/etc/security/faillock.conf"
          key: "deny"
          value: "3"
          separator: " = "
        - mechanism: config_set
          path: "/etc/security/faillock.conf"
          key: "unlock_time"
          value: "900"
          separator: " = "
```

### 5.4 Multi-Step with Escape Hatch — Non-Atomic

Step 2 uses `command_exec` (authselect), which is non-capturable. The rule must declare
`transactional: false`. Operators running the rule see the escape hatch before execution.

```yaml
# rules/audit/aide-installed.yml

id: aide-installed
title: Install and initialize AIDE
description: >
  AIDE must be installed and its database initialized to provide filesystem
  integrity monitoring.
rationale: >
  Without file integrity monitoring, unauthorized modifications to critical
  system files may go undetected.
severity: medium
category: audit
tags: [aide, file-integrity, intrusion-detection]

transactional: false    # command_exec for `aide --init` is non-capturable

references:
  cis:
    rhel8:  { section: "1.3.1",  level: "L1", type: "Automated" }
    rhel9:  { section: "1.3.1",  level: "L1", type: "Automated" }
  stig:
    rhel8: { vuln_id: "V-230263", stig_id: "RHEL-08-010359", severity: "CAT II" }
    rhel9: { vuln_id: "V-257850", stig_id: "RHEL-09-651010", severity: "CAT II" }
  nist_800_53: ["SC-28", "SI-7"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      checks:
        - method: package_state
          name: "aide"
          state: "present"
        - method: file_exists
          path: "/var/lib/aide/aide.db.gz"
    remediation:
      steps:
        # Step 1: capturable (package_present has a rollback handler)
        - mechanism: package_present
          name: "aide"
        # Step 2: non-capturable (command_exec) — the escape hatch
        - mechanism: command_exec
          run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
          unless: "test -f /var/lib/aide/aide.db.gz"
```

If step 2 fails:
- Step 1 (`package_present: aide`) is rolled back — the package is uninstalled if it was
  not previously present.
- Step 2 is not rolled back (there is no reverse for `aide --init`).
- The rule is marked as partially-applied in the transaction log.

The operator sees `transactional: false` in the pre-run summary and knows this rule is
not atomic before executing it.

### 5.5 File Permissions — Atomic

```yaml
# rules/filesystem/fs-permissions-etc-shadow.yml

id: fs-permissions-etc-shadow
title: Set permissions on /etc/shadow
description: >
  The /etc/shadow file contains hashed passwords. It must be readable only by
  root to prevent offline password cracking attacks.
rationale: >
  If /etc/shadow is world-readable, any local user can copy the password hashes
  and run offline brute-force attacks.
severity: high
category: filesystem
tags: [file-permissions, passwords, authentication]

references:
  cis:
    rhel8:  { section: "7.1.3",  level: "L1", type: "Automated" }
    rhel9:  { section: "6.1.3",  level: "L1", type: "Automated" }
  stig:
    rhel8: { vuln_id: "V-230256", stig_id: "RHEL-08-010150", severity: "CAT II" }
    rhel9: { vuln_id: "V-257843", stig_id: "RHEL-09-232130", severity: "CAT II" }
  nist_800_53: ["AC-3", "MP-2"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: file_permission
      path: "/etc/shadow"
      owner: "root"
      group: "root"
      mode: "0000"
    remediation:
      mechanism: file_permissions
      path: "/etc/shadow"
      owner: "root"
      group: "root"
      mode: "0000"
```

---

## 6. Validation

### 6.1 JSON Schema

A formal JSON Schema is provided at `schema/rule.schema.json` for automated validation.
Every rule file must pass validation before being added to the canonical set.

```bash
kensa validate rules/access-control/ssh-disable-root-login.yml
kensa validate rules/
```

### 6.2 Validation Rules Beyond Schema

1. **ID uniqueness.** No two rule files may share the same `id`.
2. **File naming.** The filename must match the `id` field: `{id}.yml`.
3. **Category consistency.** The `category` field must match the parent directory name.
4. **Exactly one default implementation.** Each rule must have exactly one
   implementation with `default: true`.
5. **Capability references.** Every capability referenced in a `when` clause must exist
   in the capabilities reference.
6. **Dependency references.** Every rule ID in `depends_on`, `conflicts_with`, and
   `supersedes` must reference an existing rule.
7. **No orphan capabilities.** Capabilities defined in the reference but never used in
   any rule trigger a warning.
8. **Atomicity consistency (NEW IN V1).** If any step in any implementation uses a
   non-capturable mechanism, the rule must declare `transactional: false`. A rule
   declaring `transactional: true` that contains a non-capturable step is a schema
   violation — the validator rejects it with a clear error identifying which step is
   non-capturable.

---

## 7. Schema Evolution

V1 is the second version of the schema. The evolution policy:

- **Additive changes** (new optional fields, new mechanism types, new check methods) are
  non-breaking and can be made freely.
- **Breaking changes** (renaming fields, changing semantics, removing fields) require a
  schema version bump and a migration path for existing rules.
- The schema version is tracked in the JSON Schema file and in this document's title.
- All existing rule files must remain valid after any schema change. The V0→V1 migration
  is mechanical: rules using `command_exec`, `manual`, or `grub_parameter_*` gain
  `transactional: false`; all other rules need no change because `true` is the default.

### 7.1 V0 → V1 Migration

A migration script (`scripts/migrate_schema_v0_to_v1.py`) scans every rule file and:

1. Detects rules containing non-capturable mechanisms.
2. Adds `transactional: false` to those rules.
3. Leaves all other rules unchanged.
4. Runs the V1 validator on the result to confirm the migration is complete.

The migration is reviewed by a human before merging — the script produces a diff for
every modified rule, and the reviewer confirms that the non-capturable usage is
intentional (not a case that should be rewritten to use a capturable mechanism).

---

*This document defines the canonical rule schema for Kensa. It is the contract between
rule authors, the transaction engine, and the reporting system. V1 formalizes the
atomicity contract that was implicit in V0 and surfaces the escape-hatch boundary via
the `transactional` declaration.*
