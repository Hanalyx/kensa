# Canonical Rule Schema Specification — Version 0

**Project:** Aegis
**Date:** 2026-02-04
**Status:** Draft
**Companion:** TECHNICAL_REMEDIATION_MP_V0.md

---

## 1. Overview

This document defines the schema for Aegis canonical rules — the atomic unit of
compliance automation described in the Technical Remediation Master Plan.

A canonical rule is a single, framework-independent statement of desired system state.
It carries its own check logic, remediation logic, framework cross-references, and
capability-gated implementation variants. It is written once and applies across all
supported OS versions and compliance frameworks.

Rules are authored in YAML. Each rule lives in its own file under the `rules/`
directory, organized by category.

### Design Principles

1. **Human-readable first.** A compliance engineer who has never seen this schema should
   be able to read a rule file and understand what it enforces, how it checks, and how
   it remediates. YAML was chosen for this reason.

2. **Declarative, not procedural.** Rules declare desired state and the mechanism to
   achieve it. They do not contain imperative scripts. The `command_exec` mechanism
   exists as an escape hatch but its use is tracked and should be minimized.

3. **The common case should be simple.** A rule that sets a single config value on all
   platforms should be ~20 lines of YAML. The schema should not impose ceremony on
   straightforward controls.

4. **The complex case should be possible.** Capability-gated variants, multi-step
   remediations, and cross-rule dependencies must be expressible without breaking the
   schema.

5. **Machine-validatable.** A JSON Schema (`schema/rule.schema.json`) provides formal
   validation. Every rule file must pass schema validation before it enters the
   canonical set.

---

## 2. File Organization

```
rules/
├── access-control/
│   ├── ssh-disable-root-login.yml
│   ├── ssh-max-auth-tries.yml
│   ├── ssh-permit-empty-passwords.yml
│   ├── pam-faillock-deny.yml
│   └── ...
├── audit/
│   ├── audit-privileged-commands.yml
│   ├── audit-identity-changes.yml
│   └── ...
├── filesystem/
│   ├── fs-tmp-noexec.yml
│   ├── fs-home-nosuid.yml
│   └── ...
├── kernel/
│   ├── sysctl-net-ipv4-forwarding.yml
│   ├── kmod-disable-cramfs.yml
│   └── ...
├── logging/
│   ├── journald-storage-persistent.yml
│   ├── journald-compress.yml
│   └── ...
├── network/
│   ├── firewalld-default-zone-drop.yml
│   └── ...
├── services/
│   ├── svc-disable-rpcbind.yml
│   ├── svc-chrony-configured.yml
│   └── ...
└── system/
    ├── crypto-policy-minimum.yml
    ├── grub-password.yml
    └── ...
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

The globally unique identifier for this rule. Kebab-case. Stable across versions —
once assigned, an ID never changes. IDs are never reused.

Format: `{scope}-{action}-{target}` or `{scope}-{target}-{property}`

Examples:
- `ssh-disable-root-login`
- `sysctl-net-ipv4-ip-forward`
- `audit-privileged-commands`
- `pam-faillock-deny`
- `kmod-disable-cramfs`
- `fs-tmp-noexec`
- `svc-disable-rpcbind`
- `crypto-policy-minimum`

#### `title` (string, required)

A concise, imperative description of the desired state. Should read as a command:
"Disable SSH root login", not "SSH root login is disabled" or "Ensuring SSH root
login is disabled".

Maximum 100 characters.

#### `description` (string, required)

A 2-4 sentence explanation of what the rule enforces and its security context. Written
for a system administrator who needs to understand why this control exists.

#### `rationale` (string, required)

The security justification. Why would an attacker exploit the absence of this control?
What risk does the control mitigate? This field supports auditors who need to justify
the control's inclusion in a baseline.

#### `severity` (enum, required)

The rule's inherent severity, independent of any framework's rating.

| Value      | Meaning                                                        |
|------------|----------------------------------------------------------------|
| `critical` | Exploitation leads to immediate, complete system compromise.   |
|            | Examples: no root password, world-writable /etc/shadow.        |
| `high`     | Exploitation leads to significant privilege escalation or      |
|            | unauthorized access. Examples: SSH root login, no audit log.   |
| `medium`   | Exploitation weakens security posture but requires additional  |
|            | conditions. Examples: weak password policy, missing mount      |
|            | options.                                                       |
| `low`      | Defense-in-depth measure. Absence does not directly enable     |
|            | compromise. Examples: banner text, log compression settings.   |

This is Aegis's own severity assessment. Framework-specific severity (STIG CAT I/II/III,
CIS Level 1/2) is recorded in the `references` section as metadata.

#### `category` (string, required)

The top-level category. Must match one of the directory names under `rules/`:

| Category         | Scope                                                      |
|------------------|------------------------------------------------------------|
| `access-control` | Authentication, authorization, PAM, SSH, sudo, sessions    |
| `audit`          | Audit daemon, audit rules, log integrity                   |
| `filesystem`     | Mount options, partition layout, file permissions           |
| `kernel`         | Sysctl parameters, kernel modules, core dumps, ASLR        |
| `logging`        | Journald, rsyslog, log forwarding, log rotation            |
| `network`        | Firewall, network parameters, wireless, IPv6               |
| `services`       | Service hardening, NTP, cron, unnecessary services          |
| `system`         | Crypto policy, bootloader, SELinux, software updates, FIPS |

#### `tags` (list of strings, optional)

Free-form labels for filtering and grouping. No controlled vocabulary — tags emerge
from usage. Recommended tags include the primary service or subsystem:

```yaml
tags: [ssh, authentication, remote-access]
tags: [auditd, logging, privileged-access]
tags: [sysctl, networking, ipv4]
tags: [pam, authentication, account-lockout]
```

### 3.3 Field Definitions — References

The `references` section maps this rule to external framework identifiers. Every
framework entry is optional. A rule may map to zero frameworks (internal-only control)
or many.

```yaml
references:

  # CIS Benchmarks — keyed by "{os}{version}_v{benchmark_version}"
  cis:
    rhel8_v4:
      section: "5.2.10"
      level: "L1"                 # L1 | L2
      type: "Automated"           # Automated | Manual
      profile: "Level 1 - Server" # Primary profile
    rhel9_v2:
      section: "5.2.3"
      level: "L1"
      type: "Automated"
      profile: "Level 1 - Server"
    rhel10_v1:
      section: "5.1.4"
      level: "L1"
      type: "Automated"
      profile: "Level 1 - Server"

  # DISA STIGs — keyed by "{os}{version}_v{stig_version}"
  stig:
    rhel8_v2r6:
      vuln_id: "V-230296"
      rule_id: "SV-230296r1017040_rule"
      stig_id: "RHEL-08-010550"
      severity: "CAT II"           # CAT I | CAT II | CAT III
      cci: ["CCI-000770"]
    rhel9_v2r7:
      vuln_id: "V-257947"
      rule_id: "SV-257947r925888_rule"
      stig_id: "RHEL-09-255045"
      severity: "CAT II"
      cci: ["CCI-000770"]

  # Other frameworks — flat lists of control identifiers
  nist_800_53: ["AC-6(2)", "AC-17(2)", "IA-2(5)"]
  pci_dss_4: ["2.2.6", "8.6.1"]
  iso27001_2022: ["A.8.9"]
  cmmc_l2: ["AC.L2-3.1.12"]
  hipaa: ["164.312(a)(1)"]
  srg: ["SRG-OS-000109-GPOS-00056"]
```

**Key design decisions:**

- CIS and STIG references are objects (not flat lists) because they carry
  version-specific metadata (section numbers change across benchmark versions,
  severity ratings differ).

- Other frameworks (NIST, PCI-DSS, ISO) use flat lists because their identifiers
  are stable across OS versions. NIST AC-6(2) does not change when RHEL 10 ships.

- CIS/STIG keys use a `{os}{version}_v{benchmark_version}` pattern so that adding
  a new benchmark version is a new key, not a replacement. When CIS RHEL 9 v3.0.0
  publishes, it becomes `rhel9_v3` alongside the existing `rhel9_v2`.

### 3.4 Field Definitions — Platforms

The `platforms` section declares which operating systems this rule applies to.

```yaml
platforms:
  - family: rhel
    min_version: 8
    # max_version: 10          # Optional. Omit for "8 and all future versions."
    # derivatives: true        # Default: true. Includes CentOS Stream, Rocky,
                               # AlmaLinux, Oracle Linux.
```

| Field         | Type    | Required | Description                               |
|---------------|---------|----------|-------------------------------------------|
| `family`      | enum    | yes      | `rhel`, `debian`, `suse` (V0: rhel only)  |
| `min_version` | integer | yes      | Minimum major version (inclusive)          |
| `max_version` | integer | no       | Maximum major version (inclusive). Omit    |
|               |         |          | for open-ended forward compatibility.      |
| `derivatives` | boolean | no       | Include binary-compatible derivatives.     |
|               |         |          | Default: `true`.                           |

**Forward compatibility:** A rule with `min_version: 8` and no `max_version` applies to
RHEL 8, 9, 10, and any future version. The capability detection system handles
behavioral differences at runtime. `max_version` should only be set when a control is
genuinely inapplicable to newer versions (e.g., a control for a removed feature).

### 3.5 Field Definitions — Implementations

The `implementations` section is the heart of the rule. It contains one or more
check+remediation pairs, each optionally gated by a capability condition.

```yaml
implementations:
  # First matching implementation wins. Evaluated top to bottom.
  # Capability-gated variants come first; the default comes last.

  - when: sshd_config_d              # Capability gate (optional)
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "PermitRootLogin"
      expected: "no"
      scan_pattern: "*.conf"         # For .d directories
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-aegis-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"

  - default: true                     # Default implementation (no capability gate)
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

#### Implementation Selection

Implementations are evaluated top-to-bottom. The first whose `when` condition is
satisfied by the target system's capability set is selected. The `default: true`
implementation is selected if no capability-gated variant matches.

**Every rule must have exactly one `default: true` implementation.** This ensures that
the rule can execute on any platform within its declared `platforms` scope, even if
no specific capability is detected.

#### `when` — Capability Gates

The `when` field references one or more capabilities from the detection system.

```yaml
# Single capability
when: sshd_config_d

# Multiple capabilities (AND — all must be true)
when:
  all:
    - authselect
    - pam_faillock

# Multiple capabilities (OR — any must be true)
when:
  any:
    - crypto_policy_modules
    - fips_mode

# Negation
when:
  not: systemd_resolved
```

Most rules use a single capability or none at all. The `all`/`any`/`not` combinators
exist for the ~5% of rules that need them.

#### `check` — Verification

The `check` object defines how to verify that the system is in the desired state.

```yaml
check:
  method: enum          # Check method (see table below)
  # ... method-specific fields
```

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
| `package_state`        | Package installed or absent                | `name`, `state` (present/absent)        |
| `sysctl_value`         | Kernel parameter value                     | `key`, `expected`                       |
| `kernel_module_state`  | Kernel module loaded/blacklisted           | `name`, `state` (loaded/blacklisted)    |
| `mount_option`         | Mount point has required options           | `mount_point`, `options` (list)         |
| `audit_rule_exists`    | Audit rule is present                      | `rule` (string or pattern)              |
| `grub_parameter`       | Kernel boot parameter set                  | `key`, `expected` (optional)            |
| `selinux_boolean`      | SELinux boolean value                      | `name`, `expected` (on/off)             |
| `selinux_state`        | SELinux enforcement mode                   | `expected` (enforcing/permissive)       |
| `pam_module`           | PAM module configured in stack             | `service`, `type`, `module`, `args`     |
| `command`              | Arbitrary command (escape hatch)           | `run`, `expected_exit`, `expected_stdout`|

**Multi-condition checks:** Some rules need to verify multiple conditions. Use a list
of check objects within a `checks` field (AND semantics — all must pass):

```yaml
check:
  checks:
    - method: config_value
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      expected: "no"
    - method: service_state
      name: "sshd"
      enabled: true
      active: true
```

When a single `method` is present (the common case), it is equivalent to `checks`
with one entry. The engine normalizes both forms internally.

#### `remediation` — Enforcement

The `remediation` object defines how to bring the system into the desired state.

```yaml
remediation:
  mechanism: enum       # Remediation mechanism (see table below)
  # ... mechanism-specific fields
```

| Mechanism              | Purpose                                      | Key Fields                              |
|------------------------|----------------------------------------------|-----------------------------------------|
| `config_set`           | Set key=value in a config file               | `path`, `key`, `value`, `separator`     |
| `config_set_dropin`    | Set key=value in a .d drop-in file           | `dir`, `file`, `key`, `value`           |
| `config_remove`        | Remove or comment out a key                  | `path`, `key`                           |
| `config_block`         | Ensure a multiline block exists              | `path`, `block`, `marker`               |
| `file_permissions`     | Set owner, group, mode                       | `path`, `owner`, `group`, `mode`        |
| `file_absent`          | Delete a file                                | `path`                                  |
| `file_content`         | Write specific content to a file             | `path`, `content`, `owner`, `group`,    |
|                        |                                              | `mode`                                  |
| `service_enabled`      | Enable and start a service                   | `name`                                  |
| `service_disabled`     | Disable and stop a service                   | `name`                                  |
| `service_masked`       | Mask a service                               | `name`                                  |
| `package_present`      | Install a package                            | `name`                                  |
| `package_absent`       | Remove a package                             | `name`                                  |
| `sysctl_set`           | Set a kernel parameter (persisted)           | `key`, `value`, `persist_file`          |
| `kernel_module_disable`| Blacklist a kernel module                    | `name`                                  |
| `grub_parameter_set`   | Set a kernel boot parameter                  | `key`, `value` (optional)               |
| `grub_parameter_remove`| Remove a kernel boot parameter               | `key`                                   |
| `mount_option_set`     | Set mount options in fstab                   | `mount_point`, `options` (list)         |
| `pam_module_configure` | Configure PAM via authselect or direct edit  | `module`, `type`, `control`, `args`     |
| `audit_rule_set`       | Add an audit rule                            | `rule`, `persist_file`                  |
| `selinux_boolean_set`  | Set an SELinux boolean                       | `name`, `value` (on/off), `persistent`  |
| `cron_job`             | Create a cron job or systemd timer           | `schedule`, `command`, `user`           |
| `command_exec`         | Run an arbitrary command (escape hatch)      | `run`, `unless` (idempotency guard)     |
| `manual`               | No automated remediation — requires human     | `note` (guidance for the operator)      |
|                        | intervention with site-specific values        |                                         |

**Multi-step remediations:** Some rules require ordered steps. Use a `steps` list:

```yaml
remediation:
  steps:
    - mechanism: package_present
      name: "aide"
    - mechanism: command_exec
      run: "aide --init"
      unless: "test -f /var/lib/aide/aide.db.gz"
    - mechanism: cron_job
      schedule: "0 5 * * *"
      command: "/usr/sbin/aide --check"
      user: "root"
```

Steps execute in order. If any step fails, execution stops and the rule is marked
failed. Earlier steps are not rolled back automatically (rollback is handled at the
execution engine level, not the schema level).

When a single `mechanism` is present (the common case), it is equivalent to `steps`
with one entry.

#### Mechanism Field Reference

**Common fields** (available on all mechanisms):

| Field     | Type   | Required | Description                                    |
|-----------|--------|----------|------------------------------------------------|
| `reload`  | string | no       | Service to reload after change (systemctl       |
|           |        |          | reload). Use when config change is picked up    |
|           |        |          | by reload.                                      |
| `restart` | string | no       | Service to restart after change (systemctl      |
|           |        |          | restart). Use when full restart is required.     |
| `notify`  | string | no       | Named handler to trigger (for batching multiple |
|           |        |          | related restarts at end of run).                |

**`config_set` fields:**

| Field       | Type   | Required | Default | Description                         |
|-------------|--------|----------|---------|-------------------------------------|
| `path`      | string | yes      |         | Absolute path to config file        |
| `key`       | string | yes      |         | Configuration key/directive name    |
| `value`     | string | yes      |         | Desired value                       |
| `separator` | string | no       | " "     | Key-value separator (space, =, :)   |
| `create`    | bool   | no       | false   | Create file if it doesn't exist     |

**`config_set_dropin` fields:**

| Field   | Type   | Required | Description                                    |
|---------|--------|----------|------------------------------------------------|
| `dir`   | string | yes      | Path to the .d directory                       |
| `file`  | string | yes      | Filename for the drop-in (e.g., 00-aegis.conf) |
| `key`   | string | yes      | Configuration key/directive name               |
| `value` | string | yes      | Desired value                                  |

**`sysctl_set` fields:**

| Field          | Type   | Required | Default                       | Description           |
|----------------|--------|----------|-------------------------------|-----------------------|
| `key`          | string | yes      |                               | Sysctl parameter name |
| `value`        | string | yes      |                               | Desired value         |
| `persist_file` | string | no       | `/etc/sysctl.d/99-aegis.conf` | Persistence file      |

**`audit_rule_set` fields:**

| Field          | Type   | Required | Default                         | Description          |
|----------------|--------|----------|---------------------------------|----------------------|
| `rule`         | string | yes      |                                 | Full audit rule text |
| `persist_file` | string | no       | `/etc/audit/rules.d/aegis.rules`| Rules file           |

**`command_exec` fields:**

| Field    | Type   | Required | Description                                     |
|----------|--------|----------|-------------------------------------------------|
| `run`    | string | yes      | Command to execute                              |
| `unless` | string | no       | Idempotency guard — skip if this exits 0        |
| `onlyif` | string | no       | Precondition — run only if this exits 0         |

### 3.6 Field Definitions — Relationships

#### `depends_on` (list of strings, optional)

Rule IDs that must be satisfied (passing check) before this rule's remediation
can execute. The execution engine resolves dependencies and orders operations
accordingly.

```yaml
# aide-periodic-check depends on aide being installed
id: aide-periodic-check
depends_on:
  - aide-installed
```

Dependencies are for operational ordering, not logical grouping. Use them when one
rule's remediation would fail or be meaningless without another rule being in place.

#### `conflicts_with` (list of strings, optional)

Rule IDs that are mutually exclusive with this rule. The execution engine will flag
an error if both are included in a run.

```yaml
# Direct PAM editing conflicts with authselect-managed PAM
id: pam-faillock-direct
conflicts_with:
  - pam-faillock-authselect
```

#### `supersedes` (list of strings, optional)

Rule IDs that this rule replaces. Used for rule evolution — when a control is
reworked and the old rule ID should no longer be used.

```yaml
id: ssh-crypto-policy-v2
supersedes:
  - ssh-crypto-policy
```

---

## 4. Capabilities Reference

Capabilities are boolean facts about the target system, detected at runtime. This
is the controlled vocabulary that `when` gates reference.

### 4.1 Defined Capabilities

| Capability              | Detection Logic                                            | True When                          |
|-------------------------|------------------------------------------------------------|------------------------------------|
| `sshd_config_d`         | `/etc/ssh/sshd_config.d` exists AND `sshd_config`         | Drop-in SSH config is available    |
|                         | contains `Include /etc/ssh/sshd_config.d/*.conf`           | and active                         |
| `authselect`            | `authselect current` exits 0                               | System uses authselect for PAM     |
| `authselect_sssd`       | `authselect current` output contains `sssd`                | Active authselect profile is sssd  |
| `crypto_policies`       | `update-crypto-policies --show` exits 0                    | System-wide crypto policy active   |
| `crypto_policy_modules` | `/etc/crypto-policies/policies/modules` directory exists    | Subpolicy modules available        |
| `fips_mode`             | `fips-mode-setup --check` reports enabled                  | FIPS 140 mode is active            |
| `firewalld_nftables`    | `firewall-cmd --get-backend` returns `nftables`            | firewalld uses nftables backend    |
| `firewalld_iptables`    | `firewall-cmd --get-backend` returns `iptables`            | firewalld uses iptables backend    |
| `systemd_resolved`      | `systemctl is-enabled systemd-resolved` exits 0            | systemd-resolved manages DNS       |
| `pam_faillock`          | `/etc/security/faillock.conf` exists                       | faillock configured via file       |
| `grub_bls`              | `/boot/loader/entries/*.conf` exists                       | GRUB uses Boot Loader Spec         |
| `grub_legacy`           | `/boot/grub2/grub.cfg` exists AND no BLS entries           | GRUB uses legacy config            |
| `journald_primary`      | `systemctl is-enabled rsyslog` fails OR not installed      | journald is the primary log system |
| `rsyslog_active`        | `systemctl is-enabled rsyslog` exits 0                     | rsyslog is active                  |
| `fapolicyd`             | `rpm -q fapolicyd` exits 0                                 | fapolicyd is installed             |
| `selinux`               | `getenforce` returns `Enforcing` or `Permissive`           | SELinux is available               |
| `aide`                  | `rpm -q aide` exits 0                                      | AIDE is installed                  |
| `tpm2`                  | `/sys/class/tpm/tpm0` exists                               | TPM 2.0 hardware present           |
| `usbguard`              | `rpm -q usbguard` exits 0                                  | USBGuard is installed              |
| `dnf_automatic`         | `rpm -q dnf-automatic` exits 0                             | dnf-automatic is installed         |
| `gdm`                   | `rpm -q gdm` exits 0                                       | GNOME Display Manager installed    |
| `tmux`                  | `rpm -q tmux` exits 0                                      | tmux is installed                  |

### 4.2 Adding New Capabilities

New capabilities are added when a genuinely new platform behavior is discovered that
requires a different implementation path. The process:

1. Identify the behavior that varies across systems.
2. Define a detection command that reliably distinguishes the two cases.
3. Add the capability to this reference table.
4. Update rules that need the new capability gate.

Capabilities should be:
- **Observable** — detectable by a single command or file existence check.
- **Stable** — unlikely to change during a remediation run.
- **Binary** — true or false (not valued). If a value is needed, model it as
  multiple binary capabilities (e.g., `firewalld_nftables` and `firewalld_iptables`
  rather than a single `firewalld_backend` with a value).

---

## 5. Complete Examples

### 5.1 Category A — Identical Across All Versions

This is the most common pattern (~70-75% of rules). No capability gates. One
implementation. Simple.

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

references:
  cis:
    rhel8_v4:  { section: "3.3.1", level: "L1", type: "Automated" }
    rhel9_v2:  { section: "3.3.1", level: "L1", type: "Automated" }
    rhel10_v1: { section: "3.3.1", level: "L1", type: "Automated" }
  stig:
    rhel8_v2r6: { vuln_id: "V-230537", stig_id: "RHEL-08-040259", severity: "CAT II" }
    rhel9_v2r7: { vuln_id: "V-257963", stig_id: "RHEL-09-253010", severity: "CAT II" }
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

20 lines of meaningful content. The sysctl parameter, the expected value, and every
framework reference this control carries. This single file replaces the same control
copy-pasted across 5 separate benchmark automation artifacts.

### 5.2 Category B — Capability-Gated Variation

This pattern covers ~15-20% of rules. The desired state is the same, but the
mechanism differs based on detected capabilities.

```yaml
# rules/access-control/ssh-disable-root-login.yml

id: ssh-disable-root-login
title: Disable SSH root login
description: >
  The SSH daemon must not permit direct login as the root account. Root access
  must be obtained by authenticating as an individual user and then escalating
  privileges via sudo or su, ensuring accountability.
rationale: >
  Direct root login over SSH exposes the highest-privilege account to network
  brute-force attacks and eliminates the ability to attribute administrative
  actions to individual users. Disabling it enforces the principle of individual
  accountability and reduces the attack surface for remote compromise.
severity: high
category: access-control
tags: [ssh, authentication, remote-access, privileged-access]

references:
  cis:
    rhel8_v4:  { section: "5.1.22", level: "L1", type: "Automated" }
    rhel9_v2:  { section: "5.1.20", level: "L1", type: "Automated" }
    rhel10_v1: { section: "5.1.20", level: "L1", type: "Automated" }
  stig:
    rhel8_v2r6:
      vuln_id: "V-230296"
      stig_id: "RHEL-08-010550"
      severity: "CAT II"
      cci: ["CCI-000770"]
    rhel9_v2r7:
      vuln_id: "V-257947"
      stig_id: "RHEL-09-255045"
      severity: "CAT II"
      cci: ["CCI-000770"]
  nist_800_53: ["AC-6(2)", "AC-17(2)", "IA-2(5)"]
  pci_dss_4: ["2.2.6", "8.6.1"]
  srg: ["SRG-OS-000109-GPOS-00056"]

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
      file: "00-aegis-permit-root-login.conf"
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

Two implementation variants. The capability `sshd_config_d` gates whether we use a
drop-in file (the preferred, durable approach on systems that support it) or modify
the main config directly. Both produce the same security outcome.

### 5.3 Category B — PAM with Authselect

A more complex capability-gated example involving PAM configuration.

```yaml
# rules/access-control/pam-faillock-deny.yml

id: pam-faillock-deny
title: Lock accounts after failed login attempts
description: >
  The system must lock an account after a defined number of consecutive failed
  login attempts. This is enforced via the pam_faillock module with a deny
  threshold.
rationale: >
  Without account lockout, an attacker can perform unlimited password guessing
  attacks. A lockout threshold of 3-5 attempts provides a strong defense against
  brute-force attacks while remaining usable for legitimate users who occasionally
  mistype their password.
severity: high
category: access-control
tags: [pam, authentication, account-lockout, brute-force]

references:
  cis:
    rhel8_v4:  { section: "5.4.2.1", level: "L1", type: "Automated" }
    rhel9_v2:  { section: "5.4.2",   level: "L1", type: "Automated" }
    rhel10_v1: { section: "5.3.3.1", level: "L1", type: "Automated" }
  stig:
    rhel8_v2r6:
      vuln_id: "V-230333"
      stig_id: "RHEL-08-020011"
      severity: "CAT II"
      cci: ["CCI-000044"]
    rhel9_v2r7:
      vuln_id: "V-258054"
      stig_id: "RHEL-09-411075"
      severity: "CAT II"
      cci: ["CCI-000044"]
  nist_800_53: ["AC-7(a)"]
  pci_dss_4: ["8.3.4"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - when:
      all: [authselect, pam_faillock]
    check:
      checks:
        - method: config_value
          path: "/etc/security/faillock.conf"
          key: "deny"
          expected: "3"
        - method: command
          run: "authselect current | grep with-faillock"
          expected_exit: 0
    remediation:
      steps:
        - mechanism: config_set
          path: "/etc/security/faillock.conf"
          key: "deny"
          value: "3"
          separator: " = "
        - mechanism: command_exec
          run: "authselect enable-feature with-faillock"
          unless: "authselect current | grep -q with-faillock"

  - default: true
    check:
      method: config_value
      path: "/etc/security/faillock.conf"
      key: "deny"
      expected: "3"
    remediation:
      mechanism: config_set
      path: "/etc/security/faillock.conf"
      key: "deny"
      value: "3"
      separator: " = "
```

### 5.4 Category A — Kernel Module Disable

Another common pattern — disabling an unused kernel module.

```yaml
# rules/kernel/kmod-disable-cramfs.yml

id: kmod-disable-cramfs
title: Disable cramfs kernel module
description: >
  The cramfs filesystem is a read-only compressed filesystem. It is rarely
  needed on production systems and provides an unnecessary attack surface
  for kernel-level exploits.
rationale: >
  Removing support for unnecessary filesystems reduces the kernel attack surface.
  A vulnerability in an unused filesystem module could be exploited if the module
  is loadable.
severity: low
category: kernel
tags: [kernel-module, filesystem, attack-surface]

references:
  cis:
    rhel8_v4:  { section: "1.1.1.1", level: "L1", type: "Automated" }
    rhel9_v2:  { section: "1.1.1.1", level: "L1", type: "Automated" }
    rhel10_v1: { section: "1.1.1.1", level: "L1", type: "Automated" }
  nist_800_53: ["CM-7"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: kernel_module_state
      name: "cramfs"
      state: "blacklisted"
    remediation:
      mechanism: kernel_module_disable
      name: "cramfs"
```

12 lines of meaningful content. This rule is identical on RHEL 8, 9, and 10. The
CIS section number is even the same across all three (1.1.1.1). One file. Done.

### 5.5 Category A — File Permissions

```yaml
# rules/filesystem/fs-permissions-etc-shadow.yml

id: fs-permissions-etc-shadow
title: Set permissions on /etc/shadow
description: >
  The /etc/shadow file contains hashed passwords. It must be readable only by
  root to prevent offline password cracking attacks.
rationale: >
  If /etc/shadow is world-readable, any local user can copy the password hashes
  and run offline brute-force attacks. Restricting access to root-only eliminates
  this vector entirely.
severity: high
category: filesystem
tags: [file-permissions, passwords, authentication]

references:
  cis:
    rhel8_v4:  { section: "7.1.3",  level: "L1", type: "Automated" }
    rhel9_v2:  { section: "6.1.3",  level: "L1", type: "Automated" }
    rhel10_v1: { section: "7.1.3",  level: "L1", type: "Automated" }
  stig:
    rhel8_v2r6: { vuln_id: "V-230256", stig_id: "RHEL-08-010150", severity: "CAT II" }
    rhel9_v2r7: { vuln_id: "V-257843", stig_id: "RHEL-09-232130", severity: "CAT II" }
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

### 5.6 Category C — OS-Specific (Bounded Applicability)

```yaml
# rules/system/crypto-policy-disable-sha1-signatures.yml

id: crypto-policy-disable-sha1-signatures
title: Disable SHA-1 in system-wide crypto policy
description: >
  The system-wide cryptographic policy must not allow SHA-1 for digital
  signatures. SHA-1 is cryptographically broken for collision resistance
  and must be excluded from all signature operations.
rationale: >
  SHA-1 collision attacks are practical and have been demonstrated publicly.
  Allowing SHA-1 signatures enables forgery of certificates, code signatures,
  and other authenticated data.
severity: high
category: system
tags: [crypto-policy, hashing, tls, signatures]

references:
  stig:
    rhel9_v2r7:
      vuln_id: "V-257953"
      stig_id: "RHEL-09-672020"
      severity: "CAT II"
      cci: ["CCI-000803"]
  nist_800_53: ["SC-13", "MA-4(6)"]

platforms:
  - family: rhel
    min_version: 9            # Subpolicy modules not available on RHEL 8

implementations:
  - when: crypto_policy_modules
    check:
      method: command
      run: "update-crypto-policies --show | grep -v SHA1"
      expected_exit: 0
    remediation:
      mechanism: command_exec
      run: "update-crypto-policies --set DEFAULT:NO-SHA1"
      unless: "update-crypto-policies --show | grep -q NO-SHA1"

  - default: true
    check:
      method: command
      run: "update-crypto-policies --show"
      expected_exit: 0
    remediation:
      mechanism: command_exec
      run: "update-crypto-policies --set DEFAULT"
      unless: "update-crypto-policies --show | grep -qE '^DEFAULT$'"
```

Note `min_version: 9` — this control is not applicable to RHEL 8 because the
subpolicy module mechanism didn't exist. The `platforms` field makes this explicit.

### 5.7 Multi-Step Remediation

```yaml
# rules/audit/aide-installed.yml

id: aide-installed
title: Install and initialize AIDE
description: >
  AIDE (Advanced Intrusion Detection Environment) must be installed and its
  database initialized to provide filesystem integrity monitoring. AIDE detects
  unauthorized modifications to system files.
rationale: >
  Without file integrity monitoring, unauthorized modifications to critical
  system files (binaries, libraries, configuration) may go undetected. AIDE
  provides a baseline against which changes are compared.
severity: medium
category: audit
tags: [aide, file-integrity, intrusion-detection]

references:
  cis:
    rhel8_v4:  { section: "1.3.1",  level: "L1", type: "Automated" }
    rhel9_v2:  { section: "1.3.1",  level: "L1", type: "Automated" }
    rhel10_v1: { section: "1.3.1",  level: "L1", type: "Automated" }
  stig:
    rhel8_v2r6: { vuln_id: "V-230263", stig_id: "RHEL-08-010359", severity: "CAT II" }
    rhel9_v2r7: { vuln_id: "V-257850", stig_id: "RHEL-09-651010", severity: "CAT II" }
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
        - mechanism: package_present
          name: "aide"
        - mechanism: command_exec
          run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
          unless: "test -f /var/lib/aide/aide.db.gz"
```

---

## 6. Validation

### 6.1 JSON Schema

A formal JSON Schema is provided at `schema/rule.schema.json` for automated validation.
Every rule file must pass validation before being added to the canonical set.

Validation is run via:

```bash
# Validate a single rule
aegis validate rules/access-control/ssh-disable-root-login.yml

# Validate all rules
aegis validate rules/
```

### 6.2 Validation Rules Beyond Schema

The following constraints are enforced by tooling beyond the JSON Schema:

1. **ID uniqueness.** No two rule files may share the same `id`.
2. **File naming.** The filename must match the `id` field: `{id}.yml`.
3. **Category consistency.** The `category` field must match the parent directory name.
4. **Exactly one default implementation.** Each rule must have exactly one
   implementation with `default: true`.
5. **Capability references.** Every capability referenced in a `when` clause must exist
   in the capabilities reference (Section 4).
6. **Dependency references.** Every rule ID in `depends_on`, `conflicts_with`, and
   `supersedes` must reference an existing rule.
7. **No orphan capabilities.** Capabilities defined in the reference but never used in
   any rule should trigger a warning.

---

## 7. Schema Evolution

This is version 0 of the schema. It will evolve as real rules are written and edge
cases surface. The evolution policy:

- **Additive changes** (new optional fields, new mechanism types, new check methods)
  are non-breaking and can be made freely.

- **Breaking changes** (renaming fields, changing semantics, removing fields) require
  a schema version bump and a migration path for existing rules.

- The schema version is tracked in the JSON Schema file (`$schema` and `version`
  fields) and in this document's title.

- All existing rule files must remain valid after any schema change. If a change
  would invalidate existing rules, provide an automated migration script.

---

*This document defines the canonical rule schema for Aegis. It is the contract
between rule authors, the execution engine, and the reporting system. Every rule
in the canonical set must conform to this schema.*
