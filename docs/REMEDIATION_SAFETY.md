# Remediation Safety Guide

**Last updated:** 2026-03-13

This document describes Kensa's remediation safety model: what is captured before changes, what can be rolled back, and where limitations exist.

---

## Safety Architecture

Kensa's remediation pipeline follows a three-step pattern for every rule:

1. **Capture** — Record the pre-remediation state of the target (file contents, config values, service states)
2. **Remediate** — Apply the change to achieve compliance
3. **Rollback** (on demand) — Restore the captured pre-state if the change needs to be reversed

Pre-state snapshots are persisted to SQLite and retained for 7 days (full rollback capability) and 90 days (inspection only), then pruned.

---

## Risk Classification

Every remediation mechanism is classified by risk level based on its blast radius and reversibility. Target file paths can escalate (but never downgrade) the risk.

### Mechanism risk levels

#### High risk — can brick boot, break mounts, or lock out users

| Mechanism | What it does |
|-----------|-------------|
| `grub_parameter_set` | Modifies GRUB bootloader parameters |
| `grub_parameter_remove` | Removes GRUB bootloader parameters |
| `mount_option_set` | Changes filesystem mount options in /etc/fstab |
| `pam_module_configure` | Modifies PAM authentication stack |
| `kernel_module_disable` | Disables kernel modules via modprobe blacklist |

#### Medium risk — can break services or change security posture

| Mechanism | What it does |
|-----------|-------------|
| `config_set` | Sets key=value in a config file |
| `config_set_dropin` | Creates a drop-in config file |
| `config_block` | Writes a multi-line config block |
| `config_remove` | Removes a key from a config file |
| `config_append` | Appends a line to a config file (idempotent) |
| `sysctl_set` | Sets a kernel runtime parameter |
| `service_masked` | Masks a systemd service |
| `service_disabled` | Disables a systemd service |
| `audit_rule_set` | Adds an audit rule to auditd |
| `selinux_boolean_set` | Sets an SELinux boolean |
| `dconf_set` | Writes a GNOME/GDM dconf setting |
| `crypto_policy_set` | Sets the system-wide crypto policy |
| `file_content` | Writes exact content to a file |

#### Low risk — narrow blast radius, easily reversed

| Mechanism | What it does |
|-----------|-------------|
| `file_permissions` | Sets file mode, owner, or group |
| `package_present` | Installs a package |
| `package_absent` | Removes a package |
| `service_enabled` | Enables a systemd service |
| `cron_job` | Creates or modifies a cron job |
| `file_absent` | Removes a file |

#### Not applicable — no automated state change

| Mechanism | What it does |
|-----------|-------------|
| `command_exec` | Runs an arbitrary shell command |
| `manual` | Describes a human action (no system change) |

### Path escalation

Certain file paths escalate risk regardless of mechanism:

**Escalate to high:**
- `/etc/pam.d/` — PAM authentication configuration
- `/etc/fstab` — Filesystem mount table
- `/etc/crypttab` — Encrypted volume configuration
- `/etc/default/grub` — Bootloader configuration
- `/etc/selinux/config` — SELinux mode configuration

**Escalate to medium (minimum):**
- `/etc/ssh/sshd_config` — SSH server configuration
- `/etc/security/` — Security limits, faillock, pwquality settings

Example: `file_permissions` on `/etc/pam.d/system-auth` is classified as **high** risk (not low), because the path escalation overrides the mechanism's base risk.

---

## Rollback Safety Tiers

### Tier 1: Fully rollback-safe

**23 typed mechanisms** have complete capture → rollback support:

- All high, medium, and low risk mechanisms listed above
- Pre-state is captured automatically before remediation
- Rollback restores the exact previous state
- Available via `kensa rollback --start <session-id>`

### Tier 2: Rollback-limited

**`command_exec`** (39 rules) — Runs arbitrary shell commands. Capture handlers exist but record limited context (the command itself and exit status). Rollback is best-effort:

- If the command created or modified a specific file, capture may record the original state
- If the command performed a complex multi-step operation, rollback cannot fully reverse it
- Always review `kensa rollback --info <session-id>` before attempting rollback

### Tier 3: Manual only

**`manual`** (114 rules) — Describes what a human should do. No system changes are made by Kensa, so no rollback is needed. These exist for controls that require:

- Organizational judgment (e.g., choosing banner text)
- Physical access or out-of-band changes
- Complex multi-system coordination
- Review of site-specific configuration before applying

---

## Snapshot Capture Modes

Control how aggressively Kensa captures pre-state:

| Mode | Behavior | Use case |
|------|----------|----------|
| `all` (default) | Capture pre-state for every step | Production remediations where rollback must be available |
| `risk_based` | Capture only when risk >= threshold | Large-scale runs where storage is a concern |
| `none` | Skip all pre-state capture | Read-only environments or re-runs of known-safe changes |

### Risk-based thresholds

With `--snapshot-mode risk_based`, the `--risk-threshold` flag controls the minimum risk level for capture:

| Threshold | Captures |
|-----------|----------|
| `low` | Low, medium, and high risk steps |
| `medium` (default) | Medium and high risk steps only |
| `high` | High risk steps only |

---

## CLI Safety Options

### Before remediation

```bash
# Always dry-run first to preview changes
kensa remediate --host target --framework cis-rhel9 --dry-run

# Dry-run a specific rule
kensa remediate --host target --rule ssh-permit-root-login --dry-run
```

### During remediation

```bash
# Default: full pre-state capture (recommended)
kensa remediate --host target --framework cis-rhel9

# Risk-based capture (medium+ only)
kensa remediate --host target --framework cis-rhel9 \
  --snapshot-mode risk_based --risk-threshold medium

# Auto-rollback on failure (reverts all steps if any step fails)
kensa remediate --host target --rule ssh-permit-root-login \
  --rollback-on-failure

# Skip pre-state capture (not recommended for production)
kensa remediate --host target --framework cis-rhel9 --no-snapshot
```

### After remediation

```bash
# Inspect what was captured
kensa rollback --info <session-id>

# Roll back a past remediation
kensa rollback --start <session-id>

# View remediation history
kensa history --host target
```

---

## Recommendations

### For production environments

1. **Always dry-run first.** Review the output before applying changes.
2. **Use default snapshot mode** (`all`) to ensure full rollback capability.
3. **Start with high-risk rules individually** rather than full-framework remediations.
4. **Review `rollback --info`** after remediating to confirm pre-state was captured.
5. **Test rollback** on a non-production host before relying on it in production.

### For high-risk mechanisms

Rules using `grub_parameter_set`, `mount_option_set`, `pam_module_configure`, or `kernel_module_disable` can render a system unbootable or inaccessible if misconfigured. For these:

1. Ensure console/IPMI access is available before remediating
2. Run with `--rollback-on-failure` to auto-revert on errors
3. Remediate one rule at a time, not in batch
4. Verify the system is accessible after each change

### For `command_exec` rules

These 39 rules execute shell commands that may not be fully reversible:

1. Review the rule YAML (`kensa info <rule-id>`) to understand what command runs
2. Dry-run first to see the exact command
3. Have a manual recovery plan before proceeding
4. Consider whether a typed alternative exists (ongoing migration effort)

---

## Limitations

- **`command_exec` rollback is best-effort.** Complex shell commands may not be fully reversible from captured state alone.
- **`manual` rules make no changes.** They report compliance status and provide guidance but do not modify the target system.
- **Snapshot retention is time-limited.** Full rollback is available for 7 days; after that, only inspection is possible (90-day archive). After 90 days, snapshots are pruned.
- **Multi-step remediations roll back in reverse order.** If step 3 of 5 fails, steps 1 and 2 are rolled back. Steps 4 and 5 were never applied.
- **Package rollback installs/removes packages** but does not restore package-specific configuration that was modified by package scripts.
