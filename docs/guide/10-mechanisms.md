# Mechanisms reference

_Applies to: Kensa v0.7.6 — last updated 2026-07-10._

A *mechanism* is the named action a rule's remediation runs to change a host,
such as `sysctl_set`, `service_enabled`, or `file_content`. You set it in a
rule's `remediation` block. Each mechanism is backed by a handler in Kensa that
knows how to apply the change and, for most mechanisms, how to undo it.

Kensa runs every change as a *transaction*: capture the prior state, apply the
change, validate it, then commit or roll back. Two handler roles matter here:

- A *capture handler* records the host's exact prior state before the change.
- A *rollback handler* restores that prior state if the transaction fails.

A mechanism that has both is *capturable*—Kensa can reverse it. A mechanism
without them is *non-capturable*: Kensa applies and audits the change but can't
roll it back, so you mark its rule `transactional: false`.

This page lists every shipped mechanism, where it runs, and what reversal you
get. For the guarantee itself, see
[Rollback and history](05-rollback-and-history.md); for the rule fields, see
[Rule authoring](06-rule-authoring.md).

## Operating system support

Each mechanism depends on a tool or kernel feature that must be present on the
host. Kensa probes for it at runtime and skips a rule whose platform or
capability the host does not meet, so a mechanism never runs where its backing
tool is missing. The **Runs on** column below names where each mechanism's
backing tool exists:

- **Any Linux**—kernel or core-filesystem features present on every supported
  distribution.
- **RHEL 8–10**—the tool ships with Red Hat Enterprise Linux 8, 9, and 10
  (and compatible rebuilds and Fedora).
- **Debian, Ubuntu**—the tool is `apt`-family.
- A named subsystem (systemd, SELinux, GRUB, GNOME)—the host must run it.

Kensa is tested on RHEL 8, 9, and 10 and on Ubuntu. The shipped rule corpus
currently targets RHEL; running it against Ubuntu skips the RHEL-only rules.

## Reversal levels

| Level | What it means |
|---|---|
| **Atomic** | The change lands completely or not at all, and rollback restores the prior state byte-for-byte. |
| **Reversible** | Rollback restores the captured prior state and verifies it. A runtime aspect may need a restart or reboot; the limit is noted, and rollback reports a partial restore when it applies. |
| **Best-effort** | Rollback restores the prior state through the host's own tool (`dnf`, `apt`, `augenrules`). It depends on that tool and on the host's policy. |
| **Staged** | The change is pending until the next reboot. A failed boot reverts automatically. |
| **None** | Kensa records the change for audit but can't roll it back. The rule is `transactional: false`. |

## Files

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `file_content` | A file's content and attributes | Any Linux | Atomic |
| `file_absent` | Removes a file | Any Linux | Atomic |
| `config_set` | A key's value in a config file | Any Linux | Atomic |
| `config_set_dropin` | A key in a drop-in config file | Any Linux | Atomic |
| `file_permissions` | A file's mode, owner, group, and SELinux context | Any Linux | Atomic |
| `config_append` | Appends a line to a config file | Any Linux | Best-effort |

## Services

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `service_enabled` | Enables and starts a systemd unit | systemd (RHEL 8–10, Ubuntu) | Reversible |
| `service_disabled` | Disables and stops a systemd unit | systemd (RHEL 8–10, Ubuntu) | Reversible |
| `service_masked` | Masks and stops a systemd unit | systemd (RHEL 8–10, Ubuntu) | Reversible |

## Kernel runtime and persistence

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `sysctl_set` | A kernel parameter (runtime and drop-in) | Any Linux | Reversible |
| `mount_option_set` | A mount option in `fstab`, then remounts | Any Linux | Reversible. Rollback restores the `fstab` line, remounts, and verifies the live options match; a mismatch is reported as a partial restore. |
| `selinux_boolean_set` | A persistent SELinux boolean | SELinux (RHEL 8–10) | Reversible |
| `kernel_module_disable` | Blacklists a kernel module | Any Linux | Reversible. If the module was loaded, rollback re-loads it and verifies; a module that can't re-load (in use, or boot-time only) is reported as a partial restore needing a reboot. |
| `audit_rule_set` | Loads an audit rule and persists it | RHEL 8–10; Ubuntu with `auditd` | Best-effort. Rollback restores the rule file and reconciles the live rules; on an immutable audit config the live ruleset is locked until reboot, which rollback reports as a partial restore. |

## Packages

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `package_present` | Installs a package with `dnf` | RHEL 8–10 | Best-effort. Rollback removes the package, which removes its dependents. |
| `package_absent` | Removes a package with `dnf` | RHEL 8–10 | Best-effort. Rollback reinstalls; the version may differ from the prior one. |
| `apt_present` | Installs a package with `apt` | Debian, Ubuntu | Best-effort. Rollback removes the package. |
| `apt_absent` | Removes a package with `apt` | Debian, Ubuntu | Best-effort. Rollback reinstalls; the version may differ. |

## Authentication and policy

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `pam_module_configure` | A PAM configuration file | RHEL 8–10, Ubuntu | Best-effort |
| `pam_module_arg` | An argument on a PAM module line | RHEL 8–10, Ubuntu | Best-effort |
| `authselect_feature_enable` | An `authselect` feature | RHEL 8–10 | Best-effort |
| `dconf_set` | A system `dconf` key, optionally locked | GNOME (RHEL 8–10, Ubuntu) | Best-effort |
| `crypto_policy_set` | The system-wide crypto policy | RHEL 8–10 | Reversible. Rollback restores and verifies the policy; services already running keep their startup crypto until restarted (for example `systemctl restart sshd`). |
| `cron_job` | A cron file | RHEL 8–10, Ubuntu | Best-effort |

## Boot parameters

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `grub_parameter_set` | Adds a kernel boot parameter | GRUB (RHEL 8–10, Ubuntu) | Staged. A trial boot promotes the change; a failed boot reverts to the prior default. |
| `grub_parameter_remove` | Removes a kernel boot parameter | GRUB (RHEL 8–10, Ubuntu) | Staged |

Kensa never edits the saved boot default directly. It stages the change through
a one-shot trial boot, so a host that fails to boot reverts on its own. Kensa
does not reboot the host; the change is pending until you do.

## Non-reversible

| Mechanism | What it changes | Runs on | Reversal |
|---|---|---|---|
| `command_exec` | Runs an arbitrary command | Any Linux | None |
| `crypto_policy_subpolicy` | Applies a crypto subpolicy | RHEL 8–10 | None |
| `manual` | Marks a step for a human to perform | Any Linux | None |

These mechanisms run but Kensa can't undo them, so their rules are
`transactional: false`. Kensa records each one in the transaction log for audit,
but it isn't covered by the rollback guarantee. Use them only when no
reversible mechanism fits.

## Crash recovery

For a capturable mechanism, the prior state is written to durable storage
before any host change. If a Kensa process is interrupted mid-transaction, run
`kensa recover -H <host>` to roll the host back to the captured prior state.
Recovery reverses every mechanism in this page that is marked Atomic,
Reversible, or Best-effort; it can't reverse a `transactional: false` step,
because none was captured.
