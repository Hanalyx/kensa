# Mechanisms reference

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

This page lists every shipped mechanism and what reversal you get. For the
guarantee itself, see [Rollback and history](05-rollback-and-history.md); for
the rule fields, see [Rule authoring](06-rule-authoring.md).

## Reversal levels

| Level | What it means |
|---|---|
| **Atomic** | The change lands completely or not at all, and rollback restores the prior state byte-for-byte. |
| **Reversible** | Rollback restores the captured prior state. A runtime aspect may need a reboot or remount; the limit is noted. |
| **Best-effort** | Rollback restores the prior state through the host's own tool (`dnf`, `apt`, `augenrules`). It depends on that tool and on the host's policy. |
| **Staged** | The change is pending until the next reboot. A failed boot reverts automatically. |
| **None** | Kensa records the change for audit but can't roll it back. The rule is `transactional: false`. |

## Files

| Mechanism | What it changes | Reversal |
|---|---|---|
| `file_content` | A file's content and attributes | Atomic |
| `file_absent` | Removes a file | Atomic |
| `config_set` | A key's value in a config file | Atomic |
| `config_set_dropin` | A key in a drop-in config file | Atomic |
| `file_permissions` | A file's mode, owner, group, and SELinux context | Atomic |
| `config_append` | Appends a line to a config file | Best-effort |

## Services

| Mechanism | What it changes | Reversal |
|---|---|---|
| `service_enabled` | Enables and starts a systemd unit | Reversible |
| `service_disabled` | Disables and stops a systemd unit | Reversible |
| `service_masked` | Masks and stops a systemd unit | Reversible |

## Kernel runtime and persistence

| Mechanism | What it changes | Reversal |
|---|---|---|
| `sysctl_set` | A kernel parameter (runtime and drop-in) | Reversible |
| `mount_option_set` | A mount option in `fstab`, then remounts | Reversible |
| `selinux_boolean_set` | A persistent SELinux boolean | Reversible |
| `kernel_module_disable` | Blacklists a kernel module | Reversible. Re-enabling a module may need a reboot. |
| `audit_rule_set` | Loads an audit rule and persists it | Best-effort. On an immutable audit config, the load is rejected and the host is left unchanged. |

## Packages

| Mechanism | What it changes | Reversal |
|---|---|---|
| `package_present` | Installs a package with `dnf` | Best-effort. Rollback removes the package, which removes its dependents. |
| `package_absent` | Removes a package with `dnf` | Best-effort. Rollback reinstalls; the version may differ from the prior one. |
| `apt_present` | Installs a package with `apt` | Best-effort. Rollback removes the package. |
| `apt_absent` | Removes a package with `apt` | Best-effort. Rollback reinstalls; the version may differ. |

## Authentication and policy

| Mechanism | What it changes | Reversal |
|---|---|---|
| `pam_module_configure` | A PAM configuration file | Best-effort |
| `pam_module_arg` | An argument on a PAM module line | Best-effort |
| `authselect_feature_enable` | An `authselect` feature | Best-effort |
| `dconf_set` | A system `dconf` key, optionally locked | Best-effort |
| `crypto_policy_set` | The system-wide crypto policy | Best-effort |
| `cron_job` | A cron file | Best-effort |

## Boot parameters

| Mechanism | What it changes | Reversal |
|---|---|---|
| `grub_parameter_set` | Adds a kernel boot parameter | Staged. A trial boot promotes the change; a failed boot reverts to the prior default. |
| `grub_parameter_remove` | Removes a kernel boot parameter | Staged |

Kensa never edits the saved boot default directly. It stages the change through
a one-shot trial boot, so a host that fails to boot reverts on its own. Kensa
does not reboot the host; the change is pending until you do.

## Non-reversible

| Mechanism | What it changes | Reversal |
|---|---|---|
| `command_exec` | Runs an arbitrary command | None |
| `crypto_policy_subpolicy` | Applies a crypto subpolicy | None |
| `manual` | Marks a step for a human to perform | None |

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
