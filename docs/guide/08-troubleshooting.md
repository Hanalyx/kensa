# Troubleshooting

_Applies to: Kensa v0.6.0 — last updated 2026-06-22._

Common failure modes, what they look like, and how to clear them. Each section
names the condition first so you can match it to what you are seeing, then the
remedy. When in doubt, run `kensa detect -H <host> --sudo` first — it reports
the host's detected OS and capability set, which explains most "why did this
rule skip / fail" questions.

## Sudo fails without a password

By default `--sudo` runs `sudo -n` (non-interactive). On a host whose sudoers
policy requires a password — itself a common CIS/STIG control — that fails fast
at connect time rather than mid-scan. Supply the password with
`--sudo-password` (omit the value for a TTY prompt) or the
`KENSA_SUDO_PASSWORD` environment variable; the password is fed over the SSH
session's stdin, never placed in argv or recorded in evidence. If the supplied
password is wrong, the probe reports a rejected sudo password. The alternative
is to configure NOPASSWD sudo for the scan user. Note that `--sudo-password`
requires `--sudo`, and `SUDO_ASKPASS` / `sudo -A` is not supported (it would
need a helper on the target, which the agentless model does not ship).

## Agent bootstrap or GLIBC errors on remediate

`remediate` defaults to agent mode: it ships a small agent binary to the target
and runs the kernel-IO primitives there. If the agent fails to start — for
example a GLIBC-version mismatch on an older target than the build host, or a
spawn/`fork-exec` error — set `KENSA_NO_AGENT=1` to drop to the shell
best-effort path, which uses the host's own tools over the SSH transport. The
shell path is always available and produces byte-identical file writes; you lose
only the direct kernel-IO primitives. The agent must run as root, so pair
agent-mode remediation with `--sudo` (which spawns `sudo kensa agent`); without
root the agent's direct `/proc` and `/etc` writes fail with permission errors.
Service-handler (`service_enabled` / `_disabled` / `_masked`) remediation
additionally needs the systemd helper installed — see
[01-install](01-install.md) "Service handlers".

## A rule skips when you expected it to run

Two independent gates produce a `SKIP` row:

- **Out of platform.** Kensa compares each rule's `platforms:` block against the
  host's detected OS and skips out-of-platform rules. The shipped corpus targets
  RHEL, so scanning Ubuntu skips the RHEL-only rules — a full Ubuntu scan can
  return everything as `SKIP`. This is faithful behavior, not a bug; those rules
  have no in-platform implementation to run. Platform gating is lenient by
  design: a rule with no `platforms:` block runs everywhere, and a host whose OS
  Kensa cannot detect gates nothing.
- **Capability mismatch.** An implementation's `when:` gate references a
  capability the host lacks (no `sshd_config_d`, no `selinux`, no `firewalld`,
  etc.) and no other implementation's gate matches. Run `kensa detect` to see
  the detected capability set, and use `-C KEY=VALUE` on `check` / `detect` to
  override a probe if it is wrong for your host (for example `-C selinux=true`).

## An audit rule only partially restores on rollback

On a host with an immutable audit configuration (`auditd` set to `enabled=2`,
the hardened CIS state), the live audit ruleset is locked until reboot.
`audit_rule_set` rollback restores the rule *file* and reconciles what it can,
but the in-kernel ruleset cannot change until the host reboots; Kensa reports
this as a partial restore. This is a limitation of immutable auditd itself
(`augenrules` has the same constraint), not of Kensa. Reboot to apply the
restored file, or set `enabled=1` if your policy permits a mutable audit config.

## "No rules found" or the wrong rules load

Rule-directory resolution follows a fixed order: an explicit `--rules-dir` wins;
positional `*.yml` paths (or `--rule FILE`) alone skip the directory walk; else
Kensa falls back to `/usr/share/kensa/rules` (where the `kensa-rules` package
installs); else it prints a usage error naming all three fix paths. If you
installed `kensa` without `kensa-rules` (for example with
`--setopt=install_weak_deps=False`), that fallback directory is empty — install
`kensa-rules` or pass `--rules-dir <path>` on every command. A from-source
checkout has the corpus at `rules/`; pass `-r rules`.

## Host-key prompts or "host key changed"

Kensa trusts the host key on first use (TOFU) by default
(`--no-strict-host-keys`), recording it for subsequent connections. If a host's
key legitimately changed (reinstall, new SSH host keys), remove the stale entry
from your `known_hosts` and reconnect to re-pin it. For a security-sensitive
run, pass `--strict-host-keys` to verify the key and reject an unknown or
changed one instead of trusting it. The transport uses system OpenSSH, so
`known_hosts`, jump hosts, and key agents behave exactly as your `ssh` config
defines them.

## Getting more detail

- `kensa detect -H <host> --sudo` — the detected OS and capability set behind
  platform/`when` skips.
- `kensa check ... -v` — expands the compacted PASS list in text output.
- `kensa check ... -o json` or `-o jsonl` — structured per-rule outcomes
  (`pass` / `fail` / `skipped` / `error`) for scripting.
- `kensa plan -H <host> <rule.yml>` — previews a rule's transaction without
  executing it.
- `kensa history` and `kensa rollback <id>` — inspect and reverse a past
  transaction (see [05-rollback-and-history](05-rollback-and-history.md)).
- A non-zero exit code distinguishes a runtime error (`1`) from a usage error
  (`2`, bad flag / missing argument).
