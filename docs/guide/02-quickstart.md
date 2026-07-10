# Quickstart

_Applies to: Kensa v0.7.4 — last updated 2026-07-10._

This chapter takes one host from "never scanned" to "remediated and rolled
back" in four commands: **detect** what the host can do, **check** its
compliance read-only, **remediate** the failures, then **roll back** if you
want the host returned to where it started. Every command here is real and
runs against the shipped binary.

You'll need `kensa` and `kensa-rules` installed (see
[the install chapter](01-install.md)) and SSH access to the target. The examples use
`-r rules/` to point at a local rules tree. If you installed `kensa-rules`,
drop `-r` and Kensa finds `/usr/share/kensa/rules` automatically.

## Before you start

The target host needs nothing installed, only OpenSSH reachable and, for
privileged checks, `sudo`. Kensa connects over your system SSH (honoring
your keys, agents, and `known_hosts`), so confirm a plain `ssh user@host`
works first.

Two flags recur on every command:

- `--sudo` wraps remote commands in `sudo`. Without it, Kensa runs as the
  login user and most hardening rules can't read or change privileged state.
- `--sudo-password` (or the `KENSA_SUDO_PASSWORD` env var) supplies a sudo
  password on hosts that don't allow `NOPASSWD`. Omit the value to be
  prompted on the TTY. With passwordless sudo you don't need it at all.

## Step 1: detect

Probe the host and print its capability set. This is read-only and mutates
nothing; it's the safe way to confirm Kensa can reach the host and to see
which subsystems (systemd, SELinux, apt, auditd, …) it found.

```bash
kensa detect -H rhel9-host.example.com -u admin --sudo
```

Add `--sudo-password` if the host needs one:

```bash
kensa detect -H rhel9-host.example.com -u admin --sudo --sudo-password
```

If detect can't connect, fix that before going further. Every other
command uses the same transport.

## Step 2: check (read-only)

Run the compliance checks. `check` never changes the host; it reports
`PASS` / `FAIL` / `ERROR` per rule, plus a `SKIP` for any rule that doesn't
apply to this host's platform, and ends with a tally. Rows stream as each
rule completes.

```bash
kensa check -H rhel9-host.example.com -u admin --sudo -r rules/
```

Narrow the run with filters, by severity, framework, or category:

```bash
# Only critical and high-severity rules
kensa check -H rhel9-host.example.com -u admin --sudo -r rules/ -s critical -s high

# Only rules mapping a CIS RHEL 9 control
kensa check -H rhel9-host.example.com -u admin --sudo -r rules/ -f cis-rhel9
```

`check` is read-only and does **not** write to the transaction log by
default. Pass `--store` if you want the scan persisted as a session you can
query later with `kensa history`.

## Step 3: remediate (apply)

`remediate` applies the failing rules. Each rule runs as a four-phase atomic
transaction (capture, apply, validate, then commit or roll back), so a rule
whose change fails validation is reversed automatically before Kensa moves
to the next rule. A transaction is Kensa's unit of atomic change: one rule's
capture-apply-validate-commit-or-rollback cycle on one host. (The mental
model is in [the concepts chapter](03-concepts.md).)

```bash
kensa remediate -H rhel9-host.example.com -u admin --sudo -r rules/
```

The output adds a `FIXED` status to the check statuses. As with `check`, you
can scope the run, remediating only what you mean to change:

```bash
# Apply only critical PCI-tagged rules
kensa remediate -H rhel9-host.example.com -u admin --sudo -r rules/ -s critical -t pci
```

Every committed transaction is written to the transaction log with a signed
evidence envelope, the tamper-evident record of what changed and the proof
it wasn't altered afterward. To preview a single rule's transaction without
touching the host, use `kensa plan` instead.

## Step 4: roll back

Remediation that *fails validation* rolls back on its own. Step 4 is the
**deliberate** rollback: returning a host to the state captured before a
remediation you've decided to undo.

First find the session you want to reverse:

```bash
kensa rollback --list
```

Inspect it (read-only) before committing to the reversal:

```bash
kensa rollback --info <SESSION_ID> --detail
```

Then execute the rollback for every committed transaction in that session.
This phase touches the host, so it needs the same target flags as
remediate:

```bash
kensa rollback --start <SESSION_ID> -H rhel9-host.example.com -u admin --sudo
```

Rollback restores each transaction's captured pre-state. A mechanism Kensa
can't reverse (a `transactional: false` rule) was never captured and is
reported as skipped rather than silently "restored." See the reversal
table in [the mechanisms reference](10-mechanisms.md).

## Where to go next

- [The concepts chapter](03-concepts.md): the four-phase transaction and why
  atomicity is the product.
- [The mechanisms reference](10-mechanisms.md): every mechanism, where it runs, and
  what reversal you get.
- `kensa history`: query past transactions; `kensa diff` compares two
  stored sessions for drift.
