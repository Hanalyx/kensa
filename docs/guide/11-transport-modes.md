# Transport modes

_Applies to: Kensa v0.9.0. Last updated 2026-08-07._

Kensa never installs a permanent daemon. Every command reaches a host over
ordinary SSH, using the same credentials you would type yourself. What changes
between modes is not how Kensa connects, but what runs on the far end once it
gets there.

This chapter covers both modes in full: how the connection is made, what each
mode can and cannot do, and how to choose between them. For the short version,
see [Concepts](03-concepts.md#agent-mode-vs-shell-fallback).

## The two modes

| | Agent mode | Direct SSH mode |
|---|---|---|
| Default for | `remediate`, `rollback`, `recover` | `check`, `detect`, `inventory` |
| What runs on the host | a short-lived `kensa agent` process | shell commands |
| How to force it | default | `KENSA_NO_AGENT=1` |
| Lives beyond the command | no | no |

Neither mode leaves anything running. The agent starts when the command starts
and exits when it ends.

`check` is read-only and does not spawn the agent. The agent matters where Kensa
writes.

## How the connection is made

Both modes use one SSH connection per host per command, held open with OpenSSH
connection multiplexing. Kensa starts a control master, then every later command
rides the same connection instead of paying for a new handshake. A scan of 700
rules is one login, not 700.

The control socket lives in your temporary directory and is named for the user,
host, port and process. It goes away when the command ends.

Agent mode adds one more session over that **same** connection. It does not dial
a second one. This matters for a practical reason: everything you passed on the
command line, the port, the identity file, the host key policy and the
authentication method, is already settled on the connection that exists. A
second connection would have to re-derive all of it and could get it wrong.

The connection the agent rides on is kept separate from the connection the rest
of the command uses, so that finishing one piece of work cannot close the
connection another piece is still using.

### Where connection settings come from

Both modes read exactly the same settings, and they apply everywhere:

| flag | meaning |
|---|---|
| `-H`, `--host` | target host |
| `-u`, `--user` | SSH user |
| `-P`, `--port` | SSH port |
| `-k`, `--key` | identity file |
| `-p`, `--password` | SSH password (attach the value with `=`) |
| `--sudo` | run privileged work through sudo |
| `--sudo-password` | sudo password for hosts without NOPASSWD |
| `--strict-host-keys` | reject unknown host keys instead of trusting on first use |

Because the agent session reuses the connection rather than building its own,
these behave identically in both modes. If `kensa check` can reach a host, so
can `kensa remediate`.

Note that `-p` and `--sudo-password` take an optional value, so the value must
be attached: `--password=secret`, not `--password secret`. Written apart, the
next argument is read as a file name.

## Agent mode in detail

When a command needs the agent, Kensa does four things:

1. **Bootstrap.** It copies the `kensa` binary to `/var/cache/kensa/agent-<sha>`
   on the target, keyed by content hash. A host that already has the right build
   skips the upload.
2. **Spawn.** It starts `kensa agent --stdio` over the existing SSH connection.
   With `--sudo`, the process is started through sudo so that it runs as root
   before the shell resolves the binary path. The cache directory is root owned,
   so an unprivileged user cannot enter it to run the binary directly.
3. **Handshake.** Controller and agent agree on a protocol version.
4. **Work, then exit.** The agent applies changes and exits when its input
   closes.

### What the agent can do that a shell cannot

The agent talks to the kernel directly instead of composing shell commands:

- **Atomic file replacement** with `O_TMPFILE` and `renameat2`. A crash midway
  through leaves either the old file complete or the new file complete. There is
  no state where a config file is half written.
- **`/proc/sys` writes** for kernel parameters.
- **`delete_module(2)`** for kernel modules.
- **systemd over D-Bus** rather than parsing `systemctl` output.
- **Audit rules over netlink** rather than shelling out.

Four mechanisms get their strongest guarantee here: `file_content`,
`file_absent`, `config_set` and `config_set_dropin`. Kensa prints a line saying
so when it starts in agent mode.

### What is the same in both modes

This is the part worth trusting: **both paths write byte-identical files and
record an identical pre-state.** Capture and rollback do not care which mode
produced a change. A transaction applied in agent mode can be rolled back later,
and the reverse holds too.

The four-phase transaction, the evidence envelope and the transaction log are
all mode independent.

The difference is confined to what happens if the machine dies in the middle of
a single write. Agent mode gives you a kernel guarantee. Direct SSH gives you
best effort.

## Direct SSH mode

Set `KENSA_NO_AGENT=1` to run everything over the plain shell transport.

Reach for it when:

- the target cannot accept the agent binary, for example a read-only or heavily
  restricted filesystem
- you are debugging and want to see the exact shell Kensa would run
- a policy forbids copying executables to the target

You keep transactions, capture, rollback and evidence. You give up kernel-atomic
file replacement, and the mechanisms that need a kernel call fall back to their
shell equivalents.

Kensa prints which mode it is using at the start of every write command. If you
are reporting a problem, include that line, because the two paths are different
code.

## Privileges

Kensa is designed to log in as an unprivileged user and escalate with sudo. It
does not need a root SSH login.

- `--sudo` escalates the privileged work. In agent mode, the agent itself runs
  as root.
- `--sudo-password` supplies a password on hosts without a NOPASSWD rule. The
  password is written to the process input rather than the command line, so it
  does not appear in the host's process list.
- **Capability probes run as root when you pass `--sudo`**, and unprivileged
  otherwise. This is worth knowing when a rule depends on a file only root can
  read: without `--sudo`, the probe cannot see it and the rule may be skipped
  for the wrong reason.

## Which mode does a command use

| command | mode |
|---|---|
| `kensa detect` | direct SSH |
| `kensa check` | direct SSH, read-only |
| `kensa remediate` | agent by default |
| `kensa rollback` | agent by default |
| `kensa recover` | agent by default |
| `kensa history`, `kensa verify` | neither, these read the local log |

`kensa history` reads a **local** ledger and takes no connection flags. Its
`-H` option filters recorded results by host; it does not connect to one.

## Safety on the connection itself

Some changes can cut the connection Kensa is using: firewall rules, SSH
configuration, PAM, networking. For six mechanisms Kensa treats the connection
as at risk and arms a dead man timer on the host before applying:
`service_enabled`, `service_disabled`, `service_masked`, `pam_module_configure`,
`package_absent` and `command_exec`.

If the controller never confirms success, the host reverses the change on its
own. The timer disarms on a clean commit. See
[Rollback and history](05-rollback-and-history.md).

## Troubleshooting

**"agent mode needs the ssh transport's control socket"**
Kensa refused to start the agent because it could not reuse the existing
connection, and it will not build a replacement that ignores your settings. Run
with `KENSA_NO_AGENT=1` to use the direct path.

**Agent bootstrap fails on a locked-down host**
The target may forbid writing to `/var/cache`. Use `KENSA_NO_AGENT=1`.

**A rule is skipped and you expected it to run**
Check whether the rule depends on a capability that needs root to detect, then
re-run with `--sudo`. See [Concepts](03-concepts.md) for capability gating.

**Results differ between two runs of the same command**
Confirm both used the same mode. The banner line at the top of a write command
says which one, and the two paths are separate implementations.

---

Next: [Troubleshooting](08-troubleshooting.md) for error messages and debug
flags, or [Reference](09-reference.md) for every flag and environment variable.
