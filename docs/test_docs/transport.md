# SSH Transport

## Purpose

The transport is how kensa-go reaches a target host. Every detect / check / remediate / plan / rollback / history (with --host) opens an SSH connection, runs commands over it, and closes it. The transport's design choices are load-bearing for security and reliability.

## Current state

DONE. Uses **system OpenSSH** (the `ssh` binary on PATH), not a Go SSH library. This is intentional — system SSH handles key agents, jump hosts, `~/.ssh/config`, and known_hosts correctly.

ControlMaster + ControlPersist multiplexes commands over a single connection: kensa pays the SSH-handshake cost once per host, every subsequent command runs in the established channel with sub-millisecond latency.

`sshpass` is used when `--password` is set (C-026); the password flows through the `SSHPASS` env var, never argv. See [`security.md`](security.md) for the threat model.

## Components

| File | Purpose |
|---|---|
| `internal/transport/ssh/ssh.go` | Connect (open ControlMaster), Run (per-command), Put / Get (file transfer), Close. |
| `internal/transport/ssh/factory.go` | Translate `api.HostConfig` → `ssh.Config` → `Connect`. |
| `internal/transport/ssh/control_channel.go` | Sensitive-mode toggle for the deadman timer. |

## Verification protocol

```bash
# 1. Unit tests (no network).
go test ./internal/transport/ssh/...

# 2. Real-host SSH integration.
KENSA_TEST_SSH_HOST=192.168.1.211 \
KENSA_TEST_SSH_USER=owadmin \
go test ./internal/transport/ssh/... -timeout 5m

# 3. ControlMaster reuse (multiplex). Should run a 5-rule scan in <1s after handshake.
time ./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    -s critical \
    --rules-dir /home/rracine/hanalyx/kensa/rules

# 4. Strict host keys.
./bin/kensa detect -H 192.168.1.211 -u owadmin --strict-host-keys
# Expected: works if the host key is in ~/.ssh/known_hosts; fails clean otherwise.

# 5. Password auth via sshpass.
./bin/kensa detect -H 192.168.1.211 -u owadmin --password=hunter2 --no-strict-host-keys
# Expected: kensa invokes `sshpass -e ssh ...` with SSHPASS env var; password never in argv.
# Verify: `pgrep -af sshpass` during the run shows the command line WITHOUT the password.

# 6. Password TTY prompt.
./bin/kensa detect -H 192.168.1.211 -u owadmin --password --no-strict-host-keys
# Expected: prompts on the controlling TTY; password not echoed.

# 7. Non-TTY guard.
echo | ./bin/kensa detect -H 192.168.1.211 -u owadmin --password --no-strict-host-keys
# Expected: usage error mentioning TTY, no hang.
```

## Configuration

| Setting | Default | Override |
|---|---|---|
| Port | 22 | `--port` / `-P` |
| User | current login user | `--user` / `-u` |
| Key | system defaults (`~/.ssh/config`, ssh-agent) | `--key` / `-k` |
| Password | (none — key-based auth) | `--password` / `-p` (requires sshpass) |
| Sudo | off | `--sudo` |
| StrictHostKeyChecking | `accept-new` (TOFU) | `--strict-host-keys` (sets `yes`) |
| UpdateHostKeys | inherited from `~/.ssh/config` | overridden to `no` under `--strict-host-keys` |
| ControlPersist | 600s | (not configurable today) |
| ConnectTimeout | 30s | (not configurable today) |

## Known limits

- **Default host-key policy is `accept-new` (TOFU).** Matches Python kensa for upgrade compatibility. Under TOFU, the first connection auto-trusts the host key; subsequent key changes are rejected. A first-connection MITM can be undetectable. Operators wanting strict-from-day-one must populate `~/.ssh/known_hosts` via `ssh-keyscan` (after out-of-band fingerprint verification) and use `--strict-host-keys`.
- **`sshpass` is required for `--password`.** Not bundled with kensa-go. Connect returns a clear error when sshpass is missing. Most distros: `apt-get install sshpass` / `dnf install sshpass`. macOS: not available in homebrew core; use `hudochenkov/sshpass`.
- **No native Go SSH password auth.** Intentional — system SSH handles key agents and config correctly; we'd lose that to ship a Go-native password path.
- **No `--known-hosts-file`.** Custom known_hosts paths require `~/.ssh/config` `UserKnownHostsFile` directives. A future deliverable may add this flag.
- **No retry / reconnect.** A connection drop during a long scan aborts the scan. Inventory mode's per-host fan-out absorbs single-host failures gracefully; single-host scans don't.
- **`UpdateHostKeys=no` only set under strict mode.** Under default `accept-new`, OpenSSH 8.5+ may silently learn rotated keys from the server. This is the OpenSSH default; kensa-go matches it under non-strict mode for compatibility.
- **No SSH-config exclusion.** kensa always inherits `~/.ssh/config`. An operator with a malicious `Match host` block in their config could route kensa's SSH commands through unexpected jump hosts. This is the same trust boundary as `ssh` itself.
