# `kensa detect`

## Purpose

Probes a host and prints its capability set. Read-only — no mutations, no rule loading. Used by operators to:
- Verify SSH connectivity and sudo before a scan.
- Inspect which capability probes (e.g., `selinux`, `apparmor`, `dpkg`, `apt`) the host has.
- Drive `--capability` overrides for downstream check/remediate.

## Current state

DONE. Runs against any reachable Linux host with SSH access. Capability vocabulary is 31 probes (see `internal/detect/detect.go`); `KnownCapabilities()` returns them sorted.

The `--capability` override produced in C-028 is supported on detect for parity with check/remediate — operators see the post-override view of what scan/remediate would consume.

## Flags

### Target options

| Flag | Status | Note |
|---|---|---|
| `-H, --host` | DONE | Required |
| `-u, --user` | DONE | Defaults to current user |
| `-k, --key` | DONE | SSH private key path |
| `-p, --password` | DONE (C-026) | TTY prompt with bare `-p`; reserved literal `<prompt>` |
| `-P, --port` | DONE | Default 22 |
| `--sudo` | DONE | |
| `--strict-host-keys` / `--no-strict-host-keys` | DONE (C-027) | Mutex enforced; under strict, `UpdateHostKeys=no` is also set |
| `-C, --capability` | DONE (C-028) | Repeatable KEY=VALUE; vocabulary-validated against `detect.KnownCapabilities()` |

### Output options

| Flag | Status | Note |
|---|---|---|
| `--format` | DEPRECATED | Use `-o`. Still works; emits warning |
| `-o, --output` | DONE | Repeatable; supports `table`, `json`, `csv` for detect |
| `-q, --quiet` | DONE | Suppresses default text body |

### General

| Flag | Status |
|---|---|
| `-h, --help` | DONE |

## Verification protocol

```bash
# 1. Help text (no network).
./bin/kensa detect --help

# 2. Negative-path validation (no network — fails before SSH).
./bin/kensa detect -C bogus-cap=true                                # exit 2
./bin/kensa detect --strict-host-keys --no-strict-host-keys -H foo  # exit 2

# 3. Live read-only against fixture.
./bin/kensa detect -H 192.168.1.211 -u owadmin --no-strict-host-keys

# 4. Capability override view (no actual scan).
./bin/kensa detect -H 192.168.1.211 -u owadmin --no-strict-host-keys \
    -C selinux=false -C apparmor=true
```

Expected: text output of 31 capabilities, prefixed `✓` or `✗`, with overrides flipping selinux to ✗ and apparmor to ✓.

## Known limits

- **Host-key default is TOFU** (`StrictHostKeyChecking=accept-new`). Matches Python kensa for upgrade compatibility but is debatable for a privileged-remediation tool. Spec C-027 documents the rationale; future v0.2 may flip the default to strict once the config-file deliverable lands.
- **`--inventory` not supported on detect.** Detect is single-host by design; multi-host capability surveys would require fan-out we haven't built.
- **Output formats limited to table / json / csv.** No PDF / OSCAL / evidence on detect — the underlying writers are scan-result-shaped, not capability-shaped.
