# Kensa

Atomic compliance remediation for Linux. Every change runs as a
four-phase transaction — `Capture → Apply → Validate → Commit/Rollback` —
with signed evidence and full rollback on failure.

```bash
kensa check     --rules-dir /usr/share/kensa/rules --severity high <host>
kensa remediate --rules-dir /usr/share/kensa/rules --severity high <host>
kensa history
kensa rollback <transaction-id>
```

One static binary. No glibc floor. No runtime dependency on the target
host beyond OpenSSH.

> **Pre-1.0 note.** Signed `rpm` and `deb` packages ship as of v0.2.0
> (amd64 + arm64), with a noarch `kensa-rules` package that installs the
> corpus to `/usr/share/kensa/rules`; `dnf install kensa` pulls it via
> `Recommends`, so `--rules-dir` becomes optional. See
> [01-install](docs/guide/01-install.md) for the package install, or
> [Building from source](#building-from-source) for the development path.
> The 0.x line is still pre-1.0: only the `api/` Go package is frozen
> under v1 semver; CLI flags, rule schema, and output formats may change
> between MINOR versions with one release of deprecation warning.

## Getting started

The operator manual is in [`docs/guide/`](docs/guide/). Start with
[01-install](docs/guide/01-install.md) and
[02-quickstart](docs/guide/02-quickstart.md). Chapters that mark
themselves **Stub** carry pre-1.0 placeholders; the binary's `--help`
and the relevant `.spec.yaml` under `specs/` are the authoritative
source until they land.

## What every remediation is

| Status | What happened | Reversible? |
|---|---|---|
| `committed` | Applied, validated, evidence signed and persisted | `kensa rollback` |
| `rolled_back` | Applied but validation failed; pre-state restored from capture | already reverted |
| `skipped` | Host was already compliant; no apply ran | nothing to revert |

A handler is *capturable* if it records the host's pre-state before
Apply. Of the 29 handlers shipped, 24 are capturable (file permissions,
file content, services, sysctl, mount options, SELinux booleans, kernel
modules, audit rules, cron, packages, PAM, authselect, crypto-policy,
dconf, and config append) and give the full atomicity guarantee. The
remaining 5 carry `transactional: false` in their rule YAML and `kensa
plan` flags them before any apply runs: 2 (`grub_parameter_set`,
`grub_parameter_remove`) stage through the boot guard and stay PENDING
until the operator reboots; 3 (`command_exec`, `crypto_policy_subpolicy`,
`manual`) are non-capturable with no rollback.

See [03-concepts](docs/guide/03-concepts.md) for the contract in full.

## Portability

`kensa` is statically linked (`CGO_ENABLED=0`) and uses the pure-Go DNS
resolver (`-tags netgo`). It depends on the Linux kernel ABI only — no
libc. The same binary runs on:

| Distribution | libc | CI gate |
|---|---|---|
| RHEL 8, Rocky 8, AlmaLinux 8 | glibc 2.28 | `rockylinux:8` |
| RHEL 9 / 10 and derivatives | glibc 2.34+ | (inherits 2.28 floor) |
| Ubuntu 22.04 / 24.04 LTS, Debian | glibc | (inherits glibc compat) |
| Alpine 3+ | musl | `alpine:3` |

A regression — a transitive dependency that pulls cgo, a Makefile
change that drops `-tags netgo`, a binary that links against
glibc-specific symbols — fails CI before merge.

## Building from source

This is how to run kensa today, pre-1.0. Requires Go 1.26+ and make.

```bash
git clone git@github.com:Hanalyx/kensa.git
cd kensa
make build                # builds all five binaries into bin/
./bin/kensa --version     # → kensa 0.2.3 (kensa)
```

The five binaries:

| Binary | Purpose |
|---|---|
| `kensa` | The CLI: `detect`, `check`, `remediate`, `rollback`, `history`, `plan`, `verify` |
| `kensa-fuzz` | Failure-injection harness for atomicity verification on real hosts |
| `kensa-validate` | Rule YAML and spec validator |
| `kensa-keygen` | Ed25519 keypair generator for evidence signing |
| `kensa-systemd-helper` | Privileged systemd D-Bus helper (sudo-invoked) |

Run a scan today:

```bash
./bin/kensa check \
    --rules-dir /path/to/kensa-rules \
    --severity high \
    <host>
```

Verify the binary is statically linked:

```bash
file bin/kensa   # "ELF 64-bit ... statically linked"
ldd  bin/kensa   # "not a dynamic executable"
```

## Status

`v0.2.3`. The 0.x line is the development phase.

The `api/` Go package is held to a stricter contract — frozen under v1
semver for OpenWatch's consumption. Behavior on the rest of the surface
(CLI flags, rule schema additions, output formats) may change between
MINOR versions with one release of deprecation warning.

Shipped since v0.1.0: signed rpm/deb + `kensa-rules` packages (v0.2.0),
rules-dir default-path resolution (`/usr/share/kensa/rules`), the
`grub_parameter_set` / `grub_parameter_remove` boot guard, the
`kensa-systemd-helper` sudoers fragment (v0.2.2), and live result-row
streaming for `check`/`remediate` (v0.2.3). All 29 handlers carry passing
spec-driven tests.

Open ship items before v1.0: RHEL 8 `$kernelopts` capture in the boot
guard, the `AUDIT_NETLINK` audit-rule path, and dual-path service
handlers on the systemd D-Bus primitive layer.

See [`VERSION`](VERSION) for the current string and
[`VERSIONING_PLAN.md`](VERSIONING_PLAN.md) for the release contract.

## Quality discipline

Every component has a `.spec.yaml` under `specs/` with acceptance
criteria that map to Go tests. The strict-coverage gate
(`make spec-coverage-strict`) enforces tier-specific thresholds:

- **Tier 1** (engine, handlers, deadman) — 100% AC-to-test
- **Tier 2** (checks, transport, API) — 80%
- **Tier 3** (CLI, formatters) — 50%

A divergence between spec and code in Tier 1 is an atomicity violation.
Run `make spec-sync` for the full pipeline.

## License

BSL 1.1, converts to Apache 2.0 on 2029-01-01.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Every engine PR carries a
human-authored failure-mode analysis. Rollback handlers require
two-human review and a real-host atomicity test via `kensa-fuzz`.
