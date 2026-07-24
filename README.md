# Kensa

[![CI](https://github.com/Hanalyx/kensa/actions/workflows/ci.yml/badge.svg)](https://github.com/Hanalyx/kensa/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Hanalyx/kensa?sort=semver)](https://github.com/Hanalyx/kensa/releases/latest)
[![License: BSL 1.1](https://img.shields.io/badge/license-BSL%201.1-blue)](LICENSE)
[![Security policy](https://img.shields.io/badge/security-policy-informational)](SECURITY.md)

Atomic compliance remediation for Linux. Every change runs as a four-phase
transaction (`Capture → Apply → Validate → Commit/Rollback`) with signed
evidence and verified rollback on failure.

```bash
kensa check     -H <host> -u <user> --sudo --severity high
kensa remediate -H <host> -u <user> --sudo --severity high
kensa history
kensa rollback  --txn <transaction-id> -H <host> -u <user> --sudo
```

One static binary. No glibc floor. No runtime dependency on the target host
beyond OpenSSH.

> **Pre-1.0.** Signed `rpm` and `deb` packages ship for amd64 and arm64, plus a
> noarch `kensa-rules` package that installs the corpus to
> `/usr/share/kensa/rules`. `dnf install kensa` pulls it in via `Recommends`, so
> `--rules-dir` is optional once installed. See
> [the install guide](docs/guide/01-install.md). Only the `api/` Go package is
> frozen under v1 semver; CLI flags, rule schema, and output formats may change
> between MINOR versions with one release of deprecation warning.

## Getting started

The operator manual is in [`docs/guide/`](docs/guide/). Start with
[install](docs/guide/01-install.md) and
[quickstart](docs/guide/02-quickstart.md).

## What every remediation is

A *transaction* is the four-phase unit of change. A handler is *capturable* when
it records the host's pre-state before Apply, so rollback can restore that state
exactly. Each transaction ends in one terminal status:

| Status | What happened | Reversible? |
|---|---|---|
| `committed` | Applied, re-validated, evidence signed and persisted | `kensa rollback` |
| `rolled_back` | Apply or validation failed; pre-state restored and machine-verified | already reverted |
| `skipped` | Already compliant, or out of platform; no apply ran | nothing to revert |
| `errored` | A phase could not complete; recorded, host left as-is | per the error |

Of the 29 handlers shipped, 24 are capturable and give the full atomicity
guarantee. The other 5 carry `transactional: false`, and `kensa plan` flags them
before any apply runs: 2 grub handlers stage through the boot guard and stay
PENDING until the operator reboots; 3 (`command_exec`, `crypto_policy_subpolicy`,
`manual`) are non-capturable with no rollback.

See [the concepts chapter](docs/guide/03-concepts.md) for the contract in full.

## The atomicity engine

On the agent path, a remediation is a *verified* transaction:

- **Durably journaled.** Intent and captured pre-state are written (fsync) before
  any host change, so an interrupted run is reverse-replayed by `kensa recover`
  instead of leaving the host half-applied.
- **Re-measured.** The host is re-read after apply: a change is `committed` only
  when machine-verified, `rolled_back` only when restoration is verified.
- **Kernel-atomic.** File mechanisms write through `O_TMPFILE` + `renameat2`,
  behind a pre-commit gate that refuses to commit if an apply touched anything it
  did not capture.

The direct-SSH path keeps a byte-identical shell fallback. See
[`CHANGELOG.md`](CHANGELOG.md) for the full release history.

## Portability

`kensa` is statically linked (`CGO_ENABLED=0`) and uses the pure-Go DNS resolver
(`-tags netgo`). It depends on the Linux kernel ABI only, not libc. The same
binary runs on:

| Distribution | libc | CI gate |
|---|---|---|
| RHEL 8, Rocky 8, AlmaLinux 8 | glibc 2.28 | `rockylinux:8` |
| RHEL 9 / 10 and derivatives | glibc 2.34+ | inherits the 2.28 floor |
| Ubuntu 22.04 / 24.04 LTS, Debian | glibc | inherits glibc compat |
| Alpine 3+ | musl | `alpine:3` |

A regression (a transitive dependency that pulls cgo, a Makefile change that
drops `-tags netgo`, a binary that links a glibc-specific symbol) fails CI before
merge.

## Building from source

Requires Go 1.26+ and make.

```bash
git clone git@github.com:Hanalyx/kensa.git
cd kensa
make build                # builds all five binaries into bin/
./bin/kensa --version     # → kensa 0.8.0 (kensa)
```

The five binaries:

| Binary | Purpose |
|---|---|
| `kensa` | The CLI: `detect`, `check`, `remediate`, `rollback`, `recover`, `history`, `plan`, `info`, `diff`, `verify`, and more (run `kensa --help`) |
| `kensa-fuzz` | Failure-injection harness for atomicity verification on real hosts |
| `kensa-validate` | Rule YAML and spec validator |
| `kensa-keygen` | Ed25519 keypair generator for evidence signing |
| `kensa-systemd-helper` | Privileged systemd D-Bus helper (sudo-invoked) |

Confirm the binary is statically linked:

```bash
file bin/kensa   # "ELF 64-bit ... statically linked"
ldd  bin/kensa   # "not a dynamic executable"
```

## Status

`v0.8.0`, released and signed. The 0.x line is the pre-1.0 development phase. The
`api/` Go package is frozen under v1 semver for OpenWatch's consumption; the rest
of the surface (CLI flags, rule schema additions, output formats) may change
between MINOR versions with one release of deprecation warning. All 29 handlers
carry passing spec-driven tests.

What shipped in each release is in [`CHANGELOG.md`](CHANGELOG.md); see
[`VERSION`](VERSION) for the current string and
[`VERSIONING_PLAN.md`](VERSIONING_PLAN.md) for the release contract.

Open before v1.0: RHEL 8 `$kernelopts` capture in the boot guard, broader
standalone Ubuntu corpus coverage, and live proof of the systemd D-Bus service
path.

## Quality discipline

Every component has a `.spec.yaml` under `specs/` with acceptance criteria that
map to Go tests. The strict-coverage gate (`make spec-coverage-strict`) enforces
tier-specific thresholds:

- **Tier 1** (engine, handlers, deadman): 100% acceptance-criterion-to-test
- **Tier 2** (checks, transport, API): 80%
- **Tier 3** (CLI, formatters): 50%

A divergence between spec and code in Tier 1 is an atomicity violation. Run
`make spec-sync` for the full pipeline.

## Security

Kensa makes privileged changes to production hosts, so we want your reports.
Do **not** open a public issue for a vulnerability — see [`SECURITY.md`](SECURITY.md)
for private disclosure (email `security@hanalyx.com` or GitHub private
vulnerability reporting), our response process, and the safe-harbor terms.

## License

Business Source License 1.1; converts to Apache 2.0 on 2029-01-01.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Every engine PR carries a human-authored
failure-mode analysis. Rollback handlers require two-human review and a real-host
atomicity test via `kensa-fuzz`.
