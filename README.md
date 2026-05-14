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

## Getting started

The operator manual is in [`docs/guide/`](docs/guide/). Start with
[01-install](docs/guide/01-install.md) and
[02-quickstart](docs/guide/02-quickstart.md).

## What every remediation is

| Status | What happened | Reversible? |
|---|---|---|
| `committed` | Applied, validated, evidence signed and persisted | `kensa rollback` |
| `rolled_back` | Applied but validation failed; pre-state restored from capture | already reverted |
| `skipped` | Host was already compliant; no apply ran | nothing to revert |

A handler is *capturable* if it records the host's pre-state before
Apply. Of the 29 handlers shipped, 19 are capturable (file permissions,
file content, services, sysctl, mount options, SELinux booleans, kernel
modules, audit rules, cron, packages, and PAM) and give the full
atomicity guarantee. The remaining 10 are non-capturable, carry
`transactional: false` in their rule YAML, and `kensa plan` flags them
before any apply runs.

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

Verify locally:

```bash
make build
file bin/kensa   # "ELF 64-bit ... statically linked"
ldd  bin/kensa   # "not a dynamic executable"
```

## Status

`v0.1.0` (codename Sentinel). The 0.x line is the development phase:
behavior may change between MINOR versions with one release of
deprecation warning. The `api/` Go package is held to a stricter
contract — frozen under v1 semver from this version onward for
OpenWatch's consumption.

See [`VERSION`](VERSION) for the current string and
[`VERSIONING_PLAN.md`](VERSIONING_PLAN.md) for the release contract.

## Quality discipline

Every component has a `.spec.yaml` under `specs/` with acceptance
criteria that map to Go tests. The strict-coverage gate (`make
spec-coverage-strict`) enforces tier-specific thresholds:

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
