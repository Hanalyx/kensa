# Kensa Go

Transactional configuration management for Linux. The Go implementation of Kensa.

This repository is the production implementation of the Kensa Vision. The Python
reference implementation lives at [Hanalyx/kensa](https://github.com/Hanalyx/kensa)
and remains the source of behavioral truth during the 40-week Go build
(per `docs/context/KENSA_GO_DAY1_PLAN.md`).

## Status

**Pre-alpha.** Week-0 scaffolding only. The first working transaction engine
milestone (M1) lands at Week 4 per the Day-1 plan.

See [`docs/context/KENSA_GO_DAY1_PLAN.md`](docs/context/KENSA_GO_DAY1_PLAN.md) for the build
sequence, architectural principles, and the full list of interface commitments.

## Binary Portability

**Compile once, run on every supported Linux distribution.** kensa-go ships
as a single static binary that depends only on the Linux kernel ABI, not on
any specific libc. The same binary built today runs on:

- **RHEL 8 / 9 / 10** and binary-compatible derivatives (Rocky, AlmaLinux,
  CentOS Stream, Oracle Linux) — glibc 2.28 floor, no upper bound. RHEL 9
  (glibc 2.34) and RHEL 10 (glibc 2.39+) inherit the guarantee because
  glibc maintains strict backward compatibility; only the floor is
  CI-tested.
- **Ubuntu 22.04 LTS / 24.04 LTS** and Debian — glibc-based, same forward-
  compatibility argument applies.
- **Alpine** and any other distribution that uses the musl C library
  instead of glibc.

This portability is delivered by two build-discipline guarantees, both
enforced on every CI run:

| Guarantee | How | CI gate (`.github/workflows/ci.yml`) |
|---|---|---|
| Statically linked, no glibc floor | `CGO_ENABLED=0` (Makefile + workflow env) | `build-static-verify` — `ldd`/`file` assertion |
| Pure-Go DNS resolver, no `getaddrinfo` cgo path | `-tags netgo` (Makefile) + `GODEBUG=netdns=go` (workflow env) | `build-static-verify` confirms flag honored |
| Runs on glibc 2.28 (RHEL 8 floor) | static linking | `build-portability-glibc228` — runs binary inside `rockylinux:8` |
| Runs on musl (Alpine) | static linking + pure-Go DNS | `build-portability-alpine` — runs binary inside `alpine:3` |

A regression in any of the four — a transitive dependency that pulls cgo,
a Makefile change that drops `-tags netgo`, a binary that links against
glibc-specific symbols — fails the workflow before merge.

**Verify locally:**
```bash
make build
ldd bin/kensa  # "not a dynamic executable"
file bin/kensa # "statically linked"
```

The strategic context (why kernel ABI is the only stable surface to bet on
for a 5-year customer trust window) is in
[`docs/context/AI_DEFENSIBILITY.md`](docs/context/AI_DEFENSIBILITY.md). The
phased migration plan that established this discipline is
[`docs/roadmap/LOW_LEVEL_MIGRATION_V1.md`](docs/roadmap/LOW_LEVEL_MIGRATION_V1.md)
Phase 0 (deliverables L-001 through L-006).

## Foundational Documents

Read in this order:

1. [`docs/context/KENSA_VISION.md`](docs/context/KENSA_VISION.md) — what Kensa is and what category it defines
2. [`docs/foundation_docs/TECHNICAL_REMEDIATION_MP_V1.md`](docs/foundation_docs/TECHNICAL_REMEDIATION_MP_V1.md) — the seven principles, the transaction model
3. [`docs/foundation_docs/CANONICAL_RULE_SCHEMA_V1.md`](docs/foundation_docs/CANONICAL_RULE_SCHEMA_V1.md) — rule YAML contract with atomicity declaration
4. [`docs/RULE_REVIEW_GUIDE_V1.md`](docs/RULE_REVIEW_GUIDE_V1.md) — six review dimensions
5. [`docs/TRANSACTION_CONTRACT_V1.md`](docs/TRANSACTION_CONTRACT_V1.md) — customer-facing commitment
6. [`docs/context/KENSA_GO_DAY1_PLAN.md`](docs/context/KENSA_GO_DAY1_PLAN.md) — this repo's architectural contract

## Specs Before Code

This repository follows spec-driven development enforced by
[Specter](https://github.com/Hanalyx/spec-dd). Every handler, engine component,
and public API has a `.spec.yaml` in `specs/` with acceptance criteria that map
to tests in `tests/`.

```bash
# Validate specs and check traceability
make spec-sync

# Dependency graph as DOT
make spec-graph
```

Spec tier policy (see `specter.yaml`):

| Tier | Coverage requirement | Components |
|------|----------------------|------------|
| 1    | 100% AC-to-test      | `specs/engine/`, `specs/handlers/`, `specs/deadman/` |
| 2    | 80%                  | `specs/checks/`, `specs/transport/`, `specs/api/` |
| 3    | 50%                  | Formatters, CLI wrappers, non-mutation paths |

Tier 1 exists because those components are what the atomicity commitment in
`TRANSACTION_CONTRACT_V1.md` depends on. A divergence between spec and code in
Tier 1 is an atomicity violation.

## Layout

```
api/           Public Go API — frozen at commit 1, stable under v1 semver
internal/      Private packages — freely refactorable
  engine/      Transaction coordinator (capture → apply → validate → commit/rollback)
  handlers/    Mechanism implementations (one package per mechanism)
  transport/   SSH transport (system OpenSSH + ControlMaster)
  deadman/     Deadman-timer rollback path for control-channel-sensitive changes
  store/       SQLite transaction log
  evidence/    Evidence envelope + Ed25519 signing + OSCAL export
cmd/
  kensa/       CLI
  kensa-fuzz/  Failure-injection harness (atomicity verification)
  kensa-validate/  Rule and spec validator
specs/         Specter .spec.yaml files (language-neutral)
tests/         Go tests, organized to mirror source layout
fixtures/      Test fixtures (language-neutral, shared with Python Kensa)
docs/          Philosophy + architecture documentation
```

## License

BSL 1.1 → Apache 2.0 on 2029-01-01.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Specifically: every engine PR carries a
human-authored failure-mode analysis; every rollback handler requires two-human
review and a spec-derived integration test that induces a real failure on a real
RHEL host.
