# Kensa Go

Transactional configuration management for Linux. The Go implementation of Kensa.

This repository is the production implementation of the Kensa Vision. The Python
reference implementation lives at [Hanalyx/kensa](https://github.com/Hanalyx/kensa)
and remains the source of behavioral truth during the 40-week Go build
(per `docs/KENSA_GO_DAY1_PLAN.md`).

## Status

**Pre-alpha.** Week-0 scaffolding only. The first working transaction engine
milestone (M1) lands at Week 4 per the Day-1 plan.

See [`docs/KENSA_GO_DAY1_PLAN.md`](docs/KENSA_GO_DAY1_PLAN.md) for the build
sequence, architectural principles, and the full list of interface commitments.

## Foundational Documents

Read in this order:

1. [`docs/KENSA_VISION.md`](docs/KENSA_VISION.md) — what Kensa is and what category it defines
2. [`docs/TECHNICAL_REMEDIATION_MP_V1.md`](docs/TECHNICAL_REMEDIATION_MP_V1.md) — the seven principles, the transaction model
3. [`docs/CANONICAL_RULE_SCHEMA_V1.md`](docs/CANONICAL_RULE_SCHEMA_V1.md) — rule YAML contract with atomicity declaration
4. [`docs/RULE_REVIEW_GUIDE_V1.md`](docs/RULE_REVIEW_GUIDE_V1.md) — six review dimensions
5. [`docs/TRANSACTION_CONTRACT_V1.md`](docs/TRANSACTION_CONTRACT_V1.md) — customer-facing commitment
6. [`docs/KENSA_GO_DAY1_PLAN.md`](docs/KENSA_GO_DAY1_PLAN.md) — this repo's architectural contract

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
