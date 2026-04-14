# Contributing to Kensa Go

Kensa modifies production Linux systems. A bug here can break customer
infrastructure at 3 AM. The discipline below is not optional.

## Spec Before Code

Every component has a `.spec.yaml` in `specs/` with constraints and acceptance
criteria. Every AC maps to at least one test in `tests/`. The spec is the
contract; the tests enforce the contract; the code satisfies the tests.

**Never adjust a test to match code output.** The spec is the source of truth.
If the code diverges from the spec, fix the code. If the spec is wrong, update
the spec first (and it needs approval before implementation changes).

Run `make spec-sync` before every PR. A PR that reduces spec coverage below the
tier threshold blocks at CI.

## Failure-Mode Analysis (engine, capture, rollback PRs)

Every PR that touches `internal/engine/`, `internal/handlers/*/capture.go`, or
`internal/handlers/*/rollback.go` includes a human-authored failure-mode
analysis in the PR description, answering:

1. What could this change do wrong in production?
2. What state is captured before the change, and is it sufficient to restore
   the system if the change or its validation fails?
3. What real-world edge case is this change *not* safe for, and is that edge
   case documented and gated?

The analysis is written by a human. AI tools may help structure or polish it;
they may not be the final reasoner. The analysis is checked into permanent PR
history — the git log is the audit trail that
`TRANSACTION_CONTRACT_V1.md` §3.2 claims a human signed off on.

## Two-Human Review for Rollback Handlers

Every rollback handler (`internal/handlers/*/rollback.go`) requires:

- Spec-derived integration test that induces a real failure on a real RHEL
  host and verifies the rollback restores the exact pre-state
- Two-human review by different engineers
- Atomicity verification via `cmd/kensa-fuzz` against all supported OS versions

Rollback handlers are where the atomicity moat lives. Ceremony is proportional.

## Per-Rule Capture Sufficiency (rule PRs)

Every rule PR with `transactional: true` includes a capture-sufficiency
analysis in the PR description:

```
## Capture Sufficiency Analysis

For each step in the remediation:
  - Step N: <mechanism>
    - Captured state: <what the capture handler records for these params>
    - Adjacent state not captured: <what the handler does NOT record>
    - Is the uncaptured state safe to leave unrestored on rollback? <yes/no/why>
```

Merge is blocked if this section is missing for a `transactional: true` rule.

## Dual-Language Fixtures During Coexistence

Fixtures in `fixtures/handlers/*/` are shared with the Python Kensa reference
implementation. Changes to a fixture must pass both the Go and Python test
suites before the fixture change merges. If the Python and Go implementations
diverge against the same fixture, the spec arbitrates — fix whichever
implementation is wrong, not the fixture.

## Style

- `go fmt` on save; `golangci-lint run` before push.
- `make spec-sync` before push.
- Tests go in `tests/` mirroring the source path (not co-located with source).
  This matches the Specter coverage layout.

## What Gets Merged Without This Discipline

Nothing. A PR that skips the failure-mode analysis, skips the rollback
integration test, or tries to adjust a test to match broken code is not
merged. This is the only way the atomicity commitment in
`docs/TRANSACTION_CONTRACT_V1.md` remains honest.
