# Contributing to Kensa Go

Kensa modifies production Linux systems. A bug here can break customer
infrastructure at 3 AM. The discipline below is not optional.

## Developer prerequisites

Beyond Go itself (toolchain version pinned in `go.mod`), kensa-go's
build expects:

- **`protoc`** (Protocol Buffers compiler). Required by `make proto`
  for regenerating `internal/agent/wirev1/wire.pb.go` from
  `wire.proto`. Install the matching version from the
  [protocolbuffers/protobuf releases](https://github.com/protocolbuffers/protobuf/releases)
  page (CI uses v25.3; aim for the same or newer). Place the binary
  on `PATH`.
- **`protoc-gen-go`** (Go bindings plugin). Install with
  `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`.
  The version is pinned via `tools.go` so all developers regenerate
  byte-identical output. `go install` puts the binary in
  `$(go env GOPATH)/bin`; make sure that's on `PATH`.

The codegen-drift gate (`make proto-check` + `TestCodegenSync`)
fails the build if checked-in `wire.pb.go` differs from what
`protoc` would produce today. Run `make proto` after editing
`wire.proto`, commit both files together.

Without `protoc` installed locally, `go test ./...` will skip
`TestCodegenSync` (with a clear message). CI installs protoc and
fails hard if it can't run the gate — so a missing-locally /
passing-in-CI workflow is fine for everyday development.

### Live-host test env vars

Some tests run against a real SSH-able host. They skip by
default; set the env vars below to opt in.

- **`KENSA_TEST_SSH_HOST`** — host (or `host:port`) for SSH
  integration tests. When unset, SSH-dependent tests under
  `internal/transport/ssh/` skip.

- **`KENSA_TEST_AGENT_MODE=1`** — opt-in for the L-014c
  agent-mode live-host parity test
  (`cmd/kensa.TestLiveAgentMode_FilePermissionsParity`).
  Requires `KENSA_TEST_SSH_HOST` AND the SSH user must be
  able to write `~/.cache/kensa/agent-<sha>` on the target.
  The test creates a temp file under the SSH user's `$HOME`,
  runs file_permissions remediate via both direct-SSH and
  agent-mode paths, and asserts the RemediationResult
  matches (modulo timestamps and transaction IDs).

Without these, `go test ./...` passes cleanly with the
live tests showing as `SKIP` in `-v` output.

## Authorship Model

The Kensa AI team and collaborator write all of the application code. The
founders conduct rigorous tests and review every change. Human review of
the code is non-negotiable — see `docs/HANALYX_MISSION_AND_ROADMAP.md`
§"The human-review commitment" for the full statement.

This means: PR authorship is typically AI; PR approval is always human.
Every section below assumes that split.

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
`internal/handlers/*/rollback.go` includes a failure-mode analysis in the PR
description, answering:

1. What could this change do wrong in production?
2. What state is captured before the change, and is it sufficient to restore
   the system if the change or its validation fails?
3. What real-world edge case is this change *not* safe for, and is that edge
   case documented and gated?

AI may draft the analysis. The reviewing founder is the final reasoner: they
walk through the change, the spec it satisfies, and the integration test
that exercises the failure path before approving the PR. Their approval is
the human signature `TRANSACTION_CONTRACT_V1.md` §3.2 claims is in the git
history.

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
