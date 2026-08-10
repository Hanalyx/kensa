# Contributing to Kensa

Kensa modifies production Linux systems. A bug here can break customer
infrastructure at 3 AM. The discipline below is not optional.

## Reporting a bug or requesting a change

Open a GitHub issue. For a bug, include: the `kensa` version (`kensa --version`),
the target OS and version, the exact command, the observed behavior, and what
you expected, plus the relevant output (`--format json` where it helps). A
minimal reproduction on a disposable host is worth more than a description.

**Do not report a security vulnerability in a public issue.** Kensa makes
privileged changes to production hosts; follow [`SECURITY.md`](SECURITY.md) for
private disclosure (`security@hanalyx.com` or GitHub private vulnerability
reporting) and the safe-harbor terms.

## Building and testing

```sh
go build ./...        # build everything
go test ./...         # unit tests (live-host tests skip without the env vars below)
golangci-lint run     # lint (CI pins the version)
make spec-sync        # spec + coverage gate (see "Spec before code")
```

Every PR must pass all of these in CI (unit tests, lint, spec coverage, the
build, and the codegen and portability gates) before it can merge. Branch off
`main`, keep the branch up to date before merging (CI re-runs on update), and
open a PR.

## Developer prerequisites

Beyond Go itself (toolchain version pinned in `go.mod`), the build expects:

- **`protoc`** (Protocol Buffers compiler). Required by `make proto` for
  regenerating `internal/agent/wirev1/wire.pb.go` from `wire.proto`. Install a
  matching version from the
  [protocolbuffers/protobuf releases](https://github.com/protocolbuffers/protobuf/releases)
  page (CI uses v25.3; aim for the same or newer) and place the binary on `PATH`.
- **`protoc-gen-go`** (Go bindings plugin). Install with
  `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`. The version
  is pinned via `tools.go` so everyone regenerates byte-identical output.
  `go install` puts the binary in `$(go env GOPATH)/bin`. Make sure that's on
  `PATH`.

The codegen-drift gate (`make proto-check` + `TestCodegenSync`) fails the build
if the checked-in `wire.pb.go` differs from what `protoc` would produce today.
Run `make proto` after editing `wire.proto`, and commit both files together.

Without `protoc` installed locally, `go test ./...` skips `TestCodegenSync` (with
a clear message). CI installs `protoc` and fails hard if it can't run the gate,
so a missing-locally / passing-in-CI workflow is fine for everyday development.

### Live-host test env vars

Some tests run against a real SSH-able host. They skip by default; set the env
vars below to opt in.

- **`KENSA_TEST_SSH_HOST`**: host (or `host:port`) for SSH integration tests.
  When unset, SSH-dependent tests under `internal/transport/ssh/` skip.
- **`KENSA_TEST_AGENT_MODE=1`**: opt in to the agent-mode live-host parity test
  (`cmd/kensa.TestLiveAgentMode_FilePermissionsParity`). Requires
  `KENSA_TEST_SSH_HOST`, and the SSH user must be able to write
  `~/.cache/kensa/agent-<sha>` on the target. The test creates a temp file under
  the SSH user's `$HOME`, runs `file_permissions` remediate via both the
  direct-SSH and agent-mode paths, and asserts the results match (modulo
  timestamps and transaction IDs).

Without these, `go test ./...` passes cleanly with the live tests shown as `SKIP`
in `-v` output.

## How changes are reviewed

Every change is reviewed before it merges. Review is not optional, because a bug
here breaks production. A reviewer walks through the change, the spec it
satisfies, and the test that exercises its failure path before approving.

The bar scales with blast radius. An ordinary change needs a green CI run and a
reviewer's approval. A change to the transaction engine, a handler's capture or
rollback path, the public `api/` surface, or anything security-sensitive carries
the additional discipline below: a failure-mode analysis, two-reviewer approval
for rollback handlers, a real-host atomicity test, and a capture-sufficiency
analysis for transactional rules. None of it is skippable.

## Spec before code

Every component has a `.spec.yaml` in `specs/` with constraints and acceptance
criteria (ACs). Every AC maps to at least one test, annotated with its
`@spec`/`@ac` so the coverage gate can find it. Tests are co-located with the
code they cover (`*_test.go` next to the source). The spec is the contract; the
tests enforce it; the code satisfies the tests.

**Never adjust a test to match code output.** The spec is the source of truth. If
the code diverges from the spec, fix the code. If the spec is wrong, update the
spec first, and that needs approval before the implementation changes.

Run `make spec-sync` before every PR. A PR that reduces spec coverage below its
tier threshold blocks at CI. A new test must carry its `@spec`/`@ac` annotations,
or the coverage gate fails.

## Failure-mode analysis (engine, capture, rollback PRs)

Every PR that touches `internal/engine/`, `internal/handlers/*/capture.go`, or
`internal/handlers/*/rollback.go` includes a failure-mode analysis in the PR
description, answering:

1. What could this change do wrong in production?
2. What state is captured before the change, and is it sufficient to restore the
   system if the change or its validation fails?
3. What real-world edge case is this change *not* safe for, and is that edge case
   documented and gated?

The reviewer is the final reasoner: they walk through the change, the spec it
satisfies, and the integration test that exercises the failure path before
approving. That approval is the human signature the atomicity commitment depends
on.

## Two-reviewer review for rollback handlers

Every rollback handler (`internal/handlers/*/rollback.go`) requires:

- A spec-derived integration test that induces a real failure on a real host and
  verifies the rollback restores the exact pre-state.
- Review by two people (different engineers).
- Atomicity verification via `cmd/kensa-fuzz` against all supported OS versions.

Rollback handlers are where the atomicity guarantee lives. The ceremony is
proportional.

## Per-rule capture sufficiency (rule PRs)

Every rule PR with `transactional: true` includes a capture-sufficiency analysis
in the PR description:

```
## Capture Sufficiency Analysis

For each step in the remediation:
  - Step N: <mechanism>
    - Captured state: <what the capture handler records for these params>
    - Adjacent state not captured: <what the handler does NOT record>
    - Is the uncaptured state safe to leave unrestored on rollback? <yes/no/why>
```

Merge is blocked if this section is missing for a `transactional: true` rule.

## Commit messages

- **Imperative, present tense** in the subject (`fix(check): reject empty stdout`,
  not `fixed` / `fixes`). Keep the first line short; wrap the body.
- The body explains the **mechanism and the why**, the same standard as code
  comments: no planning labels, no chronology, no pointers into untracked docs.
- Engine, capture, or rollback commits carry the **failure-mode analysis** in the
  body (see above). Reference the PR/issue.
- Name a branch for what the change does (`fix/login-rate-limit`). A permanent,
  resolvable reference is fine: a PR number, an issue number, a CVE.

## Style

- `go fmt` on save; `golangci-lint run` before push.
- `make spec-sync` before push.
- Tests are co-located with the source (`foo_test.go` next to `foo.go`) and carry
  `@spec`/`@ac` annotations that the coverage gate ingests.
- Comments explain why the code is the way it is, in terms a reader who has only
  the code can follow. `make comment-lint` (CI job **Comment lint**) rejects
  planning labels such as `Phase 3` or `Option B` in changed Go comments. Write
  the mechanism instead. A comment that genuinely needs one can carry the
  `planlint:allow` directive.

## Documentation

The front-door docs (`README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`SECURITY.md`) are kept consistent by `make docs-check` (CI job **Docs
consistency**). Run it after touching any of them or `VERSION`.

- **Every user-visible change adds a `## Unreleased` CHANGELOG entry in the same
  PR**: a new flag, a changed default, a fixed verdict. Use the Keep a Changelog
  categories (Added / Changed / Deprecated / Removed / Fixed / Security). Never
  delete the `## Unreleased` heading; stamp it to `## vX.Y.Z (YYYY-MM-DD)` at
  release and open a fresh empty one. The parentheses are deliberate: the
  **Doc style** check rejects the em dash.
- `VERSION` matches the newest stamped CHANGELOG version, and the README states
  the current version. Bump both and refresh the README Status in the release
  PR. Front-door docs carry no stale version string (mark a deliberate historical
  reference with a `docs-check:allow-version` comment on that line).
- Report a security issue via [`SECURITY.md`](SECURITY.md), never a public issue.

Markdown is also checked for writing style by `make docs-style` (CI job **Doc
style**), which fails on em dashes, emojis, and AI-speak filler and hype. It scans
only the Markdown a pull request changes, and it scans those files whole rather
than line by line, so touching a file means clearing anything already there. Fix
the prose rather than suppress the finding. Where a term is genuinely unavoidable
and a maintainer agrees, mark that line with `<!-- doc-style: allow -->`.

## What gets merged without this discipline

Nothing. A PR that skips the failure-mode analysis, skips the rollback
integration test, or tries to adjust a test to match broken code is not merged.
This is the only way the atomicity commitment stays honest.
