# Continuation Prompt — Kensa Go (paste into a fresh Claude Code session)

**Repo:** `git@github.com:Hanalyx/kensa-go.git` cloned at
`/home/rracine/hanalyx/kensa-go`
**Last commit at handoff:** `8af38ff` — "Add sysctl_set and service_enabled handlers"
**Date of handoff:** 2026-04-15
**Owning org:** Hanalyx
**Sister repos:**
- `/home/rracine/hanalyx/kensa` — Python reference implementation (still
  in active maintenance)
- `/home/rracine/hanalyx/openwatch` — fleet control plane that imports
  `kensa-go/api`

---

## 0. Paste-this prompt (start of new session)

> I'm continuing work on Kensa Go, the Go rewrite of Hanalyx's Kensa
> compliance/atomicity engine. The handoff document is at
> `/home/rracine/hanalyx/kensa-go/docs/NEW_SESSION_LOG.md`. Read it
> end-to-end before doing anything else, then read the documents it
> tells you to read, then ask me what chunk to work on next.
>
> The repo is at `/home/rracine/hanalyx/kensa-go`. CI is green at
> `8af38ff`. Three milestones (Weeks 1, 2, 3, plus Week-4 SSH transport
> and the api.Kensa wiring) are complete. Three handlers ship today
> (file_permissions, sysctl_set, service_enabled). M1 (trivial
> transaction against a real host through the public api/ surface) is
> reached.
>
> The user is the founder. They review code; the AI agent writes code.
> Every PR that touches the engine, capture, or rollback paths needs a
> human-authored failure-mode analysis in the commit body — see
> `CONTRIBUTING.md`. Comment style follows Google's Go Style Guide
> enforced by golangci-lint v1.64.8 with the comment-style suite.

---

## 1. Mission in one paragraph

Kensa is **transactional configuration management for Linux**. Every
mutation runs as a four-phase transaction (capture → apply → validate
→ commit-or-rollback) with the atomicity, auditability, and
reversibility commitments stated in
`docs/TRANSACTION_CONTRACT_V1.md`. Kensa Go (this repo) is the
production Go implementation; the Python repo is the reference. The
40-week build to v1.0.0 is laid out in
`docs/KENSA_GO_DAY1_PLAN.md`.

The category framing matters: **OpenWatch is to Kensa as GitHub is to
git**. OpenWatch presents, aggregates, orchestrates, and collaborates;
it never re-implements what Kensa already does for a single host. This
relationship governs API design, ownership boundaries, and where new
features land. See `docs/OPENWATCH_VISION.md` (in the Python repo) for
the detailed framing.

---

## 2. Read these documents first, in this order

All in `/home/rracine/hanalyx/kensa-go/docs/`:

1. **`KENSA_VISION.md`** — what Kensa is, why the four phases, where
   the category came from. The "Compliance is the first market, not
   the final market" framing.
2. **`TECHNICAL_REMEDIATION_MP_V1.md`** — the seven principles, the
   three-layer architecture, and the transaction model that makes
   Principle 7 (Atomicity) verifiable.
3. **`CANONICAL_RULE_SCHEMA_V1.md`** — rule YAML contract with the
   `transactional` declaration. Even though Go-side rule parsing isn't
   wired up yet (Week 21), every handler must align with this schema.
4. **`RULE_REVIEW_GUIDE_V1.md`** — six review dimensions including
   the new Rollback Safety dimension.
5. **`TRANSACTION_CONTRACT_V1.md`** — the customer-facing commitment.
   This is what every code change must remain consistent with.
6. **`KENSA_GO_DAY1_PLAN.md`** — the architectural contract for this
   repo. Section §3 is the authoritative interface design; §11 is the
   week-by-week build sequence; §15 is the First-PR scope.
7. **`HANALYX_MISSION_AND_ROADMAP.md`** — the seven trust moats and
   the **human-review commitment**. Critical: AI writes the code,
   founders review and test. Every engine/capture/rollback PR needs a
   failure-mode analysis.
8. **`KENSA_OPENWATCH_COORDINATION_2026-04-14.md`** — OpenWatch's
   memo asking for interface refinements before the api/ freeze.
9. **`KENSA_OPENWATCH_RESPONSE_2026-04-14.md`** — Kensa's response
   committing to specific interface decisions. **All commitments here
   are now in code at the api/ boundary.**
10. **`KENSA_OPENWATCH_PROGRESS_2026-04-15.md`** — the most recent
    progress memo to OpenWatch announcing M1. **Marked Status: Draft;
    awaits founder review before sending.**
11. **`CONTRIBUTING.md`** at the repo root — the per-PR discipline
    requirements (failure-mode analysis, two-human review for
    rollback handlers, per-rule capture sufficiency).

After these, skim `specs/` to see the Specter spec format. The full
list is at the end of this document.

---

## 3. Repository state at handoff

### Branch and commit

```
branch: main
HEAD:   8af38ff Add sysctl_set and service_enabled handlers
```

CI status at HEAD: ✓ Spec Sync, ✓ Unit Tests, ✓ Lint, ✓ Pre-commit
hygiene.

### Layout

```
kensa-go/
├── api/                    PUBLIC contract — frozen v1 semver
│   ├── doc.go              package-level overview with three identities
│   ├── handler.go          Handler / CaptureHandler / RollbackHandler /
│   │                       CombinedHandler / Params
│   ├── transaction.go      Transaction / TransactionResult / Step /
│   │                       StepResult / PreState / RollbackResult /
│   │                       EvidenceEnvelope / TransactionStatus / Phase
│   ├── transport.go        Transport / CommandResult
│   ├── log_query.go        LogQuery + LogFilter / FrameworkRef / Page /
│   │                       AggregateKey (5 values) / TimeBucket /
│   │                       GetOption / AggregateOption /
│   │                       ResolveGetOptions / ResolveAggregateOptions
│   ├── events.go           EventPublisher / EventSubscriber / Event /
│   │                       EventKind (8 values) / EventFilter
│   ├── planner.go          Planner / Executor / Plan / PreviewFormat /
│   │                       StepPreview / RollbackStepPreview /
│   │                       Rule / Implementation / Check / Remediation
│   ├── envelope_verifier.go EnvelopeVerifier / VerifyResult /
│   │                       VerifyWarning (KeyRotation, ClockSkew)
│   ├── deadman.go          DeadmanControl / DeadmanState
│   ├── concurrency.go      RunOption / WithNonBlocking
│   ├── errors.go           ErrNotYetImplemented / ErrHostBusy /
│   │                       ErrSchedulerUnavailable /
│   │                       ErrCaptureIncomplete / ErrNoActiveDeadman /
│   │                       PlanStaleError
│   ├── kensa.go            Kensa top-level type + Config (with Engine,
│   │                       TransportFactory, Log, Verifier fields).
│   │                       Methods delegate when wired.
│   └── kensa_test.go       wiring tests
│
├── pkg/kensa/              ASSEMBLY layer (imports api + internal)
│   └── kensa.go            Default(ctx, storePath) factory
│
├── internal/
│   ├── engine/             transaction coordinator
│   │   ├── engine.go       Engine + New + Run
│   │   ├── preflight.go    pre-flight validation
│   │   ├── capture.go      CAPTURE phase
│   │   ├── apply.go        APPLY phase
│   │   ├── validate.go     VALIDATE phase (skeleton — Week 21 wires
│   │   │                   the rule check)
│   │   ├── commit.go       COMMIT / errored finalization
│   │   ├── rollback.go     ROLLBACK phase
│   │   ├── locks.go        per-host mutex registry
│   │   ├── events.go       event publishing helpers
│   │   ├── deps.go         Store, Signer, DeadmanArmer, EventBus
│   │   │                   interfaces
│   │   ├── stubs.go        in-memory Store + noopSigner +
│   │   │                   noopDeadman + noopEventBus
│   │   ├── testing.go      FakeTransport, FakeHandler for tests
│   │   └── engine_test.go  9 spec-derived tests (engine-transaction
│   │                       AC-01 through AC-11, except AC-03/AC-04/
│   │                       AC-06 deferred)
│   ├── handler/            global handler registry
│   │   ├── registry.go
│   │   └── registry_test.go
│   ├── handlers/
│   │   ├── filepermissions/  Apply, Capture, Rollback, Params,
│   │   │                     register, tests
│   │   ├── sysctlset/        Apply, Capture, Rollback, Params,
│   │   │                     register, tests
│   │   └── serviceenabled/   Apply, Capture, Rollback, Params,
│   │                         register, tests
│   ├── store/              SQLite transaction log
│   │   ├── store.go        Store interface
│   │   ├── schema.go       migrations (v1: transactions, steps,
│   │   │                   pre_states, framework_refs, rollback_events)
│   │   ├── sqlite.go       modernc.org/sqlite v1.33.1 backend with
│   │   │                   PRAGMA synchronous=FULL + WAL
│   │   ├── log_query.go    Query / Get / Aggregate (all 5 keys)
│   │   └── sqlite_test.go  6 spec-derived tests
│   └── transport/
│       └── ssh/            SSH transport (system OpenSSH +
│                           ControlMaster)
│           ├── ssh.go      Transport (Run, Put, Get, Close)
│           ├── factory.go  Factory satisfies api.TransportFactory
│           └── ssh_test.go unit + real-host integration tests
│
├── cmd/                    BINARIES (empty .gitkeep — none built yet)
│   ├── kensa/              CLI entry point — Week 23
│   ├── kensa-fuzz/         failure injection harness — Week 7
│   └── kensa-validate/     rule + spec validator — Week 21
│
├── specs/                  Specter .spec.yaml files (8 today)
│   ├── engine/transaction.spec.yaml
│   ├── handler/interface.spec.yaml
│   ├── handlers/file_permissions.spec.yaml
│   ├── handlers/sysctl_set.spec.yaml
│   ├── handlers/service_enabled.spec.yaml
│   ├── deadman/timer.spec.yaml
│   ├── store/transaction_log.spec.yaml
│   └── evidence/envelope.spec.yaml
│
├── docs/                   foundational docs + memos (see §2)
├── tests/                  per-source-tree test mirror (sparse;
│                           handlers prefer co-located tests today)
├── fixtures/handlers/      empty — language-neutral fixtures land
│                           when handler ports against Python begin
├── schema/                 empty — JSON schemas land with rule parser
├── scripts/                empty — bench + tooling land here
│
├── .github/workflows/ci.yml  Spec Sync (soft-fail) + Unit Tests +
│                             Lint + Pre-commit hygiene
├── .golangci.yml           comment-style suite (revive, godot,
│                           misspell, gocritic, staticcheck) per
│                           Google Go Style Guide
├── .pre-commit-config.yaml file-hygiene defaults + manual-stage Go
│                           and Specter hooks
├── go.mod                  module github.com/Hanalyx/kensa-go
│                           go 1.25 (toolchain bumped by sqlite dep)
├── Makefile                build/test/lint + spec-sync/spec-watch/
│                           spec-explain/spec-graph
├── README.md
├── CONTRIBUTING.md         the discipline that makes the trust
│                           commitment honorable
└── specter.yaml            Tier 1 (engine, handlers, deadman),
                            Tier 2 (checks, transport, api),
                            Tier 3 (formatters, wrappers)
```

### Build / test / lint commands

```bash
cd /home/rracine/hanalyx/kensa-go

go build ./...                    # clean at handoff
go test ./...                     # 9 packages, all pass
make spec-doctor                  # specter pre-flight
make spec-sync                    # full Specter pipeline
make spec-watch                   # iterative auth — re-runs on save

# Lint (requires golangci-lint v1.64.8 in PATH; export PATH="$HOME/go/bin:$PATH")
golangci-lint run --config=.golangci.yml ./...

# Real-host SSH integration tests (skipped without env var)
KENSA_TEST_SSH_HOST=rhel9-test.example.com \
KENSA_TEST_SSH_USER=root \
go test ./internal/transport/ssh/...
```

---

## 4. What's done (commit history, oldest first)

```
26adce3 Initial scaffold — api/ surface, Tier-1 specs, Specter pipeline, V1 docs
7c09336 Fix CI: install Specter via go install or SPECTER_INSTALL_URL
d1abbf0 CI: make spec-sync soft-fail, decouple Go jobs during Specter-install-TBD
7546ac7 docs: update authorship model — AI writes code, founders rigorously review
52e55dc Adopt Google Go Style Guide for api/ comments; add lint and pre-commit
2ed17c8 CI: split pre-commit stages so file hygiene runs without Go/Specter
3fc8a76 Fix pre-commit config: go-vet (not go-vet-mod)
c58d527 Implement Week-2 transaction engine run loop
644a422 Implement file_permissions handler end-to-end with capture/rollback
5a008b6 Implement Week-3 SQLite transaction log
5de6502 CI: lint via goinstall so linter binary matches runner Go version
f7ce514 docs: progress memo to OpenWatch — Weeks 1, 2, 3 complete
285dc6a Implement Week-4 SSH transport and wire api.Kensa to the engine
8af38ff Add sysctl_set and service_enabled handlers   ← HEAD
```

**Milestones reached:**
- M1 (Week 4): trivial transaction runs end-to-end against a real host
  through the public `api.Kensa` surface, persisted to SQLite, with a
  structurally-correct (noop-signed) evidence envelope.
- 3 of ~30 capturable handlers shipped (file_permissions, sysctl_set,
  service_enabled).
- 8 of ~30 Tier-1 specs shipped; spec graph resolves cleanly with 0
  dangling refs.

**Not yet shipped (per `KENSA_GO_DAY1_PLAN.md` §11):**
- Week 5-8: more capturable handlers (config_set, config_set_dropin,
  package_present/absent, file_content/absent, service_disabled/masked,
  selinux_boolean_set, mount_option_set, audit_rule_set,
  kernel_module_disable, cron_job, pam_module_configure)
- Week 7: `cmd/kensa-fuzz` failure-injection harness
- Week 15-20: deadman timer (`internal/deadman`) — currently `noopDeadman`
- Week 21: rule parser, validator, capability detection, CLI
- Week 22: api.Kensa.TransactionLog wiring (currently delegates only
  if Config.Log is set — Default does this)
- Week 24: Plan / Execute (preview-then-execute; structures exist,
  bodies return ErrNotYetImplemented)
- Week 25: real Ed25519 signer (`noopSigner` records keyID="noop"
  today); Subscribe wiring; OSCAL export
- Week 27-32: remaining handlers + non-capturable escape hatches
- Week 33-40: rule corpus parity, customer cutover, v1.0.0

---

## 5. Conventions and discipline

### 5.1 Authorship model (load-bearing — read carefully)

Per `docs/HANALYX_MISSION_AND_ROADMAP.md` §"The human-review commitment":

> The founders will conduct rigorously tests, and review the
> application. The Kensa AI team and collaborator will write all of
> the application code. The founders commit and consider human review
> of the code is non-negotiable. The day we stop is the day our
> failure-mode reasoning starts decaying.

In practice: the AI agent writes Go code, commits to `main`, pushes to
GitHub. The founder reviews the diffs and runs the integration tests.
There is no PR workflow on this private repo today; commits go
directly to `main`. CI is the automated gate before the human review.

### 5.2 Failure-mode analysis on every engine/capture/rollback PR

Per `CONTRIBUTING.md`, every commit that touches `internal/engine/`,
any `internal/handlers/*/capture.go`, or any
`internal/handlers/*/rollback.go` must include in the commit body a
three-question failure-mode analysis:

1. What could this change do wrong in production?
2. What state is captured before the change, and is it sufficient to
   restore the system if the change or its validation fails?
3. What real-world edge case is this change *not* safe for, and is
   that edge case documented and gated?

AI may draft the analysis; the founder is the final reasoner. Look at
recent commit bodies (`git log --format=full -3 c58d527 644a422 5a008b6
285dc6a`) for examples.

### 5.3 Comment style (golangci-lint enforced)

All exported identifiers in `api/` and `pkg/kensa/` follow Google's Go
Style Guide:

- First sentence of every doc comment starts with the symbol name
- Cross-references use Go-1.19+ doc-link syntax: `[Type]`,
  `[Type.Method]`, `[pkg.Symbol]`
- Comments end with a period (godot enforces)
- US spelling (misspell with Kensa-vocabulary allowlist for words
  like rhel, sshd, sysctl, authselect, faillock)
- No commented-out code (gocritic enforces)
- Constants grouped under block headers ("Defined values for X",
  "Supported values")

`internal/` is freely refactorable but internal exported identifiers
should still document themselves; godot is relaxed for `internal/`.

Run `golangci-lint run --config=.golangci.yml ./...` before every
commit.

### 5.4 Spec discipline (Specter)

Every handler / engine component has a Tier 1 spec at
`specs/<area>/<name>.spec.yaml`. Tests use `// @spec <id>` and
`// @ac <AC-NN>` annotations near each test function so
`specter coverage` can track AC-by-AC progress. The `@spec` /
`@ac` pattern is documented by `specter explain <spec-id>:<ac-id>`.

When adding a new handler:

1. Write the spec FIRST. ID = `handler-<name>` (kebab-case). Status
   `draft`. Tier 1.
2. Get spec into `specter sync` parse-PASS state.
3. Implement against the spec's ACs.
4. Add tests with `@spec` / `@ac` annotations matching every AC.

When unsure about an AC's annotation pattern, run `specter explain
<id>:AC-NN` to see the exact comment format Specter expects.

### 5.5 Commit message style

Descriptive titles. No conventional-commit prefixes
(`feat:`/`fix:`/`chore:`). The Hanalyx convention from the Python
repo's CLAUDE.md carries over. Examples:

- ✓ "Implement Week-2 transaction engine run loop"
- ✓ "Add sysctl_set and service_enabled handlers"
- ✗ "feat: add transaction engine"

Commit body: long-form narrative describing what changed, why, and
the failure-mode analysis. End with `Co-Authored-By: Claude Sonnet 4.6
<noreply@anthropic.com>` when AI authored.

---

## 6. Tools and environment

### Specter (spec-driven development)

- Binary at `/usr/bin/specter`, version 0.4.1
- Project manifest: `specter.yaml` (Tier 1 = engine, handlers,
  deadman; Tier 2 = checks, transport, api)
- Subcommands: `specter doctor` (pre-flight), `specter sync` (full
  pipeline), `specter explain <id>:AC-NN` (annotation help), `specter
  watch` (iterative dev loop), `specter resolve --mermaid` (graph)
- Schema: `/home/rracine/projects/spec-dd/specter/internal/schema/spec-schema.json`
  (canonical; needed if writing new spec types)
- Specter is NOT yet installable in CI runners. The Spec Sync job
  soft-fails if install fails — that's expected. When Specter
  publishes release tarballs, set `SPECTER_INSTALL_URL` in the
  workflow.

### golangci-lint

- Pinned to `v1.64.8` in CI and `.pre-commit-config.yaml`
- CI uses `install-mode: goinstall` so the binary is built with the
  runner's Go 1.25 (the prebuilt v1.64.8 binary was built with Go 1.24
  and can't read 1.25 export data)
- Local install: `go install
  github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8`
- Config: `.golangci.yml` enables revive, godot, misspell, gocritic,
  staticcheck (full minus ST1000), gofmt, goimports, govet, errcheck,
  ineffassign, unused

### Go toolchain

- `go.mod` requires Go 1.25 (bumped by `modernc.org/sqlite v1.33.1`
  dep). Tried downgrading; sqlite needs newer toolchain.
- CI uses `actions/setup-go@v5` with `go-version: '1.25'`

### Pre-commit

- Default-stage hooks: trailing-whitespace, end-of-file-fixer,
  check-yaml, etc. (no language toolchain needed)
- Manual-stage hooks: gofmt, goimports, govet, go-mod-tidy,
  golangci-lint, specter-doctor, specter-sync
- Local: `pre-commit install` then `pre-commit` runs defaults; full
  validation: `pre-commit run --all-files --hook-stage manual`

### gh CLI

- Authenticated and works against `Hanalyx/kensa-go`
- Use to monitor CI: `gh run watch $(gh run list --repo
  Hanalyx/kensa-go --limit 1 --json databaseId -q '.[0].databaseId')
  --repo Hanalyx/kensa-go --exit-status`

### SSH

- `ssh` binary on dev machine (system OpenSSH)
- Real-host integration tests gate on `KENSA_TEST_SSH_HOST` env var.
  If you have a RHEL test host, set it.

---

## 7. Open commitments and pending work

These are obligations from prior memos / sessions that the founder may
ask you to act on. Don't take action without confirmation; flag them
when relevant.

### 7.1 Send the OpenWatch progress memo

`docs/KENSA_OPENWATCH_PROGRESS_2026-04-15.md` is marked
`Status: Draft. Review before sending.` The founder approves and sends
manually (the "send" mechanism is presumably email or Slack to the
OpenWatch team). Don't edit the memo to flip status without
confirmation.

### 7.2 `Hanalyx/kensa-spec` shared repo

Per `KENSA_OPENWATCH_RESPONSE_2026-04-14.md` §5.2, Kensa committed to
standing up a separate `kensa-spec` repo for language-neutral content
shared with Python Kensa: `rules/`, `mappings/`, `specs/`,
`fixtures/`, `schema/`, evidence envelope JSON Schema. **Not yet
done.** Default timing is "weeks 5-6" — when handler ports begin
needing the shared fixtures.

### 7.3 `LogQuery.Aggregate` benchmark

Promised in §5.2 of the response memo: hard p95 numbers against a
500K-row, 1000-host corpus, within 4 weeks of 2026-04-14. The harness
goes in `scripts/bench_aggregate.go`.

### 7.4 Weekly Kensa↔OpenWatch sync

Proposed in the progress memo §8. Awaits scheduling.

### 7.5 Specter install in CI

The `Spec Sync` job emits a warning today because Specter can't be
installed via `go install` from a public path. Once Hanalyx publishes
Specter release tarballs, set `SPECTER_INSTALL_URL` in
`.github/workflows/ci.yml` to enable strict spec-sync gating.

### 7.6 Retention task in store

`internal/store/` schema supports retention but the background task
that drops `pre_states` older than 7 days and prunes transactions
older than 90 days is not implemented. Promised by `transaction-log`
spec C-05 / AC-07.

---

## 8. Recommended next chunks

In rough priority order. The founder will pick.

### A. More capturable handlers (Week 5-8 work)

The pattern is well-proven (file_permissions, sysctl_set,
service_enabled all follow it). Each new handler is ~3-4 hours of
work. Highest-leverage candidates by frequency in CIS/STIG corpora:

1. **`config_set` + `config_set_dropin`** — used by ~30% of all rules.
   Most complex of the file-edit handlers because of separator
   variants (space, =, " = ") and the drop-in vs main-file split.
2. **`package_present` + `package_absent`** — handles `dnf`/`rpm`.
   `package_absent` has interesting capture semantics: capture must
   record the version + dependency closure since reinstall after
   rollback may pull a different version.
3. **`file_content` + `file_absent`** — straightforward; file_absent
   needs to capture the file's content, mode, and SELinux context
   for restore.
4. **`service_disabled` + `service_masked`** — symmetric with
   service_enabled.
5. **`selinux_boolean_set`** — small, contained.
6. **`mount_option_set`** — fstab editing + remount.
7. **`audit_rule_set`** — adds to `/etc/audit/rules.d/` then
   `augenrules --load`.

### B. `cmd/kensa-fuzz` failure-injection harness (Week 7)

The atomicity verification tool. For each shipped handler, induce a
real failure at each phase (capture / apply / validate / rollback) and
verify the host fingerprint pre-capture matches post-rollback. This is
how the atomicity commitment in `TRANSACTION_CONTRACT_V1.md` becomes
verifiable rather than self-reported.

Requires real RHEL test hosts. Should run nightly in CI once available.

### C. Deadman timer (Week 15-16)

`internal/deadman/` — replaces `noopDeadman` in `internal/engine/stubs.go`.
Per `specs/deadman/timer.spec.yaml` (10 ACs, 6 constraints): probe
for `at` / `systemd-run`, generate POSIX-shell rollback script from
PreStates, schedule via 120s window, cancel on success. The 10 edge
cases listed in `KENSA_GO_DAY1_PLAN.md` §6.4 must all be fuzzed.

This unlocks atomicity for control-channel-sensitive transactions
(SSH, networking, PAM, firewall handlers).

### D. CLI scaffold (`cmd/kensa/main.go`)

Lightweight. Exposes `kensa scan`, `kensa remediate`, `kensa
rollback`, `kensa history`, `kensa coverage`. Wraps `pkg/kensa.Default()`.
Useful as a smoke-test surface even before rule parsing lands.

### E. Stand up `Hanalyx/kensa-spec`

Move `rules/`, `mappings/`, `specs/`, `fixtures/`, `schema/` out to a
new repo and pull as a submodule. Required by Python↔Go fixture-bridge
work in week 9+.

### F. Aggregate benchmark

Write `scripts/bench_aggregate.go` against a synthetic 500K-row
corpus. Confirms or refutes the <500ms p95 commitment to OpenWatch.

### G. Real Ed25519 signer (Week 25)

Replace `noopSigner` in `internal/engine/stubs.go` with real Ed25519
signing of canonicalized envelopes. Per `specs/evidence/envelope.spec.yaml`
(10 ACs, 6 constraints) — including key rotation history.

### H. Validate phase wiring

`internal/engine/validate.go` is currently a no-op. Per
`engine-transaction` spec AC-03, validate must run the rule's check
plus declared validators. Blocked on rule parsing (Week 21) for the
check, but dependent validators (service health, config syntax,
control-channel reachability) can land independently.

---

## 9. Known gotchas

### 9.1 Import cycle: api/ cannot import internal/engine

The api/ package defines public types and interfaces. internal/engine
imports api/ to satisfy api.Handler etc. If api/ imports
internal/engine, you get a cycle.

**Pattern in use:** `pkg/kensa/` is the assembly layer that imports
both api/ and internal/. It provides `Default(ctx, storePath)` which
constructs the engine, store, and transport factory and assigns them
to `api.Config`. The api.Kensa methods then delegate to the wired
implementations or return ErrNotYetImplemented if unwired.

When adding a new public method on api.Kensa: define the interface in
api/, implement in internal/, wire in pkg/kensa.

### 9.2 godot lint quirk: comments referencing lowercase identifiers

godot expects sentences to start with a capital letter. Function doc
comments referencing parameter names like `nonBlocking` fail godot.
Workaround: rephrase to put a capital word first.

- ✗ `// nonBlocking controls per-host mutex acquisition.`
- ✓ `// The nonBlocking flag controls per-host mutex acquisition.`

### 9.3 godot quirk: comments ending with quoted period

Comments ending with `."` (period inside the quote) trigger godot's
"comment should end in a period" rule because godot sees the line
ending with `"`, not `.`. Workaround: rephrase to avoid quote-at-end,
or move the period outside (looks awkward).

### 9.4 golangci-lint typecheck quirk: embedded interface promotion

golangci-lint sometimes can't see methods promoted from embedded
interfaces in the same package. Workaround: assign the embedded
interface to a typed local variable first.

```go
// Triggers false typecheck failure
_ = e.events.Publish(ctx, event)

// Works
var publisher api.EventPublisher = e.events
_ = publisher.Publish(ctx, event)
```

### 9.5 SQLite schema: child tables have no FK to transactions

The engine writes pre_states BEFORE the transactions row exists (per
engine-transaction spec C-02 / AC-04). A FK from pre_states to
transactions would block this load order. Schema deliberately omits
the FK; orphan rows are cleaned up by retention.

### 9.6 modernc.org/sqlite version pinning

We're on `v1.33.1`. Newer versions (v1.34+ and certainly v1.48+) bump
required Go versions, which forces a golangci-lint version dance. If
you bump it, also bump `golangci-lint` to a version built with the
matching Go.

### 9.7 Specter `spec` root key

Every `.spec.yaml` file has `spec:` at the top with all content
nested. Easy to forget when writing new specs. The schema is at
`/home/rracine/projects/spec-dd/specter/internal/schema/spec-schema.json`.
Required fields under `spec:`: `id`, `version`, `status`, `tier`,
`context`, `objective`, `constraints`, `acceptance_criteria`.
Constraint IDs match `^C-\d{2,}$`; AC IDs match `^AC-\d{2,}$`.

### 9.8 `cancelled` vs `canceled`

misspell config uses US locale. Use "canceled", not "cancelled".

---

## 10. What's verified to work end-to-end

A consumer can do this today through the public api/ surface and it
will run a full transaction against a real RHEL host:

```go
import (
    "context"
    "github.com/Hanalyx/kensa-go/api"
    "github.com/Hanalyx/kensa-go/pkg/kensa"
    _ "github.com/Hanalyx/kensa-go/internal/handlers/filepermissions" // register
    _ "github.com/Hanalyx/kensa-go/internal/handlers/sysctlset"
    _ "github.com/Hanalyx/kensa-go/internal/handlers/serviceenabled"
)

func main() {
    ctx := context.Background()
    svc, _ := kensa.Default(ctx, "/var/lib/kensa/results.db")
    defer svc.Close()

    res, _ := svc.Transact(ctx,
        api.HostConfig{Hostname: "rhel9.example.com", User: "root", Sudo: true},
        &api.Transaction{
            RuleID: "fs-permissions-etc-shadow",
            Steps: []api.Step{{
                Index:     0,
                Mechanism: "file_permissions",
                Params: api.Params{
                    "path":  "/etc/shadow",
                    "owner": "root",
                    "group": "root",
                    "mode":  "0000",
                },
            }},
            Transactional: true,
        })

    // res.Status ∈ {Committed, RolledBack, PartiallyApplied, Errored}
    // res.Envelope.Decision matches; envelope persisted to SQLite
    // svc.TransactionLog().Query / .Get / .Aggregate work over real data
}
```

---

## 11. Spec graph at handoff (mermaid)

```
graph BT
    handler-interface["handler-interface"]
    handler-file-permissions["handler-file-permissions"]
    handler-sysctl-set["handler-sysctl-set"]
    handler-service-enabled["handler-service-enabled"]
    deadman-timer["deadman-timer"]
    transaction-log["transaction-log"]
    evidence-envelope["evidence-envelope"]
    engine-transaction["engine-transaction"]

    handler-file-permissions --> handler-interface
    handler-sysctl-set --> handler-interface
    handler-service-enabled --> handler-interface
    deadman-timer --> handler-interface
    transaction-log --> evidence-envelope
    engine-transaction --> handler-interface
    engine-transaction --> deadman-timer
    engine-transaction --> transaction-log
    engine-transaction --> evidence-envelope
```

8 specs total. 0 dangling references. All Tier 1.

---

## 12. Human review pending — flag explicitly to founder

Items the founder may want to review before more work proceeds:

1. **The `KENSA_OPENWATCH_PROGRESS_2026-04-15.md` memo** —
   Status: Draft. Founder decides when to send to OpenWatch team.
2. **Recent capture handler PRs (`644a422`, `8af38ff`)** — capture
   sufficiency analysis was AI-drafted in the commit body; per the
   review-discipline commitment the founder should personally verify
   the captured fields are sufficient against the rules they expect
   to use these handlers in.
3. **The SSH transport's `StrictHostKeyChecking=accept-new` default**
   — this trusts any new host on first contact. Federal deployments
   may want the configurable-strictness follow-up flagged in the
   ssh.go failure-mode analysis (commit `285dc6a`).

---

## 13. Where to look when stuck

- **For "what should this look like in api/?"** — check the V1 docs
  (`KENSA_GO_DAY1_PLAN.md` §3, `TECHNICAL_REMEDIATION_MP_V1.md`),
  then the relevant Specter spec under `specs/`.
- **For "is this idiomatic Go?"** — Google Go Style Guide:
  https://google.github.io/styleguide/go/decisions
  https://google.github.io/styleguide/go/best-practices
  plus go.dev/doc/comment for godoc parsing rules.
- **For "did I cover the AC?"** — `specter explain
  <spec-id>:AC-NN` shows the exact annotation pattern expected.
- **For "what are OpenWatch's expectations?"** — read the
  `KENSA_OPENWATCH_*` memos in `docs/`. Every interface refinement
  they asked for is already implemented; check the response memo's
  §3 and §4 before adding anything they might already expect to
  exist.
- **For "what's the engine doing in this corner case?"** — read
  `internal/engine/engine.go`'s Run loop top to bottom. Each phase
  file (capture.go, apply.go, validate.go, commit.go, rollback.go)
  is short and focused. The ordering is documented in
  `KENSA_GO_DAY1_PLAN.md` §3.

---

## 14. Final pre-flight before doing work

1. `cd /home/rracine/hanalyx/kensa-go`
2. `git pull` — make sure HEAD is fresh.
3. `go test ./...` — must be all green.
4. `make spec-doctor` — must be parse-PASS.
5. `gh run list --repo Hanalyx/kensa-go --limit 1` — most recent CI
   should be `success`.
6. Read `docs/CONTRIBUTING.md` if you haven't.
7. Read this document's §5 (conventions) one more time.

Then ask the founder which chunk from §8 to work on. Don't start
without confirmation — the chunks have different costs and the
founder knows the current priorities better than the docs.

---

*End of continuation prompt. The founder is your reviewer; the specs
are your contract; the failure-mode analysis is your discipline; the
atomicity commitment is your product. Don't break any of them.*
