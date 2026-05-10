# Kensa API Reference — `api/`

**Project:** Kensa Go
**Date:** 2026-05-07
**Status:** Reference documentation for the public package `github.com/Hanalyx/kensa-go/api`
**Audience:** Engineers integrating against Kensa Go (OpenWatch, the `kensa` CLI, third-party tools, future AI agents via OpenWatch); reviewers auditing the contract surface
**Companion:** `docs/context/KENSA_GO_DAY1_PLAN.md`, `docs/TRANSACTION_CONTRACT_V1.md`, `docs/foundation_docs/CANONICAL_RULE_SCHEMA_V1.md`

---

## Why This Document Exists

`api/` is the **public contract** of Kensa Go. It is the only package an
external consumer is permitted to import. OpenWatch links against it to
present the Eye / Heartbeat / Control Plane identities. The `kensa` CLI
links against it. Third-party auditors link against it. Future AI agents
that mediate through OpenWatch consume it transitively.

The package is small (≈1860 lines across 13 files) but it carries every
durable promise the product makes: every transaction terminal status,
every event kind, every error sentinel, every backend interface. Once
v1 ships, breaking changes here require a major-version bump and
coordinated migration across at least two repositories.

This document explains what is there, why it has the shape it does, and
which parts are signature-only stubs awaiting implementation.

---

## 1. Architectural Shape

The Kensa codebase has three concentric rings:

```
        ┌──────────────────────────────────────────────────────────┐
        │  api/   ── Public contract. Frozen at v1. Importable     │
        │           by anyone. No other Kensa package may be        │
        │           imported by consumers.                          │
        └──────────────────────────────────────────────────────────┘
                                   ▲
                                   │ implements
                                   │
        ┌──────────────────────────────────────────────────────────┐
        │  pkg/kensa/  ── Assembly layer. Imports api/ and          │
        │                 internal/. Provides Default(ctx, path)    │
        │                 that wires every backend into a working   │
        │                 *Kensa. Thin enough that consumers may     │
        │                 build their own composer if needed.       │
        └──────────────────────────────────────────────────────────┘
                                   ▲
                                   │ wires together
                                   │
        ┌──────────────────────────────────────────────────────────┐
        │  internal/   ── Implementation. engine, transport,        │
        │                  scan, store, evidence, deadman,          │
        │                  handlers, rule, mappings, etc.           │
        │                  Not importable across module boundary.   │
        └──────────────────────────────────────────────────────────┘
```

Why this layout:

- `api/` defines interfaces (`Engine`, `TransportFactory`, `LogQuery`,
  `EnvelopeVerifier`, `ScannerBackend`, `Handler`, `Transport`). Go
  interface satisfaction is **structural**, so the `internal/engine`
  package's concrete `Engine` struct satisfies `api.Engine` without
  `api/` ever importing the internal package. The contract is
  pull-based, not push-based.
- `pkg/kensa.Default` is the only place where internal packages are
  composed. Consumers who only need parts (or want to substitute fakes
  in tests) call `api.New` with a hand-built `Config` instead.
- `internal/` is private. Even though Kensa Go is open source, internal
  Go semantics enforce that no package outside this module can import
  from `internal/...`. This is the language-level guarantee that
  consumers cannot accidentally couple to implementation details.

### Files in `api/`

| File | Surface |
|---|---|
| `doc.go` | Package documentation. Frozen package-level comment is the canonical orientation for new consumers. |
| `kensa.go` | The `Kensa` struct, the `Config`, the four-backend interface set (`Engine`, `TransportFactory`, `LogQuery`, `EnvelopeVerifier`, `ScannerBackend`), and every top-level method. |
| `transaction.go` | `Transaction`, `Step`, `TransactionResult`, `StepResult`, `PreState`, `RollbackResult`, `EvidenceEnvelope`, `ValidatorResult`. Plus the four `TransactionStatus` constants and the five `Phase` constants. |
| `handler.go` | `Handler`, `CaptureHandler`, `RollbackHandler`, `CombinedHandler`, `Params`. The atomicity boundary lives here. |
| `transport.go` | `Transport`, `CommandResult`. SSH abstraction. |
| `events.go` | `Event`, `EventKind`, `EventFilter`, `EventPublisher`, `EventSubscriber`, plus the per-kind data payload types. |
| `planner.go` | `Planner`, `Executor`, `Plan`, `Rule`, `Implementation`, `Check`, `Remediation`, `CapabilitySet`, and every preview struct. |
| `log_query.go` | `LogQuery`, `LogFilter`, `Page`, `QueryResult`, `TransactionRecord`, `AggregateKey`, `AggregateResult`, plus all option types. |
| `envelope_verifier.go` | `EnvelopeVerifier`, `VerifyResult`, `VerifyWarning`. |
| `deadman.go` | `DeadmanControl`, `DeadmanState`. |
| `concurrency.go` | `RunOption` and the two functional options (`WithNonBlocking`, `WithAllowCommandExec`). |
| `errors.go` | Every exported error sentinel and `PlanStaleError`. |
| `kensa_test.go` | Compile-time and runtime verification of the contract. |

---

## 2. The `Kensa` Type and `Config`

`Kensa` is the single entry point. Construct it with `api.New(cfg)` and
the methods on it dispatch to whichever backends `cfg` has populated.

```go
k, err := api.New(api.Config{StorePath: ".kensa/results.db"})
```

A bare `Config` (zero value) yields a Kensa whose execution methods all
return `ErrNotYetImplemented`. This is deliberate — it lets OpenWatch
import and compile against the surface before any backend is wired,
which was non-negotiable during M1 when half the implementations did
not yet exist.

### `Config` fields

| Field | Type | Purpose | Behavior when unset |
|---|---|---|---|
| `StorePath` | `string` | SQLite file path for the transaction log. | Defaults to `.kensa/results.db`. |
| `SigningKeyPath` | `string` | Path to the Ed25519 private key for signing envelopes. | Per-deployment default managed by `kensa-keygen`. **Real signing shipped 2026-05-10 (M-012 + C-060)**: `KENSA_SIGNING_KEY` env var on `pkg/kensa.Default()` selects a persistent `.priv` file; ephemeral keypair generated otherwise. |
| `Engine` | `Engine` interface | Backs `Transact`, `Rollback`, `Plan`, `Execute`. | Methods return `ErrNotYetImplemented`. |
| `TransportFactory` | `TransportFactory` interface | Constructs SSH transport from a `HostConfig`. | Methods return `ErrNotYetImplemented`. |
| `Log` | `LogQuery` interface | Backs `TransactionLog()` and `Rollback`'s pre-state load. | `TransactionLog()` returns nil; `Rollback` returns `ErrNotYetImplemented`. |
| `Verifier` | `EnvelopeVerifier` interface | Backs `VerifyEnvelope`. | Method returns `ErrNotYetImplemented`. |
| `Scanner` | `ScannerBackend` interface | Backs `Scan` and `Remediate`. | Methods return `ErrNotYetImplemented`. |

### The five backend interfaces

These are the only seams between `api/` and the world. Each is small,
strictly-typed, and under direct semver control.

- **`Engine`** — `Run`, `RollbackTransaction`, `PlanTransaction`,
  `ExecutePlan`. Production impl in `internal/engine`.
- **`TransportFactory`** — `Connect(ctx, HostConfig) (Transport, error)`.
  Production impl in `internal/transport/ssh`.
- **`ScannerBackend`** — `Scan`, `Remediate`. Production impl in
  `internal/scan`.
- **`LogQuery`** — `Query`, `Get`, `Aggregate`. Production impl in
  `internal/store`.
- **`EnvelopeVerifier`** — `VerifyEnvelope`. Production impl in
  `internal/evidence`.

A consumer can substitute fakes for any of these without touching the
production code. This is the interface that test code uses; it is also
what a future hosted-Kensa SaaS layer would substitute for, e.g., a
Postgres-backed `LogQuery`.

---

## 3. The Method Set on `Kensa`

Methods are grouped by OpenWatch identity. Every method is signature-
stable from commit 1; bodies fill in progressively.

### Execution

```go
func (k *Kensa) Transact(ctx, host, txn, opts...) (*TransactionResult, error)
func (k *Kensa) Scan(ctx, host, rules, opts...) (*ScanResult, error)
func (k *Kensa) Remediate(ctx, host, rules, opts...) (*RemediationResult, error)
func (k *Kensa) Rollback(ctx, host, txnID) (*RollbackResult, error)
```

- **`Transact`** runs a single `Transaction` end-to-end. The result's
  `Status` is always one of the four `TransactionStatus` values.
  `Transact` is what every other execution method ultimately resolves
  to one or more of.
- **`Scan`** is read-only. It runs only the check phase of every rule
  and returns a `ScanResult`. No apply, no envelope, no log entry for
  the apply path.
- **`Remediate`** runs a scan, then runs `Transact` for every rule that
  failed. Returns a `RemediationResult` with one `TransactionResult`
  per failing rule.
- **`Rollback`** loads a past transaction's `TransactionRecord` from
  the log, reconnects to the host, and reverses every applied
  capturable step. Used by `kensa rollback --start <txnID>`.

### Control Plane (preview-then-execute)

```go
func (k *Kensa) Plan(ctx, host, rule) (*Plan, error)
func (k *Kensa) Execute(ctx, host, plan, opts...) (*TransactionResult, error)
```

`Plan` returns a complete `Plan` with captured pre-state, apply step
previews, validator previews, the rollback plan, and warnings — without
mutating the host. `Execute` consumes that plan; if host state has
diverged since planning, it returns a `PlanStaleError` and the caller
must re-plan.

The split exists because OpenWatch's Control Plane wants to surface a
preview UI for human approval before any change runs. The plan is a
commitment: approving the plan approves the captured pre-state. If the
host state changes between approval and execute, the original approval
is invalidated by design.

### Heartbeat (event subscription)

```go
func (k *Kensa) Subscribe(ctx, filter) (<-chan Event, error)
```

Currently returns `ErrNotYetImplemented` on `*Kensa` directly. The
working implementation is on `pkg/kensa.Service.Subscribe`, which wraps
an `engine.InMemoryEventBus`. Consumers should use the Service wrapper
until subscription is wired through `*Kensa` directly.

### Eye (historical query and verification)

```go
func (k *Kensa) TransactionLog() LogQuery
func (k *Kensa) VerifyEnvelope(envelope) (*VerifyResult, error)
```

`TransactionLog()` returns the `LogQuery` interface for direct query
access. `VerifyEnvelope` checks the Ed25519 signature on a stored
envelope against the deployment's key history.

### Deadman control

```go
func (k *Kensa) CancelDeadman(ctx, host, txnID) (*RollbackResult, error)
func (k *Kensa) DeadmanStatus(ctx, host, txnID) (*DeadmanState, error)
```

Both currently return `ErrNotYetImplemented` on `*Kensa`. The
`DeadmanControl` interface in `api/deadman.go` is the contract; the
implementation lives in `internal/deadman` and is reachable through the
engine path today, not yet through these top-level methods.

---

## 4. The Transaction Model

The transaction is the unit of atomicity. Every transaction terminates
in exactly one of four states; the engine guarantees this.

### `TransactionStatus`

| Status | Meaning |
|---|---|
| `StatusCommitted` | All apply steps succeeded; all validators passed; envelope signed and persisted; deadman cancelled if armed. The host is in the target state. |
| `StatusRolledBack` | Apply or validate failed; every applied capturable step was reversed using captured pre-state. The host is in the exact pre-change state. |
| `StatusPartiallyApplied` | For `transactional: false` rules, at least one non-capturable step ran before a failure. Stranded steps are flagged in `Steps[].Stranded`. Not reversed. |
| `StatusErrored` | The engine could not complete a phase within the deadline. `TransactionResult.Error` identifies the phase. |

**`StatusPartiallyApplied` is the escape hatch.** A rule with
`transactional: false` (per `CANONICAL_RULE_SCHEMA_V1.md` §3.2) opts out
of atomicity — typically because it includes a `command_exec`,
`grub_parameter_set`, `grub_parameter_remove`, or `manual` step that
cannot be captured. Pre-flight rejects any transaction where
`Transactional: true` but a step uses a non-capturable mechanism.

### `Phase`

The five phases, in execution order:

```
PhaseCapture → PhaseApply → PhaseValidate → PhaseCommit
                     ↓         ↓
                     └─────────┴── (failure) → PhaseRollback
```

`PhaseRollback` runs only on failure or deadman fire; it is never part
of a successful transaction's normal path.

### `Transaction` and `TransactionResult`

`Transaction` is the input: rule ID, host ID, ordered `Steps`,
deadlines, `Transactional` flag, `Severity`, `FrameworkRefs`.

`TransactionResult` is the output: terminal `Status`, per-step
`StepResult`s, captured `PreStates`, timing fields, the signed
`Envelope`, and an `Error` populated only when `Status` is
`StatusErrored`.

### `EvidenceEnvelope` — the durable artifact

The envelope is the per-transaction audit artifact, signed with Ed25519
and persisted in the log. It contains:

- The transaction identifiers (ID, rule, host, fleet)
- Timestamps (`StartedAt`, `FinishedAt`)
- The captured `PreStateBundle`
- The `ApplySteps` outcomes
- The `ValidatorResults`
- The terminal `Decision`
- The `PostStateBundle` (post-apply state for diff)
- `FrameworkRefs` for compliance traceability
- `SigningKeyID` and `Signature`
- `CommandExecAllowed` — records that the operator passed
  `--allow-command-exec` for this transaction, per
  `security-input-validation` AC-07

The canonical envelope schema is `specs/evidence/envelope.spec.yaml`.
The wire format is mirrored at `kensa-spec/specs/evidence/envelope-v1.yaml`
so polyglot consumers share one source of truth.

---

## 5. The Handler Atomicity Boundary

Handlers are how kensa actually changes the system. The boundary
between *capturable* (atomicity-eligible) and *non-capturable*
(stranded-on-failure) handlers is enforced at compile time by Go
interface satisfaction — not by a runtime tag the author can lie about.

### The four interfaces

```go
type Handler interface {
    Name() string
    Capturable() bool
    Apply(ctx, transport, params, pre) (*StepResult, error)
}

type CaptureHandler interface {
    Capture(ctx, transport, params) (*PreState, error)
}

type RollbackHandler interface {
    Rollback(ctx, transport, pre) (*RollbackResult, error)
}

type CombinedHandler interface {
    Handler
    CaptureHandler
    RollbackHandler
}
```

### How the boundary stays honest

Capturable handlers (`file_content`, `service_enabled`, `sysctl_set`,
…) implement `CombinedHandler`. They have all three methods.
Non-capturable handlers (`command_exec`, `manual`,
`grub_parameter_set`, `grub_parameter_remove`) implement only
`Handler`.

The engine selects a handler by `Name()` and then attempts to type-
assert it to `CombinedHandler`:

- If `Capturable()` returns `true` and the assertion succeeds → the
  step participates in atomicity.
- If `Capturable()` returns `false` and the assertion fails → the step
  is marked stranded-on-failure; the rule must be `transactional: false`
  or pre-flight rejects it.
- If `Capturable()` returns `true` and the assertion fails → compile-
  time impossibility. The author cannot ship a "claims-capturable but
  missing Capture/Rollback" handler.

This is the structural enforcement of the atomicity contract. Every
capture-completeness review the founder performs (per
`CONTRIBUTING.md`) operates downstream of this guarantee.

### `Capture` failure → transaction abort

`CaptureHandler.Capture` may return `ErrCaptureIncomplete` when it
cannot reliably record pre-state. The engine then aborts the
transaction before any `Apply` step runs, returning `StatusErrored` —
no mutation, no envelope. This is the point at which authors should
fail closed rather than apply with a partial capture.

---

## 6. The Plan Surface

`Plan` is a structured preview. Its fields cover everything a reviewer
needs to approve or reject the proposed change without seeing the
underlying rule YAML or handler internals.

```go
type Plan struct {
    ID                       uuid.UUID
    RuleID, HostID           string
    SelectedImpl             *Implementation
    Capabilities             CapabilitySet
    Transactional            bool
    ControlChannelSensitive  bool
    PreStates                []PreState
    ApplySteps               []StepPreview
    Validators               []ValidatorPreview
    RollbackPlan             []RollbackStepPreview
    EstimatedDuration        time.Duration
    Warnings                 []string
    CreatedAt                time.Time
}
```

`PlanTransaction` runs capture in read-only mode and populates
`PreStates`. `Execute` requires the host's actual pre-state to still
match `Plan.PreStates`; if any field has diverged, `Execute` returns
`PlanStaleError` with structured fields identifying which step's which
field changed.

`Plan.Preview(format)` renders the plan as text, markdown, JSON, or
plain — currently returns `ErrNotYetImplemented` until the engine
implementation lands.

---

## 7. The LogQuery Surface

`LogQuery` is the read side of the persisted transaction log.
Consumers query it to power the Eye identity: posture dashboards, audit
exports, drift trends.

### Query, Get, Aggregate

```go
func Query(ctx, filter, page) (*QueryResult, error)
func Get(ctx, txnID, opts...) (*TransactionRecord, error)
func Aggregate(ctx, filter, groupBy, opts...) (*AggregateResult, error)
```

- **`Query`** returns paginated `TransactionRecord`s matching `filter`.
  `LogFilter` covers hosts, fleets, rules, framework refs, statuses,
  phases, severities, mechanisms, and time ranges.
- **`Get`** returns one record. Default returns the full record
  including the envelope and pre-state bundles — correct for audit
  export. List views opt out via `WithoutEnvelope` and
  `WithoutPreStates` for performance.
- **`Aggregate`** returns posture summaries grouped by `AggregateKey`.
  The five supported group-bys are `by_host`, `by_rule`,
  `by_framework_control`, `by_host_then_framework_control`, and
  `by_rule_then_status_over_time` (requires `WithTimeBucket`).

### Performance commitment

The transaction-log spec (`specs/store/transaction_log.spec.yaml`)
AC-06 commits `Aggregate` to a 500ms p95 against a 500K-row, 1000-host
corpus. Each `AggregateKey` has a dedicated optimized query path;
arbitrary aggregations are not supported through this interface — by
design, so the performance commitment is testable.

---

## 8. The Event Surface

Events drive OpenWatch's Heartbeat. Eight kinds:

| Kind | When emitted | Data payload |
|---|---|---|
| `TransactionStarted` | Engine enters `PhaseCapture` for a new transaction. | None |
| `PhaseCompleted` | Each phase finishes. | `PhaseCompletedData{Phase, Success, Duration}` |
| `Committed` | Transaction reaches `StatusCommitted`. | None |
| `RolledBack` | Transaction reaches `StatusRolledBack`. | `RolledBackData{Source, Reason}` |
| `DriftDetected` | Scheduled scan finds a previously-passing rule failing. | None |
| `HeartbeatPulse` | Periodic "this host is reachable." | None |
| `DeadmanTimerArmed` | Engine schedules the rollback script before applying a control-channel change. | `DeadmanTimerData{FiresAt, ScriptPath}` |
| `DeadmanTimerFired` | The scheduled deadman script runs. | `DeadmanTimerData{FiresAt, ScriptPath}` |

### Back-pressure semantics

`EventSubscriber.Subscribe` returns a `<-chan Event`. When a consumer
falls behind:

- Non-pulse events may be dropped and counted.
- `HeartbeatPulse` events are coalesced (not dropped) so a slow
  consumer always sees at least one pulse per host per
  `EventFilter.HeartbeatInterval` while the host is alive.

This asymmetry exists because pulse loss is what triggers fleet-health
alarms in OpenWatch; coalescing protects that signal.

### `EventFilter`

Empty `Kinds` means "all kinds." Empty `HostIDs` / `FleetIDs` means "all
hosts." `HeartbeatInterval` zero defaults to 60 seconds.

---

## 9. The Transport Surface

`Transport` is the SSH abstraction. It exists in `api/` so the engine
implementation in `internal/engine` does not import `internal/transport`
directly — the engine works with anything that satisfies the interface.

```go
type Transport interface {
    Run(ctx, cmd) (*CommandResult, error)
    Put(ctx, localPath, remotePath, mode) error
    Get(ctx, remotePath, localPath) error
    ControlChannelSensitive() bool
    Close() error
}
```

The primary implementation (`internal/transport/ssh`) wraps system
OpenSSH with ControlMaster. The reasons for system-OpenSSH-not-Go-SSH
are enumerated in `KENSA_GO_DAY1_PLAN.md` §1.3 / §6.1: FIPS via RHEL's
certified OpenSSH, `~/.ssh/config` support, system crypto-policy
compliance, smaller supply chain.

A fallback (`internal/transport/crypto`) using `golang.org/x/crypto/ssh`
exists for environments without system ssh. It is not the supported
configuration for federal deployment.

`ControlChannelSensitive()` reports whether a transport is at risk of
being disrupted by the in-flight change. The deadman subsystem sets
this to true when a transaction includes mechanisms that affect SSH,
networking, PAM, or firewall state — those are exactly the cases where
the deadman timer is mandatory.

---

## 10. Run Options and Concurrency

`RunOption` is the functional-options pattern for `Transact`, `Scan`,
`Remediate`, and `Execute`. Two options exist today:

### `WithNonBlocking`

```go
k.Transact(ctx, host, txn, api.WithNonBlocking())
```

The engine enforces per-host serialization internally — only one
transaction per host runs at a time. By default, callers block on the
per-host mutex. `WithNonBlocking` causes the engine to return
`ErrHostBusy` immediately if the mutex is held. OpenWatch's job-queue
workers prefer this so they can requeue rather than stall a worker
thread.

### `WithAllowCommandExec`

```go
k.Transact(ctx, host, txn, api.WithAllowCommandExec())
```

Required to authorize a transaction containing a `command_exec`
mechanism. By default, pre-flight rejects such transactions with
`ErrCommandExecNotAllowed`. The CLI's `--allow-command-exec` flag is
the operator-facing equivalent.

The opt-in is captured in
`EvidenceEnvelope.CommandExecAllowed` so auditors can see who
approved free-form remote command execution. Per
`security-input-validation` C-06 / AC-07.

The option plumbs through `context.Context` via
`WithAllowCommandExecContext` rather than an explicit field on the
`Engine` interface — this lets the option propagate without breaking
the `Engine` signature.

---

## 11. Errors

Every exported error sentinel:

| Sentinel | Returned by | Meaning |
|---|---|---|
| `ErrNotYetImplemented` | Any method whose backend is not wired | The engine-side implementation has not yet landed. Signature is stable; consumers may write code against it today. |
| `ErrHostBusy` | `Transact`, `Execute` (with `WithNonBlocking`) | Per-host mutex is held by an in-flight transaction. |
| `ErrSchedulerUnavailable` | `Transact`, `Execute` | A control-channel-sensitive transaction was requested but the target has neither `at(1)` nor `systemd-run(1)` to arm the deadman timer. The engine fails closed because atomicity cannot be honored. |
| `ErrCaptureIncomplete` | Returned **by capture handlers** to abort a transaction | Pre-state could not be reliably recorded. The engine aborts before any apply step runs. |
| `ErrNoActiveDeadman` | `CancelDeadman`, `DeadmanStatus` | No timer is armed for the given txnID. |
| `ErrCommandExecNotAllowed` | `Transact`, `Execute` pre-flight | Transaction includes `command_exec` but `WithAllowCommandExec` was not passed. |

### `PlanStaleError`

Returned by `Execute` when the host's state has diverged from the
plan's captured pre-state. It is a structured error type, not a
sentinel:

```go
type PlanStaleError struct {
    PlanID         uuid.UUID
    StaleStepIndex int
    Mechanism      string
    Field          string      // e.g., "content", "mode", "value"
    Expected       interface{}
    Actual         interface{}
    Message        string
}
```

UIs should report which mechanism's which field changed and prompt for
re-plan, not just a generic staleness message.

---

## 12. Versioning and Stability

The package follows semver at v1 from commit 1. The `doc.go` package
comment is the canonical statement of the policy.

- **Breaking changes require a major-version bump.** Renaming an
  exported identifier, removing a field, narrowing a method's accepted
  inputs — all major-version events.
- **Additions are non-breaking** within v1: new methods, new optional
  fields on existing types, new functional options, new error
  sentinels, new event kinds. Consumers must handle unknown event
  kinds gracefully (treat as opaque).
- **Deprecations** use the `// Deprecated:` marker and remain for at
  least one minor version before removal in the next major.

### What is *not* part of the contract

These are implementation details, not part of the v1 surface, and may
change without notice:

- The exact byte format of the SQLite store at `StorePath`.
- The exact path layout under `/tmp/` for deadman scripts on the
  target host.
- Internal package layouts (`internal/engine`, `internal/scan`, etc.).
- The exact wire protocol of the `kensa agent --stdio` mode (when it
  exists; see `docs/roadmap/LOW_LEVEL_MIGRATION_V1.md`).

### Binary portability commitment

The kensa-go binary is built with `CGO_ENABLED=0` and `-tags netgo` and is
verified on every CI run to (a) be statically linked, (b) run on glibc 2.28
(RHEL 8 floor), and (c) run on musl (Alpine). One binary built today runs
across the full supported distribution range without recompilation. The
build-discipline regime is described in `README.md` §"Binary Portability"
and tracked across deliverables L-001 through L-006 in
`docs/roadmap/DELIVERABLES.md`.

---

## 13. What's Stubbed vs. Wired

Honest accounting of which surfaces are signature-only today versus
fully wired through the production implementations.

### Fully wired

- `Transact` (via `engine.Engine.Run`)
- `Scan` (via `internal/scan`)
- `Remediate` (via `internal/scan`)
- `Rollback` (via `engine.RollbackTransaction`)
- `Plan` and `Execute` (via `engine.PlanTransaction` /
  `engine.ExecutePlan`)
- `TransactionLog().Query/Get/Aggregate` (via `internal/store`)
- The full `Handler` / `CombinedHandler` registry (29 handlers)
- The `Transport` SSH implementation
- The deadman timer (via `at(1)` / `systemd-run`, not yet kernel-
  primitive based)

### Partially wired

- `VerifyEnvelope` runs real Ed25519 verification (M-012 +
  C-060 shipped 2026-05-10). The `noopSigner` placeholder
  was deleted; `engine.New()` defaults to `evidence.Generate()`
  for an ephemeral keypair, and `pkg/kensa.Default()` honors
  `KENSA_SIGNING_KEY` for persistent keys. The
  `kensa verify <evidence-file>` subcommand exposes the
  verification path to operators + auditors.
- `CommandExecAllowed` plumbing is present and tested
  (`security-input-validation` AC-07); the CLI flag exists; the
  envelope field is populated.

### Signature-only / `ErrNotYetImplemented` returns

- `Kensa.Subscribe` — use `pkg/kensa.Service.Subscribe` instead, which
  returns events from the in-memory event bus.
- `Kensa.CancelDeadman`, `Kensa.DeadmanStatus` — the `DeadmanControl`
  interface contract is defined but not yet exposed through the
  top-level `*Kensa`.
- `Plan.Preview(format)` — returns `ErrNotYetImplemented`. Render is
  done by CLI-side code today.

### Spec-defined but not yet ACfully covered

Per the v0.12 specter coverage report (2026-05-05):

- `engine-transaction` 75% (uncovered: AC-03, AC-04, AC-06)
- `evidence-envelope` 80% (uncovered: AC-07, AC-10)
- `transaction-log` 78% (uncovered: AC-07, AC-09)
- `deadman-timer` 70% (uncovered: AC-06, AC-07, AC-10)
- `transport-ssh` 50% (uncovered: AC-01, 02, 03, 04, 06, 07)
- `security-input-validation` 75% (AC-09, AC-10 are stubs; AC-12 has
  static audit but may need Convention A annotation)

Some of these are real gaps in test coverage; some are the
source-only-annotation-vs-runtime-evidence problem the v0.11/v0.12
specter migration creates. See
`docs/roadmap/LOW_LEVEL_MIGRATION_V1.md` for the broader migration
plan that touches several of these.

---

## 14. Typical Usage Patterns

### Single-shot transaction

```go
import (
    "context"
    "github.com/Hanalyx/kensa-go/api"
    "github.com/Hanalyx/kensa-go/pkg/kensa"
)

ctx := context.Background()
svc, err := kensa.Default(ctx, "/var/lib/kensa/results.db")
if err != nil { return err }
defer svc.Close()

host := api.HostConfig{
    Hostname: "web-01.example.com",
    User:     "remyl",
    Sudo:     true,
}

txn := &api.Transaction{
    RuleID:        "cis_rhel9_5_2_3",
    HostID:        host.Hostname,
    Steps:         []api.Step{ /* ... */ },
    Transactional: true,
    Severity:      "high",
    Deadline:      time.Now().Add(2 * time.Minute),
}

result, err := svc.Transact(ctx, host, txn)
if err != nil { return err }
if result.Status != api.StatusCommitted {
    // Inspect result.Steps, result.Error, or result.Envelope.Decision
}
```

### Plan-then-execute (Control Plane pattern)

```go
plan, err := svc.Plan(ctx, host, rule)
if err != nil { return err }

// Render plan.Preview(api.PreviewMarkdown) for human approval.
// On approval:
result, err := svc.Execute(ctx, host, plan)
if err != nil {
    var stale *api.PlanStaleError
    if errors.As(err, &stale) {
        // Re-plan and re-seek approval
    }
    return err
}
```

### Scan + remediate (compliance sweep)

```go
rules := loadRulesFromDir("/usr/share/kensa/rules")

result, err := svc.Remediate(ctx, host, rules)
if err != nil { return err }
for _, txn := range result.Transactions {
    // Each is one rule that failed scan and was then remediated
}
```

### Historical query (Eye pattern)

```go
log := svc.TransactionLog()

q, err := log.Query(ctx, api.LogFilter{
    HostIDs:  []string{"web-01.example.com"},
    Statuses: []api.TransactionStatus{api.StatusRolledBack},
    Since:    time.Now().Add(-24 * time.Hour),
}, api.Page{Limit: 50})

agg, err := log.Aggregate(ctx, api.LogFilter{
    Since: time.Now().Add(-7*24*time.Hour),
}, api.AggregateByHost)
```

### Verifying a stored envelope

```go
record, err := svc.TransactionLog().Get(ctx, txnID)
if err != nil { return err }

verify, err := svc.VerifyEnvelope(record.Envelope)
if err != nil { return err }
if !verify.Valid {
    // Envelope tampered or signed by an unknown key
}
for _, w := range verify.Warnings {
    if w == api.KeyRotation {
        // Signed by a previously-active key; envelope is authentic
        // but the operator may want to refresh evidence
    }
}
```

---

## 15. Anti-Patterns

Things consumers should not do, ordered by likelihood-to-attempt:

1. **Do not import anything outside `api/` and `pkg/kensa/`.** Internal
   packages are private to the module and may change without notice.
2. **Do not catch `ErrNotYetImplemented` and silently no-op.** It is a
   signal that the milestone has not landed; treating it as success
   means your code will silently miss the feature when it does land.
   Surface it to the operator instead.
3. **Do not write directly to `Config.StorePath`.** Use `LogQuery` for
   reads. The store schema is not part of the v1 contract.
4. **Do not ship a handler that lies about `Capturable()`.** The
   compiler stops you from "claims-capturable but missing methods,"
   but it cannot stop "claims-non-capturable while doing capturable
   work." Capture-completeness review is the human enforcement; do
   not ship around it.
5. **Do not assume `EventKind` is exhaustive.** New kinds may land in
   v1; treat unknown kinds as opaque rather than panicking on a switch
   default.
6. **Do not assume `Plan.PreStates` matches host state at execute
   time.** It may not. That is exactly the case `PlanStaleError`
   exists for. Always check the error type.
7. **Do not parse `CommandResult.Stdout` for state.** Use the
   structured types (`PreState`, `StepResult`, `EvidenceEnvelope`).
   Stdout is for humans and logs.

---

## 16. Where to Look Next

- **`docs/TRANSACTION_CONTRACT_V1.md`** — the customer-facing
  commitment that this surface implements.
- **`docs/foundation_docs/CANONICAL_RULE_SCHEMA_V1.md`** — the rule YAML contract,
  including the `transactional:` field that drives the
  `Transaction.Transactional` flag.
- **`docs/context/KENSA_GO_DAY1_PLAN.md`** — the architectural contract and
  milestone schedule. §11 is the surface-stability commitment that
  produced the v1-from-commit-1 frozen-API discipline.
- **`docs/roadmap/LOW_LEVEL_MIGRATION_V1.md`** — the planned migration
  from shell-over-SSH to direct kernel-ABI usage. Most of the work it
  describes happens behind the `Engine` and `Transport` interfaces in
  `internal/`, leaving this surface unchanged.
- **`specs/`** — every claim made above is traceable to a `.spec.yaml`
  with numbered acceptance criteria. `engine-transaction.spec.yaml`,
  `handler-interface.spec.yaml`, `evidence-envelope.spec.yaml`, and
  `transaction-log.spec.yaml` are the four highest-leverage starting
  points.
- **`api/kensa_test.go`** — runnable verification of the contract;
  also a working integration example.
