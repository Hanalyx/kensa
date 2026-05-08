# Kensa Go — Day 1 Build Plan

**Project:** Kensa (Go rewrite)
**Date:** 2026-04-13
**Status:** Draft v1 — Architectural foundation for the Go implementation
**Audience:** Founders and engineers executing the build
**Depends on:**
- `KENSA_VISION.md` — the category definition and four-phase primitive
- `TECHNICAL_REMEDIATION_MP_V1.md` — the atomicity principle and transaction model
- `CANONICAL_RULE_SCHEMA_V1.md` — the rule YAML contract
- `RULE_REVIEW_GUIDE_V1.md` — the six review dimensions
- `TRANSACTION_CONTRACT_V1.md` — the customer-facing commitment
- `HANALYX_MISSION_AND_ROADMAP.md` — the seven trust moats
- `HANALYX_18_MONTH_STRATEGY.md` — the GTM context the build must support
- `OPENWATCH_VISION.md` — the fleet control plane Kensa is the primitive for
- `AI_DEFENSIBILITY.md` — why building this right matters beyond the code itself

---

## 0. The North Star

Kensa Go is a **single static binary** that provides **transactional configuration
management for Linux**. Every mutation it applies is wrapped in a four-phase transaction
(capture → apply → validate → commit-or-rollback) with the atomicity, auditability, and
reversibility commitments stated in `TRANSACTION_CONTRACT_V1.md`.

The Python Kensa codebase is the reference implementation. The Go build is the
production implementation. They will coexist for 12-18 months. The Python version
continues to serve federal customers while the Go version is built; the Go version takes
over once it reaches parity + validation.

**The Go build is not a port.** It is a re-implementation against the V1 specs, using
the Python codebase as a behavioral oracle but not as a structural template. The
transaction engine is new work. The handlers are re-implementations against
language-neutral specs and fixtures. The SSH transport is different (system OpenSSH, not
Paramiko). The deadman-timer rollback path is new infrastructure. The API surface for
OpenWatch integration is new.

**Day 1 must get the foundation right.** Everything built on top — 539+ handlers, the
CLI, evidence export, the OpenWatch API — depends on the transaction engine, the
handler interface, the spec framework, and the SSH transport being correct from the
first commit. Retrofitting these is expensive; getting them right is not.

---

## 1. Day-1 Principles

These are the commitments that distinguish a Kensa Go build from a generic Go rewrite.
Every architectural decision downstream is justified against these.

### 1.1 Engine first, rules second

The transaction engine exists before the first handler is written. The first handler
exists before the first rule YAML is parsed. The first rule exists before the CLI is
wired up. Order matters — each layer must be proven against real hosts before the next
layer depends on it.

A common failure mode in rewrites is parallel development of all layers, which produces
a code-complete product that has never been validated end-to-end. We do the opposite:
narrow vertical slices, each one fully tested, built in order.

### 1.2 Atomicity is the product, not a feature

Every capability shipped must either satisfy the atomicity contract or explicitly
declare itself outside it. No handler ships without its capture and rollback handlers.
No rule ships without its `transactional` field correctly set and its rollback path
integration-tested.

The validator that enforces `CANONICAL_RULE_SCHEMA_V1.md` §6.2 item 8 (the atomicity
consistency check) is part of the `go build` pipeline. A PR that adds a non-capturable
step without flipping `transactional: false` does not compile, let alone merge.

### 1.3 System OpenSSH, not a Go SSH library

The SSH transport uses the operating system's `ssh` binary via subprocess with
ControlMaster multiplexing, not `golang.org/x/crypto/ssh`. This is a deliberate choice
with specific benefits enumerated in the broader architecture conversation:

- FIPS compliance comes from RHEL's OpenSSH, not from BoringCrypto + an internal
  transport.
- The operator's `~/.ssh/config`, ProxyJump, ProxyCommand, PKCS#11 tokens, FIDO2 keys,
  `ssh-agent`, and Kerberos/GSSAPI all work without reimplementation.
- The system crypto policy (`update-crypto-policies`) governs the transport
  automatically.
- Supply chain is smaller — no crypto library to audit beyond the system's own OpenSSH.

The fallback to `golang.org/x/crypto/ssh` exists for environments where `ssh` is not
available (rare, and not a supported configuration for federal deployment), but it is
not the primary path. The transport interface is defined such that the fallback can be
swapped in without handler changes.

### 1.4 Specs and fixtures are language-neutral

Every handler has a spec in `specs/<category>/<name>.spec.yaml` and a fixture file in
`fixtures/<handler>/*.yaml` describing `(input, expected_capture, expected_apply_result,
expected_rollback_result, expected_post_state)` tuples. These files are consumed by
**both** the Go tests and the Python tests during the coexistence period.

This is the Python→Go bridge. When the Python handler and the Go handler produce
identical outputs against identical fixtures, the port is correct. When they diverge,
the spec is the arbiter. The spec framework is the portability layer — it is what makes
the dual-codebase period tractable.

### 1.5 Handler interface stability from commit 1

The handler interface (`Handler` + `CaptureHandler` + `RollbackHandler`) is defined in
`internal/handler/handler.go` in the first commit and does not change without a major
version bump. Every mechanism handler implements this interface. Every new mechanism
added over the next five years implements this same interface.

This is non-negotiable because:
- The OpenWatch Go import depends on a stable API.
- The Python→Go handler port is mechanical only if the interface is stable.
- AI agents consuming the API in 2027+ cannot adapt to a moving target.

Breaking changes to the handler interface are a v2 decision, not a weekly decision.

### 1.6 Failure injection is a first-class tool

`cmd/kensa-fuzz` is a CLI that takes a rule, a host, and a phase (capture, apply,
validate), and deliberately induces a failure at that phase. It then verifies the
rollback path restores the exact pre-state. This tool ships in the first working
version of the engine and runs in CI against a RHEL test matrix.

This is how the atomicity commitment is verified, not self-reported. It is also what
the Mission doc's Moat 7 (long-tail production experience) is built on — every failure
mode discovered becomes a fuzz scenario that prevents regression.

### 1.7 Human-authored failure-mode analysis per PR

Every PR that touches the engine, a capture handler, or a rollback handler includes a
human-authored failure-mode analysis in the PR description, answering the three
questions from `HANALYX_MISSION_AND_ROADMAP.md` §"AI and the failure-mode analysis
commitment":

1. What could this change do wrong in production?
2. What state is captured before the change, and is it sufficient to restore the system
   if the change or its validation fails?
3. What real-world edge case is this change *not* safe for, and is that edge case
   documented and gated?

This analysis is part of the permanent git history. It is the audit trail that supports
the Liability moat, the FedRAMP SSP documentation for CM-3/CM-5/SI-10/CP-10, and the
"humans reasoned about this" claim Hanalyx makes in marketing.

### 1.8 OpenWatch integration is a product surface, not an afterthought

The Go `api/` package is designed from day 1 to be imported by OpenWatch. It is the
public contract. The CLI is one consumer of the API; OpenWatch is another; future AI
agents are a third. All three go through the same interface.

`OPENWATCH_VISION.md` defines three OpenWatch identities — the Eye (historical view),
the Heartbeat (continuous awareness), and the Control Plane (preview-then-execute) —
each of which requires specific API surface from Kensa. §3.5 enumerates those
interfaces (`LogQuery`, `EventSubscriber`, `Planner`/`Executor`) and commits to
defining all of them in `api/` at commit 1, even though implementations are staged
across milestones. Stubbed methods returning `ErrNotYetImplemented` are acceptable;
missing method signatures are not — because the latter forces OpenWatch to either
wait or build against internal state, both of which violate the "api/ is the public
contract" principle.

This means:
- The API has a semver policy from commit 1.
- API changes go through a deprecation cycle, not a breakage.
- Internal packages (`internal/`) are freely modifiable; the public API is not.
- **The three OpenWatch-facing interfaces are frozen at commit 1, not at week 28.**

---

## 2. Repository Layout

```
kensa/
├── cmd/
│   ├── kensa/                  # Main CLI binary
│   │   └── main.go
│   ├── kensa-fuzz/             # Failure injection harness
│   │   └── main.go
│   └── kensa-validate/         # Rule/spec validator
│       └── main.go
├── api/                        # PUBLIC API — stable surface for OpenWatch and agents
│   ├── doc.go                  # Package documentation and versioning policy
│   ├── transaction.go          # Transaction, TransactionResult
│   ├── rule.go                 # Rule, Implementation, Check, Remediation types
│   ├── handler.go              # Public handler registration
│   ├── capability.go           # Capability detection types
│   ├── evidence.go             # Evidence envelope types
│   └── errors.go               # Typed errors
├── internal/                   # PRIVATE — freely modifiable
│   ├── engine/                 # Transaction coordinator
│   │   ├── engine.go           # Engine.Run(transaction) entry point
│   │   ├── capture.go          # Capture phase implementation
│   │   ├── apply.go            # Apply phase implementation
│   │   ├── validate.go         # Validate phase implementation
│   │   ├── commit.go           # Commit finalization
│   │   ├── rollback.go         # Rollback phase implementation
│   │   └── orchestrator.go     # Multi-rule orchestration
│   ├── handler/                # Handler interface + registry
│   │   ├── handler.go          # Handler, CaptureHandler, RollbackHandler interfaces
│   │   ├── registry.go         # Global handler registry
│   │   ├── capturability.go    # Capturable vs non-capturable classification
│   │   └── result.go           # StepResult, PreState types
│   ├── handlers/               # Individual mechanism implementations
│   │   ├── configset/          # config_set handler + capture + rollback
│   │   ├── configsetdropin/    # config_set_dropin handler + capture + rollback
│   │   ├── filepermissions/    # file_permissions handler + capture + rollback
│   │   ├── filecontent/
│   │   ├── fileabsent/
│   │   ├── serviceenabled/
│   │   ├── servicedisabled/
│   │   ├── servicemasked/
│   │   ├── packagepresent/
│   │   ├── packageabsent/
│   │   ├── sysctlset/
│   │   ├── kernelmoduledisable/
│   │   ├── mountoptionset/
│   │   ├── pammoduleconfigure/
│   │   ├── auditruleset/
│   │   ├── selinuxbooleanset/
│   │   ├── cronjob/
│   │   ├── commandexec/        # NON-CAPTURABLE — explicit escape hatch
│   │   ├── manual/             # NON-CAPTURABLE
│   │   └── grubparameter/      # NON-CAPTURABLE
│   ├── checks/                 # Check method implementations
│   │   ├── configvalue/
│   │   ├── filepermission/
│   │   ├── servicestate/
│   │   ├── sysctlvalue/
│   │   ├── sshdeffectiveconfig/
│   │   └── ...
│   ├── transport/              # SSH transport layer
│   │   ├── transport.go        # Transport interface
│   │   ├── ssh/                # System OpenSSH implementation (primary)
│   │   │   ├── ssh.go
│   │   │   ├── controlmaster.go
│   │   │   └── multiplex.go
│   │   └── crypto/             # golang.org/x/crypto/ssh fallback
│   │       └── crypto.go
│   ├── deadman/                # Deadman-timer rollback path
│   │   ├── timer.go            # Deadman timer activation/cancellation
│   │   ├── scheduler.go        # at + systemd-run scheduler adapters
│   │   └── script.go           # Rollback script generation
│   ├── rule/                   # Rule parsing and validation
│   │   ├── parser.go           # YAML rule → Rule struct
│   │   ├── validator.go        # Schema + atomicity consistency validation
│   │   ├── selector.go         # Capability-gated implementation selection
│   │   └── capability.go       # Capability probe definitions
│   ├── detect/                 # Capability detection
│   │   ├── detect.go           # Detect(transport) → CapabilitySet
│   │   └── probes.go           # Individual capability probes
│   ├── mappings/               # Framework mapping loader
│   │   └── mappings.go
│   ├── store/                  # SQLite transaction log
│   │   ├── store.go            # Store interface
│   │   ├── sqlite.go           # SQLite implementation
│   │   ├── schema.go           # Schema migrations
│   │   └── retention.go        # 7-day active / 90-day info retention
│   ├── evidence/               # Evidence envelope generation
│   │   ├── envelope.go         # Envelope construction
│   │   ├── signer.go           # Ed25519 signing
│   │   └── oscal.go            # OSCAL export
│   ├── output/                 # Report formatters
│   │   ├── json.go
│   │   ├── csv.go
│   │   ├── pdf.go
│   │   └── transaction.go      # Transaction log rendering
│   └── risk/                   # Risk classification for remediation steps
│       └── risk.go
├── rules/                      # Canonical rule YAML files (language-agnostic)
│   ├── access-control/
│   ├── audit/
│   └── ...
├── mappings/                   # Framework mappings (language-agnostic)
│   ├── cis/
│   ├── stig/
│   ├── nist/
│   ├── pci-dss/
│   └── fedramp/
├── specs/                      # Handler and component specs (language-agnostic)
│   ├── engine/
│   ├── handlers/
│   ├── checks/
│   └── transport/
├── fixtures/                   # Test fixtures (language-agnostic)
│   ├── handlers/
│   │   ├── configset/
│   │   │   ├── basic.yaml
│   │   │   ├── missing-file.yaml
│   │   │   ├── existing-key.yaml
│   │   │   └── ...
│   │   └── ...
│   └── rules/
│       └── ...
├── schema/                     # JSON Schemas
│   ├── rule.schema.json        # V1 rule schema
│   └── spec.schema.json        # Spec file schema
├── context/                    # Reference data (baselines, OSCAL sources)
│   ├── fedramp/
│   └── cis/
├── testdata/                   # Go-specific test data that doesn't cross-port
├── scripts/
│   ├── fixture_diff.sh         # Compare Python vs Go handler outputs against fixtures
│   ├── spec_traceability.go    # AC-to-test traceability enforcement
│   └── parity_check.sh         # Python ↔ Go parity verification
├── .github/workflows/
│   ├── ci.yml                  # Build, test, lint
│   ├── integration.yml         # Real-host integration tests (RHEL 8/9/10 matrix)
│   ├── fuzz.yml                # Failure injection tests
│   └── parity.yml              # Python vs Go output parity
├── go.mod
├── go.sum
├── Makefile
├── CLAUDE.md                   # Stays a local-only file (never committed)
└── docs/                       # Documentation (V1 specs + this plan + others)
```

**Key decisions encoded in the layout:**

- `api/` is the public boundary. Everything external to Kensa — OpenWatch, third-party
  tools, future AI agents — imports only from `api/` and its sub-packages. It has a
  semver contract.
- `internal/` is freely refactorable. Go's compiler enforces this — nothing outside
  Kensa can import `internal/...`.
- `rules/`, `mappings/`, `specs/`, `fixtures/` are language-agnostic. They are shared
  between the Python and Go codebases during the coexistence period via a git subtree
  or submodule (see §12).
- Every handler lives in its own package under `internal/handlers/`. A handler package
  contains the handler, its capture, its rollback, and its tests. This enforces
  encapsulation and makes it obvious which files belong together.
- `cmd/kensa-fuzz` is separate from `cmd/kensa` because failure injection is a
  development/CI tool, not something end users run against their production fleet.

---

## 3. Core Interfaces

The interfaces below are defined in the first week of work. They do not change for the
lifetime of v1.

### 3.1 The Handler Interface

```go
// package api

// Handler is the contract every mechanism handler implements.
// A Handler knows how to apply a specific kind of system change.
type Handler interface {
    // Name returns the mechanism identifier used in rule YAML (e.g., "config_set").
    Name() string

    // Capturable returns true if this handler participates in atomic transactions.
    // Non-capturable handlers (command_exec, manual, grub_parameter) return false.
    Capturable() bool

    // Apply executes the mechanism against the target host.
    // Pre-state must have been captured by the CaptureHandler before Apply runs.
    Apply(ctx context.Context, transport Transport, params Params, pre *PreState) (*StepResult, error)
}

// CaptureHandler captures pre-state for a capturable mechanism.
// Implemented alongside Handler for every capturable mechanism.
type CaptureHandler interface {
    // Capture records the system's pre-state for this mechanism's parameters.
    // The returned PreState is persisted to the transaction log and used by Rollback.
    Capture(ctx context.Context, transport Transport, params Params) (*PreState, error)
}

// RollbackHandler reverses an applied change using the captured pre-state.
// Implemented alongside Handler for every capturable mechanism.
type RollbackHandler interface {
    // Rollback restores the system to the captured pre-state.
    // Returns RollbackResult describing what was restored and any partial-restore
    // conditions (e.g., a file was restored but the service did not reload).
    Rollback(ctx context.Context, transport Transport, pre *PreState) (*RollbackResult, error)
}

// CombinedHandler is a convenience interface for mechanisms that implement all three.
// Every capturable mechanism should satisfy CombinedHandler.
type CombinedHandler interface {
    Handler
    CaptureHandler
    RollbackHandler
}
```

**Why this shape:**

- Separate interfaces for Capture, Apply, Rollback mirror the transaction phases
  exactly. A reviewer can check each phase's implementation in isolation.
- Non-capturable handlers implement only `Handler` — they cannot satisfy
  `CombinedHandler`, and this is enforced by the compiler.
- The `context.Context` plumbs through cancellation and deadlines (important for the
  deadman timer path).
- `Params` is a typed-any wrapper; each handler decodes its specific params from it.
  This keeps the interface stable across handlers with wildly different parameter
  shapes.

### 3.2 The Transport Interface

```go
// package api

// Transport is the abstraction over "how do I reach the target host."
// The primary implementation is system OpenSSH with ControlMaster multiplexing.
// A fallback implementation uses golang.org/x/crypto/ssh for environments where
// the system ssh binary is unavailable.
type Transport interface {
    // Run executes a command on the target host and returns the result.
    // The command is run under sudo when the transport is configured with sudo=true.
    Run(ctx context.Context, cmd string) (*CommandResult, error)

    // Put uploads a file to the target host.
    Put(ctx context.Context, localPath, remotePath string, mode os.FileMode) error

    // Get downloads a file from the target host.
    Get(ctx context.Context, remotePath, localPath string) error

    // ControlChannelSensitive returns true if the transport considers itself at risk
    // of being disrupted by a change. Set by the deadman-timer subsystem when it
    // detects a control-channel-affecting mechanism in the current transaction.
    ControlChannelSensitive() bool

    // Close tears down the transport (e.g., terminates the ControlMaster).
    Close() error
}

// CommandResult is the structured return from Run.
type CommandResult struct {
    ExitCode int
    Stdout   string
    Stderr   string
    Duration time.Duration
}
```

### 3.3 The Transaction Type

```go
// package api

// Transaction represents a single rule's mutation against a single host.
// It is the unit of atomicity.
type Transaction struct {
    ID         uuid.UUID
    RuleID     string
    HostID     string
    Steps      []Step
    Validators []Validator      // Post-apply validators (service health, config syntax)
    StartedAt  time.Time
    Deadline   time.Time         // Maximum wall time before transaction is aborted

    // Declared by the rule YAML's `transactional` field.
    // true = atomic (all capturable). false = escape hatch present.
    Transactional bool
}

// Step is one mechanism invocation within a transaction.
type Step struct {
    Index     int
    Mechanism string                 // e.g., "config_set"
    Params    Params
}

// TransactionResult is the outcome of executing a Transaction.
type TransactionResult struct {
    TransactionID uuid.UUID
    Status        TransactionStatus  // Committed | RolledBack | PartiallyApplied | Errored
    Steps         []StepResult
    PreStates     []PreState
    CommittedAt   *time.Time
    RolledBackAt  *time.Time
    Evidence      *EvidenceEnvelope
    Error         error              // Non-nil only on Errored status
}
```

### 3.4 The Engine Entry Point

```go
// package engine (internal, but accessed via api.Engine wrapper)

type Engine struct {
    store    Store
    registry *handler.Registry
    signer   evidence.Signer
}

// Run executes a transaction against a host and returns the result.
// The caller is responsible for providing a Transport (typically ssh.Connect(...)).
// Run always returns — it does not panic on failure, and it does not leave the system
// in an indeterminate state (either committed, rolled back, or partially applied with
// explicit status).
func (e *Engine) Run(ctx context.Context, transport Transport, txn *Transaction) (*TransactionResult, error)
```

That's the whole engine API for executing a single transaction. Everything else is
internal orchestration. The simplicity is the point — a one-function public surface
means OpenWatch, the CLI, and future AI agents all call the same entry point for
*executing* a transaction.

But execution is only one of the three identities OpenWatch requires. See §3.5.

### 3.5 OpenWatch-Facing Interfaces (the Eye, Heartbeat, Control Plane)

`OPENWATCH_VISION.md` defines OpenWatch as the Eye (historical view), the Heartbeat
(continuous awareness), and the Control Plane (preview-then-execute). Each identity
requires a specific Kensa API surface that `Engine.Run` alone does not provide. These
interfaces are defined in `api/` at commit 1 — even though full implementations are
staged across milestones — because the engine's internal shape must accommodate them
from the start.

#### 3.5.1 The Eye — Transaction Log Query Interface

```go
// package api

// LogQuery is the read-side interface over the transaction log.
// OpenWatch's transaction log UI is a view over this interface.
type LogQuery interface {
    // Query returns transactions matching the filter, paginated.
    Query(ctx context.Context, filter LogFilter, page Page) (*QueryResult, error)

    // Get returns a single transaction by ID. Options control inclusion of the
    // evidence envelope and pre-state bundles for performance tuning on list views.
    Get(ctx context.Context, txnID uuid.UUID, opts ...GetOption) (*TransactionRecord, error)

    // Aggregate returns posture summaries grouped by AggregateKey over a time range.
    // This is how OpenWatch renders fleet-level compliance views without scanning
    // every row.
    Aggregate(ctx context.Context, filter LogFilter, groupBy AggregateKey, opts ...AggregateOption) (*AggregateResult, error)
}

// FrameworkRef is a structured framework reference. OpenWatch and other consumers
// filter by (framework, control) tuples; opaque strings would force every consumer
// to implement parsing.
type FrameworkRef struct {
    FrameworkID string  // e.g., "cis_rhel9_v2", "stig_rhel9_v2r7", "nist_800_53_r5"
    ControlID   string  // e.g., "5.2.3", "V-257947", "AC-6(2)"
}

// LogFilter selects transactions across multiple dimensions. All fields are
// optional; empty fields are treated as "no filter on this dimension."
type LogFilter struct {
    HostIDs         []string
    FleetIDs        []string
    RuleIDs         []string
    FrameworkRefs   []FrameworkRef
    Statuses        []TransactionStatus
    Phases          []Phase              // capture | apply | validate | commit | rollback
    Severities      []string             // critical | high | medium | low
    Mechanisms      []string
    Transactional   *bool                // nil = don't filter; true/false = filter
    Since           time.Time
    Until           time.Time
}

// AggregateKey enumerates the supported aggregation shapes. Consumers must use
// a defined key; arbitrary aggregations are not supported through this interface.
type AggregateKey string

const (
    AggregateByHost                     AggregateKey = "by_host"
    AggregateByRule                     AggregateKey = "by_rule"
    AggregateByFrameworkControl         AggregateKey = "by_framework_control"
    AggregateByHostThenFrameworkControl AggregateKey = "by_host_then_framework_control"
    AggregateByRuleThenStatusOverTime   AggregateKey = "by_rule_then_status_over_time"
)

// TimeBucket controls time-based aggregations. Required when AggregateKey is
// a time-over-time variant.
type TimeBucket string

const (
    HourBucket TimeBucket = "hour"
    DayBucket  TimeBucket = "day"
    WeekBucket TimeBucket = "week"
)

// GetOption controls payload inclusion on Get. Default is "include everything"
// (correct for audit export); opt out for list views where the envelope is
// expensive to load.
type GetOption func(*getOptions)

func WithEnvelope() GetOption    { return func(o *getOptions) { o.includeEnvelope = true } }
func WithoutEnvelope() GetOption { return func(o *getOptions) { o.includeEnvelope = false } }
func WithoutPreStates() GetOption { return func(o *getOptions) { o.includePreStates = false } }

// AggregateOption controls aggregation behavior, notably the time bucket.
type AggregateOption func(*aggregateOptions)

func WithTimeBucket(b TimeBucket) AggregateOption {
    return func(o *aggregateOptions) { o.bucket = b }
}

// Denormalized fields on the transaction log write path:
// Severity is derived from the rule at write time and stored on the transaction
// row. Joining against rules at query time is too expensive for OpenWatch's
// aggregation queries. The write-time denormalization is a deliberate trade-off.
```

#### 3.5.2 The Heartbeat — Event Subscription

```go
// package api

// EventPublisher is the write-side of the event stream.
// The engine publishes to it as transactions progress.
type EventPublisher interface {
    Publish(ctx context.Context, event Event) error
}

// EventSubscriber is the read-side.
// OpenWatch subscribes to it to drive real-time drift alerts, progress indicators,
// and the "fleet health" view.
type EventSubscriber interface {
    // Subscribe returns a channel that receives events matching the filter.
    // The channel closes when ctx is done. Back-pressure is handled by the caller:
    // if events arrive faster than the consumer reads, dropped events are counted
    // but not blocked — the heartbeat must not stall the engine. Dropped event
    // counts are exposed via the DropStats() method on the returned channel wrapper.
    Subscribe(ctx context.Context, filter EventFilter) (<-chan Event, error)
}

// Event is the unit of the event stream.
type Event struct {
    ID        uuid.UUID
    Kind      EventKind
    TxnID     *uuid.UUID      // Nil for fleet-level events (HeartbeatPulse)
    HostID    string
    Timestamp time.Time
    Data      any             // Kind-specific payload
}

// EventKind enumerates every event type the engine emits. Consumers filter by
// passing specific kinds in EventFilter.Kinds.
type EventKind string

const (
    TransactionStarted EventKind = "transaction_started"
    PhaseCompleted     EventKind = "phase_completed"
    Committed          EventKind = "committed"
    RolledBack         EventKind = "rolled_back"
    DriftDetected      EventKind = "drift_detected"
    HeartbeatPulse     EventKind = "heartbeat_pulse"
    DeadmanTimerArmed  EventKind = "deadman_timer_armed"
    DeadmanTimerFired  EventKind = "deadman_timer_fired"
)

// EventFilter selects which events the subscriber receives.
//
// An empty Kinds list means "all kinds." A specific Kinds list returns ONLY those
// kinds — so a subscriber that wants only DeadmanTimerFired passes
// []EventKind{DeadmanTimerFired} and receives nothing else.
type EventFilter struct {
    Kinds    []EventKind
    HostIDs  []string
    FleetIDs []string

    // HeartbeatInterval caps the rate of HeartbeatPulse events the subscriber
    // receives. The engine may emit pulses more frequently internally, but the
    // subscription delivers at most one pulse per HeartbeatInterval per host.
    // Default (zero value): 60 * time.Second. Set to a nonzero duration to
    // override. HeartbeatPulse is never dropped due to back-pressure — pulses
    // are coalesced, not lost.
    HeartbeatInterval time.Duration
}
```

#### 3.5.3 The Control Plane — Preview Before Execute

```go
// package api

// Planner produces a full transaction plan without executing it.
// OpenWatch uses this to render the preview UI before a human approves execution:
// "here is exactly what will be captured, what will be applied, what will be
// validated, and what the rollback plan is if validation fails."
type Planner interface {
    // PlanTransaction takes a rule and a target host, performs capability detection
    // and implementation selection, and returns a Plan describing every phase without
    // running anything on the target.
    //
    // Plan runs the Capture phase's pre-read (the commands that read pre-state) and
    // includes the pre-state in the plan, so the operator sees the exact "before"
    // picture. It does NOT run Apply, Validate, Commit, or Rollback.
    PlanTransaction(ctx context.Context, transport Transport, rule *Rule) (*Plan, error)
}

// Plan is the structured preview of a transaction.
type Plan struct {
    RuleID                  string
    HostID                  string
    SelectedImpl            *Implementation
    Capabilities            CapabilitySet
    Transactional           bool
    ControlChannelSensitive bool                    // Deadman timer will be armed
    PreStates               []PreState              // Read-only, from Capture phase
    ApplySteps              []StepPreview           // What Apply would do
    Validators              []ValidatorPreview      // What Validate would check
    RollbackPlan            []RollbackStepPreview   // What Rollback would reverse
    EstimatedDuration       time.Duration
    Warnings                []string                // e.g., "rule is transactional:false"
    CreatedAt               time.Time
}

// Preview renders the plan for human display. Kensa owns the rendering so CLI and
// OpenWatch UI show the same canonical form. OpenWatch may still build richer
// interactive UIs over the struct fields, but the audit-log display and the CLI
// display always go through Preview.
func (p *Plan) Preview(format PreviewFormat) (string, error)

// PreviewFormat selects the preview rendering.
type PreviewFormat string

const (
    PreviewText     PreviewFormat = "text"      // ANSI-formatted CLI output
    PreviewMarkdown PreviewFormat = "markdown"  // For OpenWatch and documentation
    PreviewJSON     PreviewFormat = "json"      // Structured, for machine consumers
    PreviewPlain    PreviewFormat = "plain"     // No ANSI, no markdown — for logs
)

// Execute takes a previously-produced Plan and executes it. The plan acts as a
// commitment — if the host's state has diverged from the plan's pre-state snapshot
// since the plan was produced, Execute fails with PlanStaleError and the caller
// must re-plan.
type Executor interface {
    Execute(ctx context.Context, transport Transport, plan *Plan) (*TransactionResult, error)
}

// PlanStaleError is returned by Execute when the host's state has diverged from
// the plan's captured pre-state. Step-level detail lets OpenWatch's UI say
// "re-plan because /etc/ssh/sshd_config changed since you last planned," not
// just "re-plan."
type PlanStaleError struct {
    PlanID         uuid.UUID
    StaleStepIndex int
    Mechanism      string       // The mechanism whose pre-state diverged
    Field          string       // The specific field that changed, e.g., "content", "mode", "value"
    Expected       interface{}  // What the plan's captured pre-state said
    Actual         interface{}  // What the host has now
    Message        string       // Human-readable summary
}

func (e *PlanStaleError) Error() string { return e.Message }
```

The Plan/Execute split is what makes OpenWatch's approval workflow correct. A human
approving a plan is approving a specific plan, not a re-derivation that might differ
by the time execution runs. The `PlanStaleError` is the explicit mechanism by which
"the world changed between plan and execute" surfaces as a first-class failure.

#### 3.5.4 Envelope Verification

OpenWatch's audit UI displays evidence envelopes and needs to verify their Ed25519
signatures. Re-implementing verification on the OpenWatch side would duplicate the
trust logic and risk divergence. Kensa owns verification:

```go
// package api

// EnvelopeVerifier verifies the authenticity of an evidence envelope produced
// by Kensa. Called by OpenWatch's audit UI, by the CLI, and by third-party
// auditor tools that import api/.
type EnvelopeVerifier interface {
    // VerifyEnvelope checks the signature against the deployment's registered
    // public keys. Returns ok=true only if a signature matches a known key.
    //
    // If the envelope was signed by a key that has since been rotated, the
    // verifier falls back to the key history and returns ok=true with a
    // KeyRotation warning in the VerifyResult. If no matching key is found,
    // ok=false with a specific error.
    VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error)
}

type VerifyResult struct {
    Valid         bool
    KeyID         string          // Which public key matched
    SignedAt      time.Time
    Warnings      []string        // e.g., "signed by rotated key"
    EnvelopeHash  [32]byte        // For audit trail
}
```

The `api/` package exposes this as `Kensa.VerifyEnvelope(...)`. OpenWatch calls it
on every audit-UI render for user-visible envelope authenticity indicators.

#### 3.5.5 Deadman Timer Control

When the engine arms a deadman timer, operators need the ability to cancel it
cleanly (execute an in-band rollback and then remove the scheduled script) from
the OpenWatch UI — without waiting for the timer window to fire.

```go
// package api

// DeadmanControl exposes cancel/status operations for armed deadman timers.
type DeadmanControl interface {
    // CancelDeadman executes an immediate clean rollback of the transaction's
    // applied steps and cancels the scheduled deadman script. Safer than
    // waiting for the timer to fire because it runs in-band over the control
    // channel, not as a scheduled out-of-band job.
    //
    // Returns ErrNoActiveDeadman if no timer is armed for this txnID.
    CancelDeadman(ctx context.Context, transport Transport, txnID uuid.UUID) (*RollbackResult, error)

    // DeadmanStatus returns the armed-timer state for a transaction.
    DeadmanStatus(ctx context.Context, transport Transport, txnID uuid.UUID) (*DeadmanState, error)
}

type DeadmanState struct {
    TxnID        uuid.UUID
    Armed        bool
    ArmedAt      time.Time
    FiresAt      time.Time       // Absolute time the scheduled script will fire
    ScriptPath   string          // Where the rollback script lives on the host
    RollbackPlan []RollbackStepPreview  // What the script would do
}
```

This is what makes the "deadman-timer visibility" UX in OpenWatch work: the UI
shows armed status with a countdown, the operator can hit "cancel and rollback
now," and the transition flows back into the regular transaction log.

#### 3.5.6 Concurrency Guarantees

Kensa enforces **per-host serialization internally**. Multiple goroutines (or
multiple OpenWatch workers sharing a `*Kensa` instance) may call `Scan`,
`Transact`, `Remediate`, or `Execute` against different hosts concurrently —
they proceed in parallel. Calls against the **same** host block on a per-host
mutex in the engine until the in-flight transaction completes.

Callers that prefer non-blocking semantics can detect contention explicitly:

```go
// package api

// ErrHostBusy is returned when a non-blocking operation is requested against a
// host that has an in-flight transaction.
var ErrHostBusy = errors.New("kensa: host has an in-flight transaction")

// WithNonBlocking returns ErrHostBusy immediately instead of waiting when the
// host lock is held.
func WithNonBlocking() Option { ... }
```

This removes a class of coordination bugs in OpenWatch's job queue. Workers can
fan out freely; they do not need to implement their own per-host locks.

#### 3.5.7 The Unified API

The seven sub-sections above compose into the full `Kensa` API in §9. The
engine's internals (`internal/engine`) implement all of them by construction —
`PlanTransaction` is a partial `Run` that halts after Capture; `Subscribe` taps
the engine's existing phase-transition points; `LogQuery` reads from the existing
SQLite store; `VerifyEnvelope` reuses the same signature logic the engine uses
at write time; `CancelDeadman` calls the existing rollback path. None of these
require a new storage engine or a new orchestrator — they are exposures of
state and operations that already exist internally.

**What this prevents.** Without these interfaces in `api/` at commit 1, OpenWatch
would be forced to either (a) build against the SQLite store directly, violating
the "`api/` is the public contract" principle in §1.8, or (b) wait until Week 28+
for Kensa to ship them, stalling OpenWatch's own 18-month roadmap. Both outcomes
are worse than committing to the interface shape upfront, even with stubbed
implementations.

---

## 4. The Transaction Engine

### 4.1 The Run Loop

`Engine.Run(ctx, transport, txn)` executes:

```
1. PRE-FLIGHT
   1.1 Validate the transaction: every step's mechanism is registered
   1.2 Check transactional consistency: if any step is non-capturable and
       txn.Transactional == true, fail immediately (schema validation bug)
   1.3 Scan for control-channel sensitivity: if any mechanism modifies SSH,
       networking, firewall, or PAM, activate deadman-timer mode

2. CAPTURE (only if txn.Transactional or at least one capturable step)
   2.1 For each step in order:
       2.1.1 If capturable: invoke CaptureHandler, collect PreState
       2.1.2 If non-capturable: record nil PreState with capturable=false
   2.2 Persist PreStates bundle to Store BEFORE any mutation runs
   2.3 If deadman mode: upload rollback script, arm timer

3. APPLY
   3.1 For each step in order:
       3.1.1 Invoke Handler.Apply with the step's params and PreState
       3.1.2 If the step returns an error OR a non-success StepResult:
             - Record failure
             - Skip to ROLLBACK
       3.1.3 Otherwise, record success
   3.2 All steps succeeded → proceed to VALIDATE

4. VALIDATE
   4.1 Run the rule's check (post-apply round-trip verification)
   4.2 Run every declared Validator (service health, config syntax, etc.)
   4.3 If deadman mode: verify control channel is still responsive
   4.4 Any failure → skip to ROLLBACK

5. COMMIT OR ROLLBACK
   5a. COMMIT:
       5a.1 If deadman mode: cancel the timer, remove the rollback script
       5a.2 Generate and sign evidence envelope
       5a.3 Write committed TransactionResult to Store
       5a.4 Return TransactionResult{Status: Committed}

   5b. ROLLBACK (on any APPLY or VALIDATE failure):
       5b.1 For each successfully-applied capturable step in REVERSE order:
            Invoke RollbackHandler.Rollback with the captured PreState
       5b.2 If deadman mode: the timer may have already fired; verify state
       5b.3 Generate and sign evidence envelope (including rollback details)
       5b.4 Write rolled-back TransactionResult to Store
       5b.5 If any non-capturable step applied successfully:
            Return TransactionResult{Status: PartiallyApplied} with explicit flags
       5b.6 Otherwise return TransactionResult{Status: RolledBack}
```

### 4.2 Durability Guarantees

- **PreStates are persisted before any APPLY runs.** If the engine crashes during
  APPLY, the PreStates are still in the transaction log and can be used by a subsequent
  `kensa rollback --start N` to restore state out of band.
- **Rollback handlers are idempotent.** If rollback is invoked twice (e.g., once by the
  deadman timer, once by the engine), the second invocation is a no-op.
- **Transaction log writes are synchronous.** SQLite is configured with
  `PRAGMA synchronous=FULL` so writes hit disk before the engine proceeds.

### 4.3 Multi-Rule Orchestration

The orchestrator (`internal/engine/orchestrator.go`) runs a sequence of independent
transactions. Each rule is its own transaction boundary — a failure in rule 37 rolls
back rule 37 only; rules 1-36 remain committed.

`--atomic-run` wraps the whole orchestration in a meta-transaction: all rules commit
together, or every successful rule is rolled back. This is an explicit opt-in with
significant performance and complexity cost, used only when the operator requires
fleet-level atomicity.

---

## 5. The Handler Model

### 5.1 Handler Package Anatomy

Every handler package follows the same structure:

```
internal/handlers/configset/
├── configset.go           # Handler.Apply implementation
├── capture.go             # CaptureHandler.Capture implementation
├── rollback.go            # RollbackHandler.Rollback implementation
├── params.go              # Params struct + decoding
├── configset_test.go      # Unit tests
├── integration_test.go    # Integration tests against real host
└── fuzz_test.go           # Failure injection tests
```

### 5.2 Handler Registration

Handlers are registered at init-time via the global registry:

```go
// internal/handlers/configset/configset.go

func init() {
    handler.Register(&Handler{})
}

type Handler struct{}

func (h *Handler) Name() string     { return "config_set" }
func (h *Handler) Capturable() bool { return true }

func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, pre *api.PreState) (*api.StepResult, error) {
    p, err := decodeParams(params)
    if err != nil {
        return nil, err
    }
    // ... implementation ...
}
```

The engine's pre-flight phase validates that every mechanism referenced in a rule is
registered. Missing handlers fail the transaction at pre-flight, never at apply time.

### 5.3 Handler Spec and Fixtures

Every handler has a spec in `specs/handlers/<name>.spec.yaml`:

```yaml
component: handlers/config_set
objective:
  description: |
    Set a key=value pair in a configuration file, creating the file if needed.
    The prior value (or "absent" state) is captured before modification.
  acceptance_criteria:
    - AC-1: Apply sets the key to the specified value using the specified separator
    - AC-2: Apply is idempotent — running twice produces the same result
    - AC-3: Capture records the prior key=value or "absent" if the key is missing
    - AC-4: Rollback restores the prior state including "absent" cases
    - AC-5: Rollback triggers the configured reload/restart if specified
    - AC-6: Apply fails cleanly if the target file is not writable
    - AC-7: Capture fails cleanly if the target file is not readable
testing:
  spec_derived:
    file: fixtures/handlers/configset/*.yaml
    runner_go: internal/handlers/configset/configset_test.go
    runner_python: tests/spec/handlers/test_configset_spec.py
```

And fixtures in `fixtures/handlers/configset/*.yaml`:

```yaml
# fixtures/handlers/configset/ac3-absent-key.yaml
ac: AC-3
description: Capture records "absent" when key is missing
inputs:
  params:
    path: /etc/ssh/sshd_config
    key: PermitRootLogin
    separator: " "
    value: "no"
  pre_host_state:
    files:
      /etc/ssh/sshd_config: |
        # SSH config without PermitRootLogin
        Port 22
expected_capture:
  state: absent
  path: /etc/ssh/sshd_config
  key: PermitRootLogin
expected_apply:
  success: true
expected_post_state:
  files:
    /etc/ssh/sshd_config: |
      # SSH config without PermitRootLogin
      Port 22
      PermitRootLogin no
expected_rollback:
  success: true
expected_rollback_state:
  files:
    /etc/ssh/sshd_config: |
      # SSH config without PermitRootLogin
      Port 22
```

**Both the Go test and the Python test load the same fixture file.** If they produce
the same output, they are equivalent implementations. If they diverge, the spec
(`spec.yaml`) arbitrates — the spec is the source of truth.

### 5.4 The First Handler

The first handler implemented is **`file_permissions`**. It is chosen because:

- It has a simple, well-defined capture (read owner, group, mode, SELinux context).
- Its apply is a single command (`chmod`/`chown`/`chcon`).
- Its rollback is a single command (restore the captured values).
- It is used by dozens of rules in the Python codebase.
- It has no control-channel implications.

The `file_permissions` handler is the first complete vertical slice: from its spec and
fixtures, through its Go implementation, through its integration tests on a real RHEL
host, through a fuzz test that induces an apply failure and verifies rollback. When
this slice works end-to-end, the foundation is proven and the next handler can follow
the same pattern.

### 5.5 Per-Rule Capture Sufficiency Review

Per-handler fixtures prove that a handler's capture is correct *for the parameter
combinations exercised in the fixtures*. They do not prove that a specific rule's
capture is sufficient for that rule's specific semantics. `RULE_REVIEW_GUIDE_V1.md`
§5.1 names this gap explicitly: the reviewer walks through the capture handler's
behavior against the specific mechanism parameters the rule uses.

This review is a per-rule gate, not a per-handler gate. The plan operationalizes it
via a mandatory field in every rule's PR description:

```
## Capture Sufficiency Analysis (required for transactional: true rules)

For each step in the remediation:
  - Step N: <mechanism>
    - Captured state: <what the capture handler records for these params>
    - Adjacent state not captured: <what the handler does NOT record>
    - Is the uncaptured state safe to leave unrestored on rollback? <yes/no/why>
```

Example: a `config_set` rule that edits `/etc/sysctl.d/99-kensa.conf` AND triggers a
`sysctl --system` reload captures the file content but not the runtime kernel
parameter. On rollback, restoring the file content is not sufficient — the runtime
parameter must also be reverted. The capture-sufficiency review catches this and
either adds a `sysctl_set` companion step or accepts the gap explicitly with
justification.

The review is enforced by a PR template that blocks merge if the section is missing
for a `transactional: true` rule. This is the rule-level analogue of the
failure-mode analysis required on engine PRs (§1.7).

---

## 6. SSH Transport & Deadman Timer

### 6.1 System OpenSSH with ControlMaster

The primary transport is `internal/transport/ssh`. It wraps the system `ssh` binary
with persistent ControlMaster multiplexing:

```go
// package ssh

type Transport struct {
    host        string
    user        string
    port        int
    sudo        bool
    socketPath  string  // ControlPath socket
    controlCmd  *exec.Cmd
}

func Connect(ctx context.Context, cfg Config) (*Transport, error) {
    // 1. Compute socket path: /tmp/kensa-<user>@<host>:<port>-<pid>
    // 2. Launch ssh -fN -o ControlMaster=yes -o ControlPath=... user@host
    //    This establishes the persistent connection and forks to background.
    // 3. Return Transport with socket path configured.
}

func (t *Transport) Run(ctx context.Context, cmd string) (*api.CommandResult, error) {
    // ssh -o ControlPath=<socket> user@host "<cmd>"
    // Every subsequent command reuses the multiplexed connection.
}

func (t *Transport) Close() error {
    // ssh -O exit -o ControlPath=<socket> user@host
}
```

### 6.2 The Deadman Timer

`internal/deadman` implements the control-channel safety path described in
`TRANSACTION_CONTRACT_V1.md` §2.2. When the engine detects a control-channel-affecting
mechanism in the current transaction, it:

1. Generates a self-contained rollback shell script from the captured PreStates.
2. Uploads the script to `/tmp/kensa-rollback-<txn-id>.sh` on the target host.
3. Schedules it via `at now + 120 seconds` or `systemd-run --on-active=120`.
4. Proceeds with APPLY and VALIDATE.
5. On successful VALIDATE: cancels the scheduled job, removes the script.
6. On failure: the job fires and restores pre-state out of band; the engine records
   the rollback outcome from the transaction log.

The deadman timer is the architectural answer to the single hardest problem in the
SSH-agentless design: *what happens when the connection Kensa is using is the thing
Kensa is changing?* Without the timer, atomicity is a marketing claim that breaks the
first time someone uses Kensa to harden sshd_config incorrectly. With the timer, the
atomicity commitment in `TRANSACTION_CONTRACT_V1.md` is honorable.

### 6.3 Deadman Script Generation

The rollback script is generated from PreStates using a template-free approach — each
mechanism type has a `ToShell(pre *PreState) string` method that emits the minimum
shell commands needed to restore that specific state. The script is self-contained,
has no external dependencies, and is POSIX shell (not bash-specific) so it runs under
the minimal shell environment that `at` provides.

Example generated script for a transaction that modified `/etc/ssh/sshd_config.d/00-kensa.conf`:

```sh
#!/bin/sh
# Kensa rollback script — txn 8a3f2e91-...
# Generated: 2026-04-13T14:22:00Z
# Expires: fire-and-forget on schedule unless cancelled

# Step 1 rollback: config_set_dropin
# Pre-state: file was absent
rm -f /etc/ssh/sshd_config.d/00-kensa.conf

# Final: reload sshd to restore effective state
systemctl reload sshd 2>/dev/null || true

# Clean up this script
rm -f "$0"
```

### 6.4 Deadman Timer Edge Cases (Required Tests)

The deadman timer is the architectural answer to the hardest problem in the design.
Every edge case that could defeat it is an atomicity violation. Day-1 testing must
explicitly cover:

| Edge case                                      | Test                                                        | Expected behavior                                                 |
|------------------------------------------------|-------------------------------------------------------------|-------------------------------------------------------------------|
| `at` not installed on target host              | Pre-flight detection; fall back to `systemd-run`            | Transport reports scheduler available; engine proceeds            |
| Neither `at` nor `systemd-run` available       | Pre-flight detection                                        | Engine refuses to execute control-channel-sensitive rules; error surfaces the scheduler requirement before any change runs |
| Script upload fails (disk full, permissions)   | Upload must verify before proceeding                        | Transaction aborts before APPLY; no change made; error returned   |
| `at` job scheduled but system clock skewed     | Sanity check `date` before and after scheduling             | Detected during pre-flight; engine logs warning and uses a longer timer margin or refuses |
| `at` job scheduled but daemon not running      | Post-schedule verification (`atq` shows the job)            | If not present, transaction aborts before APPLY                   |
| Apply runs, validate passes, cancel fails      | Network partition between successful validate and cancel    | Timer fires during the gap; rollback script runs; the committed change is reversed. Engine detects post-cancel that the script fired and records the anomaly. This is a known limitation — documented explicitly. |
| Script execution fails mid-rollback            | Induce a failure in the rollback script itself              | Operator is alerted via transaction log; manual recovery required; the alert is first-class, not silently logged |
| Timer window expires before transaction done   | Long-running apply exceeds the 120s default                 | Timer extends automatically via a keep-alive signal from the engine every 30s, or aborts if the keep-alive cannot reach the host |
| Network partition during the timer window      | Sever the SSH connection mid-transaction                    | Timer fires as scheduled; rollback runs out of band; engine detects the severed connection and reconnects post-window to read the result |
| Host reboots during the timer window           | Reboot triggered mid-transaction                            | Timer does not survive reboot (by design — the rollback script is transient). On reconnect, engine reads pre-state from the persisted transaction log and offers manual rollback via `kensa rollback --start N` |
| Deadman script cleanup fails                   | `rm -f "$0"` at end of script fails                         | Engine post-cancel scan detects residual `/tmp/kensa-rollback-*.sh` files and reports them; does not block the transaction but surfaces for operator cleanup |

These tests are part of `cmd/kensa-fuzz`'s scenario matrix from week 7 onward. The
edge-case matrix is a living document — any new failure mode discovered in production
becomes a fuzz scenario that prevents regression (the Moat 7 compounding-experience
pattern from `HANALYX_MISSION_AND_ROADMAP.md`).

**Residual risk acknowledgement.** The "apply runs, validate passes, cancel fails"
case is the one edge condition where the deadman timer produces a worse outcome than
not having it — a successful change is reversed because the cancel signal did not
reach the host in time. The timer window is tuned to make this unlikely (120s is long
enough that cancel latency under normal conditions is negligible), but it is not
impossible. This residual risk is documented in `TRANSACTION_CONTRACT_V1.md` §2.2 and
is a known limitation, not a bug. The alternative — no deadman timer — is worse in
expectation because it leaves the more common "connection died mid-apply" case
without recovery.

---

## 7. Rules, Specs, and Fixtures

### 7.1 Shared Across Python and Go

During the coexistence period, `rules/`, `mappings/`, `specs/`, and `fixtures/` are
shared between the Python and Go codebases. The preferred mechanism is a git submodule
or subtree that both repositories pull from, ensuring the two implementations cannot
drift.

When the Go implementation reaches parity, the shared directories move into the Go
repository as the canonical location, and the Python repository either pulls from Go
as a submodule or is archived.

### 7.2 Rule Parsing

`internal/rule/parser.go` parses V1 rule YAML into Go structs. Parsing enforces the
schema validation rules from `CANONICAL_RULE_SCHEMA_V1.md` §6.2:

- ID uniqueness
- File naming (filename matches `id`)
- Category consistency
- Exactly one `default: true` implementation
- Capability references exist
- Dependency references exist
- No orphan capabilities
- **Atomicity consistency**: `transactional: true` rules may not contain non-capturable
  mechanisms (this is the V1 addition, enforced at parse time)

The parser is strict — any violation is a parse error, not a warning. The build fails
on a schema violation.

### 7.3 Capability Detection

`internal/detect` runs the capability probe set from `CANONICAL_RULE_SCHEMA_V1.md` §4
against a target host. Each probe is a Go function returning `(bool, error)` based on
a single command or file check. The full probe suite runs in under 2 seconds against a
real RHEL host.

Detection results are cached per-host for the duration of a run. The cache is keyed by
`hostID` and expires at the end of the run.

### 7.4 Implementation Selection

`internal/rule/selector.go` takes a `Rule` and a `CapabilitySet` and returns the
matching `Implementation`. The selector evaluates `when` gates top-to-bottom; the
first match wins; `default: true` is the fallback.

The selector is pure: same rule + same capability set = same implementation, every
time. This is important for reproducibility — a transaction that runs twice selects
the same implementation and produces the same result.

### 7.5 Effective-vs-Static Check Validator

`RULE_REVIEW_GUIDE_V1.md` §3.1 names "effective vs. static configuration" as the
single most important review criterion. A check that reads `/etc/ssh/sshd_config`
when the system supports `sshd_config.d/` drop-ins is a defect — it produces false
positives and false negatives. V0 trusted the review process to catch this. V1 is
more ambitious: we ship tooling that catches it automatically.

`cmd/kensa-validate` includes an effective-vs-static linter that flags likely
defects:

| Pattern                                                                    | Warning                                                                                   |
|----------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| Check reads `/etc/ssh/sshd_config` via `config_value` without a `when: sshd_config_d` capability gate or a `sshd -T` companion | Likely false positive/negative when drop-ins are used                                     |
| Check reads `/etc/sysctl.conf` directly without `sysctl_value`             | Runtime state may diverge from file                                                       |
| Check reads `/etc/pam.d/*` directly without `authselect current` companion | authselect may override; check may be stale                                               |
| Check reads `/etc/fstab` without `findmnt` companion                       | Effective mount options may differ from fstab                                             |
| Check reads `/etc/selinux/config` without `getenforce` companion           | Runtime state may differ from config                                                      |

The linter is advisory (warnings, not errors) because there are legitimate cases
where the static file is the correct thing to check (e.g., `login.defs` has no
override mechanism). Warnings appear in `kensa-validate` output and in PR CI
comments, and each warning must be either fixed or explicitly suppressed with a
rule-level `# kensa-validate: allow-static-check` annotation plus a justification.

This catches the most common check-accuracy defect at parse/validation time rather
than relying on the human reviewer to notice it case by case — which is where the
V0 rule-review passes found ~40% of the 500+ defects they caught.

---

## 8. Evidence, Storage, and Audit Trail

### 8.1 SQLite Transaction Log

`internal/store/sqlite.go` persists every transaction to a SQLite database at
`.kensa/results.db` (default) or a path configured by the operator. The schema:

```sql
CREATE TABLE transactions (
    id             TEXT PRIMARY KEY,
    rule_id        TEXT NOT NULL,
    host_id        TEXT NOT NULL,
    status         TEXT NOT NULL,  -- committed | rolled_back | partially_applied | errored
    transactional  INTEGER NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT NOT NULL,
    evidence_json  TEXT NOT NULL,
    evidence_sig   BLOB NOT NULL
);

CREATE TABLE steps (
    transaction_id TEXT NOT NULL REFERENCES transactions(id),
    step_index     INTEGER NOT NULL,
    mechanism      TEXT NOT NULL,
    capturable     INTEGER NOT NULL,
    status         TEXT NOT NULL,  -- pending | succeeded | failed | skipped | rolled_back
    detail         TEXT,
    PRIMARY KEY (transaction_id, step_index)
);

CREATE TABLE pre_states (
    transaction_id TEXT NOT NULL REFERENCES transactions(id),
    step_index     INTEGER NOT NULL,
    state_json     TEXT NOT NULL,
    captured_at    TEXT NOT NULL,
    PRIMARY KEY (transaction_id, step_index)
);

CREATE TABLE rollback_events (
    transaction_id TEXT NOT NULL REFERENCES transactions(id),
    step_index     INTEGER NOT NULL,
    source         TEXT NOT NULL,  -- inline | deadman | manual
    executed_at    TEXT NOT NULL,
    status         TEXT NOT NULL,
    detail         TEXT
);
```

Writes are synchronous. The database file is the canonical record of what happened;
everything else (stdout, JSON export, PDF reports) is derived from it.

### 8.2 Evidence Envelope

`internal/evidence/envelope.go` constructs a signed evidence envelope for every
transaction. The envelope contains everything listed in `TRANSACTION_CONTRACT_V1.md`
§1.2: timestamp, host context, pre-state, change, validation results, commit/rollback
decision, post-state, framework mappings.

The envelope is signed with Ed25519 using a key managed per deployment. The signing
key is never transmitted over the wire; it lives on the operator's workstation or
(eventually) in a hardware token.

### 8.3 OSCAL Export

`internal/evidence/oscal.go` exports envelopes in OSCAL Assessment Results format for
federal submissions. This is the artifact federal auditors expect and the concrete
output that justifies the Auditor Relationships moat investment in
`HANALYX_MISSION_AND_ROADMAP.md` §Moat 2.

---

## 9. The Public API

### 9.1 API Package

`api/` is the public contract. Semver applies. Breaking changes require a major version
bump.

```go
// package api

// Kensa is the top-level entry point for programmatic consumers.
// OpenWatch imports this type; the CLI wraps it.
//
// The API surface is organized around three identities that map to OpenWatch's
// Eye (historical view), Heartbeat (continuous awareness), and Control Plane
// (preview-then-execute) per OPENWATCH_VISION.md.
type Kensa struct {
    // ... unexported fields
}

func New(cfg Config) (*Kensa, error)

// ─── Execution (all three identities consume this; CLI is the primary caller) ───

// Transact runs a single transaction end-to-end.
func (k *Kensa) Transact(ctx context.Context, host HostConfig, txn *Transaction) (*TransactionResult, error)

// Scan runs read-only checks against a host for the specified rules.
func (k *Kensa) Scan(ctx context.Context, host HostConfig, rules []*Rule) (*ScanResult, error)

// Remediate runs transactions for every failing rule in the scan.
func (k *Kensa) Remediate(ctx context.Context, host HostConfig, rules []*Rule) (*RemediationResult, error)

// Rollback executes rollback for a past transaction by ID.
func (k *Kensa) Rollback(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error)

// ─── Control Plane: preview-then-execute (OpenWatch approval workflow) ───

// Plan produces a full transaction plan without executing it. The returned Plan
// includes captured pre-state, the apply steps that would run, the validators that
// would check, and the rollback steps that would reverse applied changes on failure.
// The plan is a commitment — Execute(plan) validates that host state has not drifted
// since planning, and fails with PlanStaleError if it has.
func (k *Kensa) Plan(ctx context.Context, host HostConfig, rule *Rule) (*Plan, error)

// Execute runs a previously-produced Plan. This is the "user approved the preview,
// now run it" entry point for OpenWatch's Control Plane workflows.
func (k *Kensa) Execute(ctx context.Context, host HostConfig, plan *Plan) (*TransactionResult, error)

// ─── Heartbeat: event subscription (OpenWatch real-time views) ───

// Subscribe returns a channel of events matching the filter. Events include
// transaction lifecycle (started, phase-completed, committed, rolled-back), drift
// detection, and fleet heartbeat pulses. The channel closes when ctx is done.
func (k *Kensa) Subscribe(ctx context.Context, filter EventFilter) (<-chan Event, error)

// ─── Eye: historical query (OpenWatch transaction log UI + evidence export) ───

// TransactionLog returns a query interface over the persisted transaction log.
// This is the foundation of OpenWatch's Eye identity: every transaction Kensa has
// ever executed is queryable here, with pre-state, apply detail, validation
// results, commit/rollback decision, and signed evidence envelope.
func (k *Kensa) TransactionLog() LogQuery

// VerifyEnvelope checks the Ed25519 signature of an evidence envelope against the
// deployment's registered keys (and key history for rotations). Used by audit UIs
// and any consumer that needs to display envelope authenticity.
func (k *Kensa) VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error)

// ─── Deadman control (OpenWatch operator UI for armed timers) ───

// CancelDeadman executes an in-band clean rollback and cancels the scheduled
// deadman script for a transaction. Preferred over waiting for the timer to fire.
func (k *Kensa) CancelDeadman(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error)

// DeadmanStatus returns the armed state of a transaction's deadman timer.
func (k *Kensa) DeadmanStatus(ctx context.Context, host HostConfig, txnID uuid.UUID) (*DeadmanState, error)
```

**API versioning commitment.** All methods above are v1 from commit 1. Implementations
may be stubbed (returning `ErrNotYetImplemented`) during early milestones — see §11
for the rollout — but the signatures are frozen. OpenWatch can write against them
immediately and see `ErrNotYetImplemented` until the feature lands, rather than
discovering a breaking API change mid-integration.

### 9.2 API Versioning

- v1.0.0 is the first stable release. Breaking changes require v2.
- Additions to the API (new methods, new optional fields on existing types) are
  non-breaking and can be made freely within v1.
- Deprecations are marked with `// Deprecated:` and retained for at least one minor
  version before removal in v2.

### 9.3 OpenWatch Integration

OpenWatch imports `github.com/Hanalyx/kensa/api` and constructs a `Kensa` instance per
fleet. OpenWatch's transaction log UI is a view over `Kensa.TransactionLog()`.
OpenWatch's Control Plane API translates user intents into `Transaction` structs and
submits them via `Kensa.Transact()`.

This is the realization of "Kensa is the transaction; OpenWatch is the fleet that runs
on it" from `OPENWATCH_VISION.md`. The Go package import eliminates the subprocess +
JSON marshal boundary that the Python/Python split required.

---

## 10. Testing & Verification

### 10.1 Test Layers

1. **Unit tests** — standard Go tests for individual functions. Run on every commit.
   Fast (< 30 seconds for the whole suite).

2. **Spec-derived tests** — consume fixture files, run the handler, compare output to
   expected. Run on every commit. Exists for every handler, check, and engine phase.

3. **Integration tests** — spin up RHEL 8/9/10 containers (via the existing E2E
   container infrastructure from the Python codebase, reused), run the handler against
   a real system, verify results. Run on every PR merge. Moderate speed (5-10 minutes
   per RHEL version).

4. **Fuzz / failure-injection tests** — `cmd/kensa-fuzz` runs every capturable handler
   through an induced-failure matrix: capture succeeds + apply fails, capture succeeds
   + validate fails, apply succeeds + rollback fails. Verifies the engine lands in the
   correct terminal state for each induced failure. Run nightly against the RHEL
   matrix.

5. **Parity tests** — scripts that run the same fixture through the Python and Go
   implementations and compare outputs byte-for-byte. Run on every commit during the
   coexistence period. When Go and Python diverge, the spec arbitrates and one side
   (usually the newer implementation) is fixed.

### 10.2 CI Matrix

```
Matrix:
  os: [rhel8, rhel9, rhel10]
  transport: [ssh-system, ssh-crypto-fallback]
  fips: [enabled, disabled]

Jobs:
  - unit: go test ./... (30s)
  - lint: golangci-lint (2m)
  - spec-traceability: go run ./scripts/spec_traceability.go (1m)
  - integration: per-OS real-host tests (10m each)
  - fuzz: kensa-fuzz against full handler matrix (30m, nightly)
  - parity: Python ↔ Go comparison against fixture suite (20m)
```

Required status checks on `main`: unit, lint, spec-traceability, integration (all three
RHEL versions), parity.

### 10.3 The Atomicity Test Suite

A dedicated test suite proves the atomicity commitment. For every capturable handler,
for every representative parameter combination:

```go
func TestAtomicity_ConfigSet(t *testing.T) {
    for _, tc := range fixtures.LoadAll("handlers/configset") {
        t.Run(tc.Name, func(t *testing.T) {
            host := realHost(t, "rhel9")
            preState := captureHostFingerprint(t, host)

            // Induce failure at APPLY phase
            err := runTransactionWithForcedFailure(t, host, tc, "apply")
            require.Error(t, err)

            // Verify the host is in the exact pre-state
            postState := captureHostFingerprint(t, host)
            require.Equal(t, preState, postState, "rollback did not restore pre-state")
        })
    }
}
```

The `captureHostFingerprint` function records every piece of state the handler could
have touched (files, permissions, services, packages). If the fingerprint before and
after the forced failure matches, atomicity is proven for that fixture. Any mismatch
is a bug.

This is what makes the commitment in `TRANSACTION_CONTRACT_V1.md` §5 ("Verifying the
commitment") concrete. Customers can run the atomicity test suite themselves against
their own environments.

---

## 11. The Build Sequence

### 11.1 Weeks 1-4: Foundation

**Goal:** Repository scaffold, handler interface, transaction engine skeleton, full
`api/` surface defined (with stubs for deferred methods).

- [ ] Week 1: Repository initialization. `go.mod`, layout from §2, CI pipelines,
      full `api/` package with every interface signature from §3 and §9 — including
      `Plan`, `Execute`, `Subscribe`, `TransactionLog`. Deferred methods return
      `ErrNotYetImplemented`. OpenWatch can begin writing against the API now.
- [ ] Week 2: Transaction engine skeleton (`internal/engine`). Implements the Run loop
      with stub handlers. Engine internals are structured to expose phase-transition
      hooks (which `Subscribe` will consume later) and a plan-without-execute mode
      (which `Plan` will consume later), even though the methods return stubs.
- [ ] Week 3: SQLite transaction log (`internal/store`). Schema, migrations, synchronous
      write discipline, retention policy scaffolding. The store includes the index
      shape that `LogQuery.Query` and `Aggregate` will need — defined from the
      schema, not retrofitted.
- [ ] Week 4: SSH transport (`internal/transport/ssh`) with ControlMaster. Integration
      tests against a real RHEL 9 host. At the end of this week, we can open a
      connection, run `echo hello`, and close the connection, and the transaction log
      records the attempt.

**Milestone M1:** An engine that can run a trivial no-op transaction against a real
host and persist the result. Full `api/` surface compiled and importable by OpenWatch
(with stubs for features landing later). Foundation proven.

### 11.2 Weeks 5-8: First Handler + Failure Injection

**Goal:** `file_permissions` handler end-to-end with rollback. `kensa-fuzz` first
version.

- [ ] Week 5: `file_permissions` handler Apply. Spec and fixtures. Go tests pass.
- [ ] Week 6: `file_permissions` Capture + Rollback. Full vertical slice complete.
      Integration tests on RHEL 8, 9, 10.
- [ ] Week 7: `cmd/kensa-fuzz` first version. Induces apply failure; verifies rollback
      restores state. Atomicity test suite for `file_permissions` passes.
- [ ] Week 8: Review and polish. Failure-mode analysis in every PR for the handler and
      rollback. Two-human review of rollback handler mandatory.

**Milestone M2:** The atomicity commitment is verified for `file_permissions`.
Template established for every subsequent handler.

### 11.3 Weeks 9-14: Core Capturable Handlers

**Goal:** 10 capturable handlers end-to-end. Enough for the first complete rule.

Order (easiest → hardest, to maximize learning early):
- Week 9: `file_content`, `file_absent`
- Week 10: `sysctl_set`
- Week 11: `service_enabled`, `service_disabled`, `service_masked`
- Week 12: `config_set`, `config_set_dropin`
- Week 13: `package_present`, `package_absent`
- Week 14: Integration + polish week. Full atomicity test suite for all 10 handlers.

**Milestone M3:** 10 handlers. Atomicity verified for each. The engine can execute any
rule whose remediation uses only these mechanisms.

### 11.4 Weeks 15-20: Control-Channel Handlers + Deadman Timer

**Goal:** Handlers for SSH, PAM, firewall, network — the control-channel-sensitive set
— with the deadman timer path.

- [ ] Week 15-16: Deadman timer implementation (`internal/deadman`). Script generation,
      `at` scheduler, `systemd-run` scheduler. Integration tests that deliberately
      break the control channel and verify the deadman path restores state.
- [ ] Week 17: `sshd_config` via `config_set_dropin` (already exists) + deadman path
      integration. First control-channel-sensitive rule works end-to-end.
- [ ] Week 18: `pam_module_configure` (the authselect handler). Complex capture because
      authselect profile state has to be recorded.
- [ ] Week 19: Remaining network/firewall handlers.
- [ ] Week 20: Integration. An operator can now run a full SSH hardening rule against
      a production host with atomicity + deadman safety.

**Milestone M4:** Control-channel-sensitive rules are safe. The atomicity commitment
is honorable for the majority of the rule set.

### 11.5 Weeks 21-26: Rules, Mappings, CLI

**Goal:** CLI parity with Python Kensa for a meaningful rule subset. Rule and mapping
parsing complete.

- [ ] Week 21: Rule parser, schema validation (including the V1 atomicity consistency
      check), capability selector. `cmd/kensa-validate` with the effective-vs-static
      linter from §7.5.
- [ ] Week 22: Framework mapping loader. All V0-format mappings load correctly.
      **`LogQuery` implementation lands** — `Query`, `Get`, `Aggregate` become real.
      OpenWatch's transaction log UI becomes viable against a real Kensa backend.
- [ ] Week 23: `cmd/kensa` CLI. Commands: `detect`, `check`, `remediate`, `rollback`,
      `history`, `coverage`.
- [ ] Week 24: **`Plan` and `Execute` implementations land** — the Control Plane
      preview/approve/execute workflow becomes viable. OpenWatch can render a
      preview and execute approved plans.
- [ ] Week 25: Evidence envelope + OSCAL export + Ed25519 signing.
      **`Subscribe` / event stream implementation lands** — OpenWatch's Heartbeat
      real-time view becomes viable.
- [ ] Week 26: Polish + first end-to-end parity test vs Python Kensa on a real
      customer-representative rule set (50 rules, SSH + sysctl + file permissions +
      services). First OpenWatch integration test using the full API surface
      (Plan → Subscribe → Execute → Query).

**Milestone M5:** A customer could run `kensa remediate` against a production host for
50 core rules and get the same result as the Python version, with atomic per-rule
transactions. OpenWatch's three identities (Eye, Heartbeat, Control Plane) are all
backed by real Kensa APIs — no more stubs for the methods that matter to OpenWatch.

### 11.6 Weeks 27-32: Remaining Handlers + OpenWatch API

**Goal:** Full handler coverage. OpenWatch can import Kensa as a Go package.

- [ ] Week 27-28: Remaining capturable handlers: `mount_option_set`,
      `kernel_module_disable`, `audit_rule_set`, `selinux_boolean_set`, `cron_job`.
- [ ] Week 29: Non-capturable handlers: `command_exec`, `manual`, `grub_parameter_*`.
      These are trivial to implement (they just execute commands) but important to
      ship because they are explicitly `transactional: false` and the engine handles
      them correctly.
- [ ] Week 30-31: `api/` package refinement. OpenWatch team reviews the surface.
      v1.0.0-rc1 tagged.
- [ ] Week 32: OpenWatch integration. First scan via `Kensa.Scan()` from OpenWatch.

**Milestone M6:** Handler parity with Python Kensa. OpenWatch can import Kensa as a Go
package. The `TECHNICAL_REMEDIATION_MP_V1` +
`CANONICAL_RULE_SCHEMA_V1` contract is fully implemented.

### 11.7 Weeks 33-40: Production Hardening

**Goal:** Ready to take over from Python Kensa for federal customers.

- [ ] Week 33-34: Rule import. Every rule in `rules/` passes Go validation. Any rule
      that fails is either fixed in rule YAML or is an indication of a Go bug.
- [ ] Week 35-36: Parity test sweep. Every rule in the corpus runs under both Python
      and Go; output is compared; divergences are investigated and fixed.
- [ ] Week 37: First customer deployment. Single lighthouse customer, one fleet,
      shadow mode (Go version runs alongside Python, outputs compared, Python is
      authoritative).
- [ ] Week 38-39: Issue triage from shadow mode. Fix discrepancies.
- [ ] Week 40: Cutover. First customer uses Go Kensa as authoritative. Python moves to
      maintenance.

**Milestone M7 (release):** Kensa Go v1.0.0. Production-ready. Python is reference.

### 11.8 After v1.0.0

- Ubuntu LTS expansion (leveraging the `family` field in platforms already supported
  by the rule schema).
- SUSE expansion.
- Additional framework mappings.
- Extended AI-agent API surface (write-enabled agent API per `OPENWATCH_VISION.md` §Q6).
- FedRAMP authorization documentation leveraging the signed evidence format.

---

## 12. Migration from Python Kensa

### 12.1 Coexistence Architecture

During weeks 5-40, both codebases exist. Coordination:

- **Shared directories** (`rules/`, `mappings/`, `specs/`, `fixtures/`, `schema/`) live
  in a separate git repository (`Hanalyx/kensa-spec`) and are pulled into both
  codebases as a submodule.
- **Rule changes** (new rules, mapping updates, Kensa Labs advisories) go to
  `kensa-spec` first. Both codebases pick them up on the next submodule update.
- **Spec changes** (new acceptance criteria, new fixtures) also go to `kensa-spec`.
  Both codebases' tests consume the updated fixtures.
- **Language-specific code** (Go engine, Python engine) evolves independently in its
  own repository.

### 12.2 Port Mechanics for Each Handler

When a Python handler is ported to Go:

1. Read the handler's spec in `kensa-spec/specs/handlers/<name>.spec.yaml`. Verify
   acceptance criteria are complete.
2. Implement the Go handler against the spec.
3. Run the Go handler's tests against the shared fixtures. If any fixture fails, either
   the Go implementation is wrong OR the Python implementation was wrong and the spec
   arbitrates — fix whichever is incorrect.
4. Run the parity test suite against a real RHEL host. Compare byte-for-byte output
   from Python and Go. Any divergence is a bug in one of them.
5. Write the human-authored failure-mode analysis for the PR.
6. Two-human review for rollback handler portions.
7. Merge.

The spec framework is what makes this mechanical. Without it, every handler port would
be a reverse-engineering exercise. With it, the port is "write a Go implementation that
satisfies the same contract the Python implementation satisfies."

### 12.3 Python Codebase Disposition

- **Weeks 1-32:** Python continues shipping customer features on the 18-month roadmap.
- **Weeks 33-40:** Python enters feature freeze. Only bug fixes and security patches.
- **Week 40+:** Python is the reference implementation. New features go to Go only.
- **Month 18+ (post-v1.0.0 + 6 months):** Python is archived. Its git history is
  preserved as historical reference and as an audit artifact.

---

## 13. Connection to Hanalyx Trust Moats

This plan directly supports each of the seven moats in
`HANALYX_MISSION_AND_ROADMAP.md`:

**Moat 1 (Track Record):** The signed transaction log is the customer-months-of-
production-use evidence. Every committed transaction and every successful rollback
accumulates into the "20+ customer-months, zero Kensa-caused incidents" claim.

**Moat 2 (Auditor Relationships):** OSCAL export from `internal/evidence/oscal.go` is
the concrete artifact auditors review. Going to federal auditors with a signed OSCAL
Assessment Result beats going with a PDF every time.

**Moat 3 (FedRAMP Authorization):** The signed transaction log + OSCAL export + the
atomicity commitment map directly to NIST 800-53 Rev 5 controls CM-3 (Configuration
Change Control), CM-5 (Access Restrictions for Change), SI-10 (Information Input
Validation), and CP-10 (System Recovery). Every one of these controls is easier to
document for a tool that produces signed evidence of every change.

**Moat 4 (Community):** The Go single-binary `go install github.com/Hanalyx/kensa/cmd/kensa`
path opens the project to Go developers who would never `pip install` a Python tool.
The public `api/` package makes Kensa embeddable in other tools. Community contribution
is easier with Go's tooling and the explicit spec framework.

**Moat 5 (Liability):** The atomicity commitment in `TRANSACTION_CONTRACT_V1.md` is
the product property E&O insurance covers. The signed evidence is the audit artifact
indemnification clauses reference.

**Moat 6 (Canonical Upstream):** Kensa Go as a single-binary category reference
implementation is what "the real one" looks like in a world of AI-generated
knockoffs.

**Moat 7 (Long-Tail Production Experience):** Every fuzz-test scenario discovered
during the build, every real-host integration failure fixed, every failure mode
documented in a PR analysis — these are the long-tail experience that compounds over
time and cannot be fabricated by AI.

The Go rewrite is not a detour from the moat strategy. Done correctly, it is an
accelerator for every moat simultaneously.

---

## 13A. Multi-Fleet Transaction Log Policy

Kensa's transaction log is stored in SQLite at one file per operator workstation or
per scheduled-scan runtime (§8.1). For single-operator, single-deployment use this
is perfect — one authoritative file, low-latency queries, simple backup.

Cross-fleet / multi-operator deployments create a question: if 10 operators each
run Kensa against overlapping fleets, OpenWatch needs to aggregate across 10
SQLite files. There are two honest architectures:

### 13A.1 Federated (v1.0.0)

OpenWatch holds credentials (or SSH access) to read the N SQLite files and
aggregates client-side. This works for small deployments (<10 operators) and
imposes no additional requirement on Kensa beyond what §8 already specifies.

OpenWatch's existing PostgreSQL `transactions` table (framed per the coordination
memo as a "multi-host aggregation cache") serves this role during v1.0.0.
Cross-fleet queries hit the cache; the cache is populated by OpenWatch reading
Kensa's SQLite files.

### 13A.2 Push-to-Collector (v1.1.0+)

Post-v1.0.0, Kensa gains an optional mode: every committed transaction is
replicated to a central collector (OpenWatch's PostgreSQL or a dedicated
Kensa-run collector). SQLite remains the authoritative per-deployment store —
the collector is an append-only replica. OpenWatch queries the collector for
multi-fleet aggregation without reading SQLite files directly.

The push mode does not change Kensa's source-of-truth story — per-deployment
SQLite is still canonical. It adds a replication target, gated behind an
explicit opt-in in Kensa's configuration.

### 13A.3 Why This Sequencing

v1.0.0 ships federated because it's achievable without new Kensa architecture
and unblocks OpenWatch's cross-fleet aggregation immediately. The push mode
lands in v1.1.0 when real-world scaling shows that client-side federation is
hitting its limits (typically at 20-50 operator workstations per deployment).

OpenWatch's PostgreSQL `transactions` table **survives v1.0.0** as the
multi-fleet aggregation cache. It does not retire until Kensa ships the
push-to-collector mode — which is a v1.1.0+ decision, not a Day-1 commitment.

---

## 14. What Day 1 Is Not

Explicit non-goals, to prevent scope creep:

- **Not a parallel product.** Kensa Go replaces Kensa Python. It is not a separate
  product line.
- **Not a vehicle for feature additions beyond V1.** New features (Ubuntu support,
  SUSE support, additional frameworks, drift detection, advanced agent APIs) come
  after v1.0.0. Day 1 is parity + atomicity.
- **Not a chance to redesign the rule YAML.** `CANONICAL_RULE_SCHEMA_V1.md` is the
  contract. Rules don't change for the port.
- **Not a chance to redesign framework mappings.** Mappings are language-agnostic and
  ship as-is.
- **Not a chance to introduce a new category name.** "Transactional configuration
  management for Linux" is the category. The Go implementation is a new substrate for
  the same category.
- **Not a research project.** Every handler is a straightforward implementation
  against a known spec. If a handler turns out to need research (e.g., pam_module
  edge cases), the research goes into the spec first, then the implementation.

---

## 15. The First PR

To make this plan concrete, the first PR should contain:

1. `go.mod` initialized to Go 1.22+.
2. Repository layout from §2 (empty directories with `.keep` files).
3. `api/handler.go` — `Handler`, `CaptureHandler`, `RollbackHandler`, `CombinedHandler`
   interfaces, fully commented.
4. `api/transport.go` — `Transport` interface, `CommandResult` type.
5. `api/transaction.go` — `Transaction`, `TransactionResult`, `Step`, `StepResult`,
   `PreState`, `RollbackResult` types.
6. **`api/log_query.go`** — `LogQuery` interface with `Query`, `Get`, `Aggregate`;
   `LogFilter` (with `Phases`, `Severities` fields), `FrameworkRef` (structured),
   `Page`, `QueryResult`, `TransactionRecord`, `AggregateResult`, `AggregateKey`
   constants (5 enumerated values), `TimeBucket` constants, `GetOption` and
   `AggregateOption` functional options. The Eye contract, frozen at commit 1.
7. **`api/events.go`** — `EventPublisher`, `EventSubscriber` interfaces; `Event`,
   `EventKind` constants (8 kinds), `EventFilter` (with `HeartbeatInterval`). The
   Heartbeat contract, frozen at commit 1.
8. **`api/planner.go`** — `Planner`, `Executor` interfaces; `Plan` (with
   `Preview(format)` method), `PreviewFormat` constants, `StepPreview`,
   `ValidatorPreview`, `RollbackStepPreview`, `PlanStaleError` (with
   `StaleStepIndex`, `Mechanism`, `Field`, `Expected`, `Actual`). The Control
   Plane contract, frozen at commit 1.
9. **`api/envelope_verifier.go`** — `EnvelopeVerifier` interface, `VerifyResult`
   type. Enables OpenWatch to verify evidence envelopes without duplicating trust
   logic.
10. **`api/deadman.go`** — `DeadmanControl` interface, `DeadmanState` type,
    `ErrNoActiveDeadman`. Enables OpenWatch's armed-timer UI.
11. `api/kensa.go` — the top-level `Kensa` type with every method from §9,
    implementations returning `ErrNotYetImplemented` where the underlying feature
    has not landed. The method set is the public contract; stubs are acceptable,
    missing signatures are not.
12. `api/errors.go` — typed errors including `ErrNotYetImplemented`,
    `PlanStaleError`, `ErrSchedulerUnavailable`, `ErrCaptureIncomplete`,
    `ErrHostBusy`, `ErrNoActiveDeadman`.
13. `api/concurrency.go` — `Option` functional-options infrastructure including
    `WithNonBlocking()`. Documents the per-host serialization guarantee.
14. `api/doc.go` — package documentation, versioning policy statement, explicit
    statement that v1 signatures are frozen and stubs will be filled over the build
    sequence in §11.
15. `internal/engine/engine.go` — `Engine` struct with a stubbed `Run` method that
    returns `ErrNotYetImplemented`.
16. `Makefile` with `build`, `test`, `lint` targets.
17. `.github/workflows/ci.yml` with `unit` and `lint` jobs.
18. This document (`docs/KENSA_GO_DAY1_PLAN.md`) and the V1 docs copied or submodule-
    linked.
19. A `CONTRIBUTING.md` that states the failure-mode analysis commitment, the
    rollback-handler two-human review requirement, and the per-rule capture
    sufficiency review requirement from §5.5.
20. The PR description itself contains the failure-mode analysis for this PR (even
    though it's foundational scaffolding, the discipline starts at commit 1).

This PR is reviewable in a single sitting, establishes every convention this plan
names, **freezes the full OpenWatch-facing API surface**, and produces a buildable
(if not useful) repository. Everything from week 2 onward builds on this foundation —
and OpenWatch can begin writing against the API surface immediately, even though
many methods return `ErrNotYetImplemented` until their milestone lands.

---

## The One-Paragraph Version

**Kensa Go is a single static binary that implements transactional configuration
management for Linux. Day 1 builds the transaction engine first, the handler model
second, and the rules/CLI third. System OpenSSH is the transport. The deadman timer
is core infrastructure with explicit edge-case testing. Specs and fixtures are
language-neutral and shared with the Python reference implementation for validation
during the coexistence period. Every capturable handler ships with integration-tested
capture and rollback. Every rule ships with a human-authored capture sufficiency
analysis. Every engine PR carries a human-authored failure-mode analysis. The full
OpenWatch-facing API surface — the Eye (`LogQuery`), the Heartbeat (`Subscribe`), and
the Control Plane (`Plan`/`Execute`) — is frozen in `api/` at commit 1 with stubbed
implementations that fill in across the build sequence, so OpenWatch can begin
integration immediately rather than waiting until week 28. The atomicity commitment
from `TRANSACTION_CONTRACT_V1.md` is verified by a dedicated failure-injection test
suite that customers can run themselves. v1.0.0 lands at week 40, when Go passes
parity with Python across the full rule corpus and the first customer cutover is
complete. Everything in this plan is in service of one goal: the foundation is firm
enough that the next five years of features, platforms, and AI-agent integration are
additive work on top of it, not refactors of it.**

---

*This document is the architectural contract for Kensa Go. Every major decision —
language choice, SSH transport, deadman timer, spec framework, handler interface, API
package — is justified against the V1 philosophy docs and the Hanalyx strategic
direction. Deviations from this plan require explicit founder approval and an update
to this document before code is written.*
