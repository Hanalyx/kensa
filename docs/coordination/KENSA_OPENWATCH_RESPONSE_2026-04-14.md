# Response to Coordination Memo: OpenWatch ↔ Kensa Go Day-1

**From:** Kensa team
**To:** OpenWatch team
**Date:** 2026-04-14
**Subject:** Response to `KENSA_OPENWATCH_COORDINATION_2026-04-14.md`; confirmation, interface decisions, and Week-1 commitments
**Status:** Draft for final review before sending

---

## 1. Summary

Memo received, reviewed, and accepted substantively. All five duplication
resolutions in §3 of your memo are correct. The six interface-review asks in §5
have been incorporated into `KENSA_GO_DAY1_PLAN.md` §3.5 before Week-1 freeze.
The three open questions in §8 have decisions below.

The short version: **OpenWatch's "GitHub over Kensa's git" posture is the
correct framing, matches `OPENWATCH_VISION.md`, and Kensa's Day-1 plan is
updated to support it at the API layer.** OpenWatch can start coding against
`api/` signatures this week.

## 2. Confirmations on §3 resolutions

### 2.1 Transaction log query (§3.1)

**Accepted as written.** The POST `/api/transactions/query` endpoint URL stays
stable; its implementation delegates to `kensa.TransactionLog().Query()` once
Kensa Week 22 lands. Interim Postgres-cache-over-Python-Kensa is the right
bridge.

One small addition: when you annotate the spec as "interim," include the
specific `api/` method it will delegate to and the expected milestone week.
That gives future reviewers a grep-able connection between the OpenWatch
implementation and the Kensa convergence point.

### 2.2 Per-transaction Ed25519 signing (§3.2)

**Accepted.** The boundary you drew is correct:

| Layer | Who signs | What it attests |
|---|---|---|
| Per-transaction evidence envelope | Kensa | "This execution happened on this host at this time" |
| Aggregate audit export / quarterly report / State-of-Production | OpenWatch | "OpenWatch aggregated this data from N hosts and produced this artifact" |

Kensa `api/` exposes envelope verification so your audit UI can display
authenticity without reimplementing verification logic. See `EnvelopeVerifier`
and `Kensa.VerifyEnvelope()` in the updated `KENSA_GO_DAY1_PLAN.md` §3.5.4.

Your `Kensa.VerifyEnvelope(...)` call returns a `VerifyResult` including key
ID, warnings (e.g., "signed by rotated key"), and the envelope hash. OpenWatch's
audit UI can render an authenticity indicator from this without ever touching
the signature bytes.

### 2.3 Plan/Execute for remediation (§3.3)

**Accepted.** The revised architecture (Drift → `Kensa.Plan` → opaque blob
stored in `remediation_jobs.kensa_plan` → ApprovalQueue UI → `Kensa.Execute` →
`PlanStaleError` triggers re-plan) is the correct separation of concerns.
OpenWatch owns the workflow; Kensa owns the plan.

One addition in response to your §5.4 ask: **Kensa now ships a canonical
plan renderer.** `Plan.Preview(format PreviewFormat) (string, error)` where
`PreviewFormat` is one of `PreviewText`, `PreviewMarkdown`, `PreviewJSON`,
`PreviewPlain`. OpenWatch's ApprovalQueue UI calls `PreviewMarkdown` and
renders it; the Kensa CLI calls `PreviewText`; audit logs embed
`PreviewPlain`. One canonical display, no drift between CLI and OpenWatch UI.

### 2.4 Event subscription for Heartbeat (§3.4)

**Accepted.** OpenWatch's long-lived consumer over `Kensa.Subscribe` is the
right design. Kensa owns the event stream; OpenWatch owns aggregation,
routing, channel dispatch, deduplication, rate-limiting at the
notification-channel layer.

See §4.3 below for the `HeartbeatInterval` change and drop-semantics
clarifications.

### 2.5 Transactions table as "canonical" (§3.5)

**Accepted with nuance on timing.** Your framing of the PostgreSQL
`transactions` table as a multi-host aggregation cache is correct. The
critical point: **the cache survives v1.0.0.** It does not retire on the
original "later phase" timeline.

See §5 below on the multi-fleet transaction log architecture. The short
version: v1.0.0 ships federated (OpenWatch reads N SQLite stores and
populates its cache); v1.1.0 adds an optional push-to-collector mode that
lets OpenWatch's cache become a read-through instead of a client-side
aggregator.

On the <500ms p95 question: this is achievable for a single Kensa deployment
(one SQLite, properly indexed) but not directly addressable for multi-fleet
queries without federation or push mode. We'll publish a benchmark result
against a realistic corpus (500K rows, 1000 hosts per Kensa deployment)
within the first 4 weeks so you can plan your cache-retention strategy
against hard numbers.

## 3. Resolutions to §5 interface review requests

All six asks have been incorporated into `KENSA_GO_DAY1_PLAN.md` §3.5. Specific
decisions:

### 3.1 LogFilter additions (§5.1)

| Your ask | Decision |
|---|---|
| `Phase []Phase` field | **Added.** `Phases []Phase` with values `PhaseCapture`, `PhaseApply`, `PhaseValidate`, `PhaseCommit`, `PhaseRollback`. |
| `Severity []string` field | **Added.** `Severities []string` with `critical`/`high`/`medium`/`low`. Denormalized onto the transaction log at write time to avoid join-cost on aggregation queries. |
| `FrameworkRef` structured | **Added.** `type FrameworkRef struct { FrameworkID string; ControlID string }`. `FrameworkID` examples: `cis_rhel9_v2`, `stig_rhel9_v2r7`, `nist_800_53_r5`. `ControlID` is the benchmark's native identifier. |

### 3.2 AggregateKey enumeration (§5.2)

All five requested keys are defined as constants:

```go
const (
    AggregateByHost                     AggregateKey = "by_host"
    AggregateByRule                     AggregateKey = "by_rule"
    AggregateByFrameworkControl         AggregateKey = "by_framework_control"
    AggregateByHostThenFrameworkControl AggregateKey = "by_host_then_framework_control"
    AggregateByRuleThenStatusOverTime   AggregateKey = "by_rule_then_status_over_time"
)
```

For time-over-time aggregations, `Aggregate` takes an `AggregateOption`
`WithTimeBucket(HourBucket|DayBucket|WeekBucket)`. Callers must specify the
bucket explicitly; the engine does not infer from date range.

### 3.3 EventFilter additions (§5.3)

| Your ask | Decision |
|---|---|
| `DeadmanTimerFired` alone | **Already supported.** Passing `EventFilter.Kinds = []EventKind{DeadmanTimerFired}` returns exactly those events. Empty `Kinds` means "all kinds"; non-empty is exact match. |
| `HeartbeatPulse` rate-limit | **Added.** `EventFilter.HeartbeatInterval time.Duration` caps the per-host pulse delivery rate. Default 60s. Pulses are coalesced server-side, not dropped — the subscriber always receives at least one pulse per host per interval if the host is alive. |

Drop semantics for other event kinds: when the subscriber's channel buffer is
full, non-pulse events are dropped and counted. The returned channel is
wrapped; `DropStats()` on the wrapper exposes dropped counts per kind. This
prevents the Heartbeat from stalling the engine.

### 3.4 Plan preview and staleness (§5.4)

| Your ask | Decision |
|---|---|
| `Plan.Preview()` method | **Added.** See §2.3 above. Four formats: Text, Markdown, JSON, Plain. |
| `PlanStaleError` granularity | **Expanded.** Now includes `StaleStepIndex int`, `Mechanism string`, `Field string`, `Expected interface{}`, `Actual interface{}`, and a human-readable `Message`. Your UX can say "re-plan because step 2's config_set of PermitRootLogin found value 'prohibit-password' but the plan captured 'yes'." |

### 3.5 TransactionRecord content (§5.5)

**Decision: full envelope by default with opt-out.**

```go
// Default — full envelope included
record, err := log.Get(ctx, txnID)

// List view — skip envelope for performance
record, err := log.Get(ctx, txnID, WithoutEnvelope())

// Skip pre-state bundles too (rare)
record, err := log.Get(ctx, txnID, WithoutEnvelope(), WithoutPreStates())
```

Audit export requires the full envelope and uses the default. List views that
render only titles and timestamps can opt out.

### 3.6 Concurrency / rate limiting (§5.6)

**Decision: Kensa serializes per-host internally.**

Concurrent calls from multiple goroutines (or multiple OpenWatch workers sharing
a `*Kensa` instance) proceed in parallel across **different** hosts. Calls
against the **same** host block on a per-host mutex until the in-flight
transaction completes. OpenWatch's job queue does not need its own per-host
locks.

For non-blocking semantics:

```go
result, err := kensa.Transact(ctx, host, txn, WithNonBlocking())
if errors.Is(err, ErrHostBusy) {
    // Another worker has the host; requeue
}
```

## 4. Answers to §8 open questions

### 4.1 Agent API — OpenWatch vs Kensa direct

**Decision: Agents talk to OpenWatch, not Kensa directly.**

`OPENWATCH_VISION.md` §3 is explicit: "Humans approve; agents operate; OpenWatch
mediates." OpenWatch stands up the HTTP/gRPC agent surface that fronts
`Kensa.Plan` / `Kensa.Execute` with authorization, approval workflow, rate
limiting, and audit logging. Kensa's `api/` is the native Go interface —
importable by OpenWatch and by the CLI, but **not exposed directly over the
network** in v1.0.0.

This matches the git:GitHub pattern: developers use git CLI directly, but most
tool integrations (GitHub Actions, external CI systems, third-party apps) go
through the GitHub API, not through local git.

Consequence: Kensa v1.0.0 does not ship a network-exposed agent API. That
surface is OpenWatch's responsibility. The Agent API milestone in
`OPENWATCH_VISION.md` Q5-Q6 is correctly scoped to OpenWatch's repository.

### 4.2 Deadman-timer visibility

**Decision: OpenWatch UI renders prominent armed-state indicators.**

When Kensa emits `DeadmanTimerArmed` on the event stream, OpenWatch's UI
should show:

- A banner on the affected host/transaction view: "⚠ Deadman timer armed —
  rollback scheduled at <absolute time>"
- Countdown to fire time
- Summary of what the rollback script will do (rendered from
  `DeadmanState.RollbackPlan`)
- An operator action: "Cancel and rollback now" (calls
  `Kensa.CancelDeadman(ctx, host, txnID)` for a clean in-band rollback)

When `DeadmanTimerFired` emits, the host transitions to "rollback-in-progress"
state. Post-fire, the transaction log shows `status=rolled_back,
rollback_source=deadman`.

The Kensa `api/` has been extended to support this with `CancelDeadman()` and
`DeadmanStatus()` on the `Kensa` type. See `KENSA_GO_DAY1_PLAN.md` §3.5.5.

### 4.3 Multi-fleet transaction log

**Decision: v1.0.0 ships federated; v1.1.0 adds push-to-collector.**

#### v1.0.0 (federated)

- Each operator workstation / scheduled-scan runtime has one Kensa SQLite
  store (per §8.1 of the Day-1 plan).
- OpenWatch holds credentials (SSH or direct file access) to read N SQLite
  stores across operators.
- OpenWatch's PostgreSQL `transactions` table serves as the multi-host
  aggregation cache, populated by OpenWatch's scheduler reading each SQLite
  store.
- Cross-fleet queries hit the PostgreSQL cache, not N SQLite stores at query
  time.

#### v1.1.0+ (push-to-collector)

- Kensa gains an optional configuration to replicate committed transactions
  to a central collector (OpenWatch's PostgreSQL, or a dedicated Kensa-run
  collector).
- SQLite remains the authoritative per-deployment store; the collector is an
  append-only replica.
- OpenWatch queries the collector for multi-fleet aggregation.
- OpenWatch's PostgreSQL `transactions` table becomes a read-through of the
  collector instead of a client-side aggregator.

#### Why this sequencing

v1.0.0 federated is achievable without new Kensa architecture and unblocks
OpenWatch's cross-fleet aggregation immediately. Push mode arrives when
real-world scaling shows federation hitting limits (typically 20-50 operator
workstations per deployment).

**OpenWatch's PostgreSQL `transactions` table survives v1.0.0.** Do not plan to
retire it during the v1.0.0 build. It retires when Kensa ships push mode, which
is a v1.1.0+ decision.

`KENSA_GO_DAY1_PLAN.md` §13A now documents this explicitly.

## 5. Commitments and timeline

### 5.1 This week (Kensa side)

1. **`KENSA_GO_DAY1_PLAN.md` §3.5 updated** with all interface refinements from
   your §5 asks. Completed 2026-04-14. (The version you are citing in your
   memo is now outdated — review the refreshed §3.5 before OpenWatch's three
   inbound PRs land.)
2. **This response memo** distributed to OpenWatch for cross-check.
3. **Week-1 commit-1 stub artifacts prepared** — the `api/` package ships all
   interfaces at commit 1 with stubs returning `ErrNotYetImplemented`. See
   §15 of the refreshed Day-1 plan for the full file list (20 items).

### 5.2 Next 2 weeks

4. **Shared `kensa-spec` git repository created** (per `KENSA_GO_DAY1_PLAN.md`
   §12.1) containing `rules/`, `mappings/`, `specs/`, `fixtures/`. Both
   codebases pull via submodule. OpenWatch can consume immediately for the
   Kensa rule-reference UI.
5. **Benchmark result published** for `LogQuery.Aggregate` against a realistic
   corpus (500K rows, 1000 hosts, single Kensa deployment). This gives you
   hard numbers for the <500ms p95 target and informs your cache-retention
   strategy.
6. **Evidence envelope schema published** as a standalone spec in
   `kensa-spec/specs/evidence/envelope-v1.yaml`. OpenWatch's audit UI can
   render envelopes without reverse-engineering Go types.
7. **Standing weekly 30-minute Kensa↔OpenWatch sync** established. Async
   memos sufficed for this round; a live codebase integration surface over
   40 weeks requires cadenced coordination.

### 5.3 Milestone acknowledgments (unchanged)

| Kensa milestone | OpenWatch convergence |
|---|---|
| Week 1 — `api/` frozen with stubs | OpenWatch starts coding against signatures |
| Week 22 — `LogQuery` real | OpenWatch swaps `/api/transactions/query` to `Kensa.TransactionLog()` |
| Week 24 — `Plan`/`Execute` real | OpenWatch starts §6.2 proactive-remediation |
| Week 25 — `Subscribe` real | OpenWatch cuts Heartbeat from polling to event stream |
| Week 26 (M5) — all OpenWatch-facing APIs real | Full integration test: Plan→Subscribe→Execute→Query |
| Week 40 (M7) — Kensa Go v1.0.0 | OpenWatch is pure consumer; Python Kensa archived |

## 6. Counter-asks

Two things Kensa wants from OpenWatch in return:

### 6.1 Annotate every interim spec with its convergence milestone

Every OpenWatch spec or interim implementation that will delegate to a Kensa
`api/` method post-convergence should carry a frontmatter annotation:

```yaml
interim_implementation:
  delegates_to: kensa.TransactionLog().Query
  convergence_week: 22
  notes: |
    Current PostgreSQL-backed implementation is a cache over Python Kensa's
    SQLite output. Swaps to Kensa Go api/ at Week 22.
```

This makes drift visible in code review, lets us grep for "still using
interim implementation past convergence week" as a staleness check, and gives
future engineers a direct pointer between OpenWatch code and the Kensa API it
will consume.

### 6.2 Surface the three in-flight PRs (#397, #398, and the forthcoming Phase 6.2 scope PR)

Please share draft PRs for:

1. The signing narrowing PR ("docs: align signing scope to OpenWatch-originated
   artifacts only") so Kensa can confirm the boundary matches our read before
   it merges.
2. The transactions query reframing PR ("chore(transactions): reframe query API
   as interim over Kensa LogQuery") so the spec annotation matches the
   `api/` method it will converge with.
3. The Q1-Q3 plan rewrite PR for §6.2 and Phase 3 so Kensa can review the
   architecture before OpenWatch's Phase 6.3/6.4 implementations begin.

We review and return within 48 hours.

## 7. Decisions captured

For archive and future cross-reference:

| Decision | Location |
|---|---|
| All five §3 duplication resolutions accepted | §2 above |
| LogFilter gains Phases, Severities, structured FrameworkRef | `KENSA_GO_DAY1_PLAN.md` §3.5.1 |
| AggregateKey enumerates 5 values; TimeBucket enumerates 3 | `KENSA_GO_DAY1_PLAN.md` §3.5.1 |
| GetOption functional options on Get | `KENSA_GO_DAY1_PLAN.md` §3.5.1 |
| EventFilter gains HeartbeatInterval; drop semantics documented | `KENSA_GO_DAY1_PLAN.md` §3.5.2 |
| Plan gains Preview(format) method; PlanStaleError expanded | `KENSA_GO_DAY1_PLAN.md` §3.5.3 |
| EnvelopeVerifier / VerifyEnvelope added | `KENSA_GO_DAY1_PLAN.md` §3.5.4 |
| DeadmanControl / CancelDeadman added | `KENSA_GO_DAY1_PLAN.md` §3.5.5 |
| Per-host serialization guarantee; ErrHostBusy + WithNonBlocking | `KENSA_GO_DAY1_PLAN.md` §3.5.6 |
| Agents → OpenWatch, not Kensa direct, in v1.0.0 | §4.1 above; `KENSA_GO_DAY1_PLAN.md` §9 implicit |
| Deadman visibility: UI armed-state + Cancel action | §4.2 above |
| Multi-fleet: v1.0.0 federated, v1.1.0 push-to-collector | `KENSA_GO_DAY1_PLAN.md` §13A |
| OpenWatch Postgres `transactions` table survives v1.0.0 | `KENSA_GO_DAY1_PLAN.md` §13A |

## 8. Open items for follow-up

Not blocking Week 1, but worth resolving before Week 22-25:

- **Authorization model for `CancelDeadman`**. Who can cancel an armed timer?
  (Kensa ships a coarse "any caller with sudo access to the host can cancel"
  model; OpenWatch's approval-workflow layer may want finer-grained control.)
- **Key rotation policy** for the per-deployment Ed25519 key. Kensa ships key
  history support; OpenWatch's audit UI decides how to display rotated-key
  warnings.
- **Collector schema for v1.1.0 push mode**. Let's design this together
  rather than either team proposing unilaterally. Early draft in Q2 of
  Kensa's build, so there's time.

---

**Response summary:** Accepted. `api/` updated. OpenWatch clear to proceed
with the three in-flight PRs and the Q1-Q3 plan rewrite. Weekly sync
starting next week.

**Related documents:**
- `/home/rracine/hanalyx/kensa/docs/KENSA_GO_DAY1_PLAN.md` (updated 2026-04-14,
  §3.5 refinements)
- `/home/rracine/hanalyx/openwatch/docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md`
  (the inbound memo this responds to)
- `/home/rracine/hanalyx/openwatch/docs/OPENWATCH_VISION.md` (the source of
  the git:GitHub framing)

**Contacts:**
- Kensa: engineering (this response prepared collaboratively, human review
  pending before send)
- OpenWatch: engineering

**Status:** Reviewed.
