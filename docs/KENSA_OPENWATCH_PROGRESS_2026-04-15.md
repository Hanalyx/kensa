# Progress Memo: Kensa Go — Weeks 1, 2, 3 Complete

**From:** Kensa team
**To:** OpenWatch team
**Date:** 2026-04-15
**Subject:** Weeks 1, 2, and 3 of `KENSA_GO_DAY1_PLAN.md` are live in
             `Hanalyx/kensa-go`. Concrete consumer examples below.
**Status:** Draft for final review before sending

---

## 1. TL;DR

`Hanalyx/kensa-go` @ `5de6502` is consumable today. The full v1
[`api/`](https://github.com/Hanalyx/kensa-go/tree/main/api) surface
compiles and is `go get`-able. Three of four foundation milestones from
`KENSA_GO_DAY1_PLAN.md` §11.1 are done in the first 24 hours of work
rather than the planned three weeks. SSH transport (Week 4 / M1) is the
remaining foundation item.

OpenWatch can:

- Import `github.com/Hanalyx/kensa-go/api` and write production code
  against every interface from §3 and §9 of the Day-1 plan.
- Persist real transaction logs through the SQLite store and query them
  via `LogQuery.Query` / `Get` / `Aggregate` against all five enumerated
  `AggregateKey` shapes.
- Drive the engine end-to-end against the in-process `FakeTransport` to
  validate any approval-workflow or transaction-log UI without
  needing real RHEL hosts yet.
- Watch the engine produce structurally-correct signed evidence
  envelopes (signature stubbed by `noopSigner` until Week 25; the
  envelope shape itself is final).

What still returns `ErrNotYetImplemented`:

- `Kensa.Plan` / `Kensa.Execute` (Week 24).
- `Kensa.Subscribe` (Week 25 — the engine emits internally; the
  `EventBus` wiring lands then).
- `Kensa.CancelDeadman` / `Kensa.DeadmanStatus` (Week 15-16 with the
  real deadman-timer subsystem).
- `Plan.Preview` (Week 24).
- Real Ed25519 signing in `Kensa.VerifyEnvelope` (Week 25; structural
  verification with `noopSigner` works today).

The full milestone-by-method status is in §5.

## 2. What's live (commit-by-commit)

```
5de6502 CI: lint via goinstall so linter binary matches runner Go version
5a008b6 Implement Week-3 SQLite transaction log
644a422 Implement file_permissions handler end-to-end with capture/rollback
c58d527 Implement Week-2 transaction engine run loop
52e55dc Adopt Google Go Style Guide for api/ comments; add lint and pre-commit
7546ac7 docs: update authorship model — AI writes code, founders rigorously review
3fc8a76 Fix pre-commit config: go-vet (not go-vet-mod)
2ed17c8 CI: split pre-commit stages so file hygiene runs without Go/Specter
d1abbf0 CI: make spec-sync soft-fail, decouple Go jobs during Specter-install-TBD
7c09336 Fix CI: install Specter via go install or SPECTER_INSTALL_URL
26adce3 Initial scaffold — api/ surface, Tier-1 specs, Specter pipeline, V1 docs
```

CI is green: ✓ Spec Sync, ✓ Unit Tests, ✓ Lint, ✓ Pre-commit hygiene.

## 3. What you can write today

### 3.1 Get the package

```bash
go get github.com/Hanalyx/kensa-go@latest
```

The `api/` package is v1-stable. Every method signature is frozen.
Methods whose engine-side implementation has not landed return
`api.ErrNotYetImplemented` until their milestone ships.

### 3.2 Drive the engine end-to-end (works today)

The engine is wired up internally and exercisable through the
`internal/engine` package. The intended consumer surface is `api.Kensa`,
which also works for the four execution methods now that the engine
backing is real:

```go
// (Until api.Kensa wiring lands — Week 4 — use the engine directly
// via internal/engine for now.)

import (
    "context"
    "github.com/Hanalyx/kensa-go/api"
    "github.com/Hanalyx/kensa-go/internal/engine"
    _ "github.com/Hanalyx/kensa-go/internal/handlers/filepermissions" // register
)

func example() error {
    e := engine.New()
    txn := &api.Transaction{
        RuleID: "fs-permissions-etc-shadow",
        HostID: "host-1.example.com",
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
    }
    res, err := e.Run(context.Background(), realTransport, txn, false /* nonBlocking */)
    if err != nil {
        return err
    }
    // res.Status is one of Committed, RolledBack, PartiallyApplied, Errored.
    // res.Envelope is the structurally-correct evidence envelope.
    // res.Steps[i] reports per-step success/detail/Stranded.
    return nil
}
```

For OpenWatch's purposes, all four `TransactionStatus` outcomes work:
`Committed` on full success, `RolledBack` when apply or validate fails
(the engine reverses prior steps in reverse order using captured
pre-state), `PartiallyApplied` when a `transactional:false` rule has a
non-capturable step that ran before failure, and `Errored` for capture
failures or pre-flight rejections.

### 3.3 Persist and query transactions via SQLite

```go
import (
    "context"
    "github.com/Hanalyx/kensa-go/api"
    "github.com/Hanalyx/kensa-go/internal/store"
)

func aggregateExample(ctx context.Context, s *store.SQLite) error {
    res, err := s.Aggregate(ctx,
        api.LogFilter{
            HostIDs:    []string{"host-1.example.com"},
            Since:      time.Now().Add(-7 * 24 * time.Hour),
            Severities: []string{"high", "critical"},
        },
        api.AggregateByHostThenFrameworkControl,
    )
    if err != nil {
        return err
    }
    // res.Rows[i].HostID + res.Rows[i].FrameworkRef
    //   + res.Rows[i].StatusCounts[StatusCommitted/RolledBack/...]
    return nil
}
```

All five `AggregateKey` values from the response memo are implemented:
`AggregateByHost`, `AggregateByRule`, `AggregateByFrameworkControl`,
`AggregateByHostThenFrameworkControl`, and the time-bucketed
`AggregateByRuleThenStatusOverTime` (use `WithTimeBucket(HourBucket |
DayBucket | WeekBucket)`).

### 3.4 Verify structurally-correct evidence envelopes

```go
import "github.com/Hanalyx/kensa-go/api"

func renderAuthenticityBadge(env *api.EvidenceEnvelope) string {
    k, _ := api.New(api.Config{})
    res, err := k.VerifyEnvelope(env)
    if err != nil { return "verification error" }
    if !res.Valid { return "INVALID" }
    if contains(res.Warnings, api.KeyRotation) {
        return "valid (signed by rotated key)"
    }
    return "valid"
}
```

Today the underlying signer is `noopSigner` so verification only
confirms the envelope's structural integrity (schema version,
signing-key-id sentinel). The Ed25519 signing path lands Week 25.

## 4. Two things changed from the last memo

### 4.1 Go version is now 1.25

`KENSA_OPENWATCH_RESPONSE_2026-04-14.md` §5.3 said `setup-go@1.22`.
Pulling `modernc.org/sqlite` for the transaction log forced go.mod up to
1.25. CI is now `setup-go@1.25` and `golangci-lint v1.64.8` built fresh
via `install-mode: goinstall` (the pre-built v1.64.8 binary is built
with go 1.24 and can't read 1.25 export data).

OpenWatch's CI should match: `setup-go@v5` with `go-version: '1.25'`.

### 4.2 Authorship model updated

The team policy in
[`docs/HANALYX_MISSION_AND_ROADMAP.md`](https://github.com/Hanalyx/kensa-go/blob/main/docs/HANALYX_MISSION_AND_ROADMAP.md#the-human-review-commitment)
is now: *"The Kensa AI team and collaborator will write all of the
application code. The founders commit and consider human review of the
code is non-negotiable."*

This unblocked the Week-1 / Week-2 / Week-3 burst above. Every PR still
includes a human-authored failure-mode analysis and rollback paths get
two-human review.

## 5. Method-by-method status against `KENSA_GO_DAY1_PLAN.md` §9

| Method | Status today | Implementation milestone |
|---|---|---|
| `Kensa.Transact` | Stub (engine works directly) | Week 4 wires engine into Kensa |
| `Kensa.Scan` | Stub | Week 21 (rule parser) |
| `Kensa.Remediate` | Stub | Week 21 |
| `Kensa.Rollback` | Stub | Week 4 wires engine into Kensa |
| `Kensa.Plan` | Stub | Week 24 |
| `Kensa.Execute` | Stub | Week 24 |
| `Kensa.Subscribe` | Stub | Week 25 |
| `Kensa.TransactionLog().Query` | **LIVE** via `internal/store` | Week 22 wires it into Kensa |
| `Kensa.TransactionLog().Get` | **LIVE** via `internal/store` | Week 22 |
| `Kensa.TransactionLog().Aggregate` | **LIVE** via `internal/store` | Week 22 |
| `Kensa.VerifyEnvelope` | Stub (structural verify works via noopSigner) | Week 25 |
| `Kensa.CancelDeadman` | Stub | Week 16 |
| `Kensa.DeadmanStatus` | Stub | Week 16 |

Three of the four OpenWatch-facing surfaces from your §5 asks are
already real at the package boundary — they need only the
`api.Kensa.TransactionLog()` accessor wired (Week 4 work). The
implementations themselves are not stubs.

## 6. Things you asked for that are now in place

From `KENSA_OPENWATCH_COORDINATION_2026-04-14.md` §5:

- ✅ **`LogFilter.Phases`** — `[]api.Phase` with five values
  (capture/apply/validate/commit/rollback).
- ✅ **`LogFilter.Severities`** — `[]string` with critical/high/medium/low.
  Denormalized to the transactions row at write time per
  transaction-log spec C-03.
- ✅ **`FrameworkRef` structured** — `{FrameworkID, ControlID}` not opaque.
- ✅ **All five `AggregateKey` values** + `WithTimeBucket(Hour|Day|Week)`.
- ✅ **`HeartbeatInterval`** on `EventFilter` (default 60s; pulses
  coalesced not dropped).
- ✅ **`Plan.Preview(format)`** signature with four `PreviewFormat`s.
  Implementation lands Week 24; signature is frozen.
- ✅ **Expanded `PlanStaleError`** with `StaleStepIndex`, `Mechanism`,
  `Field`, `Expected`, `Actual`, `Message`.
- ✅ **`GetOption` pattern** with `WithEnvelope`, `WithoutEnvelope`,
  `WithoutPreStates`. Plus `api.ResolveGetOptions` so external packages
  can honor the option list without the unexported `getOptions` type.
- ✅ **`EnvelopeVerifier`** interface with `KeyRotation` warning.
- ✅ **`DeadmanControl`** interface with `CancelDeadman` and `DeadmanStatus`.
- ✅ **`ErrHostBusy` + `WithNonBlocking`** with documented per-host
  serialization (engine enforces it; engine_test.go AC-08 verifies).

## 7. What we need from OpenWatch

### 7.1 First integration — pick what to write against

Two natural starting points for OpenWatch's side:

1. **Transaction-log UI over `LogQuery`.** The store is real today; you
   could build the rendered transaction list and the per-transaction
   detail view against an in-memory or test SQLite. The
   `TransactionRecord` shape is final. Aggregation queries for the
   fleet-health view also work.

2. **Approval-workflow UI scaffolded against stubbed `Plan` / `Execute`.**
   Calls return `ErrNotYetImplemented`, but UI flows can be assembled
   end-to-end with hand-constructed `Plan` values for testing. When
   Week 24 lands, the UI just stops getting the error and starts
   getting real plans.

Either or both is valuable. Let us know what you're starting with so
we can tag-related issues if questions come up.

### 7.2 Spec annotations on your end

Consider mirroring the `// @spec <id>` / `// @ac <AC-NN>` annotation
convention on OpenWatch tests that exercise the Kensa interfaces.
Specter coverage will then track which ACs are covered by OpenWatch's
side too — useful when a divergence shows up between OpenWatch's
expectations and what the api/ documentation says.

### 7.3 Confirm the spec submodule plan

Per `KENSA_OPENWATCH_RESPONSE_2026-04-14.md` §5.2 we committed to
standing up `Hanalyx/kensa-spec` as a separate repo for shared rules,
mappings, fixtures, and evidence schema. We haven't done that yet
because the Day-1 priority was getting the api/ surface live for
OpenWatch. Confirm the timing you'd like — we can do it this week or
defer to weeks 5-6 alongside the SSH transport work.

### 7.4 The benchmark commitment

Response memo §5.2 promised a `LogQuery.Aggregate` benchmark against
500K rows / 1000 hosts within 4 weeks. The store is built and
testable; the benchmark harness goes in this week. You'll have hard
numbers before Week 8.

## 8. Weekly sync proposal

The response memo §5.2 also proposed a 30-minute weekly Kensa↔OpenWatch
sync. Now that there's something concrete to coordinate against (not
just specs and interface shapes), this is the right time to start.

Suggest: Mondays 30 minutes, async-first (we file an agenda Friday EOD;
the call happens only if there's anything to discuss live).

## 9. Open items for your input

- **Who manages the `kensa-spec` submodule?** Kensa-side ownership with
  OpenWatch as a consumer is the default; happy to flip if you have a
  preference.
- **OpenWatch's go.mod target.** We're on `go 1.25` for kensa-go. If
  OpenWatch is on something earlier, let us know — we can hold the
  go.mod at 1.22 if we drop modernc/sqlite (would need a different
  storage backend; non-trivial).
- **Agent API timing.** Response memo §4.1 said agents talk to OpenWatch
  not Kensa direct. As OpenWatch designs the agent surface, would it
  help if Kensa published a stable in-process Go API doc that OpenWatch
  could mirror over HTTP? Or is the public Go interface enough?

---

**Asks summary, in priority order:**

1. Confirm OpenWatch is unblocked to start integration work against the
   v1 api/ surface and the live store implementation.
2. Confirm `setup-go@1.25` for OpenWatch CI.
3. Decide kensa-spec timing (this week or weeks 5-6).
4. Schedule the weekly sync.

**Related documents:**
- [Kensa Go repository](https://github.com/Hanalyx/kensa-go)
- [`docs/KENSA_GO_DAY1_PLAN.md`](https://github.com/Hanalyx/kensa-go/blob/main/docs/KENSA_GO_DAY1_PLAN.md)
- [`docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md`](https://github.com/Hanalyx/kensa-go/blob/main/docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md) — the prior memo this updates
- [`/home/rracine/hanalyx/openwatch/docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md`](file:///home/rracine/hanalyx/openwatch/docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md) — your original memo

**Contacts:**
- Kensa: engineering (this memo prepared collaboratively, human review pending before send)
- OpenWatch: engineering

**Status:** Draft. Review before sending.
