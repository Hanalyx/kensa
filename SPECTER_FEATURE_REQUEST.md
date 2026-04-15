# Specter Feature Requests

Feature requests and implementation gaps discovered while integrating Specter
into kensa-go. Each entry links back to the spec AC it would unlock.

---

## FR-001: Deadman timer keep-alive — `Armer.Extend()` API (deadman AC-07)

**Related spec:** `specs/deadman/timer.spec.yaml` AC-07

AC-07 requires that for long-running applies exceeding the default 120s window, the
engine sends a keep-alive every 30 seconds that extends the scheduled fire time by
60 seconds. A failed keep-alive must abort the transaction.

Add `Armer.Extend(ctx, transport, txnID uuid.UUID) error` that re-schedules the job
with +60s. The engine would call it from a goroutine ticking every 30s during apply.

---

## FR-002: `specter.yaml` exclude list should support glob patterns (BUG-002 followup)

The current `settings.exclude` list does not filter subdirectory paths, causing
`duplicate_id` errors when git worktrees exist under excluded directories.
Support `- .claude/**` glob patterns in the exclude list.

---

## FR-003: Clock skew detection in `Armer.Arm()` (deadman AC-10)

AC-10 requires pre/post `date` comparison on the host to detect clock skew >30s
and extend the timer window proportionally before scheduling. Not yet implemented.

---

## FR-004: Fake validator injection for engine tests (engine AC-03)

AC-03 requires `Status=RolledBack` when a post-apply validator fails. Add
`engine.WithFakeValidator(fn)` so tests can inject a failing validator without
wiring a real rule-based validator.

---

## FR-005: `store.SQLite.Prune()` / `RunRetention()` (transaction-log AC-07)

AC-07 requires a background task that moves pre_states older than 7 days to
info-only state and prunes transactions older than 90 days. Neither method exists.

---

## FR-006: Evidence envelope JSON Schema generation (evidence-envelope AC-07)

AC-07 requires a JSON Schema at `evidence/envelope-v1.json`. Add a `go:generate`
target that generates it from `api.EvidenceEnvelope`, plus a roundtrip validator test.

---

## FR-007: Cross-repo schema comparison for envelope spec (evidence-envelope AC-10)

AC-10 requires that the schema published at `kensa-spec/specs/evidence/envelope-v1.yaml`
matches the Go struct in `api/envelope.go` exactly. A CI generation/comparison step
is needed to enforce this at build time.

---

## FR-008: `store.SQLite.DB()` accessor for index inspection (transaction-log AC-09)

AC-09 requires verifying that indexes exist on `(host_id)`, `(rule_id)`, `(status)`,
etc. to prevent full-table scans. Exposing the underlying `*sql.DB` (or an
`InspectIndexes` helper) would allow a test to query `sqlite_schema` directly.
