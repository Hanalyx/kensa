# Specter Feature Requests

Feature requests for the Specter tool itself. Kensa implementation gaps
that surfaced during Specter integration are tracked in BACKLOG.md.

---

## FR-002: `specter.yaml` exclude list should support glob patterns

**Status:** Added to Specter Phase 3 roadmap
**Discovered:** 2026-04-15

The current `settings.exclude` list does not filter subdirectory paths, causing
`duplicate_id` errors when git worktrees or similar tooling directories contain
copies of spec files. Support glob patterns such as `- .claude/**` so that entire
subtree hierarchies can be excluded without needing to remove the physical directory.

**Workaround until fixed:** Remove stale worktrees with `git worktree remove --force`
before running `specter sync`.

---

## FR-003: ingest live-host verification evidence as a coverage/attestation input

**Status:** Proposed
**Discovered:** 2026-07-01 (during the v0.7.0 release work)

Specter computes spec coverage from `go test -json` via `specter ingest` — i.e.
from **unit-test** results only. It has no notion that a spec was also **proven on
a live host**. For atomicity-critical Tier-1 specs this is a real gap: "the unit
test passed" is not the same guarantee as "remediate→rollback was byte-perfect on
a real RHEL 9.6 host, and the injection was confirmed inert against the vulnerable
control" — which is the evidence that actually gates a release like the
file_permissions RCE fix.

Kensa already keeps that evidence in a ledger (`catalog/sources/verifications.json`:
`rule_id`/`os`/`scope`/`host`/`verified_at`). What's missing is a Specter-side way to
**ingest a second evidence stream** (analogous to `specter ingest`) so that:

1. A spec's coverage can distinguish `unit` from `live-verified`.
2. A tier policy could *require* live-verification for Tier-1 (`strictness` could
   demand `scope=full` live evidence, not just a green unit test).
3. The coverage matrix reflects "proven on a host," which is the claim customers
   and auditors actually care about.

Concretely: an `specter ingest --kind=verification <ledger.json>` (or a mapping in
`specter.yaml` from a rule/spec id to a verification record), plus a coverage
column / tier rule for it.

**Why this is Specter's job, not Kensa's:** Kensa's job is to *produce* the
evidence (the `kensa verify --record` byproduct is tracked as a Kensa backlog
item). Deciding whether a spec is adequately *covered* — and gating on it — is
Specter's domain. Today Specter's coverage model can't see the strongest evidence
Kensa produces.

**Workaround until fixed:** the verification ledger is maintained and gated
independently (catalog drift gate + `stig_consistency_test`); it is not wired into
Specter's tier coverage.
