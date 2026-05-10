# Engine — Atomicity Contract

## Purpose

The engine is the load-bearing safety guarantee of the entire kensa product. It executes every rule's remediation as a four-phase atomic transaction:

```
Capture → Apply → Validate → Commit/Rollback
```

If Validate fails, the engine rolls back to the captured pre-state. This is the customer-facing promise (see `docs/TRANSACTION_CONTRACT_V1.md`).

## Current state

DONE for the 19 capturable handlers. The contract is enforced by:
- `internal/engine/transaction.go` (Transact / RunPlan).
- `internal/engine/capture.go` (PreState capture).
- `internal/engine/rollback.go` (rollback execution from persisted PreState).
- `internal/engine/deadman/` (deadman timer for connection-loss rollback).
- `internal/engine/plan.go` (Plan / Execute split for the kensa-go-only preview path).

Specter specs covering this:
- `engine-transaction.spec.yaml` (Tier 1, 100% coverage).
- `transaction-log.spec.yaml`.
- `evidence-envelope.spec.yaml`.
- `deadman-timer.spec.yaml`.

## Per-handler matrix

29 handlers ship total. 19 are capturable (full Apply / Capture / Rollback); 10 are non-capturable stubs (`transactional: false` in their rules).

| Handler | Capturable | Apply tested | Capture tested | Rollback tested | Real-host fuzz |
|---|---|---|---|---|---|
| `aptabsent` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `aptpresent` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `auditruleset` | ✓ (stub impl) | ✗ | ✗ | ✗ | ✗ |
| `configset` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `configsetdropin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `cronjob` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `fileabsent` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `filecontent` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `filepermissions` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `kernelmoduledisable` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `mountoptionset` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `packageabsent` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `packagepresent` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `pammoduleconfigure` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `selinuxbooleanset` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `servicedisabled` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `serviceenabled` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `servicemasked` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sysctlset` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `authselectfeatureenable` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `commandexec` | ✗ (stub, opt-in via AC-07) | ✗ | N/A | N/A | N/A |
| `configappend` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `cryptopolicyset` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `cryptopolicysubpolicy` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `dconfset` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `grubparameterremove` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `grubparameterset` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `manual` | ✗ (stub) | ✗ | N/A | N/A | N/A |
| `pammodulearg` | ✗ (stub) | ✗ | N/A | N/A | N/A |

**The 10 non-capturable stubs ship as `transactional: false` in their rules.** Atomicity is NOT promised for them; the engine marks them `StatusSkipped` for rollback. Operators using these rules must accept the lack of automatic rollback.

## Verification protocol

```bash
# 1. Engine unit tests (no network).
go test ./internal/engine/...

# 2. Per-handler unit tests (no network).
go test ./internal/handlers/...

# 3. Specter checks for engine specs.
export PATH="/home/rracine/.specter/bin:$PATH"
specter check --strict       # all specs structural
specter sync                 # dependency graph

# 4. Real-host atomicity fuzz (load-bearing test).
KENSA_TEST_SSH_HOST=<throwaway> KENSA_TEST_SSH_USER=root \
    go test ./cmd/kensa-fuzz/... -v -timeout 10m

# 5. Manual round-trip on a fixture host.
#    a. kensa check produces a fail.
#    b. kensa remediate produces a transaction; record the UUID.
#    c. Inspect host state (the rule applied).
#    d. kensa rollback --txn UUID --host HOST.
#    e. Re-inspect host state (PreState restored).
```

## Capture-sufficiency checklist (per CLAUDE.md)

Every capturable handler's PR must answer:

1. **What could this change do wrong in production?**
2. **Is the captured state sufficient to fully restore the system on rollback?**
3. **What edge case is this change *not* safe for, and is it documented and gated?**

This is human-authored failure-mode analysis in the commit body. CONTRIBUTING.md enforces it for any PR touching `internal/engine/`, any handler's `capture.go`, or any handler's `rollback.go`.

## Known limits

- **`audit_rule_set` is shipped as a stub.** The handler implements `Apply` but does not capture audit-rule pre-state correctly; rollback is incomplete. Documented in CLAUDE.md "Open items before M7 ships."
- **`grub_parameter_set` lacks a deadman guard.** A misconfigured GRUB parameter can brick the host's next boot. Even the rollback path can't help if the host doesn't boot to run kensa. Documented as M7-blocker.
- **Deadman timer end-to-end test is queued.** The deadman subsystem has unit tests; the integrated "operator-disconnect-mid-apply" scenario is not exercised in CI yet.
- ~~The `noopSigner` placeholder...~~ **RESOLVED 2026-05-10 (M-012 + C-060).** Engine default is now a real Ed25519 signer; envelopes carry valid signatures. See [`security.md`](security.md) for verification protocol.
- **Plan path doesn't capability-gate.** `engine.PlanTransaction` calls `selectDefaultImpl`, ignoring the host's capability set. See [`cli/plan.md`](cli/plan.md). Faithful preview requires the rule selector; not in this build.
