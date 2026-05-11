# L-014 design doc — first handler port (`file_permissions` via agent)

**Status**: Draft, awaiting founder review before implementation.
**Date**: 2026-05-11.
**Companion**: `docs/roadmap/DELIVERABLES.md` L-014 entry; `docs/roadmap/LOW_LEVEL_MIGRATION_V1.md` §2.

---

## What L-014 is

The proof-of-concept that the L-007 through L-013 stack actually works for real remediation. Concretely: `kensa remediate` against a real host, with the `file_permissions` handler running via the agent instead of via direct-SSH-shell-exec, producing an identical `api.RemediationResult` to the direct-SSH path.

L-014 is the **architectural bridge** between "wire protocol exists" (done) and "actual handlers run via the wire protocol" (starts here). The shape we pick at L-014 propagates into 18 more handler ports (L-015..L-032), so the decisions matter.

---

## What L-014 needs to introduce

Four new pieces, plus engine plumbing:

1. **Local-syscall `api.Transport`** on the agent side. The agent runs ON the target; when `file_permissions.Apply` calls `transport.Run("chmod 644 ...")`, that command runs LOCALLY (no SSH). New package: `internal/agent/transport/local/`.

2. **`RemoteHandler` shim** on the controller side. Wraps an `*client.Client` + a mechanism name; satisfies `api.Handler` / `api.CaptureHandler` / `api.RollbackHandler`. When the engine invokes `Apply`, RemoteHandler converts to a wire call via the AgentClient. New package: `internal/agent/remotehandler/`.

3. **Agent-side dispatcher** — replaces `agent.HandleEcho` with real handler routing. Receives `ApplyRequest{mechanism, params, pre_state}`, looks up the handler in `handler.Default()`, constructs a local Transport, dispatches, wraps the result as `ApplyResponse`. New package or file: `internal/agent/server/server.go`.

4. **Engine integration**: a way for the engine to dispatch through RemoteHandlers when running in agent mode. This is the load-bearing UX decision (Section 3 below).

---

## Decision 1: Engine-integration shape

How does the engine choose agent-mode vs direct-SSH? Three real options.

### Option A — `engine.WithAgentClient(*client.Client)` + `KENSA_USE_AGENT=1` env var

**What ships at L-014:**
- `engine.WithAgentClient(*client.Client) Option` — when set, every handler invocation routes through RemoteHandler instead of the registered handler's local code.
- `cmd/kensa/remediate.go` checks `KENSA_USE_AGENT` env var; if set, calls `bootstrap.EnsureAgent` → opens AgentClient → passes via `engine.WithAgentClient`.
- No user-facing CLI flag. Agent-mode is operator-opt-in via env var only.

**Pros:**
- Smallest UX surface — defers the "what does the CLI flag look like" question.
- Composable with existing engine options.
- L-015..L-032 add no UX work; each handler just ports.
- Hidden env var matches "proof of concept" framing.

**Cons:**
- Env vars are less discoverable than flags.
- A future change to a real `--use-agent` flag means CLI surface churn.

### Option B — `--use-agent` CLI flag from the start

**What ships at L-014:**
- New `--use-agent` flag on `kensa remediate` (and `kensa check`).
- Flag triggers the bootstrap-agent-then-dispatch path.
- Flag is documented in `kensa remediate --help`.

**Pros:**
- Operator-discoverable from day one.
- No migration cost when we want it public.
- Helps document the feature for early testers.

**Cons:**
- Locks in the CLI shape before we've ported all 19 handlers — what if mid-port we discover the flag should be per-mechanism (some handlers force agent, others don't)?
- Help text accumulates "(L-014 proof-of-concept; not all mechanisms supported yet)" caveats.
- Premature publication of an internal feature.

### Option C — Per-handler `AgentCapable` interface; engine auto-routes

**What ships at L-014:**
- New interface `AgentCapable interface { AgentApply(...) ... }` (or a tag on the handler registration).
- `file_permissions` is the first handler to implement it.
- The engine, given an agent client, checks each handler's AgentCapable status and routes accordingly. Non-AgentCapable handlers fall back to direct-SSH.

**Pros:**
- Gradual adoption: ports happen one handler at a time without engine refactors.
- Mixed-mode session natural: some mechanisms run via agent, others over SSH.
- Type-safe — opting in is compile-checked.

**Cons:**
- Every handler port needs `AgentCapable` boilerplate (~5 lines each).
- "Mixed-mode session" raises questions about transaction atomicity — is the deadman timer aware that half the steps ran via agent and half via SSH? Probably no, today.
- More code at L-014 to validate something we may not need for v1.x.

### Recommendation: **Option A**

Reasoning:
- L-014 is explicitly proof-of-concept. Locking the UX shape is premature.
- The env-var path doesn't preclude a future `--use-agent` flag — adding the flag is a 10-line cmd/kensa change once we know we want it.
- Option C's per-handler opt-in is theoretically clean but raises atomicity questions the deadman timer can't currently answer. Defer until we have a use case.
- The engine.With… options pattern is well-established in the codebase; this fits.

**Where the answer flips**: if customers immediately want agent-mode for a specific compliance benchmark before L-032 lands, Option B is justifiable. Otherwise Option A.

---

## Decision 2: Local-syscall Transport scope

The agent's handlers need an `api.Transport`. Options for the implementation:

### Option L1 — Full Transport (Run + Put + Get + Close)

`internal/agent/transport/local/local.go` implements every method:
- `Run(cmd)` → `exec.Command("sh", "-c", cmd).CombinedOutput()`
- `Put(local, remote, mode)` → `io.Copy` + `os.Chmod`
- `Get(remote, local)` → `io.Copy`
- `ControlChannelSensitive()` → always `false` (the agent IS the target)
- `Close()` → no-op

**Pros:** Drop-in replacement; every handler's existing logic just works.
**Cons:** ~80 lines of Transport implementation; some are non-trivial (sudo wrapping, working directory, env-var handling).

### Option L2 — Run-only stub, Put/Get error out

Same as L1 but Put/Get return `errors.New("agent mode does not support file transfer; the agent IS the target")`. Most handlers (file_permissions, service_*, sysctl_set) only call Run. Handlers that DO call Put (file_content) would need refactoring to use direct file IO via os package — which is the natural agent-mode evolution anyway.

**Pros:** Smaller surface; forces handler authors to be agent-mode-aware.
**Cons:** Existing handlers like file_content break under agent-mode until refactored — that's most of L-015..L-032's work shifted to "rewrite handler to not use Transport.Put."

### Option L3 — No Transport on the agent side; handlers refactored

L-014 introduces a parallel handler interface `AgentHandler` that doesn't take a Transport (since none is needed). file_permissions ports to this new interface. RemoteHandler is the shim from api.Handler → AgentHandler.

**Pros:** Cleanest type signatures. No fake Transport.
**Cons:** Doubles the handler surface area. Every ported handler is essentially rewritten. L-015..L-032 becomes 5x the work.

### Recommendation: **Option L1**

Reasoning:
- Drop-in compatibility means L-015..L-032 ports are minimal — most handlers can be agent-mode-ported in 30 min just by adding the import line and `AgentCapable` tag (under Option A above).
- The "sudo wrapping, working directory, env-var" wrinkles of Option L1 are real but bounded — ~150 lines of code total.
- Option L3's "rewrite every handler" cost is multiplied by 19 handlers; not justified by cleaner types.

---

## Decision 3: Agent-side dispatcher placement

The agent process's handler dispatcher currently lives as `agent.HandleEcho`. L-014 needs to replace this with real handler routing.

### Option D1 — Modify `HandleEcho` to do real dispatch when handler.Default() has the mechanism

Keep the function name; check if the mechanism resolves; if so dispatch, if not return the echo response.

**Pros:** Minimal code change.
**Cons:** Conflates the L-009 echo loop's purpose with the real dispatcher; tests get confused.

### Option D2 — New `internal/agent/server/` package with `Handle(req) *Response` server function

The `kensa agent --stdio` CLI calls `agent.Run(..., server.Handle)` instead of `agent.HandleEcho`. The Echo handler stays for tests.

**Pros:** Clean separation; HandleEcho remains the test-fixture handler.
**Cons:** New package + ~150 lines.

### Option D3 — `internal/agent/dispatch.go` in the existing agent package

Same logic as D2 but no new package. Easier import paths.

**Pros:** Less directory churn.
**Cons:** The agent package becomes a grab-bag (framing + echo + dispatch + Run).

### Recommendation: **Option D2**

Reasoning:
- HandleEcho is genuinely a different responsibility (test fixture for wire-roundtrip validation). Keeping them distinct prevents test/production confusion.
- New package adds 2 lines of import; not real cost.
- D3's "grab-bag" concern is real — the agent package is already at 4 files; a 5th for dispatch is the wrong way to scale.

---

## L-014 scope summary (with the recommended options)

**In scope:**
- `internal/agent/transport/local/local.go` — full Transport (Option L1)
- `internal/agent/remotehandler/remotehandler.go` — controller-side shim
- `internal/agent/server/server.go` — agent-side handler dispatcher (Option D2)
- `internal/engine/engine.go` — add `WithAgentClient(*client.Client)` option (Option A)
- `cmd/kensa/remediate.go` — `KENSA_USE_AGENT=1` env var path: bootstrap → client.Open → client.Handshake → engine.WithAgentClient
- `internal/handlers/filepermissions/` — verify it works under agent mode (likely no changes needed if Option L1 + Option A work as designed)
- Integration test: end-to-end agent-mode remediate vs direct-SSH remediate, comparing results

**Out of scope (deferred to L-015..L-033):**
- Other 18 capturable handlers (one per deliverable per the existing DELIVERABLES.md plan)
- `--use-agent` CLI flag (deferred unless customer-pulled)
- Mixed-mode session (some handlers via agent, others via SSH)
- Multi-target agent reuse (one agent process per target per session today)
- Agent-side resource limits (cgroups sandboxing — that's Stretch B in LOW_LEVEL_MIGRATION_V1.md)

---

## Spec acceptance criteria (proposed)

If founder accepts the design above, the L-014 spec proposes these ACs:

| AC | What |
|---|---|
| AC-01 | LocalTransport.Run executes commands via `sh -c`; result fields populated correctly |
| AC-02 | LocalTransport.Put writes local-bytes-→-local-file with the requested mode |
| AC-03 | RemoteHandler.Apply forwards (mechanism, params, preState) to client.Apply, returns the result unchanged |
| AC-04 | engine.WithAgentClient causes every Handler.Apply call to route via RemoteHandler |
| AC-05 | `KENSA_USE_AGENT=1 kensa remediate <host> <rule>` against a real host produces an identical `api.RemediationResult` to the direct-SSH `kensa remediate <host> <rule>` for `file_permissions` |
| AC-06 | Agent-side server.Handle dispatches Apply / Capture / Rollback by looking up handler.Default().Get(mechanism); returns envelope Error if mechanism is unknown |
| AC-07 | Failure modes: agent crash mid-Apply, mechanism unknown, validation failure — all surface as engine errors with correct mapping to the operator-facing exit codes |
| AC-08 | `go test ./...` + cli-smoke + specter strict + manpage all green |

---

## Open questions for founder

1. **Agent-mode atomicity boundary**: Today the engine treats a transaction as atomic if all steps' handlers report Success. With agent-mode, an agent crash mid-Apply leaves the target in an indeterminate state — the controller sees ErrAgentStreamClosed but the actual filesystem state is unknown. Two options:
   - (a) Treat agent-stream-close mid-Apply as "rolled-back": engine runs Rollback for all prior committed steps via the controller's direct-SSH path. This requires direct-SSH to remain wired alongside agent-mode (fallback).
   - (b) Treat it as "stranded": mark the transaction as PartiallyApplied with no rollback attempt; operator manually inspects.
   
   **Recommendation**: (b) for L-014. (a) requires keeping the deadman timer aware of which steps went through which path — heavy.

2. **Live test gating**: L-014's E2E test needs a real host. Existing pattern: `KENSA_TEST_SSH_HOST` env var; tests skip when absent. L-014 adds a NEW dependency: the controller-side kensa binary must be locally buildable AND the target must permit `~/.cache/kensa/agent-<sha>` writes. Reasonable to gate on `KENSA_TEST_SSH_HOST + KENSA_TEST_AGENT_MODE=1` env vars (the latter explicitly opts into the bootstrap+exec path). Confirm.

3. **Handler signature parity check**: I'm assuming `file_permissions.Apply(ctx, transport, params, pre)` works unchanged under LocalTransport (Option L1). If the existing handler does anything non-obvious (e.g., assumes a remote-vs-local path distinction, calls `transport.ControlChannelSensitive()` and branches on the result), L-014 grows by ~1h of handler-specific work. Worth a 10-minute review of `internal/handlers/filepermissions/filepermissions.go` before I commit to the L-014 spec.

---

## Decision summary

| Decision | Recommended option | Why |
|---|---|---|
| 1. Engine integration | A — env var + WithAgentClient | Proof-of-concept scope; defers UX commitment |
| 2. Local Transport | L1 — full Transport | Minimal per-handler port cost for L-015..L-032 |
| 3. Dispatcher placement | D2 — new server package | Clean separation from echo test fixture |

If you ratify these three, I write the L-014 spec + start implementation under the standard loop discipline (spec → tests → implement → peer review → gates → commit). If any decision flips, the spec changes accordingly before any code lands.
