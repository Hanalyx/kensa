# D-005 design — agent-mode Armer rewrite

**Status:** Draft, awaiting founder review per CONTRIBUTING.md
two-human-review rule for rollback-handler-adjacent code.
**Date:** 2026-05-12.
**Phase:** LL Phase 3, deliverable D-005.
**Companion:** `PHASE-3-BREAKDOWN.md`, `DELIVERABLES.md` D-005 entry.

---

## Why this needs a design doc

CONTRIBUTING.md flags rollback handlers for two-human review.
The Armer isn't a rollback HANDLER but it IS engine-level
rollback INFRASTRUCTURE — when the deadman fires, the
operation it triggers is rollback. If D-005 is wrong, the
rollback fires at the wrong time (or fails to fire) and a
customer sees their host in a half-applied state with no
recovery.

D-001..D-004 shipped the primitives (timerfd, pidfd, signalfd,
epoll). D-005 wires them into the engine. The contract:

- Engine calls `Armer.Arm(ctx, transport, txnID, preStates)`
  before running a control-channel-sensitive rule.
- Engine calls `Armer.Cancel(ctx, transport, txnID)` if the
  rule succeeds and the control channel survives.
- If the controller-target connection drops mid-apply, the
  deadman fires and rolls the host back autonomously.

Today's Armer (`internal/engine/deadman/deadman.go`, just
renamed from `internal/deadman/`) does this via at(1) /
systemd-run scheduling a shell script on the target. D-005
adds agent-mode dispatch: when the engine is talking to an
agent (per Q1.c, agent is the default), use kernel
primitives in-process; direct-SSH retains the shell path.

---

## Surface area

### Engine-side: `internal/engine/deadman/Armer`

Existing implementation stays as-is for the direct-SSH path.
The dispatch becomes:

```go
func (a *Armer) Arm(ctx, transport, txnID, preStates) (string, int64, error) {
    if agentClient := a.agentClientFor(transport); agentClient != nil {
        return a.armViaAgent(ctx, agentClient, txnID, preStates)
    }
    return a.armViaShell(ctx, transport, txnID, preStates)  // existing path
}

func (a *Armer) Cancel(ctx, transport, txnID) error {
    if a.isAgentTxn(txnID) {
        return a.cancelViaAgent(ctx, txnID)
    }
    return a.cancelViaShell(ctx, transport, txnID)  // existing path
}
```

Question: how does the Armer know it's in agent-mode? The
`transport` argument is `api.Transport`, not a richer type.
Options:
- (a) Type-assert `transport.(fsatomic.Transport)` like the
  Phase 2 handlers do. Reuses the established pattern.
- (b) Inject an `AgentClient` into the Armer at construction
  time (`deadman.New(... , deadman.WithAgentClient(c))`).
  Cleaner because the Armer holds the agent client directly.
- (c) Have the engine pass the agent client as a separate
  parameter to Arm/Cancel.

**Recommendation: (b).** The agent client is plumbed through
`pkg/kensa.DefaultWithEngineOptions(... , engine.WithAgentClient(c))`
today; extending the Armer with the same option keeps it
parallel.

### Agent-side: new `internal/agent/deadman/armer.go`

Receives RPC from the engine; spins up the event loop;
executes rollback commands on parent-death / timer / SIGTERM.

```go
type Armer struct {
    handlerRegistry *handler.Registry
    activeArms      map[uuid.UUID]*armedJob
    mu              sync.Mutex
}

type armedJob struct {
    cancel context.CancelFunc  // cancels the loop goroutine
    done   chan struct{}        // signals goroutine exit
}

// ArmDeadman is the RPC handler. The engine sends pre-state
// + window; the agent dry-runs the rollback commands and
// spawns an event-loop goroutine.
func (a *Armer) ArmDeadman(ctx, req *protocol.ArmDeadmanRequest) (*protocol.ArmDeadmanResponse, error) {
    // 1. Generate rollback commands (reuse existing
    //    recordingTransport pattern from the engine-side
    //    Armer).
    // 2. Spawn the event loop goroutine:
    //    - timer := timerfd.New(); timer.Arm(req.Window)
    //    - parent, _ := pidfd.OpenParent()  // ignore ErrParentGone for now
    //    - sigfd := signalfd.New(SIGTERM)
    //    - loop := eventloop.New()
    //    - loop.Register(timer.FD(), EventTimer)
    //    - loop.Register(parent.FD(), EventParentDeath)
    //    - loop.Register(sigfd.FD(), EventSignal)
    //    - go func() {
    //          event, _ := loop.Run(ctx)
    //          // Got an event → execute rollback commands
    //          //   in-process. If the event was timer/parent/sig,
    //          //   the rollback should fire. If ctx was canceled
    //          //   (via CancelDeadman), exit cleanly.
    //          executeRollback(req.Commands)
    //      }()
    // 3. Return immediately — the goroutine handles the
    //    waiting + firing.
}

func (a *Armer) CancelDeadman(ctx, req *protocol.CancelDeadmanRequest) (*protocol.CancelDeadmanResponse, error) {
    // Cancel the goroutine via ctx; clean up the fds; remove
    // from activeArms.
}
```

### Wire protocol additions

`internal/agent/protocol/` already has wire schema for
Apply/Capture/Rollback/Heartbeat (per L-009). D-005 adds:

```protobuf
message ArmDeadmanRequest {
    string txn_id = 1;            // uuid
    int64 window_seconds = 2;     // default 120
    repeated string rollback_commands = 3;  // generated by dry-running Rollback
}

message ArmDeadmanResponse {
    int64 fires_at = 1;           // unix-seconds when the timer will fire
}

message CancelDeadmanRequest {
    string txn_id = 1;
}

message CancelDeadmanResponse {
    bool was_active = 1;          // false if no arm was in flight for txn_id
}
```

The existing wire-protocol schema framing handles these as
two new typed message kinds in the channel.

### Direct-SSH path: keep as-is

`armViaShell` and `cancelViaShell` are renamed from the
existing `armer.go` body (just splitting the public methods
into agent-vs-shell paths). All existing tests pass against
the shell path unchanged. Q1.c ratification: this path
stays available for environments where agent bootstrap isn't
viable.

---

## Failure modes

1. **Agent-mode arm fails (RPC error).** Engine fallback:
   should it (a) refuse to run the rule, (b) silently fall
   back to shell-based arm? **Recommendation: (a) refuse.**
   The operator can re-run with `KENSA_NO_AGENT=1` if they
   want shell-based. Silent fallback would surprise.

2. **Agent process dies between Arm and Cancel.** The
   engine sends Cancel; agent doesn't respond. Per Q3.a, the
   in-process timer goroutine is gone too — no rollback
   fires. Documented limit. Operator must manually rollback.

3. **Engine-side Armer is canceled while agent-side goroutine
   is running.** Engine sends CancelDeadman RPC; agent's
   goroutine ctx is canceled; loop exits without firing
   rollback. Clean.

4. **Concurrent Arms with the same txn_id.** Should not
   happen (engine generates UUID per txn) but defensive:
   reject second Arm with `ErrAlreadyArmed`.

5. **Parent death between Arm and event-loop registration.**
   `pidfd.OpenParent()` may return `ErrParentGone`. Action:
   fire rollback IMMEDIATELY (the parent is already dead).
   Per D-002's documented contract.

6. **pidfd unsupported (kernel <5.3 or seccomp).** `pidfd.
   OpenParent` returns `ErrKernelTooOld` or `ErrPidfdBlocked`.
   Fallback: call `signalfd.SetParentDeathSignal(SIGKILL)`
   so the kernel SIGKILLs the agent on parent death. Per
   Q3.a, the deadman won't fire under SIGKILL but the agent
   doesn't linger.

---

## Test plan

### Unit tests (D-005 in this drop):
- `TestArmer_AgentMode_RegistersAllSources` — Arm spawns
  goroutine with timer+pidfd+signalfd+loop all registered.
- `TestArmer_AgentMode_FiresOnTimer` — Arm(100ms); wait
  120ms; verify rollback commands executed.
- `TestArmer_AgentMode_CancelStopsRollback` — Arm(5s);
  Cancel after 100ms; wait 200ms; verify NO rollback.
- `TestArmer_AgentMode_FiresOnParentDeath` — fork a parent
  shim, start Arm with pidfd on shim, kill shim, verify
  rollback fires.
- `TestArmer_AgentMode_FiresOnSIGTERM` — Arm with signalfd
  on SIGUSR1; raise SIGUSR1; verify rollback fires.
- `TestArmer_AgentMode_PidfdFallbackUsesPrctl` — mock probe
  returns ErrKernelTooOld; verify prctl path is used.
- `TestArmer_AgentMode_FiresImmediatelyOnParentGone` — mock
  OpenParent returns ErrParentGone; verify rollback fires
  immediately.
- `TestArmer_DirectSSH_UnchangedFromCurrent` — existing
  deadman_test.go suite passes against the dispatcher.

### Live-host tests (D-006 in next drop):
- `TestFuzz_DeadmanFiresAfterSuspend` — apply + systemctl
  suspend + resume + verify rollback fired (CLOCK_BOOTTIME).
- `TestFuzz_DeadmanFiresAfterClockJump` — apply + date -s
  forward + verify rollback DOES NOT fire from the jump.
- `TestFuzz_DeadmanFiresOnSSHKill` — apply + kill -9 SSH +
  verify pidfd path fires rollback <200ms.
- `TestFuzz_DeadmanCancelStopsRollback` — apply, normal
  complete, verify no rollback within window+5s.

### Two-human review checklist (CONTRIBUTING.md)

D-005 commit body MUST contain:

1. **What could this change do wrong in production?**
2. **Is captured state sufficient to fully restore on rollback?**
3. **What edge case is this change NOT safe for?**

PLUS a real-host test pass against `inventory.ini` BEFORE
merge (kensa-fuzz harness — D-006's `TestFuzz_DeadmanFiresOnSSHKill`
is the minimum acceptance).

---

## Size estimate

~3-4 days per the original breakdown. Splits roughly:
- Day 1: wire-protocol additions (ArmDeadman/CancelDeadman) +
  agent-side RPC handler shell.
- Day 2: agent-side Armer with eventloop integration + unit
  tests.
- Day 3: engine-side dispatcher (agent vs shell) + integration
  tests.
- Day 4: peer review + fix-up + live-host smoke.

---

## Open questions

### Q1. Should engine-mode-arm fail-back to shell on RPC error?
**Recommendation: NO** — refuse the rule run instead. Surface
the agent-bootstrap failure rather than silently degrade
atomicity. Operators can opt back via `KENSA_NO_AGENT=1`.

### Q2. Where should the agent-side Armer struct live?
**Recommendation:** `internal/agent/deadman/armer.go` — same
package as the primitives. Single Go package boundary;
internal types visible without exporting.

### Q3. Should D-005 also remove the at(1)/systemd-run shell path?
**Recommendation: NO** — Q1.c kept it for direct-SSH fallback.
Removal scoped to D-006 only if the fuzz harness passes on
all four target OSes. Defer.

---

## Stop conditions before D-005 implementation

Per the migration_loop_preapproval, autonomous merge of
properly-FMA'd Phase 3 deliverables is pre-approved. D-005
is "rollback-handler-adjacent" per CONTRIBUTING.md, requiring
two-human review. The loop pauses HERE for founder approval
of:

1. This design doc (Q1, Q2, Q3 recommendations).
2. The wire-protocol additions (msg names, field shapes).
3. The decision to keep the shell path (Q3).

After approval, D-005 implementation proceeds through the
4-day plan; final merge requires the founder's explicit
sign-off after the peer-review + live-host smoke.
