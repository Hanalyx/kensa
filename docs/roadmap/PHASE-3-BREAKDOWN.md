# Phase 3 deliverable breakdown — deadman timer rebuild

**Status**: Draft, awaiting founder review before deliverables enter DELIVERABLES.md.
**Date**: 2026-05-11.
**Companion**: `docs/roadmap/LOW_LEVEL_MIGRATION_V1.md` §3 Phase 3; `docs/roadmap/DELIVERABLES.md`.

---

## What Phase 3 is

The deadman timer is the safety net for control-channel-sensitive
remediation. Today (`internal/deadman/deadman.go`, 464 LOC), the engine
arms a deadman BEFORE running an SSH-affecting / firewall-affecting /
PAM-affecting rule. The deadman uploads a self-extracting shell script
to `/tmp/kensa-rollback-<txn>.sh` and schedules it via `at(1)` or
`systemd-run` to fire in 120 seconds. If the rule succeeds and the
control channel survives, the engine cancels the timer. If the
connection drops mid-apply, the scheduler fires the script and the
host rolls back autonomously.

Phase 3 rebuilds this on **kernel primitives running inside the
agent process** (which Phase 1 put on the target host). The replacement:

| Primitive | Today | After Phase 3 | Property gained |
|---|---|---|---|
| Timer | `at now + 120s` | `timerfd_create(CLOCK_BOOTTIME)` | Survives suspend (BOOTTIME counts during sleep; MONOTONIC doesn't) and clock-jumps (independent of wall clock) |
| Parent-death | (none — relies on at(1) firing regardless) | `pidfd_open(getppid(), 0)` | Race-free parent-death notification; no PID-reuse window |
| Belt-and-suspenders | (none) | `prctl(PR_SET_PDEATHSIG, SIGKILL)` | Fallback if pidfd race; kernel kills the child on parent death |
| Signal | (none) | `signalfd_create` for SIGTERM | Clean shutdown signal handling without restart-loop |
| Event loop | (none) | `epoll_create1` integrating timerfd + pidfd + signalfd + control-channel fd | Single-thread event loop; no race between fds |

**Goal:** The deadman survives suspend, clock jumps, parent SIGSTOP,
and absence of `at(1)`/`systemd-run` on the target.

---

## Why break it down

The 2-week single-deliverable plan in `LOW_LEVEL_MIGRATION_V1.md` §3 is
the right scope but the wrong unit. Reasoning:

1. **Five primitives, four with no kensa-go precedent.** `timerfd`,
   `pidfd_open`, `signalfd`, `epoll`, `prctl(PR_SET_PDEATHSIG)` — none
   are wrapped in any kensa-go package today. Each needs a focused
   reviewable unit before integration.
2. **`Armer.Arm()` is a CONTRIBUTING-flagged path.** It's engine-level
   rollback infrastructure; per CONTRIBUTING.md the rewrite needs a
   failure-mode-analysis commit body AND two-human review AND a
   real-host fuzz test before merge. Splitting the primitive packages
   from the Armer rewrite lets each get the full discipline.
3. **The shell-based path doesn't go away cleanly.** Direct-SSH mode
   (Phase 2's preserved fallback for hosts without agent bootstrap)
   has no in-process deadman possible — the controller is on a
   different machine. Direct-SSH must either keep `at(1)`/`systemd-run`
   OR refuse to run control-channel-sensitive rules. **This is a
   founder decision** (see §4 Q1 below).
4. **The fuzz harness needs new cases.** Clock jumps, suspend-mid-
   transaction, SIGSTOP — none are tested today. The harness work is
   substantial enough to be its own deliverable.

---

## Proposed breakdown — six deliverables

### D-001 — `internal/agent/deadman/timerfd/` primitive

**Phase**: LL Phase 3
**Deps**: L-032 (Phase 1 complete — agent runs on target)
**Size**: ~1-2 days
**Scope**:
- `Timer` type wrapping `unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC)`.
- `Arm(d time.Duration) error` — calls `unix.TimerfdSettime` with the
  given relative deadline.
- `Cancel() error` — settime with zero `it_value` to disarm.
- `FD() int` — exposes the fd for epoll registration.
- `Wait(ctx context.Context) error` — blocking read on the fd, returns
  when the timer fires or ctx cancels.
- `Close() error` — releases the fd.

**Acceptance**:
- `TestTimerfd_FiresAfterWindow` — Arm(100ms), expect Wait() to return
  in 100-200ms.
- `TestTimerfd_SurvivesSuspendNotice` — this one's hard to test without
  systemd-suspend; cover via doc-string contract + integration test in
  D-006 fuzz harness. **Add a unit test that exercises the FD read on
  a manually-fired timer to verify the wire shape (8-byte le-uint64
  read returns expiration count).**
- `TestTimerfd_CanCancel` — Arm + Cancel + verify no fire within 200ms.
- `TestTimerfd_ContextCancel` — Wait() returns ctx.Err on context cancel.

**Risk**: Low. timerfd is a stable kernel ABI (kernel ≥2.6.25).

**No engine integration in this deliverable.** Standalone primitive.

---

### D-002 — `internal/agent/deadman/pidfd/` primitive

**Phase**: LL Phase 3
**Deps**: L-032
**Size**: ~1 day
**Scope**:
- `ParentPidfd` type wrapping `unix.PidfdOpen(unix.Getppid(), 0)`.
- `FD() int` — exposed for epoll.
- `Wait(ctx context.Context) error` — blocking read; returns on
  parent exit (pidfd is `EPOLLIN`-readable when the process exits).
- `Close() error`.

**Acceptance**:
- `TestPidfd_FiresOnParentExit` — fork a child that opens
  `PidfdOpen(getppid())`; parent exits; child's Wait returns.
- `TestPidfd_DoesNotFireOnUnrelatedExit` — second test child exits;
  primary child's pidfd doesn't fire.
- Race-free: no PID-reuse window (the pidfd is bound to the original
  process identity, not the PID number).

**Risk**: Low-medium. PidfdOpen requires kernel ≥5.3 (RHEL 8 floor is
4.18 — **may not be available there**). Fallback path is
`PR_SET_PDEATHSIG` (see D-003). Document the version floor; require
fallback to work on older kernels.

---

### D-003 — `internal/agent/deadman/signalfd/` + `prctl` wrapper

**Phase**: LL Phase 3
**Deps**: L-032
**Size**: ~½ day
**Scope**:
- `SignalFD` type wrapping `unix.Signalfd` for SIGTERM (and optionally
  SIGINT / SIGHUP).
- `FD()`, `Wait(ctx)`, `Close()` — same shape as timerfd/pidfd.
- `SetParentDeathSignal(sig unix.Signal) error` — wraps
  `unix.Prctl(unix.PR_SET_PDEATHSIG, ...)`. Called once at agent
  startup so the kernel SIGKILLs the agent if the SSH parent dies
  while we're between epoll iterations.

**Acceptance**:
- `TestSignalfd_DeliversSIGTERM` — install signalfd, raise SIGTERM
  via syscall.Kill(syscall.Getpid()), Wait returns with the signal.
- `TestPrctl_PDeathsig` — fork-and-exec a child that calls
  `SetParentDeathSignal(SIGKILL)`, parent exits, verify child gets
  SIGKILL.

**Risk**: Low.

---

### D-004 — `internal/agent/deadman/eventloop/` epoll integrator

**Phase**: LL Phase 3
**Deps**: D-001, D-002, D-003
**Size**: ~2-3 days
**Scope**:
- `Loop` type holding an `epoll_create1(EPOLL_CLOEXEC)` fd.
- `Register(fd int, handler func() Event) error` — adds an fd with an
  associated event-producing handler.
- `Run(ctx context.Context) (Event, error)` — blocking epoll_wait loop;
  returns the first event produced by a registered handler (timer
  fire, parent death, SIGTERM) OR ctx cancellation.
- Event types: `TimerFired`, `ParentDied`, `SignalReceived(unix.Signal)`,
  `ControlChannelActivity`.

**Acceptance**:
- `TestEventLoop_TimerFiresFirst` — register timer (100ms) + pidfd of
  long-running parent + signalfd; Run() returns TimerFired in 100-200ms.
- `TestEventLoop_ParentDeathWins` — register timer (5s) + pidfd; kill
  the test parent immediately; Run() returns ParentDied in <200ms.
- `TestEventLoop_SignalWins` — register timer (5s) + signalfd(SIGTERM);
  raise SIGTERM; Run() returns SignalReceived in <200ms.
- `TestEventLoop_CtxCancel` — Run() returns ctx.Err on context cancel
  without other events.

**Risk**: Medium. The event loop is the integration point. The reviewer
note specifically flagged this. Pre-empt by:
1. Single-thread event loop (no goroutines per fd). Linearizes ordering.
2. Each handler is a pure function fd→Event. No side effects in the
   handler — Run() returns the Event, caller decides.
3. Property test: spawn 100 concurrent
   `Register+Arm+TriggerFirstEvent+VerifyEvent` cycles. No leaks.

---

### D-005 — Agent-mode Armer rewrite (in-process deadman)

**Phase**: LL Phase 3
**Deps**: D-004 (event loop)
**Size**: ~3-4 days
**Scope**:
- New `internal/agent/deadman/armer.go` that satisfies the existing
  `engine.DeadmanArmer` interface (same `Arm`/`Cancel` signatures)
  but uses kernel primitives instead of `at(1)`/`systemd-run`.
- `Armer.Arm(ctx, transport, txnID, preStates)`:
  - When `transport` is `fsatomic.Transport` (agent-mode):
    1. Build rollback commands via the existing
       `recordingTransport` dry-run.
    2. Marshal commands into an RPC payload + send to the agent via a
       new `Agent.ArmDeadman(txnID, cmds, window)` RPC.
    3. The agent process spins up a goroutine running the
       `eventloop.Loop` with timerfd(window) + pidfd(getppid) +
       signalfd(SIGTERM); on any event, executes the rollback
       commands in-process (via the agent's local transport).
    4. Return scriptPath="" (no script on disk in agent-mode),
       firesAt=time.Now()+window.
  - When `transport` is NOT fsatomic.Transport (direct-SSH):
    - Fall back to the existing shell-based path
      (`at(1)`/`systemd-run`). **Decision pending — see Q1.**
- `Armer.Cancel(ctx, transport, txnID)`:
  - Agent-mode: `Agent.CancelDeadman(txnID)` RPC → agent goroutine
    cancels timerfd, exits without rollback.
  - Direct-SSH: existing `atrm`/`systemctl stop` path.

**Acceptance**:
- All existing deadman tests pass against the agent-mode path.
- `TestArmer_AgentMode_RollbackFiresOnSSHDrop` (fuzz harness): live
  test that severs the SSH connection mid-apply; the agent's pidfd
  notices, fires the in-process rollback, the target host's state
  is restored.
- `TestArmer_AgentMode_CancelStopsRollback` (fuzz harness): live
  test that lets apply complete; the in-process timerfd is canceled;
  no rollback fires after `window` elapses.
- `TestArmer_DirectSSH_FallbackUnchanged` (existing test): verifies
  direct-SSH path is byte-equivalent to today.
- Failure-mode analysis in commit body per CONTRIBUTING.md.
- Two-human review per CONTRIBUTING.md's rollback-handler discipline.

**Risk**: High. The Armer is the only thing protecting customers from
"connection dropped mid-apply leaves the system in a torn state."
Mitigations:
- Keep the shell-based path AVAILABLE (not removed yet) until D-006's
  fuzz harness confirms the new path is reliable on RHEL 8 / RHEL 9 /
  Ubuntu 22.04 / Ubuntu 24.04.
- Live-host integration test BEFORE merge.

---

### D-006 — Fuzz harness extensions + Phase 3 close

**Phase**: LL Phase 3
**Deps**: D-005
**Size**: ~2-3 days
**Scope**:
- `cmd/kensa-fuzz/` test cases:
  - `TestFuzz_DeadmanFiresAfterSuspend` — apply a rule, immediately
    `systemctl suspend`; resume after window elapses; verify the
    deadman fired (rolled back). CLOCK_BOOTTIME contract.
  - `TestFuzz_DeadmanFiresAfterClockJump` — apply, `date -s` to a
    future time; verify the deadman does NOT fire from the jump (it
    counts boot-time seconds, not wall-clock).
  - `TestFuzz_DeadmanFiresOnSSHKill` — apply, kill -9 the SSH
    process on the controller side; verify rollback fires via
    pidfd_open within 200ms.
  - `TestFuzz_DeadmanCancelStopsRollback` — apply, normal complete,
    verify no rollback within window+5s.
- Remove the shell-based path from `internal/deadman/` after the fuzz
  harness is green on all four target OSes.
- Docs: update `docs/TRANSACTION_CONTRACT_V1.md §1.1 Reversibility`
  to name the kernel-primitive deadman explicitly + agent-mode
  requirement. Update `docs/test_docs/security.md` with the new
  failure-mode list (suspend, clock-jump, SIGSTOP — survives all).

**Acceptance**:
- Four fuzz tests pass on RHEL 8, RHEL 9, Ubuntu 22.04, Ubuntu 24.04.
- Old shell-based path removed; `git grep -E "at\(1\)|systemd-run"`
  returns only docs/historical references.
- CHANGELOG entry.

**Risk**: Low-medium. Test infrastructure work.

---

## Founder ratifications (2026-05-12)

After clarifying that kensa-go is pre-production (no backcompat
burden), the founder ratified:

| Q | Decision | Implication |
|---|---|---|
| Q1 | **(c) Keep both deadman impls, flip default to agent mode** | Agent-mode is the default; direct-SSH retains the shell-based deadman as an explicit opt-in fallback. Spawns **P-007** (Phase 2 follow-up — env-var flip) BEFORE Phase 3 D-001 starts. |
| Q2 | **(b) Probe + PR_SET_PDEATHSIG fallback** | D-002 (pidfd) probes for kernel ≥5.3; falls back to D-003's `prctl(PR_SET_PDEATHSIG, SIGKILL)` on older kernels. RHEL 8 (4.18) stays supported. |
| Q3 | **(a) Accept the agent-SIGKILL risk** | No parallel at(1) deadman for SIGKILL resilience in agent-mode. Documented in `docs/test_docs/security.md` as a known limit. |
| Q4 | **Recommendation: rename + new package** | `internal/deadman/` → `internal/engine/deadman/` (engine-side Armer, calls into agent via RPC). New `internal/agent/deadman/` for agent-side primitives + event loop. |

Loop UNBLOCKED. P-011 lands first (Phase 2 follow-up); then
D-001..D-006 in dependency order.

---

## P-011 — Phase 2 follow-up: agent-mode default

**Phase**: LL Phase 2 follow-up (lands before Phase 3 D-001)
**Deps**: Phase 2 corrected drop (merge `ef2e122`, done 2026-05-11)
**Size**: ~½ day
**Scope**:
- Replace `KENSA_USE_AGENT=1` (opt-in) with `KENSA_NO_AGENT=1`
  (opt-out) in `cmd/kensa/main.go` remediate path.
- Update the stderr atomicity-basis disclosure to reflect the
  new sense ("agent mode (default)" vs "direct-SSH mode (opt-out)").
- Update CHANGELOG.md under `## Unreleased` (Changed section) —
  this is a breaking change for any operator who built scripts
  around the env-var.
- Update `docs/test_docs/security.md §1.5` to remove the
  "Sign-off question pending" line; document the ratified default.
- Update `docs/TRANSACTION_CONTRACT_V1.md §2.6` matrix —
  kernel-atomic file ops are now "default" not "agent mode only".
- Update `CONTRIBUTING.md` live-host env-var section if it
  references `KENSA_USE_AGENT`.

**Acceptance**:
- Existing tests that gate on `KENSA_USE_AGENT=1` are updated.
- `cli-smoke.sh` still passes (the smoke harness doesn't currently
  set the env var; verify the new default doesn't break it OR
  the smoke harness gets `KENSA_NO_AGENT=1` set explicitly).
- Failure-mode analysis in commit body.

**Risk**: Low. Single-flag-sense flip; documented breaking change
in CHANGELOG.

---

## Original Q&A captured below for history

### Q1. What does direct-SSH mode do for deadman protection?

After Phase 3 ships, **agent mode** uses in-process kernel-primitive
deadman (no scheduler dependency). **Direct-SSH mode** has no agent
process on the target to run the in-process timer.

Three options:

**Option A: Keep shell-based path for direct-SSH.**
Pro: backward-compatible; direct-SSH users (the v1.0 default per the
Phase 2 founder decision still pending) keep the existing safety net.
Con: kensa-go ships with TWO deadman implementations indefinitely.
The shell-based path keeps working but doesn't gain the kernel-primitive
properties (suspend-resistance, clock-jump-resistance).

**Option B: Refuse to arm deadman in direct-SSH.**
Engine returns `api.ErrSchedulerUnavailable` for control-channel-
sensitive rules under direct-SSH. Operators must enable
`KENSA_USE_AGENT=1` to remediate firewall/SSH/PAM rules.
Pro: One deadman implementation. Forces agent mode for the highest-
risk operations. Aligns with the Phase 2 atomicity story (agent mode
= safer).
Con: Breaks the operator workflow for any customer running
control-channel-sensitive rules without agent bootstrap.

**Option C: Keep shell-based path, mark as deprecated.**
Pro: backward-compatible AND the deprecation pressure pushes operators
toward agent mode over time. Removal target: v2.0.
Con: Maintenance burden through v1.x.

**Recommendation: Option C** if the Phase 2 founder decision keeps
direct-SSH as the v1.0 default (still pending — see
`docs/test_docs/security.md §1.5`). If Phase 2 flips to agent-default,
go with Option B and remove direct-SSH deadman in the same drop.

### Q2. Should `pidfd_open` failure on RHEL 8 (kernel 4.18 < 5.3) gate Phase 3?

RHEL 8 ships kernel 4.18. `pidfd_open` requires kernel ≥5.3. If we
mandate pidfd, RHEL 8 customers can't use the new deadman.

Three options:

**A. Mandate pidfd; require kernel ≥5.3.**
RHEL 8 EOL is 2029. Federal customers on RHEL 8 today wouldn't get
Phase 3 deadman benefits but could keep the at(1) path (Q1 Option A/C).

**B. Use `PR_SET_PDEATHSIG` only on kernel <5.3; pidfd on ≥5.3.**
The agent probes at startup; fallback path is robust but loses
race-freeness of pidfd_open.

**C. Wait for RHEL 8 EOL before shipping Phase 3.**
2029. Not a real option.

**Recommendation: B.** Probe + fallback gives us coverage without
dropping a supported OS.

### Q3. Is the in-process deadman crash-resilient enough?

The current shell-based deadman survives ANY agent process death
because at(1) is a separate scheduled job. The Phase 3 in-process
deadman dies if the agent process is SIGKILLed.

Risk profile:
- Agent process dies cleanly via SIGTERM → signalfd catches it →
  rollback fires before exit. ✓
- Agent process dies via SIGKILL (the operator forcibly killed the
  agent, OR oomkiller hit it) → no rollback. ✗
- Agent's host kernel panics → no rollback (matches current behavior;
  at(1) wouldn't fire on a panicked host either). ✓ (no regression)

Mitigation options:
- **Belt-and-suspenders**: keep at(1)/systemd-run scheduled IN
  PARALLEL with the in-process timer. The shell-based deadman fires
  if the agent dies AND the timer expires. Adds back the safety net
  at the cost of "two timers exist."
- **Accept the risk**: agent process dying mid-transaction is rare
  enough; the failure modes that the in-process timer catches
  (suspend, clock-jump, SSH-drop) are more common.

**Recommendation: accept the risk** for v1.0; document explicitly in
`docs/test_docs/security.md`. Reconsider for v2.0 if a real-world
agent-crash mid-transaction incident occurs.

### Q4. Where does the deadman package live in the import graph?

Phase 1 put the agent in `internal/agent/`. The current deadman is
in `internal/deadman/` (controller-side). After Phase 3, the deadman
logic is split:
- Engine-side: `Armer` (in `internal/deadman/`) calls
  `Agent.ArmDeadman(...)` RPC.
- Agent-side: actual timerfd+pidfd+signalfd+epoll loop lives in
  `internal/agent/deadman/` (or `internal/agent/deadmanloop/`).

Two packages with similar names will confuse. Three naming options:
- `internal/agent/deadman/` (agent-side) vs `internal/deadman/`
  (engine-side, Armer). Confusing but minimal churn.
- Rename `internal/deadman/` → `internal/engine/deadman/`. Cleaner
  but touches every importer.
- Single package `internal/deadman/` with subpackages `armer/` and
  `loop/`. Compromise.

**Recommendation: the third option.** Lowest churn while making the
two halves visible.

---

## Ratification expected

Per the migration_loop_preapproval, autonomous merge of properly-
FMA'd Phase 3 deliverables is pre-approved once the founder has
answered Q1-Q4 above. Until then, loop is HALTED pending decisions.

After ratification, the loop picks up:
- D-001 first (no dependencies once Phase 3 is approved).
- D-002, D-003 in parallel (or sequential, both quick).
- D-004 after D-001/D-002/D-003.
- D-005 after D-004.
- D-006 after D-005.

Estimated full-Phase-3 wall-clock: ~10-13 days at sustained loop
cadence.
