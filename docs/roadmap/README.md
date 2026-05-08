# Roadmap — kensa-go

This directory holds the forward-looking plans that move kensa-go from
where it is today to the state described in `docs/TRANSACTION_CONTRACT_V1.md`
and the mission statement:

> kensa-go is the production-grade Go engine that makes "no Linux change
> should ever be unsafe, unauditable, or unreversible" literally true at
> the kernel-primitive level, starting with federal Linux compliance and
> broadening to the safety substrate that AI agents and SREs will need to
> operate on production systems.

## What lives in this directory

| File | Role |
|---|---|
| `README.md` | This file — synthesized plan, sequencing, decisions |
| `STATUS.md` | Per-item current state and next action |
| `INDEX.md` | File inventory only |
| `LOW_LEVEL_MIGRATION_V1.md` | The atomicity / kernel-primitive plan |
| `CLI_GNU_POSIX_MIGRATION_V1.md` | The CLI overhaul plan |

`README.md` and `STATUS.md` are the AI-facing entry points: read these
first when planning work. The two `*_V1.md` plans are the detailed
specifications referenced from here.

---

## The Plan in One Page

kensa-go has three concurrent workstreams and one ship gate.

### Workstream 1 — M7 production hardening (the ship gate)

Tracked in `CLAUDE.md` §"Open items before M7 ships." This is what
v1.0.0 needs before it ships. Not a roadmap doc; lives in CLAUDE.md
because it is operational, not architectural.

Items today: Ed25519 signer (task #12); first-principles integration
tests for the 10 untested handlers; `audit_rule_set` real implementation;
`grub_parameter_set` deadman guard; default `/usr/share/kensa/rules`
path resolution. See `STATUS.md` for the live state.

### Workstream 2 — Kernel-primitive atomicity migration

Spec: `LOW_LEVEL_MIGRATION_V1.md`. Phased plan (Phase 0 through
Phase 7 plus stretch phases) that takes today's shell-over-SSH
orchestration to direct kernel-ABI usage. Phase 1 is the gating
architectural change: introduce a `kensa agent --stdio` multi-call
binary mode that runs target-locally over framed protobuf. Without
that, every kernel primitive (`renameat2`, `O_TMPFILE`, `fsync`,
`timerfd`, `pidfd_open`, `unshare`, `BPF_PROG_LOAD`) is unreachable
from the controller's process.

This is the workstream that makes `TRANSACTION_CONTRACT_V1.md`'s
atomicity claim *literally* true at the kernel level rather than
"true under non-pathological failure modes."

### Workstream 3 — CLI GNU/POSIX overhaul

Spec: `CLI_GNU_POSIX_MIGRATION_V1.md`. Five phases that bring the
three CLI binaries (`kensa`, `kensa-validate`, `kensa-fuzz`) to
strict GNU/POSIX flag style and the full feature set Python kensa
demonstrated. Python kensa is being archived as an internal-only
prototype; kensa-go's CLI is canonical, not compatibility-driven.

Phase 1 (pflag swap, `-h` works, `--help` exits 0, top-level
`kensa --help` / `kensa --version`) is the highest-leverage half-day
of work in this directory and can ship today regardless of what else
is in flight.

---

## Sequencing — how the workstreams interact

```
                 M7 ship gate
                      │
                      ▼
            ┌─────────┴──────────┐
            ▼                    ▼
   Kernel migration         CLI overhaul
   (LOW_LEVEL)              (GNU_POSIX)
            │                    │
            ▼                    ▼
   Phase 0 build discipline      Phase 1 pflag swap
   (CGO_ENABLED=0, netgo)        (~half day; no deps)
            │                    │
            ▼                    ▼
   Phase 1 agent mode            Phase 2 -o FORMAT[:PATH]
   (4–6 weeks; gates the rest)   (~1 week)
            │                    │
            ▼                    ▼
   Phases 2–7                    Phases 3–5
```

**Key independence:** the two workstreams do not gate each other.
The CLI plan touches only `cmd/kensa/`, `cmd/kensa-validate/`,
`cmd/kensa-fuzz/`. The kernel migration touches `internal/engine/`,
`internal/handlers/`, `internal/transport/ssh/`, and a new
`internal/agent/` package.

**Key dependency inside the kernel migration:** Phase 1 (agent mode)
gates Phases 2 through 7. Until the multi-call binary ships, the
kernel-primitive work cannot land on the target.

**Cheapest immediate wins** that should land regardless of what else
is happening:
1. CLI Phase 1 (pflag, GNU/POSIX flags, `--help` exits 0) — ~half day
2. Kernel migration Phase 0 (`CGO_ENABLED=0`, `-tags netgo`) — ~half day
3. Update `TRANSACTION_CONTRACT_V1.md` "Current Implementation Status"
   preamble (already done in this session; verify it stays accurate
   as Workstreams 1 and 2 ship items)

---

## Open Decisions for the Founder

These gate roadmap progression. Listed in priority order.

1. **v1.0 scope: ship-with-current-architecture vs.
   ship-after-Phase-2.** The current code can ship a v1.0 that
   honors the transaction contract under non-pathological failure
   modes. Phase 2 of the kernel migration (file atomicity primitives)
   makes the contract literal for file handlers. The trade is "ship
   sooner with a scoped contract" vs. "ship later with a stronger
   product." Both are defensible. Recommendation: ship v1.0 with the
   current architecture and the scoped `TRANSACTION_CONTRACT_V1.md`
   preamble; treat Phases 1–2 of the kernel migration as v1.1.

2. **Agent push model: bundle per session vs. pre-install.** Affects
   ops documentation and the "single static binary" pitch. Per-session
   push is the simpler operator story; pre-install is faster on
   high-frequency targets. Recommendation: pre-install on the
   `kensa-rules` RPM model (binary cached at
   `/usr/local/lib/kensa/agent-<sha>` with version handshake fallback).

3. **CLI rollout sequence: ship Phase 1 first, or fold into a single
   bigger CLI PR.** Phase 1 alone fixes the four ergonomic bugs
   operators and agents hit immediately (`-h` doesn't work, `--help`
   exits 1, etc.). Recommendation: ship Phase 1 immediately; phase
   the rest as the agent-mode work proceeds.

4. **Documentation cadence: when to refresh `STATUS.md`.** This
   directory's discipline depends on `STATUS.md` not going stale
   like `NEW_SESSION_LOG.md` did. Recommendation: update at every
   merge that closes one of the items; treat staleness > 14 days as
   a documentation bug.

---

## How to Use These Docs

**For an AI engineer:** read `STATUS.md` first to understand current
state, then this README for the synthesis, then the relevant
`*_V1.md` plan for the deep specification. Don't propose work that
contradicts the mission statement (loaded from project memory) or
the transaction contract.

**For the founder:** the README is the briefing. STATUS is the
dashboard. The two `*_V1.md` plans are the source-of-truth. Anything
in flight should be reflected in STATUS within 14 days.

**For a future maintainer:** if you're picking up the project after a
gap, read in this order: `CLAUDE.md` → `docs/TRANSACTION_CONTRACT_V1.md`
→ `docs/roadmap/README.md` (this file) → `docs/roadmap/STATUS.md`.
Skip the long `*_V1.md` plans until you need them.

---

*Last updated: 2026-05-07.*
