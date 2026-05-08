# Low-Level Migration Plan — Version 1

**Project:** Kensa Go
**Date:** 2026-05-07
**Status:** Draft — Roadmap document, not yet ratified
**Audience:** Kensa engineers, founder/reviewer, future AI sessions
**Companion:** `docs/TRANSACTION_CONTRACT_V1.md`, `docs/foundation_docs/TECHNICAL_REMEDIATION_MP_V1.md`, `docs/context/KENSA_GO_DAY1_PLAN.md`

---

## Why This Document Exists

`TRANSACTION_CONTRACT_V1.md` makes three external commitments — atomicity,
auditability, reversibility. An audit of the current code (2026-05-05) found that
those commitments are backed predominantly by shell commands executed over SSH,
rather than by Linux kernel primitives or stable userspace ABIs. The atomicity
claim is therefore aspirational where it should be literal: a crash mid-Apply
leaves the system in whatever state shell IO produced, and rollback depends on a
deadman scheduler (`at(1)` / `systemd-run`) running on a host that may itself be
the source of the failure.

The strategic argument for going lower is straightforward and uncontested:
**the kernel ABI is the only stability surface in Linux you can count on for
the lifetime of a federal compliance customer's purchase.** glibc has a
compatibility floor. Userspace daemons change. CLI output formats are not
contracts. The kernel ABI is.

This document plans the migration in phases, identifies what gates on what,
and is explicit about which subsystems will continue to use CLI shell-out
because no honest direct API exists.

---

## 1. Scope and Non-Goals

### In scope

- Replacing shell-based handler execution with direct kernel syscalls,
  Linux-stable D-Bus interfaces, and netlink protocols where they exist.
- Restructuring the binary so the kernel-primitive work can execute on the
  target host rather than only on the controller.
- Build discipline that delivers the static-binary portability claim
  (`CGO_ENABLED=0`, pure-Go DNS, no glibc floor).
- Updating `TRANSACTION_CONTRACT_V1.md` to match what is literally true once
  each phase lands.

### Out of scope

- Re-implementing what dpkg, rpm, dnf, GRUB, cron, PAM, or
  `update-crypto-policies` do. These subsystems do not expose a stable direct
  API and will continue to be invoked via CLI. We will instrument the
  invocations more carefully, not replace them.
- Changing the rule corpus or the `api/` public surface. This migration is
  internal — handler-by-handler refactors with unchanged inputs and outputs.
- A from-scratch rewrite. Each phase delivers user-visible improvement on its
  own and does not require subsequent phases to ship.

---

## 2. The Gating Architectural Shift: Agent Mode

Kernel syscalls are local. The controller cannot `renameat2`,
`fsync`, `timerfd_create`, `pidfd_open`, or `mount(2)` against a remote target
from its own syscall surface. As long as the wire-level vocabulary between
controller and target is shell, the kernel-primitive bet is unreachable.

**The fix:** make `kensa` a multi-call binary. The same static binary runs in
two modes:

- **Controller mode** (current behavior): orchestrates transactions, opens an
  SSH ControlMaster session to each target.
- **Agent mode** (new): invoked by the controller via
  `ssh <host> kensa agent --stdio`, runs to completion, exits when SSH closes.
  Performs all kernel-syscall and D-Bus work on the target.

The wire protocol between controller and agent is length-prefixed protobuf or
msgpack over the SSH stdin/stdout channel. The deadman heartbeat travels on
the same channel — no second connection to fail independently.

This preserves the single-static-binary commitment literally. There is one
binary. It runs in two modes. (Same pattern as busybox; same pattern that
`kubectl` and `kubelet` would have if they had been designed as one binary.)

**Phase 1 below is this shift.** Every subsequent phase depends on it.

---

## 3. Phased Migration

Each phase is independently shippable: stop after any phase and the binary is
strictly better than before. Phases are ordered by leverage — earlier phases
unlock more downstream wins per unit of effort.

### Phase 0 — Build Discipline (no agent required)

**Goal:** Deliver the static-binary portability claim today, independent of
the agent rework.

**Deliverable:**
- `CGO_ENABLED=0` and `-tags netgo` in the Makefile, in
  `.github/workflows/ci.yml`, and in any release/goreleaser config.
- `GODEBUG=netdns=go` baked into the binary via a build-time constant or a
  `default.go` `init()`.
- A CI step that runs `ldd ./kensa` after build and fails if the output is
  anything other than `not a dynamic executable`.
- A CI step that runs the binary inside a `glibc 2.28` container (RHEL 8
  vintage) and a `musl` container (Alpine) to prove the portability claim.

**Dependency:** Verify `modernc/sqlite` (the current store backend) is pure
Go. It is, but pin the version and add a `go test ./...` step that runs with
`CGO_ENABLED=0` to guard against accidental cgo introduction by transitive
deps.

**Risk:** Low. `modernc/sqlite` is already pure-Go; no other transitive deps
in `go.mod` look cgo-bound. If a later dep introduces cgo, the new CI gate
catches it.

**Size:** Half a day. Does not require an agent and should land first.

---

### Phase 1 — Multi-Call Agent Binary

**Goal:** The same `kensa` binary, when invoked as `kensa agent --stdio`,
becomes a target-local executor that talks to the controller over framed
stdin/stdout.

**Deliverable:**
- New subcommand `kensa agent --stdio` in `cmd/kensa/main.go`.
- `internal/agent/` package with:
  - Wire-protocol framing (length-prefixed protobuf; reuse the existing
    `api/` types where applicable).
  - A request dispatcher that maps wire messages to handler invocations.
  - A heartbeat consumer for the deadman channel.
- New transport adapter under `internal/transport/ssh/` that, instead of
  shipping shell commands, ships the agent binary (via `scp`-equivalent or
  inline base64 if not already present, with caching by SHA256 in
  `~/.cache/kensa/agent-<hash>`) and invokes it with `ssh <host> kensa agent
  --stdio`.
- Version-skew detection: controller and agent exchange version handshakes
  on session start; mismatched majors abort.

**Migration approach:**
- Introduce agent mode behind a feature flag (`--agent` on the controller).
  Default off for one release.
- One handler at a time gets ported to "runs in agent" alongside its existing
  "runs as shell over SSH" path. Both paths produce identical
  `api.RemediationResult` envelopes; differential testing keeps them honest.
- When all handlers ported, agent mode becomes default. The shell-only path
  is removed in the release after.

**Dependency:** None (this is the gate).

**Risk:** Medium. Two real concerns:
1. **Binary push cost.** Pushing a ~30 MB Go binary on every session adds
   latency. Mitigation: SHA-pinned cache on the target side
   (`/usr/local/lib/kensa/agent-<sha>`), and an optional pre-installed agent
   for high-frequency targets.
2. **Privilege model.** Agent runs as the SSH user. If that user isn't root,
   privileged operations need sudo escalation just as today. The agent does
   not increase the privilege floor. This is fine but must be documented.

**Size:** Estimate 4–6 weeks of focused work. This is the largest phase by
far. Suggest two-engineer review; the wire protocol and dispatcher are
security-load-bearing.

---

### Phase 2 — File Atomicity Primitives

**Goal:** `file_content`, `file_permissions`, `config_set`,
`config_set_dropin`, `file_absent` use kernel-level atomicity primitives.

**Deliverable:**
- `internal/agent/fsatomic/` package wrapping
  `golang.org/x/sys/unix.Renameat2(..., RENAME_EXCHANGE)`,
  `O_TMPFILE` + `unix.Linkat`, `unix.Fsync` on file fd and parent-dir fd, and
  `unix.Syncfs` for batched commit.
- `Apply` for the five handlers above writes through this package:
  1. Open `O_TMPFILE` in the target directory.
  2. Write content.
  3. `fsync(fd)`.
  4. `linkat(fd, dirfd, name)` to publish atomically — or, when replacing
     existing content, `renameat2(RENAME_EXCHANGE)` on a temp-name sibling.
  5. `fsync(dirfd)`.
- Commit phase issues a single `syncfs()` per touched filesystem instead of
  per-file syncs.

**Dependency:** Phase 1.

**Risk:** Low. These primitives are decade-stable. The one trap:
`RENAME_EXCHANGE` requires both paths to exist; the publish path for *new*
files uses `O_TMPFILE` + `linkat` instead. Handler tests cover both.

**Size:** ~2 weeks.

**Validates:** First phase where the literal atomicity claim becomes true for
any handler. Update `TRANSACTION_CONTRACT_V1.md` to scope the atomic claim to
file-handler operations explicitly.

---

### Phase 3 — Deadman Timer Rebuild on Kernel Primitives

**Goal:** The deadman survives suspend, clock jumps, parent SIGSTOP, and
absence of `at(1)` / `systemd-run` on the target.

**Deliverable:**
- `internal/deadman/` rewritten to use:
  - `unix.TimerfdCreate(unix.CLOCK_BOOTTIME, 0)` for the rollback timer.
  - `unix.PidfdOpen(getppid(), 0)` for parent-death detection.
  - `unix.Prctl(unix.PR_SET_PDEATHSIG, unix.SIGKILL)` as the
    belt-and-suspenders fallback.
  - `unix.SignalfdCreate` for SIGTERM.
  - `unix.EpollCreate1` single-event-loop integrating timerfd + pidfd +
    signalfd + the control-channel socket fd.
- The current `at(1)` / `systemd-run` path is removed once the new path
  passes the kensa-fuzz harness on RHEL 8, RHEL 9, Ubuntu 22.04, and Ubuntu
  24.04 — RHEL 8 is the floor because of `glibc 2.28`, but the kernel ABI
  does not depend on glibc, so this should pass uniformly.

**Dependency:** Phase 1 (the deadman runs in the agent).

**Risk:** Low–medium. The primitives are stable. The risk is in the
event-loop design — the reviewer's note specifically called out clock-jump,
suspend-mid-transaction, and SIGSTOP edge cases. Each gets a dedicated test
in `cmd/kensa-fuzz/`.

**Size:** ~2 weeks.

---

### Phase 4 — systemd via D-Bus

**Goal:** `service_enabled`, `service_disabled`, `service_masked` stop
shelling out to `systemctl`.

**Deliverable:**
- `internal/agent/systemdbus/` wrapping
  `github.com/coreos/go-systemd/v22/dbus`. Connects to the system bus at
  `/run/dbus/system_bus_socket`.
- Handler ports use `EnableUnitFiles`, `DisableUnitFiles`, `MaskUnitFiles`,
  `StartUnit`, `StopUnit`, `GetUnitFileState`, with explicit handling of
  the two well-known traps:
  1. `StartUnit` returns a job object asynchronously — subscribe to
     `JobRemoved` and wait for the matching `path` before returning.
  2. `EnableUnitFiles` writes symlinks but does not reload — call
     `Reload()` immediately after.

**Dependency:** Phase 1.

**Risk:** Low. The systemd D-Bus interface is one of the most explicitly
stability-promised surfaces in Linux userspace. The library is mature.

**Size:** ~1 week.

---

### Phase 5 — Linux Audit via AUDIT_NETLINK

**Goal:** Two wins from one library.

**Deliverable:**
- `internal/agent/auditnl/` using
  `github.com/elastic/go-libaudit/v2`, which is a pure-Go netlink client
  (no cgo).
- `audit_rule_set` handler: replace `auditctl` shell-out with direct rule
  configuration via `AUDIT_ADD_RULE` netlink messages. State capture reads
  the loaded rule set via `AUDIT_LIST_RULES`.
- **New:** transaction-phase audit-event emission. The engine emits a
  structured AUDIT_USER message at the start and end of each transaction
  phase (Capture, Apply, Validate, Commit, Rollback), landing those events
  in `auditd`'s log. This is the AUDIT_NETLINK observability the reviewer
  flagged — non-negotiable for FedRAMP customers, and the netlink path is
  the only one that integrates with existing SIEM pipelines without
  additional plumbing.

**Dependency:** Phase 1.

**Risk:** Low. AUDIT_NETLINK is a kernel ABI. The library is used by
`auditbeat` in production at scale.

**Size:** ~2 weeks (1 week for the handler, 1 week for engine event
emission and audit-log envelope schema).

**Validates:** The auditability commitment in `TRANSACTION_CONTRACT_V1.md`
becomes literal — every transaction phase produces an event in the
host's `auditd` log, not just in Kensa's own evidence file.

---

### Phase 6 — Direct kernel IO for sysctl, mount, kernel-module

**Goal:** Drop the `sysctl`, `mount`, and `modprobe` shell-outs for runtime
operations.

**Deliverable:**
- `sysctl_set`: write to `/proc/sys/<key>` for runtime apply, write to
  `/etc/sysctl.d/*.conf` for persistence. Both are file IO at the agent
  level. The shell-out to `sysctl -w` goes away.
- `mount_option_set`: `unix.Mount` for runtime; `/etc/fstab` file edit for
  persistence.
- `kernel_module_disable`: `/etc/modprobe.d/<name>.conf` blacklist file
  for persistence; optional `unix.DeleteModule` for runtime unload.

**Dependency:** Phase 1, Phase 2 (re-uses the file-atomicity primitives for
the persistence paths).

**Risk:** Low.

**Size:** ~1 week total across the three handlers.

---

### Phase 7 — SELinux runtime + dconf

**Goal:** Reduce the SELinux and dconf shell-outs to the minimum unavoidable
set.

**Deliverable:**
- `selinux_boolean_set`: write to `/sys/fs/selinux/booleans/<name>` for the
  runtime apply (kernel ABI). Persistence still requires `semanage` because
  the file format under `/var/lib/selinux/` is not a documented contract.
  Tag this handler explicitly in the audit envelope as "kernel-runtime +
  semanage-persistence" so the audit trail records *how*.
- `dconf_set`: D-Bus calls to `ca.desrt.dconf` via `godbus/dbus/v5` directly.

**Dependency:** Phase 1.

**Risk:** Medium for SELinux: the persistence file format is an
implementation detail; we will not write to it, only invoke `semanage`. Be
honest about this in the contract update.

**Size:** ~1 week.

---

## 4. Stretch Phases (Post-1.0)

These deliver real value but are too large or too dependent on customer-side
prerequisites to gate v1.0 on. Listed in rough decreasing-leverage order.

### Stretch A — Btrfs / ZFS opportunistic snapshots

Detect Btrfs/ZFS at session start. When the touched paths fall under a
single subvolume/dataset, snapshot before the transaction
(`BTRFS_IOC_SNAP_CREATE_V2` or `zfs snapshot`). Rollback becomes "discard
the snapshot" instead of "replay reverse operations" — dramatically simpler
and atomic in a way the WAL approach can never quite be. Most customer hosts
are still ext4 today, so this is a feature flag and a fall-through, not a
mandatory path.

### Stretch B — Per-handler sandboxing

`clone3(CLONE_INTO_CGROUP)` to launch each handler in a cgroups v2 slice
with memory/CPU/IO caps; seccomp-bpf to drop syscalls a handler cannot
need. Limits blast radius from a misbehaving handler on the target. Real
work, real win, but post-1.0.

### Stretch C — eBPF tracepoint capture-sufficiency verification

Hook `sched_process_exec`, `openat`, and `unlinkat` from a small BPF program
loaded via `cilium/ebpf`. Records exactly what files a handler touches
during Apply, then mechanically verifies that Capture recorded all of those.
Closes the capture-completeness review loop the founder currently does by
hand. Requires CO-RE and a target kernel ≥ 5.4. Customer-environment
prerequisite makes this post-1.0.

### Stretch D — Mount-namespace + overlayfs Plan substrate

For filesystem-effect handlers, run Plan inside `unshare(CLONE_NEWNS)` with
an overlayfs whose lowerdir is the real rootfs. Diff the upperdir to compute
the real change set. Does not work for handlers that mutate kernel state
(`sysctl`, `selinux`), systemd state (`service_*`), or package-manager state
— so its applicability is a strict subset. Useful enough to pursue, but not
a v1.0 commitment.

---

## 5. Subsystems That Will Continue to Shell Out

Not every handler has a viable direct API. The honest answer for these is:
keep the shell-out, but make it auditable, well-tested, and honestly
characterized in the audit envelope.

| Handler / subsystem | Why CLI is the answer |
|---|---|
| `package_present`, `package_absent`, `apt_present`, `apt_absent` | `libapt-pkg` is C++; `librpm` is C with cgo. PackageKit is an incomplete D-Bus wrapper not always installed. CLI is the stable interface in practice. |
| `grub_parameter_set`, `grub_parameter_remove` | No API. `/etc/default/grub` edit + `grub-mkconfig` regeneration is the only path. |
| `cron_job` | No API. Crontab files only. |
| `pam_module_configure`, `pam_module_arg` | `libpam` is C; no structured config API. `/etc/pam.d/*` files only. |
| `crypto_policy_set`, `crypto_policy_subpolicy` | `update-crypto-policies` is a Python script. No API. |
| `authselect_feature_enable` | CLI only. |
| `command_exec`, `manual` | By definition operator-supplied; no atomicity claim. |

For these, Phase 5's audit emission becomes the substitute observability
guarantee: every CLI invocation is recorded with argv, exit code, stderr
hash, and a timing envelope. The customer gets a real audit trail even
where the kernel cannot guarantee atomicity.

---

## 6. Updates to TRANSACTION_CONTRACT_V1.md

Each phase changes what the contract can honestly claim. Suggested phasing
of contract amendments:

- **After Phase 0:** add the static-binary portability commitment with
  glibc-floor independence. This is currently aspirational; Phase 0 makes
  it literal.
- **After Phase 2:** scope the atomicity commitment for *file* handlers
  explicitly to the kernel-primitive guarantee. The contract today
  over-claims for these; Phase 2 lets it stop over-claiming.
- **After Phase 3:** the rollback-survives-suspend-and-clock-jump claim
  becomes literal. Add the failure-mode list the deadman now actually
  handles.
- **After Phase 5:** the auditability commitment becomes literal in the
  AUDIT_NETLINK sense. Customer SIEM integration is no longer an exercise
  for the customer.
- **After Phase 7:** the contract should add a per-handler "atomicity
  basis" table. Each handler is tagged as one of:
  - `kernel-atomic` (file primitives + fsync barriers)
  - `kernel-runtime + file-persistence` (sysctl, mount, kernel-module,
    selinux-boolean)
  - `daemon-atomic` (systemd D-Bus job-completion synchronization)
  - `cli-best-effort` (package, GRUB, cron, PAM, crypto-policies)

Tagging matters because customer auditors will ask which handlers the
atomicity claim applies to, and "all of them" is not the right answer.

---

## 7. Sequencing and Dependencies

```
Phase 0 (build discipline) ── ships independently, week 1
                              │
                              ▼
Phase 1 (agent mode) ─────────┬─── 4–6 weeks, gates everything below
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
Phase 2 (file atomicity) Phase 3 (deadman)    Phase 4 (systemd)
   ~2 weeks                ~2 weeks              ~1 week
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                       Phase 5 (audit-netlink)
                              ~2 weeks
                              │
                              ▼
                       Phase 6 (sysctl/mount/module)
                              ~1 week
                              │
                              ▼
                       Phase 7 (SELinux + dconf)
                              ~1 week
```

Phases 2/3/4 can run in parallel after Phase 1 lands; they touch disjoint
subsystems. Phase 5 reuses the engine-level event emission from Phase 3's
deadman work, so it's slightly easier if Phase 3 ships first.

**Total elapsed time, single engineer, sequential:** ~14 weeks after Phase 0.
**Total elapsed time, two engineers, parallel where possible:** ~10 weeks.

This is post-M7 work. It does not block v1.0 if v1.0 is scoped to "what
the current orchestrator-over-SSH design can honestly deliver." It is
v1.1 / v2.0 work if v1.x is scoped to "what the contract literally claims."
The product decision of which scope v1.0 takes is the gating call for this
roadmap.

---

## 8. Decision Points

The founder/reviewer should explicitly decide:

1. **v1.0 scope.** Ship v1.0 with the current architecture and amend the
   contract to match — or hold v1.0 until at least Phase 2 lands and the
   atomicity claim is literal for file handlers? The first ships sooner;
   the second ships a stronger product.
2. **Agent push model.** Push the agent every session (always-fresh, slower
   start) or pre-install via package (faster, version-skew handling
   needed)? Both are supportable; the choice affects ops documentation.
3. **Phase 0 timing.** Phase 0 is independent of the rest and is a
   half-day's work. Recommend landing it on the current branch or the next
   one regardless of the rest of this plan.

Once these are decided, this document graduates from "Draft" to "Adopted"
and the phase scopes become work-tracked.
