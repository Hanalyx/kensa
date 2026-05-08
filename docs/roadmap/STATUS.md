# Roadmap Status

Per-item current state and next action. Update at every merge that
closes an item; treat staleness > 14 days as a documentation bug.

**Last refreshed:** 2026-05-07

---

## Status taxonomy

- **Not started** — not yet picked up
- **Draft** — plan written, not yet ratified by the founder
- **Adopted** — ratified; ready for implementation
- **In progress** — implementation underway on a branch
- **Shipped** — merged to `main`
- **Deferred** — explicitly deprioritized; will revisit
- **Archived** — abandoned or superseded

---

## M7 ship-gate items (`CLAUDE.md` punch list)

These block v1.0.0. Tracked here for visibility because they are the
critical path to first release.

| Item | Status | Owner | Next action |
|---|---|---|---|
| Ed25519 signer (task #12) | Not started | — | Replace `internal/engine/stubs.go` `noopSigner`; wire `kensa-keygen`; thread real signature through `EvidenceEnvelope` |
| First-principles integration tests for 10 untested handlers | Not started | — | Add tests for `authselectfeatureenable`, `commandexec`, `configappend`, `cryptopolicyset`, `cryptopolicysubpolicy`, `dconfset`, `grubparameterremove`, `grubparameterset`, `manual`, `pammodulearg` |
| `audit_rule_set` real implementation | Stub only | — | Replace stub in `internal/handlers/auditruleset/` with `auditctl` shell-out (or `AUDIT_NETLINK` per kernel migration Phase 5) |
| `grub_parameter_set` deadman guard | Not started | — | Wire deadman timer for grub-touching transactions before the handler is unmarked-experimental |
| Default `/usr/share/kensa/rules` path resolution | Not started | — | Implement `internal/rules/paths.go`; remove `--rules-dir` mandatory check |
| ~~Parity test sweep vs Python kensa~~ | **Retired** | — | Python kensa has no production users; retired as ship-blocker on 2026-05-07 |

---

## Roadmap workstreams

### `LOW_LEVEL_MIGRATION_V1.md` — kernel-primitive atomicity

**Overall status:** Draft — not yet ratified.
**Estimated total scope:** ~6 weeks elapsed (Phase 0) + 14 weeks single-engineer sequential (Phases 1–7); 10 weeks with two engineers parallelizing where possible.
**Dependencies:** None external. Phases 2–7 gate on Phase 1 (agent mode).

| Phase | Status | Estimated size | Next action |
|---|---|---|---|
| Phase 0 — Build discipline (`CGO_ENABLED=0`, `netgo`, `GODEBUG=netdns=go`) | **DONE** (6 of 6 items, 2026-05-08) | ~½ day | All shipped: L-001 `08a195f`, L-002 `f51cba7`, L-003 `798945d`, L-004 `26844b0`, L-005 `969be68`, L-006 `22c1c95`. Static binary, pure-Go DNS, ldd assertion, glibc 2.28 + musl tests, README portability docs — all live. |
| Phase 1 — Multi-call agent binary (`kensa agent --stdio`) | Not started | 4–6 weeks | Founder ratification on wire-protocol decision (L-007 in DELIVERABLES.md); gates Phases 2–7 |
| Phase 2 — File atomicity primitives (`renameat2`, `O_TMPFILE`, `fsync`, `syncfs`) | Not started | ~2 weeks | Gates on Phase 1 |
| Phase 3 — Deadman timer rebuild (`timerfd(CLOCK_BOOTTIME)`, `pidfd_open`, `epoll`, `signalfd`) | Not started | ~2 weeks | Gates on Phase 1 |
| Phase 4 — systemd D-Bus for service handlers | Not started | ~1 week | Gates on Phase 1 |
| Phase 5 — `AUDIT_NETLINK` (rule mgmt + transaction event emission) | Not started | ~2 weeks | Gates on Phase 1; pairs with `audit_rule_set` M7 item |
| Phase 6 — Direct kernel IO for sysctl, mount, kernel-module | Not started | ~1 week | Gates on Phases 1, 2 |
| Phase 7 — SELinux runtime + dconf D-Bus | Not started | ~1 week | Gates on Phase 1 |
| Stretch A — Btrfs/ZFS opportunistic snapshots | Not started | post-1.0 | Customer demand signal will trigger |
| Stretch B — Per-handler sandboxing (seccomp + cgroups v2 + `clone3`) | Not started | post-1.0 | — |
| Stretch C — eBPF tracepoint capture-sufficiency verification | Not started | post-1.0 | Requires kernel ≥ 5.4; bumps RHEL 8 EOL constraint |
| Stretch D — Mount-namespace + overlayfs Plan substrate | Not started | post-1.0 | — |

### `CLI_GNU_POSIX_MIGRATION_V1.md` — CLI overhaul

**Overall status:** Draft — not yet ratified.
**Estimated total scope:** ~6 weeks single-engineer sequential.
**Dependencies:** Independent of the kernel migration; no `api/` impact.

| Phase | Status | Estimated size | Next action |
|---|---|---|---|
| Phase 1 — pflag swap, `-h, --help`, `--version`, exit codes 0/1/2 | In progress (2 of 10 items done) | ~2 days | C-001 (`cde364d`) + C-002 (`f91980d`) merged 2026-05-08. C-003 (runCheck pflag migration) is next |
| Phase 2 — `--output FORMAT[:PATH]` mechanism (json, jsonl, csv, pdf, evidence, oscal, markdown) | Not started | ~1 week | PDF library decision needed (`unidoc/unipdf` vs `gofpdf` vs `maroto`) |
| Phase 3 — Full `target_options` + `rule_options` parity | Not started | ~1.5 weeks | Inventory glob matching, password prompt, strict-host-keys, capability override, workers, full rule filtering |
| Phase 4 — Session model in store + `kensa diff`, framework `kensa coverage`, `kensa list frameworks`, `kensa info`, `--stats`/`--prune` | Not started | ~2 weeks | SQLite schema migration needed; `kensa coverage` → `kensa mechanisms` rename with deprecation cycle |
| Phase 5 — kensa-go-specific surfaces (`jsonl` everywhere, `oscal` everywhere, signed envelopes, manpage, `agent` placeholder) | Not started | ~1 week | Gates on signer (M7) for signed-envelope output to be cryptographically real |

---

## Stale / unfinished items in the broader doc corpus

Surfaced by the audit on 2026-05-07. Not roadmap items proper, but
worth tracking here so they aren't forgotten.

| Item | Status | Next action |
|---|---|---|
| `NEW_SESSION_LOG.md` 23 days stale (references M1 as current achievement when M1–M6 are complete) | **Closed 2026-05-07** | Banner added at top pointing readers at `CLAUDE.md` and `docs/roadmap/README.md`; body preserved as historical record |
| `KENSA_GO_DAY1_PLAN.md` 40-week schedule reframing | Not started | Replace "Week N" with "Phase N"; add note that the calendar was AI-compressed |
| `RULE_REVIEW_GUIDE_V1.md` test-status note | Not started | Add paragraph after §1 noting which handlers ship without integration tests |
| Specter version pin update (CLAUDE.md says 0.10.2; local install is 0.12.0) | In progress | The current branch `feat/specter-0.10.2-rollout` is the migration; bump pin and CI when merged |

---

## Decisions awaiting founder ratification

1. **v1.0 scope** — ship now with scoped contract, or wait until kernel-migration Phase 2?
2. **Agent push model** — per-session push vs pre-install via package?
3. **CLI Phase 1 timing** — ship today as a tightly-scoped fix, or fold into a bigger CLI PR?
4. **Rule-corpus housing** — stay in `/home/rracine/hanalyx/kensa/rules/`, move to a new `kensa-rules` repo, or fold into kensa-go?
5. **OpenWatch coordination memo refresh** — `docs/coordination/KENSA_OPENWATCH_PROGRESS_2026-04-15.md` is stale (M3-era) and was never sent; refresh with M6 state and send, or archive in place?

---

*This file is maintained by AI sessions working on kensa-go. Update at every merge that closes one of the items above. If you find this file is more than 14 days stale, that is a documentation bug — flag it and either refresh it or note the staleness explicitly.*
