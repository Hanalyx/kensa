# Roadmap Status

Per-item current state and next action. Update at every merge that
closes an item; treat staleness > 14 days as a documentation bug.

**Last refreshed:** 2026-05-09

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
| Phase 1 — pflag swap, `-h, --help`, `--version`, exit codes 0/1/2 | **DONE** (10 of 10 items, 2026-05-08) | ~2 days | All shipped: C-001..C-010. Latest merge: `b1ff51a`. All 3 CLI binaries pflag-based; GNU/POSIX exit codes 0/1/2 enforced; UsageError type; centralized short-letter table; legacy single-dash long forms preserved with deprecation warnings; cli-smoke.sh CI gate. cmd/kensa unit-test coverage 65.6% (90% gap is architectural — TransportFactory mock pending). |
| Phase 2 — `--output FORMAT[:PATH]` mechanism (json, jsonl, csv, pdf, evidence, oscal, markdown) | **DONE** (10 of 10, 2026-05-08) | ~1 week | All shipped. Latest merge: `7c24dc3` (C-020). Full surface: parser (C-011), per-payload writer interfaces (C-012), CSV (C-013), PDF via maroto v2 (C-014/C-015), OSCAL wired (C-016), evidence wired (C-017), `--quiet` (C-018), concurrent fan-out for `-o FORMAT[:PATH]` (C-019), `--format`/`--oscal` deprecation warnings + CHANGELOG (C-020). cli-smoke.sh grew 41→54 over the phase. Spec corpus 22→31. Static-binary discipline preserved. KENSA_NO_DEPRECATION_WARNINGS=1 env-var opt-out for CI noise control. |
| Phase 2.5 — Operator UX refresh | **DONE** (3 of 3, 2026-05-08) | ~2.5 days | All shipped. Latest merge: `cfe93aa` (C-023). Full surface: rule ordering + conflict/supersedes resolution (C-021), textScanWriter operator-UX rewrite (C-022), OS detection + `-i`/`-v` short forms (C-023). The default `kensa check` output now matches the founder's mockup at ~70% fidelity: failure-first grouped layout, severity badges, fix-line synthesis, glob-compacted PASSED, progress bar, host banner with detected OS ("─── 192.168.1.211 · RHEL 9.6 ──"). Remaining mockup features tracked for follow-up: auth method ("· root via sudo") needs SSH transport threading, wall-clock duration needs scan-result instrumentation, report-path callout needs cmd/kensa to thread `-o`. cli-smoke: 54/54. Spec corpus: 31→34 over the phase. Live-verified against the 539-rule corpus on 192.168.1.211. |
| Phase 3 — Full `target_options` + `rule_options` parity | **DONE** (13 of 13; 2 deferred to 3.5; 2026-05-09) | ~1.5 weeks | C-024..C-033, C-035, C-037, C-038 shipped (latest `771c57e`). **C-034 + C-036 deferred to Phase 3.5** (variable-infra design pass). Phase 3 surface: --password/-p, --strict-host-keys/--no-strict-host-keys, --capability/-C, --workers/-w, --severity/-s, --tag/-t, --category/-c, --framework/-f, --control, --rule, plus C-024 inventory and C-025 --limit (already in M1). C-038 help-grouping wraps the Phase: detect/check/remediate `--help` now categorized into Target/Rule/Output/General sections per migration doc §3.2-3.5. cli-smoke.sh grew 54→99. Spec corpus 34→47. Live-verified end-to-end: `-s critical -t pci -f cis-rhel9` filter chain works with disambiguating empty-after-filter errors. |
| Phase 3.5 — Rule-variable infrastructure | **DONE** (2 of 2; 2026-05-09; merged `bb96a28`) | 1-2 days | C-034 + C-036 shipped together. Built `internal/varsub` package (Substitute / LoadDefaults / Merge / ErrUndefined sentinel), `rule.ParseFileWithVars`, `--var/-x KEY=VALUE` and `--config-dir DIR` flags. Resolution priority: CLI --var > <config-dir>/defaults.yml (2-tier minimum; Phase 3.6 adds per-host / per-group / conf.d). Dir-walk path aggregates ErrUndefined skips into an end-of-load summary so the missing-infrastructure signal isn't buried. 32 unit tests (incl. Merge-associativity for forward-compat). Live-verified `kensa check --rule pam-faillock-deny.yml -x pam_faillock_deny=3` end-to-end on 192.168.1.211. Spec: `specs/cli/variable-substitution.spec.yaml` (7 constraints, 23 ACs). |
| Phase 3.6 — Multi-tier variable resolution | **DONE** (2026-05-09; merged `cc68f0e`) | 1 day | Completes the Python kensa 5-tier chain. Added LoadHost / LoadGroups / LoadConfDir / ResolveTiers to internal/varsub. Single-host check + remediate use full 5-tier resolution (defaults → conf.d → groups → hosts → CLI). Inventory mode runs 3-tier (defaults + conf.d + CLI); per-host inventory vars deferred to Phase 3.7 with stderr warning when operator's config-dir has hosts/ or groups/ subdirs. 18 new tests covering all four loaders + 5-tier full-chain priority + symmetry checks (validation applies uniformly across all tier sources). Live-verified host file beating defaults+conf.d, CLI beating host file. Spec: `specs/cli/variable-tiers.spec.yaml` (7 constraints, 15 ACs). |
| Phase 3.7 — Per-host vars active in inventory mode | **DONE** (2026-05-09; merged `60f8933`) | ~4 hours | Closes the Phase 3.6 inventory gap. Each per-host fan-out goroutine resolves its own 5-tier vars (defaults + conf.d + groups (from inventory) + hosts/<addr>.yml + CLI) and re-loads the corpus with those vars. Output rendering uses per-host rule slice (hostResult.rules) instead of a global one — fixes a misalignment bug surfaced in peer review where rules with host-only vars would mis-align in csv/text writers. Phase 3.6's stderr warning removed. New ruleLoadFilterSpec helper in cmd/kensa/rule_pipeline.go captures load+filter inputs for per-host re-load. 4 new unit tests + live-verified end-to-end: defaults → host-file priority works in inventory mode; mixed templated + untemplated corpus renders with correct IDs. Spec: `specs/cli/inventory-perhost-vars.spec.yaml` (6 constraints, 11 ACs). |
| Embedded defaults + --config-dir auto-detect | **DONE** (2026-05-09; merged `33f6d57`) | ~4 hours | Closes the silent-skip gap on the canonical command. Vendored Python kensa's `defaults.yml` `variables:` block via `go:embed` as the lowest tier (6) of the resolution chain. Implemented C-036's auto-detect chain: `$KENSA_CONFIG_DIR` → `$XDG_CONFIG_HOME/kensa` → `$HOME/.config/kensa` → `/etc/kensa`. Operator-reported regression ("23 rule(s) skipped — undefined variables" on `kensa check -s critical -s high`) eliminated; rule set expands from ~47 to 70 rules out of the box. 13 new tests (5 embedded + 8 auto-detect). Spec: `specs/cli/embedded-defaults.spec.yaml` (6 constraints, 13 ACs). |
| Phase 4 — Session model in store + `kensa diff`, framework `kensa coverage`, `kensa list frameworks`, `kensa info`, `--stats`/`--prune` | **DONE** (12 of 12, 2026-05-09) | ~2 weeks | All shipped. C-039 `21885a7`, C-040 `391d878`, C-041 `aea016f`, C-042 `2b0a61e`, C-043 `3a69700`, C-044 `33db2e4`, C-045 `a194195`, C-046 `5c1f97f`, C-047 `389534e`, C-048 `be4820c`, C-049 `c99ca33`, C-050 (close) `66d080c`. Spec corpus 50→63 over the phase. cli-smoke 99→173 (+74 scenarios). Phase 4 surface: session schema + `kensa migrate`, `kensa check --store`, `kensa history --stats / --prune`, `kensa mechanisms` (formerly `coverage`) + `coverage --framework` repurpose, `kensa list frameworks` / `list sessions`, `kensa info`, `kensa diff`, `kensa rollback --list/--info/--start/--detail`. **Two P2 follow-ups deferred**: (1) dual-store-handle smell in runRollbackStart — extend kensa.Default service interface with session-aware methods; (2) DRY refactor of cleanSessionLookupError twins between diff.go and rollback_session.go. |
| Phase 5a — jsonl wiring (3 subcommands), OSCAL regression sweep, manpage, `agent --stdio` stub, deprecation cleanup | **DONE** (6 of 6, 2026-05-10) | ~3 days | All shipped. C-051 `3470703`, C-052 `9bc3d9c`, C-053 `1cde0b1`, C-054 `23b19c5`, C-055 `4d9969f`, C-056 (close) `a09f6f0`. Spec corpus 63→69 over the phase. cli-smoke 173→214 (+41). Phase 5a surface: jsonl on history/list-sessions/info-QUERY (with document-mode rejection); OSCAL golden-file regression sweep with UPDATE_GOLDEN refresh path; `kensa agent --stdio` v1.0 placeholder reserving the name; `kensa(1)` Unix manpage hybrid (hand-written wrapper + generated body, drift gate via `make manpage-check`); CHANGELOG brought current with Phase 4 + Phase 5a surfaces. **Two P2 follow-ups still deferred from C-049/C-050**: (1) dual-store-handle smell in runRollbackStart; (2) DRY refactor of cleanSessionLookupError twins. |
| Phase 5b — signed-envelope output (Ed25519 through evidence path, kensa-keygen, verifier) | **Blocked** | ~1 week | C-060 gates on M7 task #12 (signer impl). Ships in v1.1 — v1.0 has no `noopSigner` placeholder claiming to sign. |

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
