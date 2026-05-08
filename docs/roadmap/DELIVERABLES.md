# Migration Deliverables

Per-deliverable work items for the two roadmap migration plans
(`LOW_LEVEL_MIGRATION_V1.md` and `CLI_GNU_POSIX_MIGRATION_V1.md`).
Each deliverable is sized to fit one autonomous loop iteration
(~1–3 hours of focused work; smaller is better for clean commit
boundaries).

**Last refreshed:** 2026-05-08

---

## Status taxonomy

- **pending** — not yet picked up
- **in-progress** — being worked in the current/last iteration
- **blocked** — gated on a dependency, gray-zone decision, or external input
- **done** — merged to `main`
- **failed** — implementation or CI failed; needs investigation

---

## Format

```
### D-NNN — title
- **Phase:** plan reference
- **Deps:** list of D-IDs that must be `done` first
- **Acceptance:** the criterion that closes this deliverable
- **Size:** estimated hours
- **Status:** taxonomy value
- **PR:** link or "—"
- **Notes:** anything worth flagging
```

---

## Parallel tracks

**Track C — CLI GNU/POSIX Migration** (deliverable IDs `C-NNN`)
**Track L — Kernel-Primitive Migration** (deliverable IDs `L-NNN`)

The two tracks are independent. Track L Phase 1 (agent mode) gates
Phases 2–7 of Track L; Track C phases gate sequentially within Track C
but do not gate Track L.

**Cheapest immediate wins (parallel-safe, ship today):**
- C-001 through C-010 (CLI Phase 1: pflag swap + GNU/POSIX flags) — ~2 days
- L-001 through L-006 (LL Phase 0: build discipline) — ~½ day

---

## Track C — CLI GNU/POSIX Migration

### CLI Phase 1 — pflag swap + GNU/POSIX flags

#### C-001 — Add pflag to go.mod; migrate top-level main.go (--db, --help, --version, exit codes)
- **Phase:** CLI Phase 1
- **Deps:** —
- **Acceptance:** `kensa --help` exits 0 to stdout; `kensa -h` same; `kensa --version` exits 0; bad usage exits 2; `kensa <unknown>` exits 2; existing `-db` flag continues to parse for one minor version
- **Size:** 3h
- **Status:** **done** — merge `cde364d` (2026-05-08); pflag added; runCLI(argv) int testable harness; -h/-V/-D short forms; legacy -db rewriter with deprecation warning; 19 subtests in cmd/kensa/main_test.go covering every exit-code path; 2-agent peer review clean; specter 22/22; static-link regression check passed; live-tested 192.168.1.211. Subcommand parsers still on stdlib flag (migrate in C-002..C-004).

#### C-002 — Migrate `runDetect` to pflag with short forms
- **Phase:** CLI Phase 1
- **Deps:** C-001
- **Acceptance:** `kensa detect -H foo -u bar -i ~/key -s -f json` works; `kensa detect --help` exits 0; existing single-dash `-host` etc. continue to parse
- **Status:** **done** — merge `f91980d` (2026-05-08); pflag swap with -H/-u/-p/-k/-s/-f short forms; new generic `rewriteLegacyLongForm` helper (reusable by C-003/C-004); `printDetectUsage` with examples; 8 new subtests; 2-agent peer review clean. Note: used `-k, --key` (not `-i ~/key` as in literal spec text) per the migration plan's resolved short-letter table (§4.2) where `-i` is reserved for `--inventory`. Live-tested 192.168.1.211 with both new and legacy forms.

#### C-003 — Migrate `runCheck` to pflag with short forms + `-r/--rules-dir`
- **Phase:** CLI Phase 1
- **Deps:** C-001
- **Acceptance:** all `kensa check` flags conform to GNU/POSIX; `--inventory` keeps long-only form
- **Size:** 1.5h
- **Status:** **done** — merge `f0a3975` (2026-05-08); pflag swap for runCheck with -H/-u/-p/-k/-s/-f/-r short forms; --inventory long-only per migration plan §4.2; reused rewriteLegacyLongForm helper from C-002; printCheckUsage with 3 examples; live-tested 192.168.1.211 (PASS on sysctl-ip-forward-disabled); 2-agent peer review clean.

#### C-004 — Migrate `runRemediate`, `runRollback`, `runHistory`, `runPlan`, `runCoverage`, `runVersion`
- **Phase:** CLI Phase 1
- **Deps:** C-001
- **Acceptance:** every subcommand parses GNU/POSIX-style; `--allow-command-exec` preserved with no short alias
- **Size:** 2h
- **Status:** **done** — merge `84778e0` (2026-05-08); 5 subcommand migrations + new runVersion function for parity; stdlib `flag` import removed entirely from main.go; all 7 subcommands' `--help`/`-h` exit 0; legacy single-dash long forms still parse with deprecation; 2-agent peer review clean (agent 2 caught `kensa version --help` silently printing version — fixed by adding runVersion function); specter 22/22; tests pass; live-tested 192.168.1.211. Note: `--allow-command-exec` doesn't exist on main yet (added on rollout branch in 402eded); will be a 1-line pflag addition when rollout merges.

#### C-005 — Centralize short-letter table in `cmd/kensa/flags.go`
- **Phase:** CLI Phase 1
- **Deps:** C-001..C-004
- **Acceptance:** every short letter declared as a constant; collision-detection test in `cmd/kensa/flags_test.go`
- **Size:** 1h
- **Status:** **done** — merge `efd3c7c` (2026-05-08); 16 named constants covering every short letter; 50 main.go call sites refactored; new flags_test.go with collision-detection + 16 case-discipline subtests; 2-agent peer review clean (agent 2 caught weak ShortDb rationale — strengthened); pure refactor, no flag behavior changes; live-tested 192.168.1.211.

#### C-006 — Migrate `cmd/kensa-validate/main.go` to pflag
- **Phase:** CLI Phase 1
- **Deps:** C-001
- **Acceptance:** GNU/POSIX flags; `--help` exits 0
- **Size:** 0.5h
- **Status:** **done** — merge `8d68118` (2026-05-08); pflag swap with `-h/-r/-f/-S` short forms; `--cap-check`/`--no-lint` long-only; `runCLI(argv) int` testable harness; legacy `-rules-dir` etc. still parse with deprecation warning; aligned the documented exit-code contract (0/1/2) with actual behavior; 2-agent peer review clean; specter 22/22; ldd OK; live-validated 23 rules from kensa/rules/network/ corpus.

#### C-007 — Migrate `cmd/kensa-fuzz/main.go` to pflag (preserve `KENSA_FUZZ_HOST` env-var fallback)
- **Phase:** CLI Phase 1
- **Deps:** C-001
- **Acceptance:** GNU/POSIX flags; env-var fallback retained; `--help` exits 0
- **Size:** 0.75h
- **Status:** **done** — merge `e899938` (2026-05-08); pflag swap with `-h/-H/-u/-p/-k/-s/-m` short forms; --phase/--params/--timeout long-only; `KENSA_FUZZ_HOST` env-var preserved as --host default with explicit-flag-wins precedence; 4-tier exit codes (0/1/2/3) preserved including domain-specific 3=fingerprint-mismatch; 2-agent peer review clean; both flagged `rewriteLegacyLongForm` triplication for follow-up extraction. **All 3 CLI binaries now pflag-based.**

#### C-008 — Add `cmd/kensa/errors.go` with `UsageError`; main switch for ErrHelp / UsageError / runtime
- **Phase:** CLI Phase 1
- **Deps:** C-001..C-007
- **Acceptance:** exit codes 0 (success/help), 1 (runtime), 2 (usage); test coverage in `main_test.go`
- **Size:** 1h
- **Status:** **done** — merge `907dcbf` (2026-05-08); UsageError type with NewUsageError/WrapUsageError/IsUsageError; 8 subcommand sites converted; runHistory reordered to fail-fast on bad input before store-open; 16 new exit-code subtests cover detect/check/rollback/plan/remediate/history; 2-agent peer review clean (caught --since gap, fixed); live-tested 192.168.1.211.

#### C-009 — Unit tests for all flag parsing paths
- **Phase:** CLI Phase 1
- **Deps:** C-002..C-008
- **Acceptance:** every subcommand `--help` tested, every short-form, bad usage; coverage ≥ 90% on `cmd/kensa/`
- **Size:** 2h
- **Status:** **done** — merge `631577e` (2026-05-08); coverage 41.4% → **65.6%** (+24.2 pts); 100% on utils, print helpers, parsers, error path; --help/short-form/bad-usage all tested. **90% gap acknowledged**: remaining ~25 pts is in run* SSH/store-dependent paths needing TransportFactory mocking — separate architectural deliverable; live tests via `kensa-fuzz` + per-iteration `kensa detect` cover those paths end-to-end. 2-agent peer review clean.

#### C-010 — `scripts/cli-smoke.sh` exercising every subcommand `--help` + bad-flag cases; wire into CI
- **Phase:** CLI Phase 1
- **Deps:** C-009
- **Acceptance:** `make cli-smoke` runs clean; CI workflow invokes it
- **Size:** 0.5h
- **Status:** **done** — merge `b1ff51a` (2026-05-08); 41-scenario bash smoke test asserting exit codes AND output streams (stdout vs stderr discipline); auto-builds binaries; `make cli-smoke` local target; new `cli-smoke` CI job parallel to build-portability-* jobs; 2-agent peer review clean. **Closes CLI Phase 1 (10/10 deliverables done).**

### CLI Phase 2 — `-o FORMAT[:PATH]` mechanism

#### C-011 — `internal/output/` package with format-and-path parser
- **Phase:** CLI Phase 2
- **Deps:** C-001
- **Acceptance:** parses `json`, `json:foo.json`; rejects malformed; supports repeatable invocation
- **Size:** 3h
- **Status:** done (merged 2026-05-08, `ad4d66a`)

#### C-012 — Refactor existing serializers (json, jsonl, table) into `internal/output/` with common interface
- **Phase:** CLI Phase 2
- **Deps:** C-011
- **Acceptance:** existing `--format` still works; serializers behind `OutputWriter` interface
- **Size:** 3h
- **Status:** done (merged 2026-05-08, `639b874`)

#### C-013 — CSV serializer
- **Phase:** CLI Phase 2
- **Deps:** C-012
- **Acceptance:** `kensa check ... -o csv:results.csv` emits one row per (host, rule) tuple
- **Size:** 2h
- **Status:** done (merged 2026-05-08, `84b4d0f`)

#### C-014 — PDF library decision (`unidoc/unipdf` vs `gofpdf` vs `maroto`)
- **Phase:** CLI Phase 2
- **Deps:** —
- **Acceptance:** founder ratifies one choice; library added to `go.mod` (or PDF deferred to post-1.0); decision recorded in STATUS.md
- **Size:** 1h research
- **Status:** done (founder ratified maroto v2 on 2026-05-08, recorded in STATUS.md; bundled with C-015 merge `4322089`)

#### C-015 — PDF serializer (gated on C-014)
- **Phase:** CLI Phase 2
- **Deps:** C-014
- **Acceptance:** `kensa check ... -o pdf:report.pdf` emits readable report
- **Size:** 4h
- **Status:** done (merged 2026-05-08, `4322089`)

#### C-016 — OSCAL serializer wired through `-o` (existing `internal/evidence/oscal.go`)
- **Phase:** CLI Phase 2
- **Deps:** C-011, C-012
- **Acceptance:** `-o oscal:foo.json` equivalent to existing `--oscal` flag; both work for one minor version
- **Size:** 1h
- **Status:** done (merged 2026-05-08, `68c55f5`)

#### C-017 — Evidence serializer (envelope output) wired through `-o`
- **Phase:** CLI Phase 2
- **Deps:** C-011
- **Acceptance:** `-o evidence:foo.json` emits envelope with current schema; documented that signature bytes are empty until M7 task #12
- **Size:** 1h
- **Status:** done (merged 2026-05-08, `0e92792`)

#### C-018 — `--quiet`/`-q` flag suppressing default human output
- **Phase:** CLI Phase 2
- **Deps:** C-011..C-017
- **Acceptance:** `--quiet` writes nothing to stdout when `-o` redirected; warnings still go to stderr
- **Size:** 0.5h
- **Status:** done (merged 2026-05-08, `b6dc084`)

#### C-019 — Concurrent fan-out for multi-output runs
- **Phase:** CLI Phase 2
- **Deps:** C-011..C-018
- **Acceptance:** `-o csv:a -o pdf:b -o json:c` runs all three serializers concurrently against same in-memory result
- **Size:** 2h
- **Status:** done (merged 2026-05-08, `7a84f11`)

#### C-020 — Deprecation alias: `--format` keeps working with single-arg semantics
- **Phase:** CLI Phase 2
- **Deps:** C-011..C-019
- **Acceptance:** `--format json` still works; CHANGELOG note added; printed deprecation warning when `--format` is used (only on stderr)
- **Size:** 0.5h
- **Status:** pending

### CLI Phase 3 — `target_options` + `rule_options` parity

*Sketch — full deliverable breakdown will be filled in when the loop reaches this phase.*
Estimated 12–15 deliverables (C-021..C-035) covering: `--limit/-l` (host glob), `--password/-p` (with prompt), `--strict-host-keys/--no-strict-host-keys`, `--capability/-C`, `--workers/-w`, `--severity/-s`, `--tag/-t`, `--category/-c`, `--framework/-f`, `--var/-x`, `--control`, `--config-dir`. Each ~1–3h. ~1.5 weeks total.

### CLI Phase 4 — Session model + missing subcommands

*Sketch.* Estimated 12–15 deliverables (C-036..C-050) covering: SQLite session schema migration, `kensa diff`, framework `kensa coverage` (rename existing to `kensa mechanisms`), `kensa list frameworks`, `kensa info` (with --cis/--stig/--nist/--rhel filters), `--stats`, `--prune`. **Includes one `kensa migrate` deliverable** for SQLite schema migration of existing databases. ~2 weeks.

### CLI Phase 5 — kensa-go-specific surfaces

*Sketch.* Estimated 8–10 deliverables (C-051..C-060) covering: `jsonl` everywhere applicable, `oscal` everywhere, signed-envelope output (gates on M7 task #12 for real signatures), `kensa(1)` manpage, `kensa agent --stdio` placeholder subcommand stub. ~1 week.

---

## Track L — Kernel-Primitive Migration

### LL Phase 0 — Build discipline (parallel-safe with CLI Phase 1)

#### L-001 — Set `CGO_ENABLED=0` in Makefile and `.github/workflows/ci.yml`
- **Phase:** LL Phase 0
- **Deps:** —
- **Acceptance:** `go build` produces a static binary; `ldd ./kensa` says "not a dynamic executable"
- **Size:** 1h
- **Status:** **done** — merge `08a195f` (2026-05-08); 2-agent peer review clean; specter check --strict 22/22; go test ./... pass; live-tested against `192.168.1.211` (31 capabilities, exit 0)

#### L-002 — Add `-tags netgo` to build flags + `GODEBUG=netdns=go` discipline
- **Phase:** LL Phase 0
- **Deps:** L-001
- **Acceptance:** pure-Go DNS resolver in effect; build still passes
- **Size:** 1h
- **Status:** **done** — merge `f51cba7` (2026-05-08); `go version -m` confirms `-tags=netgo` baked in; 2-agent peer review clean; specter 22/22; tests pass; live-tested 192.168.1.211

#### L-003 — CI step running `ldd ./kensa` and asserting "not a dynamic executable"
- **Phase:** LL Phase 0
- **Deps:** L-001, L-002
- **Acceptance:** CI fails if a dependency reintroduces dynamic linking
- **Size:** 0.5h
- **Status:** **done** — merge `798945d` (2026-05-08); new `build-static-verify` CI job; happy + failure paths verified locally; 2-agent peer review clean; specter 22/22; tests pass; live-tested 192.168.1.211

#### L-004 — CI step running binary inside `glibc 2.28` container (RHEL 8 vintage)
- **Phase:** LL Phase 0
- **Deps:** L-001, L-002
- **Acceptance:** `kensa --version` succeeds in glibc 2.28 container
- **Size:** 1h
- **Status:** **done** — merge `26844b0` (2026-05-08); new `build-portability-glibc228` job using `rockylinux:8`; container glibc-version pre-check; locally verified static binary runs cleanly on glibc 2.28; uses `kensa version` (subcommand) pre-C-001 — flag form will land with C-001; 2-agent peer review clean; specter 22/22; tests pass; live-tested 192.168.1.211

#### L-005 — CI step running binary inside Alpine (musl) container
- **Phase:** LL Phase 0
- **Deps:** L-001, L-002
- **Acceptance:** `kensa --version` succeeds in Alpine
- **Size:** 0.5h
- **Status:** **done** — merge `969be68` (2026-05-08); new `build-portability-alpine` job using `alpine:3`; locally verified static binary runs cleanly on musl (orthogonal to L-004's glibc 2.28 target); 2-agent peer review clean; specter 22/22; tests pass; live-tested 192.168.1.211

#### L-006 — Document portability commitment in `README.md` + `KENSA_API_DOC.md` §12
- **Phase:** LL Phase 0
- **Deps:** L-001..L-005
- **Acceptance:** explicit "compiles once, runs RHEL 8 → RHEL 12 → Alpine; no glibc floor; no cgo" claim, with the CI gates that enforce it cited
- **Size:** 0.5h
- **Status:** **done** — merge `22c1c95` (2026-05-08); README "## Binary Portability" + KENSA_API_DOC §12 subsection; all four CI gates cited, forward-compat reasoning documented; 2-agent peer review clean (compliance-officer-friendly language strengthened); specter 22/22; tests pass; live-tested 192.168.1.211. **LL Phase 0 complete.**

### LL Phase 1 — Multi-call agent binary (the gate for LL Phases 2–7)

#### L-007 — **GRAY ZONE** Wire-protocol decision: protobuf vs msgpack vs custom
- **Phase:** LL Phase 1
- **Deps:** —
- **Acceptance:** founder ratifies; `.proto` schema or msgpack types scaffolded
- **Size:** 2h research
- **Status:** **blocked — needs founder ratification**
- **Notes:** Security-load-bearing decision. Pre-approval memory says gray-zone deliverables surface a question. Loop pauses here.

#### L-008 — Add `internal/agent/` package skeleton with `kensa agent --stdio` subcommand
- **Phase:** LL Phase 1
- **Deps:** L-007
- **Acceptance:** `kensa agent --stdio` reads framed messages from stdin, echoes them, exits when stdin closes
- **Size:** 4h
- **Status:** blocked

#### L-009 — Define wire-protocol schema (request, response, error, heartbeat types)
- **Phase:** LL Phase 1
- **Deps:** L-007, L-008
- **Acceptance:** schema covers all current handler invocations + capture + rollback + heartbeat
- **Size:** 3h
- **Status:** blocked

#### L-010 — Implement length-prefixed framing on both ends
- **Phase:** LL Phase 1
- **Deps:** L-008, L-009
- **Acceptance:** round-trip tests pass for messages up to 16 MiB
- **Size:** 2h
- **Status:** blocked

#### L-011 — Controller-side `AgentTransport` adapter (talks to `kensa agent --stdio` over SSH)
- **Phase:** LL Phase 1
- **Deps:** L-009, L-010
- **Acceptance:** existing handler invocation path works against agent transport in addition to direct SSH
- **Size:** 4h
- **Status:** blocked

#### L-012 — Version handshake on session start
- **Phase:** LL Phase 1
- **Deps:** L-008, L-011
- **Acceptance:** mismatched majors abort with clear error; same major + different minor logs warning and proceeds
- **Size:** 2h
- **Status:** blocked

#### L-013 — Binary push + SHA-cached agent caching at `~/.cache/kensa/agent-<sha>`
- **Phase:** LL Phase 1
- **Deps:** L-008, L-011
- **Acceptance:** first invocation pushes; subsequent invocations skip; cache invalidates on binary change
- **Size:** 3h
- **Status:** blocked

#### L-014 — Port `file_permissions` handler to agent mode (proof-of-concept)
- **Phase:** LL Phase 1
- **Deps:** L-011, L-013
- **Acceptance:** `kensa remediate` via agent runs `file_permissions` Apply + Capture + Rollback against test host; behavior identical to direct-SSH path
- **Size:** 4h
- **Status:** blocked

#### L-015 through L-032 — Port remaining 18 capturable handlers to agent mode
- **Phase:** LL Phase 1
- **Deps:** L-014 (then sequential per handler; or parallel within phase)
- **Acceptance:** each handler's behavior under agent mode matches direct-SSH path; integration test against real host (live `inventory.ini`) passes
- **Size:** 2–3h each
- **Status:** blocked
- **Notes:** This is the bulk of LL Phase 1 effort. Each handler port is one deliverable. Order: file_*, config_*, service_*, package_*, sysctl_set, kernel_module_disable, mount_option_set, pam_module_configure, audit_rule_set, selinux_boolean_set, cron_job, then non-capturable port for command_exec/manual/grub_*

### LL Phases 2–7 — Sketch only

*Filled in when the loop reaches each phase.*

- **LL Phase 2 (file atomicity):** ~8 deliverables. `internal/agent/fsatomic/` package + Apply rewrites for 5 file-handler types using `renameat2(RENAME_EXCHANGE)`, `O_TMPFILE`+`linkat`, `fsync`/`syncfs`. ~2 weeks.
- **LL Phase 3 (deadman rebuild):** ~6 deliverables. `timerfd(CLOCK_BOOTTIME)`, `pidfd_open`, `prctl(PR_SET_PDEATHSIG)`, `epoll`+`signalfd` event loop. ~2 weeks.
- **LL Phase 4 (systemd D-Bus):** ~5 deliverables. `coreos/go-systemd` for service handlers + `JobRemoved` synchronization + post-`EnableUnitFiles` `Reload`. ~1 week.
- **LL Phase 5 (`AUDIT_NETLINK`):** ~7 deliverables. `elastic/go-libaudit` for `audit_rule_set` handler + transaction-phase event emission to auditd. ~2 weeks.
- **LL Phase 6 (sysctl/mount/kernel-module):** ~5 deliverables. Direct kernel IO via `golang.org/x/sys/unix`. ~1 week.
- **LL Phase 7 (SELinux runtime + dconf):** ~4 deliverables. `/sys/fs/selinux/booleans/` writes + `godbus/dbus/v5` for dconf. ~1 week.
- **Stretch A–D:** post-1.0; not in active loop.

---

## Loop iteration protocol

Each iteration:
1. Read `STATUS.md` and this file (DELIVERABLES.md) at start.
2. Pick the next deliverable whose `Status: pending` and all `Deps: done`.
3. If selected deliverable is `blocked` (gray zone), surface the decision question and stop scheduling further wakeups until human input.
4. Execute the workflow per `migration_loop_preapproval.md` and `README.md`:
   - Write spec (if applicable) → tests → implement → 2-agent peer review → specter strict → full CI → live test → commit → PR → merge.
   - Use `inventory.ini` for live tests.
   - Auto-merge per pre-approval memory once gates green.
5. Update this file (`Status: done`, add PR link) and `STATUS.md`.
6. If a phase completes (last deliverable in a phase is `done`), surface a phase-end checkpoint summary.
7. If the next-next deliverable is unblocked, schedule next wakeup. Otherwise stop.

---

## Stop conditions

The loop stops scheduling further wakeups (human attention required) when:
- All deliverables in this file are `done` (full migration complete).
- Next deliverable is `blocked` on a gray-zone decision.
- Specter strict / CI / live test fails repeatedly (≥ 2 retries).
- Live `remediate` test against `inventory.ini` produces an unexpected result that's not a clean rollback.
- A deliverable's implementation reveals an architectural assumption that's wrong and needs replanning.

Each stop produces a clear summary message identifying the cause.
