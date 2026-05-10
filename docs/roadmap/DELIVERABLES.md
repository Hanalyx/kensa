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
- **Status:** done (merged 2026-05-08, `7c24dc3`)


### CLI Phase 2.5 — Operator UX refresh

Inserted post-Phase-2 in response to a UX critique of the default
`kensa check` text output: detail column leaked mechanism strings;
no failure/pass grouping; no severity surfacing; no fix guidance.
Mockup target lives in the conversation thread that triggered this
phase (founder review on 2026-05-08).

#### C-021 — Rule ordering + conflict/supersedes resolution
- **Phase:** CLI Phase 2.5
- **Deps:** —
- **Acceptance:** `internal/rule/ordering.go` ports `ordering.py` from sister Python kensa repo. Returns `ResolvedRules{Order, Cycles, CycleMembers, Conflicts, Superseded, Skipped}`. Wired into scan/check/remediate so superseded rules don't run; resolved.Order carries the active rule list to scan and writers (api/ frozen contract preserved — Resolved is not exposed publicly).
- **Size:** 1 day
- **Status:** done (merged 2026-05-08, `ee9a1e3`)

#### C-022 — `textScanWriter` operator-UX rewrite
- **Phase:** CLI Phase 2.5
- **Deps:** C-021
- **Acceptance:** `kensa check` default output groups FAILED / WARN / PASSED, surfaces severity badges, compacts PASSED list with glob patterns, synthesizes fix-line guidance from handler params (~5 common handler types), shows progress bar + summary line + host banner. WARN is a display-only category (passes/fails with `severity: low` and skipped rules; no engine changes).
- **Size:** 1 day
- **Status:** done (merged 2026-05-08, `44c8459`)

#### C-023 — Polish: OS probe, `-i`, `-v`/`--verbose`
- **Phase:** CLI Phase 2.5
- **Deps:** C-022
- **Acceptance:** `os_release` capability probe (parses `/etc/os-release` for "RHEL 9.6" etc.) wired into the host banner. `-i` registered as short form for `--inventory`. `-v`/`--verbose` flag wired (`ShortVerbose = "v"` already reserved); under `-v`, the compacted PASSED list expands to full rule IDs.
- **Size:** 0.5 day
- **Status:** done (merged 2026-05-08, `cfe93aa`)

### CLI Phase 3 — `target_options` + `rule_options` parity

Brings kensa-go's flag surface to parity with Python kensa's
`target_options` and `rule_options` per `CLI_GNU_POSIX_MIGRATION_V1.md`
§3.2–3.3. Honors the short-letter table from §4.2; deviations from
Python (5 cases) are the canonical kensa-go design and not migrations.

#### C-024 — Short-letter table reconciliation
- **Phase:** CLI Phase 3
- **Deps:** —
- **Acceptance:** Per §4.2 reconciliation: `--port` moves from `-p` to `-P`; `--sudo` loses its `-s` short; `--txn` moves from `-t` to `-T`; `--format`'s `-f` short is freed. Hard-cut (no deprecation period — pre-1.0, no production users per migration doc §4.3); CHANGELOG.md gets a Breaking-changes entry. 9 new Phase 3 placeholder constants declared in flags.go for downstream wiring.
- **Size:** 1h
- **Status:** done (merged 2026-05-08, `4611058`)

#### C-025 — `--limit/-l` host glob filter
- **Phase:** CLI Phase 3
- **Deps:** C-024
- **Acceptance:** `kensa check -i inventory.ini -l 'web-*'` runs only against hosts matching the glob; supports inventory group names (e.g., `-l prod-servers`). Ansible `--limit` semantics: comma-separated patterns; `!` excludes; bare hostname is exact-match.
- **Size:** 2h
- **Status:** done (merged 2026-05-09, `e8bab57`)

#### C-026 — `--password/-p` with secure prompt
- **Phase:** CLI Phase 3
- **Deps:** C-024
- **Acceptance:** `--password VALUE` uses VALUE; `--password` with no argument prompts on the controlling TTY via `golang.org/x/term.ReadPassword`. Falls back to long-only when stdin isn't a TTY. Wired into SSH transport's password auth path.
- **Size:** 2h
- **Status:** done (merged 2026-05-09, `f352547`). Wired into detect/check/remediate/plan via `registerPasswordFlag`. SSH transport routes through `sshpass -e` (env var, never argv). `--password` + `--inventory` rejected with usage error (per-host passwords differ). Stderr scrubbed for password substrings on connect failure. Reserved sentinel literal `<prompt>` for prompt mode. Spec: `specs/cli/password.spec.yaml` (6 constraints, 9 ACs).

#### C-027 — `--strict-host-keys` / `--no-strict-host-keys`
- **Phase:** CLI Phase 3
- **Deps:** —
- **Acceptance:** Boolean pair flags wire into SSH transport's known_hosts policy. Default off (matches Python kensa). When on, unknown host keys cause connect failure rather than silent acceptance.
- **Size:** 2h
- **Status:** done (merged 2026-05-09, `8586db3`). Wired into detect/check (single + inventory)/remediate/rollback/plan via `registerStrictHostKeysFlag`. Mutual-exclusion enforced (both flags = usage error). Under strict mode, masterArgs also emits `UpdateHostKeys=no` to prevent OpenSSH 8.5+ silent key rotation. Connect-failure stderr augmented with operator hint for the unknown-host case (ssh-keyscan + fingerprint guidance). Spec: `specs/cli/strict-host-keys.spec.yaml` (5 constraints, 8 ACs). Live-verified read-only on 192.168.1.211.

#### C-028 — `--capability/-C` capability override
- **Phase:** CLI Phase 3
- **Deps:** —
- **Acceptance:** Repeatable `-C KEY=VALUE` (e.g., `-C apparmor=true -C selinux=false`). Overrides the detected capability set per-key. KEY must be in the known capability vocabulary; VALUE is `true|false`. Wired into the rule selector's `when:` evaluation.
- **Size:** 2h
- **Status:** done (merged 2026-05-09, `f4f9ddb`). Wired into detect/check (single + inventory)/remediate; plan path explicitly excluded (PlanTransaction uses selectDefaultImpl, not capability-gated). Permissive VALUE parser (true/false/yes/no/on/off/1/0). Unknown KEY usage error lists all valid capabilities inline. New `api.ScannerWithOverrides` interface; legacy `ScannerBackend` unchanged for backward compat. Spec: `specs/cli/capability-override.spec.yaml` (6 constraints, 11 ACs incl. risk-model stanza). Live-verified flipping selinux + apparmor on 192.168.1.211.

#### C-029 — `--workers/-w` parallel SSH
- **Phase:** CLI Phase 3
- **Deps:** —
- **Acceptance:** `--workers N` (1–50, default 1) sets the inventory-mode goroutine pool size. Currently inventory mode is sequential per host; this knob bounds the concurrency. Workers > 50 reject with usage error.
- **Size:** 3h
- **Status:** done (merged 2026-05-09, `c6ea837`). Replaced unbounded inventory fan-out with generic `fanOutBounded[T]` helper using acquire-before-spawn semaphore. Out-of-range values rejected up front (validateWorkers). Inventory runs with >5 hosts at default workers=1 emit a one-line stderr hint suggesting -w 5+ (suppressed by --quiet). Spec: `specs/cli/workers-flag.spec.yaml` (5 constraints, 10 ACs). 11 unit tests (5 fanOutBounded + 6 validateWorkers). Live-verified `-w 2` against 192.168.1.211.

#### C-030 — `--severity/-s` rule filter
- **Phase:** CLI Phase 3
- **Deps:** C-024
- **Acceptance:** Repeatable `-s critical -s high` (choice: critical/high/medium/low). Filters rules at load time; rules with severity not in the set are skipped. Empty set = all severities (default).
- **Size:** 1h
- **Status:** done (merged 2026-05-09, `4fba2bc`). Wired into check + remediate. Up-front flag-only validation (unknown severity → usage error listing valid choices). Empty filtered set → usage error (deliberate; documented trade-off in spec). Case-insensitive on input + rule severity match. Spec: `specs/cli/severity-filter.spec.yaml` (5 constraints, 11 ACs). 9 unit tests. Live-verified critical+high reduced 539-rule corpus to 70 on 192.168.1.211.

#### C-031 — `--tag/-t` rule filter
- **Phase:** CLI Phase 3
- **Deps:** C-024
- **Acceptance:** Repeatable `-t pci -t cis`. Filters rules whose `tags:` array intersects the operator's set. AND semantics within a `--tag` value isn't supported (each value is a separate tag).
- **Size:** 1h
- **Status:** done (merged 2026-05-09, `3e7e001`). Wired into check + remediate. Free-form vocabulary (no validation; empty-after-filter surfaces typos). OR semantics across operator values; AND across filter types (severity narrows first, tags narrow further). Empty-after-tag error discloses pre-tag count for filter-chain disambiguation. Spec: `specs/cli/tag-filter.spec.yaml` (5 constraints, 11 ACs). 10 unit tests. Live-verified: `-t network` reduced 539-rule corpus to 16 on 192.168.1.211.

#### C-032 — `--category/-c` rule filter
- **Phase:** CLI Phase 3
- **Deps:** —
- **Acceptance:** Single value `-c access-control`. Filters by rule's `category:` field. Lone short is `-c`; lowercase free.
- **Size:** 1h
- **Status:** done (merged 2026-05-09, `d05fdb8`). Single-value StringVarP (NOT repeatable like -s/-t — help text discloses); case-insensitive exact match. Composes AND with --severity and --tag. Empty-after-filter discloses pre-category count for filter-chain disambiguation. Spec: `specs/cli/category-filter.spec.yaml` (5 constraints, 8 ACs). 7 unit tests. Live-verified: `-c logging` reduced 539-rule corpus to 14 on 192.168.1.211.

#### C-033 — `--framework/-f` rule filter
- **Phase:** CLI Phase 3
- **Deps:** C-024
- **Acceptance:** `--framework cis-rhel9` loads only rules with a mapping entry for that framework. Requires framework-mapping infrastructure: `internal/mappings/` already loads framework files (M3); this deliverable wires the filter at rule-load time and adds usage-error for unknown framework IDs.
- **Size:** 3h
- **Status:** done (merged 2026-05-09, `e7c2467`). Single-value flag wired via `mappings.RefsFromReferences`. Validation against pre-filter corpus snapshot (so unknown-framework error reflects loaded corpus, not what survived upstream filters). Hyphen/underscore aliasing on operator input. Composes AND with severity/tag/category. Spec: `specs/cli/framework-filter.spec.yaml` (6 constraints, 16 ACs). 17 unit tests covering CIS/NIST/STIG shapes. Live-verified `-f cis-rhel9` reduced 539-rule corpus to 278 on 192.168.1.211.

#### C-034 — `--var/-x` rule-variable override
- **Phase:** CLI Phase 3 → **deferred to Phase 3.5** (founder decision 2026-05-09)
- **Deps:** rule-variable infrastructure (does not exist in kensa-go today)
- **Acceptance:** Repeatable `-x KEY=VALUE` (e.g., `-x pam_faillock_deny=5`). Overrides the corresponding rule variable at evaluation time. Wires into the existing rule-variable resolution path; unknown KEY values produce a usage error to prevent silent typos.
- **Size:** 2h (stated) — actual scope is 1-2 days because the existing path doesn't exist in kensa-go.
- **Status:** done (merged 2026-05-09 in Phase 3.5 combined deliverable, `bb96a28`). Built `internal/varsub` package with Substitute/LoadDefaults/Merge + ErrUndefined sentinel. Wired `--var/-x` into check + remediate. Resolution priority: CLI --var > <config-dir>/defaults.yml. Phase 3.6 will add per-host / per-group / conf.d tiers (associative Merge keeps that additive). Spec: `specs/cli/variable-substitution.spec.yaml` (7 constraints, 23 ACs combining C-034 + C-036). 32 unit tests (16 varsub + 7 defaults + 9 var-flag).

#### C-035 — `--control` framework-control filter
- **Phase:** CLI Phase 3
- **Deps:** C-033
- **Acceptance:** `--control cis-rhel9:5.1.12` runs only rules mapped to that framework control. Long-only (no short letter). Multiple `--control` values supported (repeatable). Unknown control IDs produce usage error.
- **Size:** 1h
- **Status:** done (merged 2026-05-09, `afb56c0`). Long-only repeatable flag (`-c` is --category). Two-stage validation (parse FRAMEWORK:CONTROL + validate pair exists in pre-filter corpus). Framework portion reuses C-033's hyphen/underscore normalization; control portion preserves case (NIST AC-1, STIG V-257974). OR across filter values, AND with upstream filters. Spec: `specs/cli/control-filter.spec.yaml` (6 constraints, 15 ACs). 15 unit tests. Live-verified `--control cis_rhel9:5.1.12` reduced 539-rule corpus to exactly 1 rule on 192.168.1.211.

#### C-036 — `--config-dir` config directory override
- **Phase:** CLI Phase 3 → **deferred to Phase 3.5** (founder decision 2026-05-09)
- **Deps:** config-directory loader (paired with C-034 rule-variable infrastructure)
- **Acceptance:** `--config-dir /etc/kensa` overrides the auto-detected config dir. Long-only (no short letter). Default auto-detect: `$KENSA_CONFIG_DIR`, then `$XDG_CONFIG_HOME/kensa`, then `$HOME/.config/kensa`, then `/etc/kensa`. The resolved path is logged once on first use under `--verbose`.
- **Size:** 1h
- **Status:** done (merged 2026-05-09 in Phase 3.5 combined deliverable, `bb96a28`). Wired `--config-dir DIR` reading `<DIR>/defaults.yml` `variables:` block. Phase 3.5 ships only the defaults.yml tier; per-host / per-group / conf.d tiers (the rest of the Python 5-tier chain) are Phase 3.6 follow-ups. KEY validation against [A-Za-z][A-Za-z0-9_]* in defaults.yml mirrors --var to catch unreachable entries. Spec is shared with C-034 at `specs/cli/variable-substitution.spec.yaml`.

#### C-037 — `--rule` single rule file
- **Phase:** CLI Phase 3
- **Deps:** —
- **Acceptance:** Long-only (no short). `--rule /path/to/foo.yml` loads just that file (no directory walk). Repeatable. Complements the existing positional `*.yml` arg form. `--rule` and positional args can be mixed.
- **Size:** 0.5h
- **Status:** done (merged 2026-05-09, `0234d67`). Long-only repeatable StringArrayVar. Behavior change: pre-C-037 --rules-dir + explicit files were XOR (dir wins); post-C-037 they compose additively. Strict loading for explicit files (parse error → fail), skip-invalid preserved for dir walks. concatPaths helper at both check + remediate call sites. flags.go comment on ShortRule updated to record that long form `--rule` is now file-loading; future filter-by-ID feature needs different long name. Spec: `specs/cli/rule-flag.spec.yaml` (5 constraints, 8 ACs). 8 unit tests covering loader matrix. Live-verified single + repeated `--rule` against 192.168.1.211.

#### C-038 — Phase 3 close: help-text consolidation + smoke
- **Phase:** CLI Phase 3
- **Deps:** C-024, C-025, C-026, C-027, C-028, C-029, C-030, C-031, C-032, C-033, C-035, C-037 (C-034 + C-036 deferred to Phase 3.5; not blocking the Phase 3 close)
- **Acceptance:** Each subcommand's `--help` output groups flags by category (Target options / Rule options / Output options / Subcommand-specific) per §5 of the migration doc. cli-smoke.sh adds 1–2 scenarios per new flag. Spec-corpus addition for the Phase 3 surface.
- **Size:** 1h
- **Status:** done (merged 2026-05-09, `771c57e`). detect/check/remediate `--help` now categorizes flags into Target options / Rule options (where applicable) / Output options / General sections. formatGroupedUsages helper with drift-resistant "Other options" catch-all. cli-smoke.sh grew 54→99 (45 new C-038 scenarios — flag advertisement matrix, help-grouping section presence, 8 Phase 3 validation usage errors). Spec: `specs/cli/phase3-close.spec.yaml` (5 constraints, 8 ACs).

### CLI Phase 4 — Session model + missing subcommands

12 deliverables (C-039..C-050). Founder-approved 2026-05-09 to proceed via the loop pre-approval (option C in the breakdown discussion). Foundation first (session schema + migrate), then the surface layer.

#### C-039 — Session schema in store
- **Phase:** CLI Phase 4
- **Deps:** —
- **Acceptance:** Migration 2 adds `sessions` table (id, started_at, finished_at, hostname, subcommand, args_summary) + `session_id` column on `transactions` (NULL for migration-2-and-earlier rows). Existing rows get a backfilled synthetic session per-host. Loader API gains session-scope query helpers.
- **Size:** ~1 day. High-blast-radius — operator data shape change.
- **Status:** done (merged 2026-05-09, `21885a7`). Migration 2 appended; sessions table + session_id column on transactions. Session API: CreateSession / FinishSession / AttachTransaction / GetSession / ListSessions. Backward-compat: pre-Phase-4 rows have NULL session_id and remain queryable. Spec: `specs/store/session-schema.spec.yaml` (6 constraints, 10 ACs). 9 unit tests. Backfill of pre-existing rows is C-040 (kensa migrate).

#### C-040 — `kensa migrate` subcommand
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** `kensa migrate --db PATH` detects pre-Phase-4 schema (schemaVersion < 2), applies migration 2, backfills sessions for existing transactions. Idempotent on already-migrated DBs (no-op + exit 0).
- **Size:** ~3h
- **Status:** done (merged 2026-05-09, `391d878`). BackfillSessions groups orphan transactions one-synthetic-session-per-host with subcommand="legacy-backfill". Idempotent. printUsage now advertises both `migrate` and `version` (the latter was also missing). Spec: `specs/cli/kensa-migrate.spec.yaml` (5 constraints, 8 ACs). 6 unit tests covering empty/single/multi/idempotent/preserves-post-Phase-4/CurrentSchemaVersion.

#### C-041 — `--store` flag on `kensa check`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** `kensa check --store` writes the scan as a session+transactions record. Default off (matches current behavior — check is read-only, store is opt-in).
- **Size:** ~2h
- **Status:** pending

#### C-042 — `kensa history --stats`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Aggregate counts (sessions, transactions, by status, by severity, by host). Output respects `-o json` / text.
- **Size:** ~3h
- **Status:** pending

#### C-043 — `kensa history --prune DAYS`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Deletes sessions older than N days (cascade to transactions + steps + pre_states). Requires `--force` for non-interactive runs; otherwise prompts. Long-only (no short — destructive). Honors transaction-log spec C-05 retention semantics.
- **Size:** ~3h
- **Status:** pending

#### C-044 — Rename `kensa coverage` → `kensa mechanisms`
- **Phase:** CLI Phase 4
- **Deps:** —
- **Acceptance:** Both subcommands work; `kensa coverage` (old behavior — list mechanisms) emits a stderr deprecation warning pointing at `kensa mechanisms`. Frees `kensa coverage` for the new framework-coverage report (C-045).
- **Size:** ~2h
- **Status:** pending

#### C-045 — `kensa coverage` (NEW: framework control coverage)
- **Phase:** CLI Phase 4
- **Deps:** C-044
- **Acceptance:** `kensa coverage --framework cis_rhel9 --rules-dir DIR` walks the corpus, computes per-control coverage, prints summary (e.g., "212 / 318 CIS RHEL9 L1 controls covered (66.7%)"). `-o json` emits structured shape.
- **Size:** ~5h
- **Status:** pending

#### C-046 — `kensa list frameworks`
- **Phase:** CLI Phase 4
- **Deps:** —
- **Acceptance:** Lists framework IDs available in the loaded corpus (via `mappings.RefsFromReferences`) with control counts. `-o json` for programmatic use.
- **Size:** ~2h
- **Status:** pending

#### C-047 — `kensa info` (rule/control lookup)
- **Phase:** CLI Phase 4
- **Deps:** C-046
- **Acceptance:** Multi-criteria search: `--rule R`, `--control FRAMEWORK:ID`, `--list-controls/-L FRAMEWORK`, `--cis`/`--stig`/`--nist` filters, `--rhel 8|9|10` (filters platforms). Positional QUERY does free-text search over title/description. `-o json` for programmatic.
- **Size:** ~6h. Largest single subcommand.
- **Status:** pending

#### C-048 — `kensa diff SESSION1 SESSION2`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Compares two sessions by ID; emits drift report (per-rule status changes, new/removed rules). `--show-unchanged` includes rules whose status is identical. `-o json` for programmatic.
- **Size:** ~5h
- **Status:** pending

#### C-049 — `kensa rollback --list/--info/--start/--detail`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Closes the partial-implementation gap from Phase 1..3. `--list` shows rollback-able sessions; `--info ID` shows session detail; `--start ID` triggers rollback (replaces today's `--txn UUID`); `--detail` adds per-step breakdown to list output.
- **Size:** ~5h
- **Status:** pending

#### C-050 — Phase 4 close: help grouping + smoke + spec corpus
- **Phase:** CLI Phase 4
- **Deps:** C-039..C-049
- **Acceptance:** Apply the C-038 grouping pattern to new subcommands. cli-smoke.sh adds 1-2 scenarios per new flag. Spec-corpus close.
- **Size:** ~2h
- **Status:** pending

### CLI Phase 5 — kensa-go-specific surfaces

*Sketch.* Estimated 8–10 deliverables (C-054..C-063) covering: `jsonl` everywhere applicable, `oscal` everywhere, signed-envelope output (gates on M7 task #12 for real signatures), `kensa(1)` manpage, `kensa agent --stdio` placeholder subcommand stub. ~1 week.

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
