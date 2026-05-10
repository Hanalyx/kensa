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
- **Status:** done (merged 2026-05-09, `aea016f`). persistScanResult helper synthesizes envelopes for check transactions (the scan layer doesn't construct envelopes; engine path does that for remediate). Single-host wiring done; inventory mode rejected with a usage error pending future per-host fan-out write path. Spec: `specs/cli/store-flag.spec.yaml` (5 constraints, 6 ACs). 4 unit tests. Live-verified 70 transactions persisted readable via `kensa history -n 3`. Inherited M1 issue (transactional column hardcoded true in PersistResult) flagged as separate cleanup.

#### C-042 — `kensa history --stats`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Aggregate counts (sessions, transactions, by status, by severity, by host). Output respects `-o json` / text.
- **Size:** ~3h
- **Status:** done (merged 2026-05-09, `2b0a61e`). `*SQLite.ComputeStats` runs 5 queries (total + bounds, sessions, 3 GROUP BYs); top-10 host rollup with `(other)` bucket; deterministic alphabetical tiebreak. Text output canonical-ordered + legend footer disambiguating rolled_back semantics. JSON output snake_case tags. 11 unit tests (8 store + 3 formatter). Spec: `specs/cli/history-stats.spec.yaml` (6 constraints, 9 ACs). Live-verified.

#### C-043 — `kensa history --prune DAYS`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Deletes sessions older than N days (cascade to transactions + steps + pre_states). Requires `--force` for non-interactive runs; otherwise prompts. Long-only (no short — destructive). Honors transaction-log spec C-05 retention semantics.
- **Size:** ~3h
- **Status:** done (merged 2026-05-09, `3a69700`). `(*SQLite) PruneSessions` runs single-tx cascade across sessions + transactions + steps + pre_states + framework_refs + rollback_events. `runHistoryPrune` gates on `--force` or TTY-confirmed "y\n"; non-TTY without --force exits 2. `cutoff = time.Now().AddDate(0, 0, -days)` avoids int64-nanosecond overflow; pruneDaysMax=36500 catches typos. Mutex extends to 8 query flags (added --limit + --format + 6 originally-spec'd). PruneReport surfaces OrphanTransactionsDeleted as sub-count for pre-Phase-4 backfill auditing. Audit summary writes to stderr regardless of --quiet (destructive-op telemetry must remain visible). Spec: `specs/cli/history-prune.spec.yaml` (6 constraints, 10 ACs). 9 store tests (incl. schema-drift guard + mid-loop atomic-rollback) + 11 CLI tests. cli-smoke 99→108. Live-verified.

#### C-044 — Rename `kensa coverage` → `kensa mechanisms`
- **Phase:** CLI Phase 4
- **Deps:** —
- **Acceptance:** Both subcommands work; `kensa coverage` (old behavior — list mechanisms) emits a stderr deprecation warning pointing at `kensa mechanisms`. Frees `kensa coverage` for the new framework-coverage report (C-045).
- **Size:** ~2h
- **Status:** done (merged 2026-05-09, `33db2e4`). `case "mechanisms"` canonical; `case "coverage"` calls warnRepurposedSubcommand then delegates to runMechanisms. **Rewording:** warning says "will change meaning in v0.2" not "deprecated/removed" — peer review caught the silent-flip risk where operators misread "removed" as "feature gone" and fail to migrate before v0.2 produces silently-different output. WARNING block leads the `--help` body. **Two-knob env contract:** KENSA_NO_REPURPOSE_WARNINGS=1 silences this only; KENSA_NO_DEPRECATION_WARNINGS=1 does NOT — semantic-flip warnings are categorically louder than flag renames, and a stale CI silence cannot mask the new signal. Spec: `specs/cli/coverage-mechanisms-rename.spec.yaml` (5 constraints, 8 ACs). 9 unit tests + retargeted TestQuietFlag_NotInCoverage to TestQuietFlag_NotInMechanisms (kept alias variant for the deprecation window). cli-smoke 108→117 (added 9 scenarios including two-knob env, "removed" guard). CHANGELOG entry under ### Changed (NOT ### Deprecated — the latter implies removal). Live-verified.

#### C-045 — `kensa coverage` (NEW: framework control coverage)
- **Phase:** CLI Phase 4
- **Deps:** C-044
- **Acceptance:** `kensa coverage --framework cis_rhel9 --rules-dir DIR` walks the corpus, computes per-control coverage, prints summary (e.g., "212 / 318 CIS RHEL9 L1 controls covered (66.7%)"). `-o json` emits structured shape.
- **Status:** done (merged 2026-05-09, `a194195`). **Numerator-only ship cut**: report shows "controls with rules: N (numerator only — framework total not bundled)" because a denominator-% reading would need an external control catalog kensa-go doesn't bundle at v1.0; future deliverable. JSON shape is forward-compatible (adding controls_total later is additive). New behavior gated on `--framework`; without it `kensa coverage` remains the C-044 deprecation alias. `kensa mechanisms --framework FOO` rejected with usage error pointing at `kensa coverage`. **Peer-review-driven UX polish**: labels reworded ("controls with rules" not "controls mapped"; "rules referencing FRAMEWORK" not "rules matching") to prevent reading numerator as a percentage; ASCII separators (not Unicode box-drawing) for LANG=C terminals; `--full` flag for unlimited rule listing; `--format` validated against {text,json}; alias `--help` advertises the new surface; `--framework FOO --help` emits the C-044 repurpose warning so operators reading docs see the v0.2 flip. `hasFrameworkFlag` uses a permissive pflag pre-parse so merged-short-bool forms (`-qfcis_rhel9`) route correctly. Spec: `specs/cli/framework-coverage.spec.yaml` (10 constraints, 14 ACs). 7 store-layer + 12 CLI tests. cli-smoke 117→126. Live-verified against 539-rule corpus: cis_rhel9 → 251 distinct controls across 259 rules; nist_800_53 → 76 controls across all 516 rules.

#### C-046 — `kensa list frameworks`
- **Phase:** CLI Phase 4
- **Deps:** —
- **Acceptance:** Lists framework IDs available in the loaded corpus (via `mappings.RefsFromReferences`) with control counts. `-o json` for programmatic use.
- **Size:** ~2h
- **Status:** done (merged 2026-05-09, `5c1f97f`). New `list` parent subcommand with `frameworks` as its first child (future-extensible namespace). `internal/coverage.ListFrameworks(rules)` + CLI `runList` sub-dispatcher. Output: per-framework_id row with distinct controls + distinct rules counts. JSON envelope `{frameworks:[...]}` for forward-compat with future fields. **Peer-review-driven UX polish**: bare `kensa list` returns exit 2 (CI-script footgun prevention — both reviewers flagged silent no-op risk); column header reworded to `rules ref'g` + footer legend (operators were reading "516 rules" as "516 NIST rules" rather than "516 corpus rules referencing NIST"); flag-before-subject hint suggests the rewrite; `--format` validated against `{text,json}`. Spec: `specs/cli/list-frameworks.spec.yaml` (7 constraints, 9 ACs). 5 store-layer + 10 CLI tests. cli-smoke 126→135. Live-verified against 539-rule corpus: 9 frameworks (cis_rhel10/8/9, nist_800_53, pci_dss_4, srg, stig_rhel10/8/9) with controls + rules counts.

#### C-047 — `kensa info` (rule/control lookup)
- **Phase:** CLI Phase 4
- **Deps:** C-046
- **Acceptance:** Multi-criteria search: `--rule R`, `--control FRAMEWORK:ID`, `--list-controls/-L FRAMEWORK`, `--cis`/`--stig`/`--nist` filters, `--rhel 8|9|10` (filters platforms). Positional QUERY does free-text search over title/description. `-o json` for programmatic.
- **Size:** ~6h. Largest single subcommand.
- **Status:** done (merged 2026-05-09, `389534e`). Four operating modes (--rule / --control / --list-controls / positional QUERY) sharing one entry point. New `internal/info` package with `DescribeRule` / `RulesForControl` / `ListFrameworkControls` / `SearchRules`. Exit-code contract: valid invocation + no match → exit 1 (`ErrNotFound`, runtime); bad input → exit 2 (usage). **Two P1 fixes from peer review**: spec-vs-code drift on `--rule + QUERY` / `--control + QUERY` composition (spec claimed compose, code ignored — tightened to "all four modes pairwise exclusive"); `--nist --rhel N` was producing silent no-match (nist_800_53 is unversioned), now rejected with usage error. **UX polish**: Platform `max_version=0` renders as ">= MIN" / "any version" not "max=0" (operators were reading literal zero); `--limit N` (default 100) for output truncation with visible footer; family-shortcut help text names matched framework_ids; coalesced missing-rules-dir + missing-mode error. Spec: `specs/cli/info.spec.yaml` (11 constraints, 16 ACs). 14 store-layer + 21 CLI tests. cli-smoke 135→149. Live-verified: `info ssh` → 35 hits; `info --rule sysctl-ip-forward-disabled` shows full details with clean platform rendering; `info --list-controls cis_rhel9` → 251 controls; `info file --limit 5` → truncation footer.

#### C-048 — `kensa diff SESSION1 SESSION2`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Compares two sessions by ID; emits drift report (per-rule status changes, new/removed rules). `--show-unchanged` includes rules whose status is identical. `-o json` for programmatic.
- **Size:** ~5h
- **Status:** done (merged 2026-05-09, `be4820c`). New `internal/diff` package with `RuleChange` / `SessionDiff` / `ComputeSessionDiff`. Store gained `TransactionsForSession` + `SessionTxn`. SESSION1 = "before", SESSION2 = "after" (git diff convention). Cross-hostname comparison allowed with informational stderr note. Multiple txns per rule within one session dedup to LATEST started_at. **Three peer-review-driven P1 fixes**: shipped `kensa list sessions` alongside the diff (peer review caught session UUIDs were undiscoverable — `kensa history --stats` shows counts only, no IDs); cleaned up "session not found" error to remove SQL leak ("store: GetSession: sql: no rows in result set" → "session X not found in store (try 'kensa list sessions')"); strengthened dedup test to exercise the store-side ORDER BY ASC invariant. **P2 polish**: JSON shape always populates every section as array (never null); --show-unchanged now governs only text rendering; column header has "BEFORE -> AFTER" label. Spec: `specs/cli/session-diff.spec.yaml` (9 constraints, 15 ACs). 7 store-layer + 12 diff CLI + 7 list-sessions CLI tests. cli-smoke 149→158. Live-verified: two `kensa check --store` runs against same host produce 0/0/0 diff (correct, no drift); cleaned-up missing-session error emits discovery hint.

#### C-049 — `kensa rollback --list/--info/--start/--detail`
- **Phase:** CLI Phase 4
- **Deps:** C-039
- **Acceptance:** Closes the partial-implementation gap from Phase 1..3. `--list` shows rollback-able sessions; `--info ID` shows session detail; `--start ID` triggers rollback (replaces today's `--txn UUID`); `--detail` adds per-step breakdown to list output.
- **Size:** ~5h
- **Status:** done (merged 2026-05-09, `c99ca33`). Refactored `runRollback` from imperative single-txn flow into a 4-mode dispatcher (--list/--info/--start/--txn legacy + --detail modifier). Store gained `RollbackableSessions` (filtered) + `CommittedTxnIDs` + `TxnRef`. **CRITICAL P1 caught by peer review**: original draft surfaced `kensa check --store` sessions as rollback-able, but those have no captured pre-state — `svc.Rollback` would silently report `succeeded: 10/10` while doing nothing (engine's `!Capturable → continue` skips every step and returns Success=true). Fixed with two-layer defense: SQL filter `subcommand IN ('remediate')` excludes check sessions from --list; runner-level guard rejects direct `--start <check-id>` with clean error. Also fixed empty-hostname bypass (legacy backfill sessions can't safely target a --host). Spec: `specs/cli/rollback-session-aware.spec.yaml` (8 constraints, 14 ACs). 17 CLI tests including the safety-filter regression coverage. cli-smoke 158→165. Live-verified end-to-end: check-only DB correctly shows "(no rollback-able sessions)"; direct --start against check session rejected; --info on remediate session shows expected per-txn detail.

#### C-050 — Phase 4 close: help grouping + smoke + spec corpus
- **Phase:** CLI Phase 4
- **Deps:** C-039..C-049
- **Acceptance:** Apply the C-038 grouping pattern to new subcommands. cli-smoke.sh adds 1-2 scenarios per new flag. Spec-corpus close.
- **Size:** ~2h
- **Status:** done (merged 2026-05-09, `66d080c`). Applied help-grouping to `kensa info` (Mode / Filter / Output sections) and `kensa rollback` (Mode / Target / Output) — the two flag-heavy new surfaces. Smaller surfaces (diff, list sessions/frameworks, history) kept flat help (≤6 flags each, readable as-is). cli-smoke gained 8 assertions confirming section headers appear and no flag falls into "Other options" catch-all. Spec: `specs/cli/phase4-close.spec.yaml` (4 constraints, 4 ACs). cli-smoke 165→173. Specter 62→63. Two P2 follow-ups intentionally deferred from this close: dual-store-handle smell in runRollbackStart; DRY duplication of cleanSessionLookupError between diff.go and rollback_session.go. **Phase 4 complete (12/12).**

### CLI Phase 5 — kensa-go-specific surfaces

Founder-ratified 2026-05-10 with five scope decisions:

1. **jsonl** wires only where output is a sequence: `kensa history`, `kensa list sessions`, `kensa info` (QUERY mode only — rule/control/list-controls modes reject jsonl). Other subcommands skipped (single-document shape).
2. **OSCAL** stays on check/remediate only. Phase 5's OSCAL work is regression-sweep, not new wiring.
3. **Phase 5 splits**: 5a is signer-independent (ships on its own); 5b is signer-dependent (gated on M7 task #12, ships in v1.1).
4. **v1.0 makes no cryptographic-signing claims**. No empty-signature middle state in any released version.
5. **Manpage** is hand-written wrapper (header + footer roff) + generated flag body, single `kensa.1` file.

#### C-051 — `kensa history --format jsonl`
- **Phase:** CLI Phase 5a
- **Deps:** —
- **Acceptance:** `kensa history --format jsonl` emits one transaction record per line as a parseable JSON object. Existing text/json/csv unchanged. Help text + cli-smoke updated.
- **Size:** ~2h
- **Status:** done (merged 2026-05-10, `3470703`). One compact JSON object per line via `json.NewEncoder` (not the indented JSONValueWriter). Document-shaped modes (--aggregate / --stats / --txn) reject --format jsonl with usage error pointing at --format json. Pagination trailer to stderr (csv convention; stdout is a row stream). Spec: `specs/cli/history-jsonl.spec.yaml` (4 constraints, 6 ACs). 6 unit tests. cli-smoke 173→177. Live-verified: 10 transactions round-trip cleanly through `jq -c '.'`.

#### C-052 — `kensa list sessions` and `kensa info` (QUERY mode) jsonl
- **Phase:** CLI Phase 5a
- **Deps:** —
- **Acceptance:** Both subcommands accept `--format jsonl`. `kensa info --rule R --format jsonl` and `kensa info --control X:Y --format jsonl` REJECT with usage error (those modes emit single documents, not sequences). `kensa list frameworks` does NOT get jsonl (small fixed-shape list; JSON-array suffices).
- **Size:** ~3h
- **Status:** done (merged 2026-05-10, `9bc3d9c`). Same compact-encoder pattern as C-051. The three info document-modes (--rule / --control / --list-controls) REJECT --format jsonl with usage error pointing at --format json — rejection fires BEFORE corpus load (initial draft placed it after, polluting the error path with rule-loader warnings; caught during live verification). Spec: `specs/cli/list-sessions-info-jsonl.spec.yaml` (4 constraints, 5 ACs). 7 unit tests. cli-smoke 177→183. Live-verified: `list sessions --format jsonl` round-trips through `jq -c .`; `info ssh --format jsonl` produces 35 single-line hits; document-mode rejection emits clean message without rule-loader noise.

#### C-053 — OSCAL regression sweep
- **Phase:** CLI Phase 5a
- **Deps:** —
- **Acceptance:** Add golden-file OSCAL output tests for `kensa check` and `kensa remediate` against a small fixture corpus. Catch any drift introduced by the Phase 4 session-model + scan-persist changes. New `internal/output/oscal/` test fixtures. cli-smoke validates the output shape against an OSCAL JSON schema if available, otherwise asserts top-level field presence.
- **Size:** ~3h
- **Status:** done (merged 2026-05-10, `1cde0b1`). 3 golden files (`internal/evidence/testdata/oscal_golden_{committed,rolled_back,multi_framework}.json`) capturing normalized OSCAL output. UUIDs and timestamps replaced with `GENERATED_UUID` / `FIXTURE_TIMESTAMP` placeholders so byte-diff is stable across runs. `UPDATE_GOLDEN=1 go test ./internal/evidence/` regenerates all three. TestOSCALGolden_StructuralPaths is the defense-in-depth complement (assessment-results / metadata / results / findings / observations / target.status.state). TestOSCALGolden_RegenerateRoundTrip locks normalize idempotency. Spec: `specs/cli/oscal-regression.spec.yaml` (4 constraints, 6 ACs). Specter 65→66. Full schema validation deliberately deferred — would require pulling in NIST's OSCAL schema + a validator library; structural assertions cover the high-traffic drift modes.

#### C-054 — `kensa agent --stdio` placeholder subcommand
- **Phase:** CLI Phase 5a
- **Deps:** —
- **Acceptance:** `kensa agent --stdio` reserves the subcommand name in v1.0. Exits 1 with a clear message: "agent mode is planned for v1.1 with the kernel-primitive migration (Track L Phase 1); use direct SSH transport in v1.0." `kensa agent --help` describes the planned interface so OpenWatch and consumers can write integration code. Help text and cli-smoke updated.
- **Size:** ~2h
- **Status:** done (merged 2026-05-10, `23b19c5`). Three operating paths: bare invocation exits 2 (usage), `--stdio` exits 1 (runtime, v1.1 placeholder), `--help` exits 0 with wire-protocol disclosure. Exit-code distinction follows the C-047 / C-048 / C-049 convention (1 = runtime/feature-not-ready, 2 = bad invocation). Help text discloses planned stdin/stdout/length-prefixed-framing direction so v1.0 consumers can write integration code today; the exact wire format ratifies through Track L Phase 1 (L-007 through L-014). Spec: `specs/cli/agent-placeholder.spec.yaml` (5 constraints, 6 ACs). 5 unit tests. cli-smoke 183→189. Top-level `kensa --help` now lists agent with v1.1 marker.

#### C-055 — `kensa(1)` manpage
- **Phase:** CLI Phase 5a
- **Deps:** —
- **Acceptance:** `docs/man/kensa.1.header.roff` and `docs/man/kensa.1.footer.roff` hand-written (NAME / SYNOPSIS / DESCRIPTION / ENVIRONMENT / FILES / EXIT CODES / SEE ALSO / AUTHORS sections). `docs/man/gen-manpage.go` walks every subcommand, captures `--help`, transforms to `.SS` subsections. `make manpage` produces `dist/kensa.1`. CI step regenerates and asserts no drift. Single file ships at `/usr/share/man/man1/kensa.1` (per package).
- **Size:** ~5h
- **Status:** done (merged 2026-05-10, `4d9969f`). Hybrid hand-written wrapper (header + footer) + generator. Generator subprocesses `bin/kensa <cmd> --help` so the manpage's flag text stays byte-identical to operator-facing help. Source-of-truth committed at `docs/man/kensa.1` (not `dist/kensa.1` — `/dist/` is gitignored; dist/ becomes a transient build artifact that distro packagers copy from). `make manpage-check` is the drift gate (regenerates to tmp + diffs; fails on drift). `coverage` deprecated alias deliberately excluded from the generator (would duplicate `mechanisms` content). Spec: `specs/cli/manpage.spec.yaml` (6 constraints, 8 ACs). 3 generator unit tests + 25 cli-smoke structural assertions. cli-smoke 189→214. Live-verified: `man -l docs/man/kensa.1` renders cleanly with no roff syntax errors.

#### C-056 — Phase 5a close
- **Phase:** CLI Phase 5a
- **Deps:** C-051..C-055
- **Acceptance:** Final `--format`/`--oscal` deprecation review (warn-on-use entries already shipped in C-020; verify CHANGELOG accurate and removal target still v0.2). Help-grouping pass on the new `agent` subcommand if it has flags. Spec corpus close.
- **Size:** ~1h
- **Status:** done (merged 2026-05-10, `a09f6f0`). CHANGELOG.md ## Unreleased ### Added gained two structured entries: Phase 4 (12 deliverables: sessions model + migrate / check --store / history --stats/--prune / mechanisms / coverage --framework / list frameworks/sessions / info / diff / rollback session-aware) and Phase 5a (jsonl wiring / agent stub / manpage). v0.2 removal target verified consistent between CHANGELOG and warnDeprecatedFlag's runtime message. Help-grouping skipped for `agent` (only 2 flags). Spec: `specs/cli/phase5a-close.spec.yaml` (3 constraints, 4 ACs). Specter 68→69. **Phase 5a complete (6/6).**

### CLI Phase 5b — signed-envelope output (gated on M-012)

#### C-060 — Wire Ed25519 signing through the engine + ship verify CLI
- **Phase:** CLI Phase 5b
- **Deps:** M-012, C-056
- **Acceptance:** With M-012's signer + `kensa-keygen` binary in place, plumb the signing path through every engine call-site that writes an `EvidenceEnvelope.Signature` (today they all flow through `noopSigner.Sign` returning empty bytes). Update `pkg/kensa.Default()` factory to accept a signing-key path (CLI flag + env var, e.g. `KENSA_SIGNING_KEY`). Add `kensa verify <evidence-file>` subcommand: reads a JSON envelope from disk, looks up the public key by `signing_key_id` against a configured trust directory (default `$XDG_CONFIG_HOME/kensa/keys/`), validates the Ed25519 signature, exits 0 on valid + 1 on invalid + 2 on usage error. Existing v1.0 evidence files (with empty `noop` signatures) remain valid as audit logs but cannot be cryptographically verified post-hoc — release notes call this out. v1.1 ships with this completed.
- **Size:** ~2 days on top of M-012
- **Status:** **blocked on M-012**

---

## Track M — M7 ship-gate items

The remaining v1.0.0 release-blockers from `CLAUDE.md`'s "Open items before M7 ships" punch list. Numbering preserves the
historical "task #N" lineage from `docs/KENSA_GO_DAY1_PLAN.md` so the
existing cross-references in `docs/test_docs/security.md`,
`docs/KENSA_API_DOC.md`, etc. stay accurate. Track M deliverables are
independent of Track C / Track L and can be picked up in any order
once the founder ratifies them.

#### M-012 — Ed25519 signer (replace noopSigner)
- **Phase:** M7
- **Deps:** —
- **Acceptance:**
  - `internal/evidence/signer.go` (or equivalent) implements `Sign` and `Verify` against Ed25519 keys via `crypto/ed25519` stdlib.
  - JSON canonicalization (deterministic field order) before signing — so the same envelope bytes produce the same signature regardless of map-iteration order or encoder version.
  - `cmd/kensa-keygen/main.go` (new binary) generates an Ed25519 keypair, writes `<keyid>.priv` (mode 0600) and `<keyid>.pub` (mode 0644), prints the key_id to stdout. Keys go to `$XDG_CONFIG_HOME/kensa/keys/` by default.
  - Tests: round-trip (sign then verify with the same key passes); tamper-detection (modifying a single byte of the canonical envelope makes verify fail); key-mismatch (signed by key A, public key B in trust dir, fails verify); key-rotation history (envelope's `signing_key_id` field locked into the signed bytes — rotating keys doesn't retroactively invalidate old envelopes).
  - `specs/evidence/envelope.spec.yaml` status flips from `draft` to `active`; the 6 constraints + 10 ACs already drafted lock to the implementation.
  - `noopSigner` deleted from `internal/engine/stubs.go`. Tests using it migrated to a fixture-based real-signer.
  - `docs/test_docs/security.md` Critical Limit #1 ("Evidence envelopes are unsigned") removed.
  - `docs/KENSA_API_DOC.md` `noopSigner` placeholder notes removed.
- **Size:** ~5 days
- **Status:** pending
- **Notes:** This is the v1.0 ship-blocker for the cryptographic-evidence-chain story. C-060 (Phase 5b) gates on this; the operator-facing `kensa verify` command and `kensa-keygen` binary land in C-060, not here. M-012's job is the cryptographic primitive only.

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
