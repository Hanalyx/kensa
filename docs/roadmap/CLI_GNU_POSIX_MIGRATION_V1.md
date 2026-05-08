# CLI GNU/POSIX Migration & Python Feature Parity Plan — Version 1

**Project:** Kensa Go
**Date:** 2026-05-07
**Status:** Draft — Roadmap document, not yet ratified
**Audience:** Kensa engineers, founder/reviewer, future AI sessions
**Companion:** `docs/KENSA_API_DOC.md`, `docs/roadmap/LOW_LEVEL_MIGRATION_V1.md`,
sister-repo `/home/rracine/hanalyx/kensa/runner/cli.py`

---

## Why This Document Exists

The kensa-go CLI today (`cmd/kensa/main.go`, `cmd/kensa-validate/main.go`,
`cmd/kensa-fuzz/main.go`) uses Go's stdlib `flag` package with the
defaults. The result is functional but not conventional: flags render
as `-host` (single-dash long form), no short aliases exist, `--help`
exits 1 with `"flag: help requested"` printed, `-h` is unregistered,
and `kensa --help` / `kensa --version` fall through to the
"unknown command" error path. Linux operators and AI agents alike
expect GNU/POSIX-conventional CLI behavior; kensa-go does not provide
it today.

Python kensa was the internal prototype that established the rule
corpus, framework mappings, and a well-designed CLI shape (eleven
subcommands; full rule-filtering; target/rule/output option groups;
multi-format `-o FORMAT[:PATH]` output). It has **no production
users** and is being phased out. Its CLI design is solid prior art
that kensa-go adopts; it is **not** a compatibility constraint that
kensa-go must honor.

This plan therefore resolves *one* gap, not two: bring kensa-go to
strict GNU/POSIX flag style and the full feature set Python kensa
informed. The design calls are:

- **GNU/POSIX is sacred.** `-h, --help`, `-V, --version`,
  `-v, --verbose`, `--` end-of-options, and standard exit codes are
  non-negotiable.
- **Full feature set, informed by Python kensa's design.** Every
  subcommand and option group Python kensa shipped is reproduced in
  kensa-go where it makes sense. The implementation is canonical, not
  compatibility-driven — where Python's choices conflict with GNU/POSIX
  reservations, kensa-go picks the GNU-conformant alternative without
  apology.
- **kensa-go enhancements are first-class.** kensa-go's lower-level
  architecture supports things Python kensa did not: NDJSON streaming
  output, OSCAL Assessment Results, signed evidence envelopes,
  `--help=json`, structured stderr under `--output json`,
  schema-versioned wire formats, and an agent-mode binary
  (per `LOW_LEVEL_MIGRATION_V1.md`). The CLI surfaces these directly.

This is a multi-week CLI build-out, phased so partial value lands
early.

---

## 1. Scope

### In scope

- Migrate all three CLI binaries to `github.com/spf13/pflag`.
- Add full GNU/POSIX flag style (`-x, --xxx`, `--option=value`,
  combinable shorts, `--` end-of-options).
- Reserve `-h, --help`, `-V, --version`, `-v, --verbose` strictly.
- Build the eleven Python kensa subcommands (or a deliberate subset) into
  kensa-go: `detect`, `check`, `remediate`, `history`, `diff`, `coverage`,
  `list frameworks`, `info`, `rollback`, plus existing `plan`, `mechanisms`
  (renamed from `coverage`).
- Implement the full target-options, rule-options, and output-options
  groups Python kensa exposes, with kensa-go-specific additions
  (`jsonl`, `oscal`, `evidence`-as-signed-envelope).
- Implement `--output FORMAT[:PATH]` parser, repeatable, with `-q, --quiet`
  to suppress terminal output when redirecting to files.
- Distinguish exit codes: 0 success, 1 generic runtime, 2 usage error.
- `--help` and `--version` exit 0 with content on stdout.
- Cross-command short-letter table to prevent collisions.

### Out of scope (separate plans)

- Distinct exit codes per failure class (host unreachable, plan stale,
  command_exec not allowed, etc.). Sketched in earlier review; not in
  this PR. Add as a follow-up.
- `--help=json` machine-readable command tree. High value but bigger;
  treat as a follow-up PR.
- Structured error JSON output under `--output json`. Follow-up.
- Env-var fallbacks (`KENSA_HOST`, etc.). Follow-up.
- The kernel-ABI / agent-mode work in `LOW_LEVEL_MIGRATION_V1.md`.
  Independent.

---

## 2. The GNU/POSIX Checklist (Sacred)

| Convention | Reserved letter / behavior |
|---|---|
| Help | `-h, --help` — every subcommand and top-level. Exits 0. Stdout. |
| Version | `-V, --version` — top-level. Exits 0. Stdout. |
| Verbose | `-v, --verbose` — every subcommand that has a verbosity dimension. |
| End of options | `--` — pflag default. |
| Stdin/stdout marker | `-` alone for read/write to stdin/stdout where applicable. |
| Long with value | `--option=value` and `--option value` both parse. |
| Short with value | `-ovalue` and `-o value` both parse. |
| Combinable shorts | `-vqf` = `-v -q -f` for bool flags. |
| Bad usage | Exit 2. Message on stderr. |
| Runtime error | Exit 1. Message on stderr. |
| `NO_COLOR` env | Honored where any color output is added. |

These are immutable. Every conflict in the Python → kensa-go mapping is
resolved by *moving the Python letter*, never by overriding a GNU
reservation.

---

## 3. Python kensa CLI — Complete Surface Inventory

Source: `/home/rracine/hanalyx/kensa/runner/cli.py` (3274 lines).

### 3.1 Subcommands

| Command | Purpose | Status in kensa-go today |
|---|---|---|
| `detect` | Probe host capabilities | ✓ implemented |
| `check` | Read-only compliance check | ✓ implemented |
| `remediate` | Apply changes with snapshot/rollback | ✓ implemented |
| `history` | Query scan history (sessions, prune, stats) | ⚠ partial — `kensa history` exists but lacks `--stats`, `--prune`, session model |
| `diff` | Compare two scan sessions for drift | ✗ missing |
| `coverage` | Framework coverage report (% of controls covered by rules) | ✗ missing — `kensa coverage` in Go means "list mechanisms"; Python's `coverage` is a different thing |
| `list frameworks` | List available framework mappings | ✗ missing |
| `info` | Rule/control lookup with multi-criteria search | ✗ missing |
| `rollback` | List/info/start rollback sessions | ⚠ partial — `kensa rollback --txn UUID` exists; the session-list / session-info workflow does not |
| `plan` | (kensa-go addition) preview-without-executing as structured Plan | ✓ kensa-go-only — no Python equivalent |
| `mechanisms` | (kensa-go) list registered handler mechanisms | ✓ exists as `kensa coverage`; **rename to `mechanisms`** to free `coverage` for the Python meaning |

### 3.2 `target_options` (used by detect / check / remediate)

| Long | Python short | Notes |
|---|---|---|
| `--host` | `-h` | comma-separated; multi-host glob via `--limit` |
| `--inventory` | `-i` | Ansible inventory file (INI/YAML) |
| `--limit` | `-l` | Limit to group or hostname glob (ansible `--limit` semantics) |
| `--user` | `-u` | SSH username |
| `--key` | `-k` | SSH private key path |
| `--password` | `-p` | Prompts securely if `-p` given without value |
| `--port` | `-P` | SSH port; capital P |
| `--verbose` | `-v` | Show capability detection details |
| `--sudo` | (no short) | Run all remote commands via sudo |
| `--strict-host-keys / --no-strict-host-keys` | (no short) | Boolean pair; default off in Python |
| `--capability` | `-C` | Repeatable, KEY=VALUE; override detected capability |
| `--workers` | `-w` | Parallel SSH connections; 1–50, default 1 |

### 3.3 `rule_options` (used by check / remediate)

| Long | Python short | Notes |
|---|---|---|
| `--rules` | `-r` | Path to rules directory (recursive) |
| `--rule` | (no short) | Path to single rule file |
| `--severity` | `-s` | Repeatable, choice: critical/high/medium/low |
| `--tag` | `-t` | Repeatable |
| `--category` | `-c` | Filter by category |
| `--framework` | `-f` | Filter to rules in framework mapping (e.g., `cis-rhel9`) |
| `--var` | `-V` | Repeatable, KEY=VALUE; override rule variable |
| `--control` | (no short) | Run only rules for a framework control (e.g., `cis-rhel9:5.1.12`) |
| `--config-dir` | (no short) | Config directory; default auto-detect |

### 3.4 `output_options` (used by check / remediate)

| Long | Python short | Notes |
|---|---|---|
| `--output` | `-o` | Repeatable; format `csv\|json\|pdf\|evidence`; optional `:path` to write to file |
| `--quiet` | `-q` | Suppress terminal output |

### 3.5 Subcommand-specific options

**`check`:**
| Long | Short | Purpose |
|---|---|---|
| `--store` | (none) | Persist results to local SQLite |

**`remediate`:**
| Long | Short | Purpose |
|---|---|---|
| `--dry-run` | (none) | Preview without changes |
| `--rollback-on-failure` | (none) | Auto-rollback on failure |
| `--allow-conflicts` | (none) | Proceed despite rule conflicts |
| `--no-snapshot` | (none) | Skip pre-state capture |

**`history`:**
| Long | Python short | Purpose |
|---|---|---|
| `--host` | `-h` | Filter by host |
| `--rule` | `-r` | Filter by rule ID |
| `--id` | `-S` | Show specific session |
| `--limit` | `-n` | Max entries (head/tail-style) |
| `--stats` | (none) | Database stats |
| `--prune DAYS` | (none) | Remove results older than N days |

**`diff`:** positional `SESSION1 SESSION2`, plus `--host/-h`, `--show-unchanged`, `--json`.

**`coverage`** (Python):
| Long | Python short | Purpose |
|---|---|---|
| `--framework` | `-f` | Required; framework mapping ID |
| `--rules` | `-r` | Path to rules directory |
| `--json` | (none) | JSON output |

**`info`:** positional `QUERY` (optional), plus `--control/-c`, `--rule/-r`, `--list-controls/-l`, `--framework/-f`, `--prefix-match/-p`, `--json`, `--cis`, `--stig`, `--nist`, `--rhel` (8/9/10).

**`rollback`:** `--list`, `--info ID`, `--start ID`, `--detail`, `--rule`, `--host/-h`, `--inventory/-i`, `--limit/-l`, `--max/-n`, `--json`, full SSH-cred set, `--dry-run`, `--force`.

---

## 4. The Resolved Short-Letter Table

This is the central artifact. Every short alias kensa-go accepts is here.
The constants are checked into `cmd/kensa/flags.go` so collisions surface
in code review.

### 4.1 Reserved (GNU/POSIX — never reused)

```
-h    --help
-V    --version
-v    --verbose
--    end of options
-     stdin/stdout (where applicable)
```

### 4.2 Resolved table — kensa-go vs Python kensa

Bold rows are **deviations from Python**. Italic rows are **GNU/POSIX
reservations that override Python**. The "kensa-go short" column is what
kensa-go ships.

| Long | kensa-go short | Python short | Status |
|---|---|---|---|
| `--help` | `-h` | (top-level only, conflicts on subcommands) | _GNU reservation_ |
| `--version` | `-V` | (top-level Click default, no short) | _GNU reservation_ |
| `--verbose` | `-v` | `-v` | matches |
| `--host` | **`-H`** | `-h` | **deviation — `-h` is help** |
| `--inventory` | `-i` | `-i` | matches |
| `--limit` (host glob, in target_options) | `-l` | `-l` | matches |
| `--limit` (row count, in history/rollback) | `-n` | `-n` | matches; head/tail convention |
| `--user` | `-u` | `-u` | matches |
| `--key` | `-k` | `-k` | matches |
| `--password` | `-p` | `-p` | matches |
| `--port` | `-P` | `-P` | matches; capital P, lowercase taken by password |
| `--sudo` | (no short) | (no short) | matches |
| `--strict-host-keys` | (no short) | (no short) | matches |
| `--capability` | `-C` | `-C` | matches |
| `--workers` | `-w` | `-w` | matches |
| `--rules` | `-r` | `-r` | matches |
| `--rule` (single file in check/remediate) | (no short) | (no short) | matches |
| `--rule` (filter in history/info/rollback) | `-R` | `-r` (in history/info/rollback) | **deviation** — Python uses `-r`, but `-r` is `--rules` in target/rule scope. kensa-go uses capital `-R` for the filter form to avoid cross-command confusion |
| `--severity` | `-s` | `-s` | matches |
| `--tag` | `-t` | `-t` | matches |
| `--category` | `-c` | `-c` | matches |
| `--framework` | `-f` | `-f` | matches |
| `--var` | **`-x`** | `-V` | **deviation — `-V` is version**; lowercase x ("eXtra var", ansible-`-e` mnemonic) |
| `--control` | (no short) | (no short) | matches |
| `--config-dir` | (no short) | (no short) | matches |
| `--output` | `-o` | `-o` | matches; repeatable; `format[:path]` |
| `--quiet` | `-q` | `-q` | matches |
| `--id` (session ID) | `-S` | `-S` | matches |
| `--store` | (no short) | (no short) | matches |
| `--dry-run` | (no short — destructive) | (no short) | matches |
| `--rollback-on-failure` | (no short) | (no short) | matches |
| `--allow-conflicts` | (no short) | (no short) | matches |
| `--no-snapshot` | (no short) | (no short) | matches |
| `--stats` | (no short) | (no short) | matches |
| `--prune` | (no short — destructive) | (no short) | matches |
| `--show-unchanged` | (no short) | (no short) | matches |
| `--list` (rollback session list) | (no short) | (no short) | matches |
| `--info` (rollback session detail) | (no short) | (no short) | matches |
| `--start` (rollback execute) | (no short) | (no short) | matches |
| `--detail` | (no short) | (no short) | matches |
| `--max` (rollback list cap) | `-n` | `-n` | matches |
| `--list-controls` | **`-L`** | `-l` | **deviation** — `-l` is `--limit`; capital L for list |
| `--prefix-match` | (no short) | `-p` | **deviation — `-p` is password** |
| `--cis` | (no short) | (no short) | matches |
| `--stig` | (no short) | (no short) | matches |
| `--nist` | (no short) | (no short) | matches |
| `--rhel` | (no short) | (no short) | matches |
| `--force` | (no short — destructive) | (no short) | matches |
| `--json` (legacy boolean alias) | (no short) | (no short) | matches; **deprecate in favor of `--output json`** |
| `--allow-command-exec` (kensa-go only) | (no short — destructive) | n/a | kensa-go addition |
| `--db` (top-level) | `-D` | n/a | kensa-go addition |
| `--no-color` | (no short) | n/a | kensa-go addition; honors `NO_COLOR` env |

### 4.3 Five canonical short-letter choices

The table preserves GNU/POSIX reservations on the five letters where
Python kensa's prior art conflicted with GNU. These are not deviations
to apologize for — they are the canonical kensa-go design. Documented
in `--help` and the manpage as the table is, not as a delta from
something else:

```
Reserved short letters (GNU/POSIX, never reused):
  -h, --help              GNU help convention
  -V, --version           GNU version convention
  -v, --verbose           GNU verbose convention

Where Python kensa's prior art conflicted with the above, kensa-go's
canonical choice:
  -H, --host              (Python used -h; -h is help in kensa-go)
  -x, --var               (Python used -V; -V is version in kensa-go)
  -R, --rule              (filter form; -r is --rules)
  -L, --list-controls     (-l is --limit host glob)
  --prefix-match (no short)  (-p is --password)
```

Python kensa is being phased out as an internal prototype with no
production users, so there is no operator muscle memory to migrate.
The table above is the kensa CLI.

---

## 5. Per-Subcommand kensa-go Specification

For each subcommand: positional args, flag set, output behavior. All
flags follow §4 short-letter table.

### 5.1 `kensa detect`

**Positional:** none.
**Flags:** full target_options group; `--output/-o` (csv|json|jsonl|evidence; no PDF for detect).
**Status today:** implemented; missing `--limit`, `--password`, `--strict-host-keys`, `--capability`, `--workers`. Add these.
**Output today:** Unicode `✓`/`✗` glyphs; replace with ASCII when not on TTY.

### 5.2 `kensa check`

**Positional:** none (rule files come via `--rules` or `--rule`; positional argv reserved for future).
**Flags:** target_options + rule_options + output_options + `--store`.
**Status today:** implemented but missing `--severity`, `--tag`, `--category`, `--framework`, `--var`, `--control`, `--config-dir`, `--store`, `--strict-host-keys`, `--password`, `--workers`, `--capability`. Add all.
**Output today:** `--format table|json|jsonl`. Migrate to `-o csv|json|jsonl|evidence|oscal` and keep `--format` as a deprecated alias for one minor version.

### 5.3 `kensa remediate`

**Positional:** none.
**Flags:** target_options + rule_options + output_options + `--dry-run` + `--rollback-on-failure` + `--allow-conflicts` + `--no-snapshot` + **`--allow-command-exec`** (kensa-go-only).
**Status today:** implemented but missing every rule-filter, `--store`, `--rollback-on-failure`, `--allow-conflicts`, `--no-snapshot`, plus the `--oscal` flag should fold into `-o oscal:path`.
**Output today:** `--format`, plus `--oscal path`. Migrate to `-o oscal:path` (single canonical mechanism).

### 5.4 `kensa history`

**Positional:** none.
**Flags:** `--host/-H`, `--rule/-R`, `--id/-S`, `--limit/-n`, `--stats`, `--prune`, `--output/-o`.
**Status today:** has filter flags, but no `--id`, no `--stats`, no `--prune`. Add session model (Python kensa stores sessions; kensa-go stores transactions; the conceptual mapping is 1:N — one scan session contains many transactions). Add session-level grouping in the store.

### 5.5 `kensa diff` (NEW)

**Positional:** `SESSION1 SESSION2`.
**Flags:** `--host/-H`, `--show-unchanged`, `--output/-o`.
**Output:** drift report — rules that changed status between two sessions.
**kensa-go enhancement:** include the per-step pre-state hash so the diff identifies *what* changed in addition to *that* it changed. Python's diff is status-only.

### 5.6 `kensa coverage` (REPURPOSED — was "list mechanisms")

**Positional:** none.
**Flags:** `--framework/-f` (required), `--rules/-r`, `--output/-o`.
**Output:** framework-coverage report — % of controls in `--framework` that have at least one matching rule, plus the gap list.
**Migration note:** the existing `kensa coverage` (list mechanisms) renames to `kensa mechanisms`. This is a breaking change to scripts using `kensa coverage` for mechanism listing; document in CHANGELOG with one minor version of deprecation warning.

### 5.7 `kensa list frameworks` (NEW)

**Positional:** none.
**Flags:** `--output/-o`.
**Output:** list every framework mapping kensa knows about (loaded from `internal/mappings`). Python has this; kensa-go's mappings package has the data already.

### 5.8 `kensa info` (NEW)

**Positional:** `QUERY` (optional — rule ID, control ID, or freetext).
**Flags:** `--control/-c`, `--rule/-R`, `--list-controls/-L`, `--framework/-f`, `--prefix-match`, `--cis`, `--stig`, `--nist`, `--rhel`, `--output/-o`.
**Output:** rule/control lookup with framework cross-references.

### 5.9 `kensa rollback` (REWORKED)

**Positional:** none.
**Flags:** `--list`, `--info ID`, `--start ID`, `--detail`, `--rule R`, `--host/-H`, `--inventory/-i`, `--limit/-l`, `--max/-n`, `--output/-o`, full SSH cred set, `--dry-run`, `--force`.
**Status today:** kensa-go's `kensa rollback --txn UUID` is one path (Python's `--start` semantics); add `--list` and `--info` for session browsing.
**kensa-go enhancement:** when `--info` is requested with `--output evidence`, emit the *signed* envelope from the original transaction — Python emits unsigned evidence.

### 5.10 `kensa plan` (kensa-go-only — keep)

Already exists. No Python equivalent. The Plan-as-structured-artifact
with `PlanStaleError` re-execute semantics is meaningfully better than
Python's `--dry-run`. Document this as a kensa-go capability; do not
remove or hide it.

### 5.11 `kensa mechanisms` (renamed from `kensa coverage`)

Already exists. Add `--output/-o` for json. Cosmetic rename only.

### 5.12 `kensa version`

Already exists as subcommand. Keep, but the canonical form is the
top-level `--version`/`-V` flag. Mark `kensa version` as deprecated in
the next minor release.

---

## 6. The `--output FORMAT[:PATH]` Mechanism

Single mechanism for all data emission. Replaces `--format`, `--oscal`,
`--json`, and shell redirection patterns.

### 6.1 Syntax

```
-o FORMAT             # write to stdout in FORMAT
-o FORMAT:PATH        # write to file at PATH in FORMAT
-o FORMAT1 -o FORMAT2 # multiple outputs in one run
```

### 6.2 Format vocabulary

Every kensa-go format. Per-subcommand availability:

| Format | detect | check | remediate | history | diff | coverage | info | rollback | plan | Python? |
|---|---|---|---|---|---|---|---|---|---|---|
| `text` | ✓ default | ✓ default | ✓ default | ✓ default | ✓ default | ✓ default | ✓ default | ✓ default | ✓ default | yes (default) |
| `json` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | yes |
| `jsonl` | ✓ | ✓ (multi-host streaming) | ✓ (multi-host streaming) | n/a | n/a | n/a | n/a | n/a | n/a | **no — kensa-go addition** |
| `csv` | n/a | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | yes |
| `pdf` | n/a | ✓ | ✓ | n/a | n/a | ✓ | n/a | ✓ | n/a | yes (requires path) |
| `evidence` | n/a | ✓ | ✓ | n/a | n/a | n/a | n/a | ✓ (per-session) | n/a | yes (kensa-go: signed envelope) |
| `oscal` | n/a | ✓ | ✓ | n/a | n/a | ✓ | n/a | n/a | n/a | **no — kensa-go addition** |
| `markdown` | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | ✓ | no |

`pdf` and `oscal` always require a `:PATH`; rejecting `-o pdf` (no path)
with a usage error matches Python's behavior.

### 6.3 Repeatability

`-o json -o csv:report.csv -o evidence:bundle.json` is valid and runs
all three serializers against the same in-memory result. kensa-go fans
out concurrently to multiple writers — measurably faster than Python's
sequential approach for large fleets.

### 6.4 `--quiet/-q`

Suppresses default human output. Useful with `-o`:

```
kensa check -H prod --sudo -o evidence:bundle.json -q
```

writes the evidence file without any terminal noise.

---

## 7. Where kensa-go Does It Better — Document These Loudly

Per the founder's directive, these are kensa-go capabilities that
exceed Python kensa. The CLI surfaces them; documentation calls them
out by name.

### 7.1 `jsonl` for streaming multi-host scans

Python's `--output json` against a 500-host inventory builds a single
JSON object in memory and emits it at the end. kensa-go's
`-o jsonl[:PATH]` emits one NDJSON line per host as the scan completes.
Critical for OpenWatch ingest pipelines and `jq`-based ops scripts.

### 7.2 `oscal` Assessment Results

OSCAL is the federal compliance standard for assessment results.
kensa-go has `internal/evidence/oscal.go` already; Python kensa does
not emit OSCAL natively. Folding it into `-o oscal:PATH` makes it a
first-class output and lets kensa-go's results land in any
FedRAMP-compliant SIEM/GRC tool without translation.

### 7.3 Signed evidence envelopes

Python's `evidence` format is per-rule raw output. kensa-go's
`evidence` format is the `EvidenceEnvelope` (per `api/transaction.go`)
with Ed25519 signature, canonical schema, framework refs, and the
`CommandExecAllowed` audit field. Auditors get cryptographic
attestation, not just data. (Currently signer is `noopSigner`; real
signatures land with task #12 and the CLI surface is ready for them.)

### 7.4 `kensa plan` as a structured artifact

Python's `--dry-run` produces preview text. kensa-go's `kensa plan`
produces a full `Plan` with captured pre-state, capability detection
results, validators, rollback plan, and `PlanStaleError` re-execute
semantics. Approve once, execute exactly that plan; stale state
returns a structured error identifying what diverged. This is the
control-plane primitive that makes preview-then-execute meaningful.

### 7.5 Single static binary

Python kensa needs Python 3 + `runner` package + dependencies.
kensa-go is one static binary. With `CGO_ENABLED=0` discipline (per
`LOW_LEVEL_MIGRATION_V1.md` Phase 0), one binary built today runs on
RHEL 8 through RHEL 12. Python kensa's deployment story is markedly
weaker for restricted/air-gapped customers.

### 7.6 `--allow-command-exec` audit gate

Python kensa has no equivalent. kensa-go's pre-flight rejects any
transaction containing the `command_exec` mechanism unless the
operator explicitly opts in, and the opt-in is captured in
`EvidenceEnvelope.CommandExecAllowed`. Free-form remote command
execution requires deliberate, audit-trailed authorization.

### 7.7 Schema-versioned wire formats

Every kensa-go JSON output carries `schema_version`. Python's outputs
do not consistently. Agents and SIEMs can detect format evolution and
adapt; kensa-go can change wire shapes safely across minor versions.

### 7.8 `agent` mode (planned, per LOW_LEVEL_MIGRATION_V1.md)

`kensa agent --stdio` runs as a target-local executor, talking to the
controller via length-prefixed protobuf over SSH stdin/stdout.
Unlocks every kernel-primitive in the low-level migration. Python
kensa has no analog — it shells out for everything. The CLI surface
gets one new top-level subcommand when this lands; it is not
operator-facing in normal use.

### 7.9 Concurrent multi-format output

`-o csv:a.csv -o pdf:b.pdf -o oscal:c.json -q` fans out via Go
goroutines. Python iterates sequentially. For a 1000-host fleet
with three output formats, the wall-clock difference is measurable.

### 7.10 Live event subscription (existing in `api`, surface in CLI as follow-up)

`api.Kensa.Subscribe` returns a channel of typed events
(`TransactionStarted`, `PhaseCompleted`, `Committed`, `RolledBack`,
`DriftDetected`, `HeartbeatPulse`, `DeadmanTimerArmed`,
`DeadmanTimerFired`). A future `kensa watch --filter rolled_back -o
jsonl` would stream them live. Python is fundamentally batch.

---

## 8. Phased Migration

Each phase is independently shippable and adds value on its own.

### Phase 1 — pflag swap + GNU/POSIX flag style

**Goal:** Cure the immediate ergonomic bugs.

- `pflag` for all three binaries.
- Centralized `cmd/kensa/flags.go` with the §4 short-letter table.
- `--help` exits 0 with content on stdout; `-h` works everywhere.
- `kensa --help`, `kensa --version`, `kensa -V` work at top level.
- Bad usage exits 2; runtime errors exit 1.
- `--` end-of-options handling.
- Existing flags renamed/reshorted per §4 with old names accepted as
  deprecated aliases for one minor version.

**Risk:** Low. **Size:** ~1 day.

### Phase 2 — `--output FORMAT[:PATH]` mechanism

**Goal:** Single canonical output mechanism replacing `--format`,
`--oscal`, and shell redirection.

- `-o, --output` repeatable; parser for `format:path`.
- Format dispatcher with serializers for `text`, `json`, `jsonl`,
  `csv`, `pdf` (requires `:path`), `evidence`, `oscal`, `markdown`.
- `-q, --quiet` to suppress default terminal output.
- Concurrent fan-out for multi-output runs.
- `--format` retained as deprecated alias for one minor version.

**Risk:** Medium. CSV serializer needs design (column set per data type
— rule results, history rows, diff rows, info results). PDF serializer
is a real new dependency (`gofpdf` or similar pure-Go). Evidence/OSCAL
serializers exist. JSONL exists.

**Size:** ~1 week.

### Phase 3 — Full `target_options` and `rule_options` parity

**Goal:** Every Python kensa target/rule flag works in kensa-go.

- Add `--limit/-l` (host glob) — needs `internal/inventory` to grow
  glob-pattern matching.
- Add `--password/-p` with prompt-if-no-value semantics.
- Add `--strict-host-keys / --no-strict-host-keys` boolean pair
  through the SSH transport.
- Add `--capability/-C KEY=VALUE` repeatable into the detect path.
- Add `--workers/-w` with `IntRange(1, 50)` clamp.
- Add `--severity/-s`, `--tag/-t`, `--category/-c`, `--framework/-f`,
  `--var/-x KEY=VALUE`, `--control`, `--config-dir` — all rule
  filtering. Map to `internal/rule` selector logic.

**Risk:** Medium. The selector and inventory glob are new code paths.
Existing handler / engine API does not change.

**Size:** ~1.5 weeks.

### Phase 4 — Session model and missing subcommands

**Goal:** `--store`, `--stats`, `--prune`, `kensa diff`, `kensa
coverage` (framework), `kensa list frameworks`, `kensa info`, full
`kensa rollback`.

- Session abstraction in `internal/store`: a session is a group of
  transactions ran from one CLI invocation. Currently the store has
  transactions but no session header.
- Implement the seven new or repurposed subcommands per §5.
- Rename existing `kensa coverage` to `kensa mechanisms`; deprecate
  the old name.

**Risk:** Medium-high. The session model is a real schema change to
the SQLite store. Migration script needed for existing databases.

**Size:** ~2 weeks.

### Phase 5 — kensa-go-specific surfaces

**Goal:** Make the §7 advantages visible.

- `--output jsonl` available everywhere it makes sense.
- `--output oscal` everywhere it makes sense.
- `--output evidence` produces signed envelopes once task #12 lands;
  before then, produces unsigned envelopes with a documented warning.
- Document the GNU/POSIX deviations from Python in `kensa --help`,
  in a new `man kensa(1)` page, and in the operator quickstart.
- `kensa watch --filter <kind>` (live event subscription) — sketch
  for follow-up PR.
- `kensa agent --stdio` placeholder subcommand (real implementation
  is in `LOW_LEVEL_MIGRATION_V1.md`).

**Risk:** Low. Mostly wiring already-existing functionality through
the new output mechanism.

**Size:** ~1 week.

### Total

Phases 1–5 sequential: ~6 weeks single engineer. Phase 1 alone (~1
day) is enough to fix the immediate ergonomic bugs and can ship today.
Phase 2 is the next-highest-leverage drop.

---

## 9. Operator-Facing Promise

Document this verbatim in `kensa(1)` and the quickstart:

> kensa-go follows GNU/POSIX command-line conventions. Every flag has
> a long form (`--option`) and, where useful, a single-letter short
> form (`-x`). `-h, --help`, `-V, --version`, and `-v, --verbose` work
> as expected. `--` ends option parsing. `-q, --quiet` suppresses
> default output. `-o, --output FORMAT[:PATH]` is repeatable for
> multi-format output (`json`, `jsonl`, `csv`, `pdf`, `evidence`,
> `oscal`, `markdown`, depending on subcommand). Exit codes are 0
> (success), 1 (runtime error), 2 (usage error).

(Internal note for engineers familiar with Python kensa: kensa-go's
CLI design is informed by Python kensa's option groups but does not
constrain itself to Python's short-letter table where Python conflicted
with GNU reservations. See §4.3 for the five letters that differ.
Python kensa has no production users and is being phased out; there is
no migration path to engineer.)

---

## 10. Decision Points

1. **Order vs `LOW_LEVEL_MIGRATION_V1.md`.** This plan is independent
   of the kernel-ABI migration. **Recommendation:** Phase 1 of *this*
   plan can land *now* on the current branch; the rest can run in
   parallel with the low-level work.
2. **Scope of breaking changes.** Renaming `kensa coverage` →
   `kensa mechanisms` is a breaking change. Migration period: one
   minor release with `kensa coverage` printing a deprecation
   warning that points at `kensa mechanisms`. **Recommendation:**
   ship the rename in Phase 4 alongside the new framework-coverage
   `kensa coverage`.
3. **`--format` retention period.** Existing scripts use `--format
   json`. Phase 2 introduces `--output json`. Keep `--format` as a
   deprecated alias for one minor version, then remove. **Recommendation:**
   document in CHANGELOG; warn on use.
4. **PDF serializer dependency.** Pure-Go PDF library introduces a
   new transitive dep. **Recommendation:** evaluate `unidoc/unipdf`,
   `phpdave11/gofpdf`, `johnfercher/maroto`. Pick the one with
   smallest dep tree and pure-Go discipline. None are in `go.mod`
   today.
5. **Session schema migration.** Phase 4 changes the SQLite schema.
   **Recommendation:** ship a one-time `kensa migrate` subcommand
   that converts existing databases on first run; document in
   release notes.

Once the founder ratifies, this graduates from "Draft" to "Adopted"
and the phases become work-tracked.
