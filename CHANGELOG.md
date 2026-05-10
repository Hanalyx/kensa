Changelog
=========

All notable user-visible changes to kensa-go are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/) loosely:
sections grouped by category (Added / Changed / Deprecated / Removed
/ Fixed / Security) under each release heading. Pre-1.0 we ship
unreleased changes under `## Unreleased` and stamp them at tag time.

The CLI is governed by GNU/POSIX conventions per
`docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md`. Long-form flags are
the canonical names; short forms are listed in
`cmd/kensa/flags.go`.

## Unreleased

### Breaking changes

- **CLI Phase 3 short-letter table reconciliation (C-024).** Four
  short letters are reassigned to align with `Python kensa` parity
  per `docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md` §4.2. Operators
  scripting kensa-go with the old short forms must migrate before
  upgrade. Long forms are unchanged; only the short letters move.

  | Flag | Old short | New short | Migration |
  |---|---|---|---|
  | `--port` | `-p` | `-P` | use `--port` long form, or `-P` |
  | `--sudo` | `-s` | (none) | use `--sudo` long form |
  | `--txn` | `-t` | `-T` | use `--txn` long form, or `-T` |
  | `--format` | `-f` | (none) | `--format` already deprecated; use `-o`/`--output` |

  The freed short letters (`-p`, `-s`, `-t`, `-f`) are reserved for
  Phase 3 deliverables: `--password` (C-026), `--severity` (C-030),
  `--tag` (C-031), `--framework` (C-033). Operators using the old
  short forms after upgrade get pflag's "unknown shorthand" error
  (exit code 2). No deprecation period — kensa-go is pre-1.0 and
  the migration doc explicitly notes Python kensa has no production
  users to migrate.

### Added

- `-o, --output FORMAT[:PATH]` (repeatable) on `kensa detect`,
  `kensa check`, and `kensa remediate` (C-019). Operators can
  dispatch one in-memory result to multiple destinations
  concurrently:
  ```
  kensa check -H prod-01 -u admin --sudo \
      -o json -o csv:results.csv -o pdf:report.pdf
  ```
  Supported formats: `text`, `json`, `jsonl`, `csv`, `pdf`,
  `evidence`, `oscal`, `markdown`. Not every format applies to
  every payload type — `oscal`/`evidence` are remediation-only;
  `pdf`/`text`/`csv` apply to scan and remediation;
  `jsonl` is scan-only. Specifying an unsupported format
  returns exit code 2 (usage error) with a clear message.

- `-q, --quiet` flag on body-emitting subcommands (C-018).
  Suppresses default human-readable output to stdout. Errors
  and warnings still emit on stderr; exit codes (0/1/2) are
  unchanged. Pairs naturally with `-o FILE` for CI scripts:
  `kensa check --quiet -o json:results.json`.

- CSV serializer (C-013) registered for scan, remediation, and
  history result types. RFC 4180-compliant escaping via
  `encoding/csv`.

- PDF serializer (C-015) using `maroto v2` (MIT, pure Go, no
  cgo). Registered for scan and remediation; produces operator
  triage / handoff PDFs (NOT audit-grade evidence — that's the
  signed envelope output from `--output evidence:PATH`).

- OSCAL Assessment Results serializer wired through `-o`
  (C-016). Equivalent to the legacy `--oscal` flag (which is
  now deprecated).

- Evidence-envelope JSON serializer wired through `-o` (C-017).
  Each transaction's signed `*api.EvidenceEnvelope` emits as an
  independently-verifiable JSON document. Pre-M7, signatures
  are empty bytes; the wire shape is final.

- **Session model + session-aware subcommands (CLI Phase 4,
  C-039 .. C-050).** SQLite migration 2 introduces a `sessions`
  table that groups transactions from one CLI invocation.
  Twelve new operator-facing surfaces:

  - `kensa migrate` (C-040) — applies pending schema
    migrations; backfills synthetic sessions for pre-Phase-4
    transactions. Idempotent.
  - `kensa check --store` (C-041) — persists a check run as a
    session + transactions in the SQLite log. Default off
    (check is read-only by convention).
  - `kensa history --stats` (C-042) — aggregate counts by
    session / transaction / status / severity / host. Works
    with `--host` and `--since` filters.
  - `kensa history --prune DAYS` (C-043) — destructive
    cleanup. Deletes sessions older than N days plus the
    cascade (transactions, steps, pre_states, framework_refs,
    rollback_events). Requires `--force` for non-interactive
    runs; otherwise prompts on TTY.
  - `kensa mechanisms` (C-044) — canonical name for the
    handler-mechanism listing. `kensa coverage` is a
    deprecated alias (see Changed section below).
  - `kensa coverage --framework FRAMEWORK --rules-dir DIR`
    (C-045) — framework control coverage report. Numerator
    only (controls referenced); denominator (controls in
    framework) is a future deliverable.
  - `kensa list frameworks` (C-046) — list framework_ids in
    the loaded corpus with control + rule counts.
  - `kensa list sessions` (C-048) — surface session UUIDs
    from the transaction store for use with `kensa diff` and
    `kensa rollback --start`.
  - `kensa info` (C-047) — multi-criteria rule/control
    lookup. Four modes: `--rule R`, `--control FRAMEWORK:ID`,
    `--list-controls/-L FRAMEWORK`, positional `QUERY`. All
    pairwise mutually exclusive. Filters: `--cis` / `--stig`
    / `--nist` / `--rhel`.
  - `kensa diff SESSION1 SESSION2` (C-048) — per-rule drift
    report between two stored sessions. SESSION1 is "before";
    SESSION2 is "after" (git-diff convention). `--show-
    unchanged` includes the unchanged section in text output.
  - `kensa rollback --list / --info SESSION_ID / --start
    SESSION_ID / --detail` (C-049) — session-aware rollback.
    `--list` and `--info` are read-only; `--start` executes
    bulk rollback with a hostname guard. Legacy `--txn UUID`
    form preserved for surgical single-txn rollback. Only
    sessions created by `kensa remediate` are rollback-able
    (check sessions have no captured pre-state to revert).

- **Phase 5a operator surfaces (C-051 .. C-056).**
  - `--format jsonl` on `kensa history` (C-051), `kensa list
    sessions` (C-052), and `kensa info QUERY` (C-052). One
    compact JSON object per line — natural for piping into
    Splunk / ELK / Loki. Document-shaped modes (history's
    --aggregate / --stats / --txn; info's --rule / --control
    / --list-controls) reject `--format jsonl` with usage
    error pointing at `--format json`.
  - `kensa agent --stdio` placeholder (C-054) — reserves the
    subcommand name in v1.0. Exits 1 with "planned for v1.1
    with the kernel-primitive migration (Track L Phase 1)";
    `kensa agent --help` discloses the planned wire-protocol
    direction so consumers can write integration code today.
  - `kensa(1)` Unix manpage (C-055). Hand-written wrapper
    + generated flag body. `make manpage` produces
    `dist/kensa.1`; `make manpage-check` is the drift gate
    for CI. Source-of-truth committed at `docs/man/kensa.1`.

### Changed

- `kensa history` paginated output trailer ("N of M transactions
  shown") now goes to stderr when `--format` is anything other
  than `text` (e.g., `json`, `csv`) so the trailer doesn't
  corrupt row-oriented formats. The `text` format still emits
  the trailer on stdout for human readability.

- `kensa coverage` → renamed to `kensa mechanisms` (C-044). The
  canonical name for the handler-mechanism listing is now
  `kensa mechanisms`. The `coverage` name remains a working
  alias today and emits a stderr warning explaining the
  upcoming v0.2 repurpose. **The `coverage` name is NOT being
  removed — it is being repurposed in v0.2 to report framework
  control coverage** (a different feature). Migrate scripts to
  `mechanisms` to preserve current output across the upgrade.
  Suppress the warning in pre-migrated CI with
  `KENSA_NO_REPURPOSE_WARNINGS=1` (a SEPARATE knob from the
  `KENSA_NO_DEPRECATION_WARNINGS` flag-rename switch — the
  semantic-flip warning is categorically louder).

### Deprecated

- `--format` / `-f` on `detect`, `check`, and `remediate`
  (C-020). Emits a one-line stderr warning when used. Use
  `--output` / `-o` instead. **Will be removed in v0.2.**

- `--oscal` on `remediate` (C-020). Emits a one-line stderr
  warning when used. Use `--output oscal:PATH` instead.
  **Will be removed in v0.2.**

  Migration:
  ```
  # before
  kensa check ... --format json
  kensa remediate ... --format json --oscal /tmp/asmt.json

  # after
  kensa check ... -o json
  kensa remediate ... -o json -o oscal:/tmp/asmt.json
  ```

  The deprecation warnings always emit on stderr regardless of
  `--quiet` so operators can't accidentally silence the
  migration signal.

  Operators who have planned the migration but can't migrate
  immediately can silence the warnings with the env var
  `KENSA_NO_DEPRECATION_WARNINGS=1` (exact match on "1"). Use
  `2>/dev/null` would silence real errors too; the env var is
  the targeted opt-out. NOT a substitute for migrating — the
  flags will still be removed in v0.2 regardless of whether
  the warning was visible.

### Fixed

- `kensa history --format csv` no longer corrupts the CSV file
  with a trailing pagination summary (the summary now goes to
  stderr instead of being mixed into stdout).

- `kensa remediate --oscal /path` no longer creates a 0-byte
  file when no transaction produced an envelope; the file is
  not created and a stderr line explains why.

- Long SCAP-style rule IDs in PDF reports (`xccdf_org.ssgproject.
  content_rule_…` 75-95 chars) wrap with character-level breaks
  instead of overflowing into adjacent table columns.
