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

### Changed

- `kensa history` paginated output trailer ("N of M transactions
  shown") now goes to stderr when `--format` is anything other
  than `text` (e.g., `json`, `csv`) so the trailer doesn't
  corrupt row-oriented formats. The `text` format still emits
  the trailer on stdout for human readability.

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
