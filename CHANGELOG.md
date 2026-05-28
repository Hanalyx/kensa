Changelog
=========

All notable user-visible changes to kensa are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/) loosely:
sections grouped by category (Added / Changed / Deprecated / Removed
/ Fixed / Security) under each release heading. Pre-1.0 we ship
unreleased changes under `## Unreleased` and stamp them at tag time.

The CLI is governed by GNU/POSIX conventions. Long-form flags are
the canonical names; short forms are listed in `cmd/kensa/flags.go`.

## Unreleased

(no changes yet)

## v0.1.1 — 2026-05-27

First tag carrying the ratified Kensa/OpenWatch boundary, so OpenWatch can
pin a kensa with the agreed `api/` surface. No `api/` contract change since
v0.1.0 — the public Go API is identical; this is a documentation +
internal-quality release.

### Changed

- `api/` event-stream godoc (`EventKind`) corrected to the ratified
  Kensa/OpenWatch boundary: OpenWatch owns liveness / heartbeat / drift;
  Kensa emits the shared event vocabulary (`transaction_started`,
  `committed`, `rolled_back`, `drift_detected`, `heartbeat_pulse`,
  `deadman_timer_armed` / `_fired`). Godoc only — the types are unchanged.

### Internal

- Spec-driven tests added for 10 previously-untested handlers.
- Code comments scrubbed of planning labels (e.g. roadmap phase / option
  names) per the new "Comments" section of `CONTRIBUTING.md`; a
  `make comment-lint` check guards new comments.

## v0.1.0 — 2026-05-14 (Sentinel)

First versioned release on the renamed repository (formerly
`Hanalyx/kensa-go`, now `Hanalyx/kensa` after the Python kensa was
archived). The 0.1.0 line is the development phase: the public
`api/` Go package is held to v1 semver for OpenWatch's consumption,
and the rest of the surface may change between MINOR versions with
one release of deprecation warning. See
[`VERSIONING_PLAN.md`](VERSIONING_PLAN.md) for the full release
contract.

### Added

- **VERSION file at the repo root** as the single source of truth for
  the version string. All five binaries (`kensa`, `kensa-fuzz`,
  `kensa-validate`, `kensa-keygen`, `kensa-systemd-helper`) read it
  via `-ldflags "-X main.version=$(cat VERSION)"` and report `0.1.0`
  from `--version` / `-V`.
- **`VERSIONING_PLAN.md`** documenting SemVer 2.0.0 discipline,
  codename Sentinel (guardianship theme), atomicity-contract changes
  as always-MAJOR, and the frozen `api/` v1 contract.
- **`docs/guide/`** operator manual skeleton: index plus nine chapter
  stubs (install, quickstart, concepts, scan-and-remediate,
  rollback-and-history, rule-authoring, integration, troubleshooting,
  reference). Content lands in subsequent releases.

### Changed

- **Module path**: `github.com/Hanalyx/kensa-go` →
  `github.com/Hanalyx/kensa`. GitHub keeps a URL redirect from the
  old path so existing `go get` continues to resolve, but consumers
  should migrate when convenient. Re-run `go mod tidy` after bumping.
- **`docs/man/` → top-level `man/`.** The manpage source
  (`gen-manpage.go`) is real Go code and `kensa.1` ships in the RPM;
  it doesn't belong under `docs/`. Makefile, specter.yaml, and CI
  paths updated.
- **`docs/*` is now gitignored except `docs/guide/`.** Internal
  working notes (vision, roadmap, foundation contracts, coordination,
  AI session logs, founder release sign-off) stay locally as
  untracked working material. The published documentation surface is
  the operator guide.
- **README rewritten** to operator-facing voice per the new
  documentation style guide: runnable example up top, guarantees
  stated as facts (no marketing language), portability and atomicity
  contract as compact tables, explicit pre-1.0 callouts so today's
  reader knows what works (`make build` + `--rules-dir <local-path>`)
  versus the documented v1.0 ship state.

### Security

- **Kernel-primitive deadman timer for control-channel-
  sensitive remediation (Phase 3 P-011/D-001..D-006).** The
  deadman timer — the safety net that rolls back a
  half-applied rule if the controller-target SSH connection
  drops mid-Apply — now uses kernel primitives instead of
  `at(1)`/`systemd-run` scheduled shell scripts when running
  in agent mode. The new architecture:
  - `timerfd(CLOCK_BOOTTIME)`: counts elapsed seconds INCLUDING
    system suspend. A laptop or VM suspended mid-Apply
    resumes with the correct deadline (the old `at(1)` path
    fired late or not at all because wall-clock-based
    scheduling missed the suspended interval).
  - `pidfd_open(getppid(), 0)`: race-free SSH-parent-death
    detection in <200ms. The old path had no equivalent —
    it relied on the scheduler firing on its own deadline,
    with second-granularity latency.
  - `signalfd` for SIGTERM (via `signal.Notify` + self-pipe
    forwarder, the Go-runtime-friendly equivalent).
  - `epoll_wait` single-thread event loop integrating all
    three.

  RHEL 8 kernels (<5.3) lack `pidfd_open`; the agent probes
  at startup and falls back to
  `prctl(PR_SET_PDEATHSIG, SIGKILL)` — the kernel SIGKILLs
  the agent on parent death (rollback doesn't fire under
  SIGKILL, accepted risk per Q3.a; the agent at least
  doesn't linger orphaned).

  **Direct-SSH mode retains the shell-based path** (opt-in via
  `KENSA_NO_AGENT=1`) for environments where agent bootstrap
  isn't viable. It does NOT gain suspend-resistance or
  clock-jump-immunity — those properties require the
  in-process agent-side primitives.

- **Kernel-atomic file operations under agent mode (Phase 2,
  fix/phase-2-rework drop + P-011 default flip).** For the
  file-touching capturable handlers — `file_content`,
  `file_absent`, `config_set`, `config_set_dropin` — kensa now
  delivers literal kernel-primitive atomicity when remediation
  runs in agent mode (the default; opt-out via
  `KENSA_NO_AGENT=1`). The primitives:
  - `AtomicWrite` (new files): `O_TMPFILE` + `linkat` via
    `/proc/self/fd/<N>` — partially-written bytes are never
    visible as a half-named file in the directory.
  - `AtomicReplace` (existing files): `renameat2(RENAME_EXCHANGE)`
    for symmetric old↔new swap, with `renameat` rename-into-
    place fallback for filesystems that don't support the
    flag (kernel <3.15, NFS, vfat, some overlayfs).
  - `AtomicRemove`: `unlinkat` + parent-dir `fsync`.
  - Every primitive issues a parent-directory `fsync` barrier so
    the directory entry persists across crashes.

  **Direct-SSH mode is preserved as an explicit opt-out.**
  Operators who set `KENSA_NO_AGENT=1` get the shell-pipeline
  best-effort semantics for these mechanisms — intended for
  environments where agent bootstrap is not viable (noexec
  /tmp, locked-down SSH user, etc.). The `kensa remediate` CLI
  prints a one-line stderr disclosure on every run
  ("agent mode (default) — kernel-atomic primitives" or
  "direct-SSH mode (KENSA_NO_AGENT=1) — shell-pipeline
  best-effort; unset KENSA_NO_AGENT for kernel-atomic") so
  audit reviewers see the basis without reading the source.

- **Typed `ErrParentDirMissing`.** Returned by all three
  primitives when the parent directory of the target doesn't
  exist (or an intermediate component is missing). Replaces
  the previous generic "open intermediate" wrap. Operators
  hitting this error get a clear pointer to the missing
  component name.

- **Symlink-traversal refusal.** The fsatomic primitives walk
  the target path component-by-component with `O_NOFOLLOW` and
  refuse to operate if any component (including the base) is a
  symlink. An attacker who plants
  `/etc/sudoers.d/99-foo → /etc/passwd` cannot use kensa to
  rewrite the symlink target; the operation fails with a
  typed `ErrSymlinkInPath` error and the original target is
  unmodified. Rules that legitimately want to target a symlink
  must pass the resolved path; today's corpus has none.

- **Path-traversal defense.** Every file-touching handler
  rejects rule-supplied paths that are relative or contain
  `..` segments after `filepath.Clean`. Closes the previously-
  undefended direct-SSH shell path where
  `path: "../../etc/shadow"` would have been honored.

- **`renameat2` probe is per-filesystem, not global.** The
  RENAME_EXCHANGE support probe caches by `st_dev` so a
  heterogeneous mount layout (ext4 + NFS + xfs, typical on
  federal hosts) cannot poison the cache. First observation
  of an unsupported filesystem emits a one-time stderr
  warning to the operator.

### Fixed

- **Mode preservation across re-Apply (P0-A from the
  post-merge correctness review).** When a rule omits the
  `mode` parameter and the target file exists, `file_content`
  and `config_set_dropin` now preserve the file's current
  mode bits instead of silently widening to `0o644`. Matches
  `printf > file` shell semantics. A file previously
  tightened to `0o600` (e.g., one containing secrets) is no
  longer widened on re-Apply.

- **setuid/setgid/sticky bit preservation in `config_set`.**
  The Apply and Rollback paths previously used
  `info.Mode().Perm()` which silently dropped the special
  bits. `config_set` now uses `fsatomic.FileModeBits` which
  preserves all 12 Unix mode bits. `sed -i` preserves all 12;
  kensa now matches.

- **`config_set` regex char-class divergence on CRLF files.**
  The Go `[[:space:]]` class matches `\t\n\v\f\r ` but `sed
  -E` with `LC_ALL=C` matches only `\t ` — divergence on
  CRLF-line-ending files. The regex now spells the class as
  `[\t ]`, byte-equivalent to sed.

- **Rollback no longer silently defaults missing captured
  mode to `0o644`.** A `file_content` or `file_absent`
  rollback with an empty captured `mode` (indicating a
  Capture bug) now fails loudly rather than widening
  permissions on the restored file. Operator is instructed
  to re-run capture.

### Changed

- **`api.AtomicTransport` moved to
  `internal/agent/fsatomic.Transport`.** The capability
  interface previously lived in `api/` but atomicity is an
  agent-side concern that external `api.Transport`
  implementers (OpenWatch) are not expected to provide.
  Moving it to `internal/agent/fsatomic` prevents the
  `api/` surface from growing to 6+ sibling capability
  interfaces by Phase 7. Public consumers should not be
  affected; OpenWatch does not type-assert this interface.
  See `internal/agent/fsatomic/transport.go` for the new
  location.

### Breaking changes

- **Agent-mode is now the default for `kensa remediate` (P-011).**
  The `KENSA_USE_AGENT=1` env-var (opt-in) is replaced by
  `KENSA_NO_AGENT=1` (opt-out). Operators scripting against the
  old sense must invert the check OR drop the env-var entirely
  to get the new default behavior. Rationale (Q1.c ratified
  2026-05-12): kensa is pre-production; the kernel-atomic
  path is the safer default. Direct-SSH stays available for
  hosts where agent bootstrap is not viable. No deprecation
  period — kensa is pre-1.0.

- **CLI Phase 3 short-letter table reconciliation (C-024).** Four
  short letters are reassigned to align with `Python kensa` parity.
  Operators scripting kensa with the old short forms must migrate
  before upgrade. Long forms are unchanged; only the short letters move.

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
  (exit code 2). No deprecation period — kensa is pre-1.0 and
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
    for CI. Source-of-truth committed at `man/kensa.1`.

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
