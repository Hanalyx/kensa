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

### Added

- **Per-rule OSCAL export on `pkg/kensa`** — `ExportOSCALOutcome` /
  `WriteOSCALOutcome` render a single `api.RuleOutcome` as its own valid
  one-finding OSCAL 1.0.6 AR document, preserving the parent scan's host
  context (HostID/Capabilities/Platform). The per-rule counterpart of
  `ExportOSCALScan`, for a UI that exports OSCAL from one expanded rule
  rather than the whole scan.

### Fixed

- **Unmapped rule produced invalid OSCAL.** A result with no
  framework-mapped control emitted an empty `include-controls`, which the
  OSCAL 1.0.6 schema rejects (`reviewed-controls` is required and a
  control-selection must select `include-all` or a non-empty
  `include-controls`). A whole-host scan never hit this (some rule is
  always mapped), but a single-rule document for an unmapped rule — the
  per-rule UI expansion — did. The exporter now falls back to OSCAL
  `include-all` when there are no control refs, on both the scan
  (`ExportOSCALScan`) and remediation (`ExportOSCAL`) paths.

## v0.4.1 — 2026-06-14

Public OSCAL export for `api` consumers. PATCH bump: the addition lives
on `pkg/kensa` (the public-but-not-frozen assembly layer); the frozen
`api/` surface is untouched. With v0.4.0's `RuleOutcome.Evidence`, this
makes the whole evidence-and-OSCAL feature reachable from outside the
CLI: `LoadRules → NewScanner → Scan → Outcomes → ExportOSCALScan` is now
entirely public for embedders (OpenWatch).

### Added

- **Public OSCAL export on `pkg/kensa`** — `ExportOSCALScan` /
  `WriteOSCALScan` (an `api.ScanResult` → OSCAL 1.0.6 Assessment
  Results) and `ExportOSCAL` / `WriteOSCAL` (a signed
  `api.EvidenceEnvelope` → OSCAL 1.0.6 AR). v0.4.0 shipped OSCAL export
  only through the CLI and `internal/evidence`, which an embedder cannot
  import; these thin wrappers lift it to the public-but-not-frozen
  assembly layer (where `LoadRules`/`NewScanner` live), completing the
  public chain `LoadRules → Scan → Outcomes → OSCAL` for consumers like
  OpenWatch. The frozen `api/` surface is untouched; byte production
  still lives in (and is conformance-gated by) `internal/evidence`. The
  scan-path export stays unsigned by design; the signature guarantee
  remains exclusive to the envelope path. Spec `oscal-public-export`
  (Tier 2).

## v0.4.0 — 2026-06-13

Native-evidence parity and OSCAL enrichment: a compliance **scan** now
produces reproducible, structured evidence — per-check command/output
proof — in two surfaces: a Kensa-native JSON document and a
standards-conformant OSCAL 1.0.6 Assessment Results document. MINOR
bump: the `api/` surface gains additive fields only; nothing is removed
or changed. Both schemas are vendored and validated in CI, and the
output was validated end-to-end against the live test fleet (RHEL
8.10/9.7, Ubuntu 24.04/26.04, full 539-rule corpus).

### Added

- **Structured per-check observation evidence on the scan path.**
  `api.RuleOutcome` gains `Evidence []api.CheckEvidence` — one
  `CheckEvidence` per command a rule's check executed, carrying the
  exact `Method`, `Command`, captured `Stdout`/`Stderr`, `ExitCode`, and
  the `Expected` value. This is the reproducible proof behind a verdict:
  an auditor can re-run the command and compare without re-running the
  scan. Captured via a recording transport that wraps the check
  transport, so none of the 24 check functions changed. Oversized output
  is truncated at a 64 KiB per-field cap and flagged (`Truncated`). (#74)
- **`-o evidence:PATH` on `kensa check`** — emits the Kensa-native
  evidence document (`schemas/kensa-evidence-v1.schema.json`): session +
  host context (hostname, detected platform, capabilities, effective
  variables) and one result per rule with its embedded `CheckEvidence`
  and framework refs, plus a pass/fail/skip summary. Full-file parity
  with the prior Python Kensa evidence shape. (#75)
- **`-o oscal:PATH` on `kensa check`** — renders the scan as an OSCAL
  1.0.6 Assessment Results document: one finding + observation per rule,
  the check evidence embedded as namespaced `relevant-evidence` props
  with the verbatim command in `remarks`, raw stdout carried as base64
  back-matter referenced by href, and framework refs as deduplicated
  control-id tokens. Unsigned by design (the signature guarantee remains
  exclusive to the remediation evidence-envelope path). (#77)
- **Host context on `api.ScanResult`** — `Capabilities CapabilitySet`
  and `Platform DetectedPlatform` (new `DetectedPlatform{Family,
  Version}` type), so a consumer records the exact capability/OS context
  a verdict was computed under without re-probing. (#75)
- **Vendored schemas + conformance gate** — the official NIST OSCAL
  1.0.6 Assessment Results schema and the `kensa-evidence-v1` schema are
  vendored, and a hard test gate validates every emitted document
  against OSCAL 1.0.6 (using a pure-Go validator that handles the
  schema's ECMA `\p{}` regex and draft-07 anchors). (#73, #76)

### Fixed

- **OSCAL 1.0.6 conformance gaps surfaced by the live test fleet** that
  the clean unit fixtures never exercised: a multi-line check command
  cannot live in an OSCAL prop value (single-line token), so it now goes
  to `relevant-evidence` remarks with prop values guarded; and NIST
  control-enhancement parentheses (`AU-5(2)`) are illegal in an OSCAL
  control-id token, now coerced to the dot-enhancement form (`AU-5.2`)
  on both the scan and remediation export paths. (#78)

## v0.3.2 — 2026-06-12

Public scanner construction with a caller-supplied transport. PATCH
bump: additions live on `pkg/kensa`; the frozen `api/` surface is
untouched. With v0.3.1's loader this completes the public consumer
chain: `LoadRules` → construct → `Scan` → `Outcomes`.

### Added

- **Public construction with a caller-supplied `TransportFactory`**
  (`pkg/kensa`) — for embedders whose credential model the bundled
  on-disk-key ssh factory cannot serve (e.g. an orchestrator holding
  SSH credentials in memory only):
  - `kensa.NewScanner()` — the standard `api.ScannerBackend`, for
    scan-only composition via `api.New(Config{Scanner, TransportFactory})`;
    no engine, store, or signer is constructed. Stateless and safe for
    concurrent `Scan` calls sharing one instance. `Remediate` on such a
    construction errors (engine not wired), by design.
  - `kensa.DefaultWithTransportFactory(ctx, storePath, tf, engineOpts...)`
    — `Default`'s full wiring with the transport swapped for the
    caller's factory (nil rejected at construction). `Default` and
    `DefaultWithEngineOptions` are unchanged.

## v0.3.1 — 2026-06-11

Public rule loader for programs that import the `api` package. PATCH
bump: additions live on `pkg/kensa` (the public-but-not-frozen assembly
layer); the frozen `api/` surface is untouched.

### Added

- **`pkg/kensa` public rule-loader surface** — external consumers (e.g.
  OpenWatch) can now load the shipped corpus without copying rule files
  or re-implementing the loader:
  - `kensa.LoadRules(dir, paths, vars)` — corpus → `[]*api.Rule` ready
    for `Scan`/`Remediate`. Follows the CLI's path-resolution policy
    (explicit dir → explicit files → the `kensa-rules` package's
    installed corpus at `/usr/share/kensa/rules`), and substitutes
    `{{ name }}` rule templates against kensa's embedded defaults merged
    with the caller's `vars` (caller wins) — the hook for
    operator-configured values. **Strict** by design: any unparseable
    file or undefined variable fails the load naming the file; nothing
    is skipped silently (deliberate divergence from the CLI's
    warn-and-skip directory walk).
  - `kensa.BuiltInVars()` — the embedded variable defaults (29 vars,
    STIG-strict), for rendering an operator configuration UI. The
    `rsyslog_remote_server`, `chrony_ntp_pool`, and `banner_text`
    defaults are organization-specific placeholders operators should
    always review.
  - `kensa.RuleVariables(dir)` — template variable → rule IDs using it,
    so operators can see what an override affects.

  Locked by spec `rule-public-loader`, including a production-corpus
  test: all 539 rules — the 23 `{{ var }}` templates included — load
  strictly with nil vars on built-in defaults alone.

### Documentation

- `docs/guide/04-scan-and-remediate.md` documents the v0.3.0 `SKIP`
  status (platform gating) for `check` and `remediate`.
- `docs/guide/07-integration.md` carries the api-consumer pointers:
  read verdicts from `ScanResult.Outcomes`; load rules via
  `kensa.LoadRules`; do not copy the rule files or re-implement the
  loader.

## v0.3.0 — 2026-06-11

Compliance-verdict API on `Scan`, platform gating for the standalone CLI,
and the param-contract fix that restores ~201 corpus rules whose handlers
read the wrong parameter names. MINOR bump: additive surface on the frozen
`api/` package (new types + a new `ScanResult` field; nothing existing
changed signature or semantics).

### Added

- **`api`: compliance-verdict surface on `Scan`** — `ScanResult` gains
  `Outcomes []RuleOutcome`, one per scanned rule in input order, each with
  a `ComplianceStatus` of `pass` / `fail` / `skipped` / `error`, the rule's
  severity, a human-readable detail, the error cause (iff `error`), and the
  rule's `FrameworkRefs` (CIS / NIST 800-53 / STIG, normalised from the
  rule's References block) so a consumer attributes verdicts to frameworks
  without re-joining the corpus. This is the canonical compliance result;
  the check-only `Transactions` entries (whose `committed` / `rolled_back`
  statuses double as compliant / non-compliant) are retained unchanged for
  backward compatibility. (#62, #63)
- **Platform gating for `check` and `remediate`** — kensa now detects the
  host OS (`/etc/os-release`) and compares each rule's `platforms:` block
  (family + `min_version` / `max_version`) against it. A rule that does not
  apply to the host — e.g. a `rhel >= 9` control on a RHEL 8 host — is
  reported `SKIP` (with a "not applicable: host RHEL 8.10, rule targets
  rhel >=9" detail) instead of a misleading pass/fail, and on `remediate`
  its remediation is **never applied**. Rules with no `platforms:` block
  run everywhere; an undetectable host OS gates nothing. The live row
  stream renders a dim `SKIP` status and a `N skipped` tally entry. (#64)
- **Param-contract gate** — `internal/mechanism` is now the single source
  of truth for each mechanism's parameter contract
  (CANONICAL_RULE_SCHEMA_V1.md §3.5.4). The rule validator rejects
  remediation params that violate the contract (`kensa-validate` + CI),
  and an integration test decodes every corpus rule's params through its
  real handler with a ratcheting divergence ledger — now empty. (#50)

### Fixed

- **Seven handlers read parameter names that contradicted the canonical
  schema and the shipped corpus**, so ~201 corpus rules failed at the
  Capture phase instead of remediating. Each handler now decodes the
  schema's names (pre-state data shapes unchanged, so existing rollback
  records still restore): `config_set` reads `path` (was `file`) (#51);
  `config_set_dropin` composes `dir`+`file` (#52); `kernel_module_disable`
  reads `name` (was `module`) (#53); `pam_module_configure` reads
  `type`/`args` (was `module_type`/`options`) (#54); `audit_rule_set`
  reads absolute `persist_file` (was bare `rule_file`) (#55);
  `mount_option_set` reads the `options` list (was singular `option`)
  (#56); `cron_job` makes `name` optional and supports an absolute `file`
  path (#57). Verified end-to-end on a live host: previously-failing rules
  across these mechanisms now apply and roll back byte-perfectly.

### Changed

- **Scanning a host whose OS no rule targets now reports `SKIP` per rule**
  (e.g. the RHEL corpus against a non-RHEL host renders all-SKIP) rather
  than a wall of misleading FAIL/ERROR rows. This is the honest result —
  those rules do not apply to that host.
- Dependency refresh: `godbus/dbus` v5.2.2, `golang.org/x/sys` v0.46,
  `golang.org/x/term` v0.44, `modernc.org/sqlite` v1.52 (pure-Go SQLite,
  portability CI unchanged). (#58)

### Internal

- CI lint stack modernised: golangci-lint v1.64.8 → **v2.12.2** (native
  Go 1.26 support) with `golangci-lint-action` v9 and a `GOTOOLCHAIN`
  pin that prevents the linter from being built against an older Go
  (the root cause of a repo-wide SA5011 false-positive storm); the full
  staticcheck `S*`/`ST*`/`QF*` tiers are now enforced. Specter pinned at
  v0.13.2 in CI with annotation-strictness sync. (#49, #59, #60, #61)

## v0.2.3 — 2026-06-08

Live result-row streaming for the default human output, plus engine and
agent/transport fixes surfaced while building it. No machine-format or
`api/` contract changes.

### Added

- **Live result-row streaming for `kensa check` and `kensa remediate`** —
  the default text output now renders one aligned row per rule **as each
  rule completes**, in scan order, directly on stdout:
  `STATUS  SEVERITY  RULE-ID  DESCRIPTION [detail]`, under a `── Host ──`
  banner, ending with a tally. `check` shows `PASS` / `FAIL` / `ERROR`;
  `remediate` shows `PASS` (already compliant) / `FIXED` / `FAIL` /
  `ERROR`. Status and severity are colored when stdout is a terminal.
  Machine formats (`--format json`, `-o FILE`) are unchanged — still
  buffered and structured, never interleaved with rows.

### Changed

- **`kensa check`'s default text output is now an in-order live row
  stream** rather than a grouped, buffered end-of-scan report. The result
  rows are the canonical text rendering and go to stdout; there is no
  separate progress channel. Machine/`-o` output is unchanged.
- **`--sudo` fails fast with an actionable error when the SSH user lacks
  passwordless sudo.** kensa runs sudo non-interactively (`sudo -n`) on
  every path and has no password fallback by design; a one-time probe at
  connect now reports *"configure passwordless sudo … or drop --sudo"*
  instead of letting every remote command fail cryptically. A non-password
  sudo failure (e.g. user not in sudoers) is surfaced verbatim.

### Fixed

- **Engine event-bus panic** — `InMemoryEventBus.Publish` could send on a
  closed channel when a subscription's context was canceled concurrently,
  panicking a live transaction. Delivery and channel-close are now mutually
  exclusive (Tier-1 spec `engine-event-bus` with a regression test).
- **Server login banner leaking into agent-mode output** — `remediate` /
  `rollback` (agent mode) re-authenticate over a fresh ssh session whose
  stderr is forwarded to the operator; a server consent/login banner (e.g.
  a USG banner) leaked there. The agent ssh now passes `-o LogLevel=ERROR`
  to suppress the banner while preserving real ssh errors, matching
  `kensa check`.

## v0.2.2 — 2026-06-05

Supply-chain and service-handler hardening on top of v0.2.1. The
headline operator-facing change is that the package now provisions the
systemd-helper sudo escalation path itself; the rest is supply-chain
trust posture (a govulncheck gate that immediately paid for itself by
forcing two toolchain CVE bumps) and a new capability probe.

### Added

- **Sudoers fragment + `kensa` group, shipped by the package** — the
  rpm and deb now install `/etc/sudoers.d/kensa-systemd-helper` (mode
  `0440`, root-owned, registered as a config file) granting
  `%kensa ALL=(root) NOPASSWD: /usr/libexec/kensa-systemd-helper`, and
  `postinst` creates the `kensa` group **empty**. The service handlers
  (`service_enabled` / `_disabled` / `_masked`) previously required a
  manual sudoers step; the operator's remaining action shrinks to
  `usermod -aG kensa <user>`. The empty group means a fresh install
  grants the escalation to nobody. Spec `packaging-sudoers-helper`.
- **`pam_tally2` capability probe** — detects the legacy account-lockout
  module present on older Debian/Ubuntu (≤18.04) and RHEL 7, where
  `pam_faillock` is absent, so rules can gate a fallback.
- **Supply-chain CI gates** — a `govulncheck` vulnerability scan, a
  `go mod tidy` drift check, top-level `GOFLAGS=-mod=readonly`, a
  `detect-secrets` baseline + pre-commit hook, and Dependabot for the
  `gomod` and `github-actions` ecosystems.

### Changed

- **Go toolchain pinned to 1.26.4** via the `go.mod` `go` directive;
  building from source now requires Go 1.26.4+.
- **CI actions moved to their Node 24 majors** — `actions/checkout@v5`,
  `actions/setup-go@v6`, `actions/setup-python@v6` — ahead of GitHub's
  Node 20 removal. `setup-go` now installs the exact toolchain from
  `go.mod` (`go-version-file`).
- **Install guide** rewritten for the now-automatic service-handler
  setup and the Go 1.26.4 build requirement.

### Security

- The shipped `%kensa` NOPASSWD rule is **inert on install**: the group
  is created empty, and the post-install guard checks `/etc/group`
  directly rather than via `getent`, so a same-named directory
  (LDAP/NIS/SSSD) group cannot silently inherit the grant. The residual
  limit — `sudo`'s own `%kensa` resolution still consults nsswitch — is
  documented as an explicit install-time precondition.
- **Eight standard-library CVEs cleared.** The new govulncheck gate
  surfaced six stdlib advisories (fixed by the 1.26.3 bump) and then
  `GO-2026-5039` (net/textproto) + `GO-2026-5037` (crypto/x509), fixed
  by 1.26.4.
- CI now **asserts the sudoers fragment ships at `0440` root:root** in
  both the rpm and the deb on every build (owner drift would silently
  disable the rule).

### Fixed

- The secret-scan CI job no longer false-fails on `detect-secrets`
  baseline metadata churn — it uses the non-mutating `detect-secrets-hook`
  entrypoint, the same code path as the pre-commit hook.
- Removed a stray committed gitlink (`.claude/worktrees/...`) that made
  every `git checkout` emit a submodule warning.

## v0.2.1 — 2026-05-28

Packaging-UX hardening on top of v0.2.0's first signed packages. No
binary-behaviour change — every difference here is in the package
metadata, install scripts, archive variants, and operator docs.

### Added

- **`KEYS` at repo root** — single canonical file holding both
  verification keys (Hanalyx LLC GPG public + Kensa cosign public) with
  inline `rpm --import` / `apt`-add / `cosign verify-blob` instructions
  as a fallback if the install guide is unreachable. Operators can
  point `rpm --import` straight at the raw GitHub URL.
- **`kensa_<v>_linux_<arch>_with-rules.tar.gz`** — second per-arch
  tarball variant carrying the full 539-rule corpus next to the
  binaries + LICENSE + KEYS. Single-download air-gap path called out
  in CLAUDE.md's packaging plan. Topic-dir layout preserved
  (`rules/<topic>/<rule>.yml`) so it matches the `kensa-rules`
  package's installed tree.
- **`packaging/postinst.sh`** — POSIX `/bin/sh` script wired into the
  `kensa` rpm and deb. Surfaces a warning when `/usr/share/kensa/rules`
  is empty after install with explicit next-step commands (install
  `kensa-rules` or pass `--rules-dir`). No network access, no signature
  re-verification — Fedora packaging guidelines forbid the former and
  the latter belongs to dnf/apt's existing trust chain.
- **`docs/guide/01-install.md` rewritten** for the packaged-release
  reality: signed-key import is Step 1, three install paths (dnf, apt,
  air-gap tarball), explicit verify with `cosign verify-blob` +
  `sha256sum -c` for the air-gap flow, and build-from-source kept as
  the contributors' path. Version references bumped 0.1.0 → 0.2.1.

### Changed

- **`kensa` rpm + deb now `Recommends: kensa-rules`** — `dnf install
  kensa` / `apt install kensa` alone pulls the corpus by default.
  Operator can opt out with `--setopt=install_weak_deps=False` (rpm)
  or `--no-install-recommends` (apt) if they bring their own corpus
  via `--rules-dir`.

### Internal

- Goreleaser bumped one notch on the second `archives:` entry —
  the `kensa-with-rules` ID adds `KEYS` to the bundled file list.
- The release-snapshot CI smoke job now produces 11 artifacts (was 9):
  the two `with-rules` tarballs added a binary-tarball variant per arch.

### Not changed

- The kensa CLI itself is byte-identical to v0.2.0 (same source, same
  build flags). The release is metadata + scripts + docs only.
- No `api/` change.
- All signing posture (GPG-signed rpm/deb + cosign-signed checksums)
  preserved from v0.2.0.

### Known follow-ups

- File the nfpm `gnu-dummy` subkey-decrypt bug upstream
  (`goreleaser/nfpm` `internal/sign/pgp.go:readSigningKey`). Once
  fixed, the GitHub `GPG_PRIVATE_KEY` secret can go back to a
  subkey-only export (smaller blast radius than the current full
  encrypted master+subkey).
- v0.3.x: ship the kensa-systemd-helper sudoers fragment in the rpm
  (`%files /etc/sudoers.d/kensa-systemd-helper`) so the manual step
  in `docs/guide/01-install.md` § "Service handlers" disappears.

## v0.2.0 — 2026-05-28

First "real" packaged release. Operators can now install kensa via
`dnf install kensa kensa-rules` (rpm) or
`apt install ./kensa_0.2.0_linux_amd64.deb ./kensa-rules_0.2.0_noarch.deb`
(deb) and run `kensa check <host>` with no flags — the default-path
fallback (this release) picks up the corpus from
`/usr/share/kensa/rules` automatically.

Also lands the full grub deadman guard (set + remove paths), the
`grub_parameter_set` and `grub_parameter_remove` handlers wired through
it, the first operator-guide chapter, and the supporting plumbing.

### Added

#### Packaging
- `LICENSE` at repo root — Business Source License 1.1 (→ Apache 2.0 on
  2029-01-01); same terms as the archived Python kensa. Required by
  rpm/deb metadata.
- `kensa` rpm + deb (amd64, arm64) — installs `/usr/bin/{kensa,
  kensa-validate, kensa-keygen}` + `/usr/libexec/kensa-systemd-helper`
  + `/usr/share/doc/kensa/{LICENSE,README,CHANGELOG}`. Signed with the
  Hanalyx GPG key.
- `kensa-rules` noarch rpm + deb — installs the 539-rule corpus to
  `/usr/share/kensa/rules`. Updates independent of the binary release.
  Signed with the Hanalyx GPG key.
- `kensa_<version>_linux_<arch>.tar.gz` — air-gapped install bundle for
  amd64 + arm64 (all 4 binaries + LICENSE + docs).
- `kensa_<version>_checksums.sha256` — sha256 over the full artifact
  set. cosign-signed.
- `.goreleaser.yaml` + tag-triggered `.github/workflows/release.yml` —
  hard-fails if any of GPG_PRIVATE_KEY, GPG_PASSPHRASE,
  COSIGN_PRIVATE_KEY, COSIGN_PASSWORD secrets is missing (no silent
  unsigned ship). Snapshot smoke job in `ci.yml` exercises the same
  pipeline on every PR.

#### Rules
- `rules/` — vendored the 539 SCAP-derived rules from the archived
  Python kensa (`/home/rracine/hanalyx/kensa.archive/rules`),
  byte-identical to source. Eight topic dirs (`access-control` 129,
  `audit` 101, `filesystem` 73, `kernel` 22, `logging` 14, `network`
  23, `services` 107, `system` 70). 2.2 MB. The archive is frozen;
  rule edits land via PR here going forward. `rules/README.md`
  documents layout, validate workflow, and provenance.
- `internal/rules.Resolve` — default-path resolution for `--rules-dir`.
  Explicit `--rules-dir` still wins; positional rule YAML paths alone
  skip the walk; when neither is given the CLI falls back to
  `/usr/share/kensa/rules` (where `kensa-rules` installs); when that
  path also doesn't exist the loader surfaces a usage error naming all
  three fix paths. Specced as `rule-default-path-resolution` v0.1.0;
  `cli-rule-flag` bumped to v0.2.0.

#### Grub deadman guard
- `internal/bootguard/` (PR #15) — Option-B one-shot trial entry +
  saved-default auto-fallback for grub parameter changes. RHEL/BLS
  via `grubby --copy-default`; Ubuntu legacy via `/etc/grub.d/11_kensa_bootguard`
  + `update-grub`. Confirm unit installed at arm time; healthy boot
  promotes onto the default, failed boot auto-reverts. Specs:
  `bootguard-{capture,arm-gate,allowlist,oneshot,confirm}`.
- `internal/handlers/grubparameterset` — replaces direct
  `GRUB_CMDLINE_LINUX` editing with `bootguard.ArmOneshot`. Refuses
  off-allowlist keys + non-armable hosts. PENDING until reboot.
- `internal/handlers/grubparameterremove` (PR #21) — same flow for
  REMOVAL via `bootguard.ArmOneshotRemove`. `bootguard-oneshot` bumped
  to v0.4.0 (C-07/C-08, AC-08..AC-11); `bootguard-confirm` v0.5.0.
- Verified end-to-end on real RHEL 9.7 (.213) and Ubuntu 24.04 (.249)
  with the destructive reboot matrix.

#### Docs
- `docs/guide/01-install.md` (PR #12) — first real operator-guide
  chapter.

### Changed
- `cli-rule-flag` C-04 + AC-04 — now acknowledge the default-path
  fallback layer and the three-fix-paths error wording.

### Internal
- `.golangci.yml` — extended the existing `internal/` godot exclusion
  to `cmd/` (same rationale: Go's identifier-first convention conflicts
  with `capital: true`).

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
