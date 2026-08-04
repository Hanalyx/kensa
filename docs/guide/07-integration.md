# Integration

_Applies to: Kensa v0.9.0. Last updated 2026-08-03._

This chapter is for programs that **embed** Kensa (notably OpenWatch) rather
than run the CLI, consuming its `api`/`pkg/kensa` Go surfaces. The division of
labor: Kensa is to a single host what `git` is to a repository; OpenWatch (or
your own control plane) presents, schedules, and aggregates across a fleet, and
never re-implements what Kensa does for one host. Embedders import the **frozen**
`api/` contract (semver-stable; additive-only) plus the assembly layer
`pkg/kensa` (public, not frozen).

Programs importing the `api` Go package
(`github.com/Hanalyx/kensa/api`) should read a scan's compliance verdicts
from `ScanResult.Outcomes` (since v0.3.0): one `RuleOutcome` per rule
with a `ComplianceStatus` of `pass` / `fail` / `skipped` / `error`, the
rule's severity, a human-readable detail, and the rule's normalised
compliance-framework references (`FrameworkRefs`). Since v0.4.0 each
`RuleOutcome` also carries `Evidence []CheckEvidence`, one entry per
command the check ran, with the exact `Command`, captured
`Stdout`/`Stderr`, `ExitCode`, and `Expected` value: the reproducible
proof behind a verdict, so a consumer can show or re-verify the finding
without re-running the scan. `ScanResult` additionally exposes the
`Capabilities` and `Platform` the scan evaluated against, so the host
context a verdict was computed under is self-describing. The check-only
`ScanResult.Transactions` entries remain for backward compatibility, but
their `committed`/`rolled_back` statuses are a legacy encoding of
compliant/non-compliant; prefer `Outcomes` for an unambiguous verdict.
The doc comments in `api/scan.go` are the authoritative reference.

Loading the rule corpus from a consuming program is public surface too
(package `github.com/Hanalyx/kensa/pkg/kensa`, since v0.3.1):

- `kensa.LoadRules(dir, paths, vars)`: corpus → `[]*api.Rule` ready for
  `Scan`/`Remediate`. Uses the CLI's path-resolution policy (explicit
  dir → explicit files → the `kensa-rules` package's installed corpus at
  `/usr/share/kensa/rules`), and substitutes `{{ name }}` rule templates
  against kensa's embedded defaults merged with the caller's `vars`
  (caller wins). That `vars` map is where an orchestrator injects
  operator-configured values. Strict: a bad file or undefined variable
  fails the load with the file named; nothing is skipped silently.
- `kensa.BuiltInVars()`: the embedded variable defaults (name → value),
  for rendering an operator configuration UI. Review
  `rsyslog_remote_server`, `chrony_ntp_pool`, and `banner_text`: their
  defaults are organisation-specific placeholders.
- `kensa.RuleVariables(dir)`: template variable → rule IDs using it,
  for showing operators what an override affects.

Do not copy the rule files into a consuming repo and do not re-implement
the loader: the corpus ships as the signed `kensa-rules` package, and 25
of its rules are `{{ var }}` templates that only parse through the
substitution chain above.

Constructing a scanner with your own transport is public surface as well
(since v0.3.2): embedders whose credential model the bundled on-disk-key
ssh factory cannot serve (for example, credentials decrypted in memory only)
supply their own `api.TransportFactory`:

- Scan-only (no engine, store, or signer constructed):
  `api.New(api.Config{Scanner: kensa.NewScanner(), TransportFactory: yours})`.
  The backend is stateless: one shared instance is safe for concurrent
  `Scan` calls. `Remediate` on this construction errors by design.
- Full service (remediate, history, transaction log, where a transaction is
  Kensa's four-phase change operation: capture, apply, validate, then commit
  or roll back):
  `kensa.DefaultWithTransportFactory(ctx, storePath, yours, engineOpts...)`.

Exporting a scan as a standards artifact is public surface too (package
`github.com/Hanalyx/kensa/pkg/kensa`, since v0.4.1). A scan's verdicts
and their embedded check evidence convert to an Open Security Controls
Assessment Language (OSCAL) 1.0.6 Assessment Results document with no
shelling out to the CLI:

- `kensa.ExportOSCALScan(result, hostname)` → `[]byte` of OSCAL 1.0.6 AR
  JSON (`kensa.WriteOSCALScan(w, result, hostname)` streams to an
  `io.Writer`). One finding + observation per rule, the `CheckEvidence`
  embedded as relevant-evidence, framework refs as control-ids. The scan
  document is **unsigned** by design; it is derived from the read-only
  `ScanResult`.
- `kensa.ExportOSCAL(envelope)` / `kensa.WriteOSCAL(w, envelope)`: the
  remediation counterpart, rendering a signed `api.EvidenceEnvelope`
  (the audit-truth-of-record a transaction produces) as OSCAL. This path
  is anchored on the envelope's Ed25519 signature.

The OSCAL byte production is conformance-gated against the vendored NIST
OSCAL 1.0.6 schema; these `pkg/kensa` functions are the importable entry
points to it.

Showing an operator what a transaction found on the host before it changed
anything is public surface as well:

- `kensa.DescribePreState(pre)` → one operator-readable line for an
  `api.PreState`, such as `PASS_MAX_DAYS 99999 in /etc/login.defs` or
  `auditd, enabled, active`. It accepts a pre-state from a
  `TransactionResult`, from a `TransactionRecord` read back out of the
  transaction log, or from a `Plan` in a preview flow.

The line comes from the handler that captured the state, because
`PreState.Data` is mechanism-specific: each capturable mechanism records its
own keys, and only the handler knows what they mean. Handlers register by
importing `pkg/kensa`, so nothing further is wired up. A mechanism that is
not capturable renders a fixed marker rather than an empty string, so a
consumer can tell "this mechanism cannot capture" apart from "no summary
available".

Two properties to build on:

- **The summary is a projection, not evidence.** `PreState.Data` stays the
  authoritative capture and the thing an auditor reads. The rendered text is
  not semver-frozen, not parseable, and may change in any release including
  a patch. Deriving it on read costs nothing and always matches the
  installed version; a consumer that persists it instead should record the
  Kensa version alongside, so a corrected description can be re-run over the
  rows it affects.
- **A summary never contains a captured file body.** Captured state is kept
  verbatim so rollback can restore it, and is not scrubbed, but a summary
  is shown inline where the raw capture usually is not. Multi-line or long
  values are replaced by a size marker (`/etc/pam.d/sshd, 1.4 KiB`). Values
  under field names denoting credentials are redacted, and configuration
  lines are additionally scanned for a credential-bearing key inside the
  line. This is elision by construction, not a secret scanner: a credential
  in an unexpected shape can still reach a summary, so treat the output as
  operator-visible text. Render
  `PreState.Data` itself only where you would show the full capture.

End-to-end, the whole consumer chain is public:
`kensa.LoadRules(…, operatorVars)` → construct (either form above) →
`Scan` → `ScanResult.Outcomes` → `kensa.ExportOSCALScan(…)`.
