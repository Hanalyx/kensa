# Integration

_Applies to: Kensa v0.6.0 — last updated 2026-06-22._

This chapter is for programs that **embed** Kensa (notably OpenWatch) rather
than run the CLI — consuming its `api`/`pkg/kensa` Go surfaces. The division of
labor: Kensa is to a single host what `git` is to a repository; OpenWatch (or
your own control plane) presents, schedules, and aggregates across a fleet, and
never re-implements what Kensa does for one host. Embedders import the **frozen**
`api/` contract (semver-stable; additive-only) plus the assembly layer
`pkg/kensa` (public, not frozen).

Programs importing the `api` Go package
(`github.com/Hanalyx/kensa/api`) should read a scan's compliance verdicts
from `ScanResult.Outcomes` (since v0.3.0) — one `RuleOutcome` per rule
with a `ComplianceStatus` of `pass` / `fail` / `skipped` / `error`, the
rule's severity, a human-readable detail, and the rule's normalised
compliance-framework references (`FrameworkRefs`). Since v0.4.0 each
`RuleOutcome` also carries `Evidence []CheckEvidence` — one entry per
command the check ran, with the exact `Command`, captured
`Stdout`/`Stderr`, `ExitCode`, and `Expected` value: the reproducible
proof behind a verdict, so a consumer can show or re-verify the finding
without re-running the scan. `ScanResult` additionally exposes the
`Capabilities` and `Platform` the scan evaluated against, so the host
context a verdict was computed under is self-describing. The check-only
`ScanResult.Transactions` entries remain for backward compatibility, but
their `committed`/`rolled_back` statuses are a legacy encoding of
compliant/non-compliant — prefer `Outcomes` for an unambiguous verdict.
The doc comments in `api/scan.go` are the authoritative reference.

Loading the rule corpus from a consuming program is public surface too
(package `github.com/Hanalyx/kensa/pkg/kensa`, since v0.3.1):

- `kensa.LoadRules(dir, paths, vars)` — corpus → `[]*api.Rule` ready for
  `Scan`/`Remediate`. Uses the CLI's path-resolution policy (explicit
  dir → explicit files → the `kensa-rules` package's installed corpus at
  `/usr/share/kensa/rules`), and substitutes `{{ name }}` rule templates
  against kensa's embedded defaults merged with the caller's `vars`
  (caller wins) — that `vars` map is where an orchestrator injects
  operator-configured values. Strict: a bad file or undefined variable
  fails the load with the file named; nothing is skipped silently.
- `kensa.BuiltInVars()` — the embedded variable defaults (name → value),
  for rendering an operator configuration UI. Review
  `rsyslog_remote_server`, `chrony_ntp_pool`, and `banner_text`: their
  defaults are organisation-specific placeholders.
- `kensa.RuleVariables(dir)` — template variable → rule IDs using it,
  for showing operators what an override affects.

Do not copy the rule files into a consuming repo and do not re-implement
the loader: the corpus ships as the signed `kensa-rules` package, and 23
of the 539 rules are `{{ var }}` templates that only parse through the
substitution chain above.

Constructing a scanner with your own transport is public surface as well
(since v0.3.2): embedders whose credential model the bundled on-disk-key
ssh factory cannot serve (e.g. credentials decrypted in memory only)
supply their own `api.TransportFactory`:

- Scan-only (no engine, store, or signer constructed):
  `api.New(api.Config{Scanner: kensa.NewScanner(), TransportFactory: yours})`.
  The backend is stateless — one shared instance is safe for concurrent
  `Scan` calls. `Remediate` on this construction errors by design.
- Full service (remediate, history, transaction log):
  `kensa.DefaultWithTransportFactory(ctx, storePath, yours, engineOpts...)`.

Exporting a scan as a standards artifact is public surface too (package
`github.com/Hanalyx/kensa/pkg/kensa`, since v0.4.1). A scan's verdicts
and their embedded check evidence convert to an OSCAL 1.0.6 Assessment
Results document with no shelling out to the CLI:

- `kensa.ExportOSCALScan(result, hostname)` → `[]byte` of OSCAL 1.0.6 AR
  JSON (`kensa.WriteOSCALScan(w, result, hostname)` streams to an
  `io.Writer`). One finding + observation per rule, the `CheckEvidence`
  embedded as relevant-evidence, framework refs as control-ids. The scan
  document is **unsigned** by design — it is derived from the read-only
  `ScanResult`.
- `kensa.ExportOSCAL(envelope)` / `kensa.WriteOSCAL(w, envelope)` — the
  remediation counterpart, rendering a signed `api.EvidenceEnvelope`
  (the audit-truth-of-record a transaction produces) as OSCAL. This path
  is anchored on the envelope's Ed25519 signature.

The byte production lives in `internal/` and is conformance-gated against
the vendored NIST OSCAL 1.0.6 schema; these are the importable entry
points to it.

End-to-end, the whole consumer chain is public:
`kensa.LoadRules(…, operatorVars)` → construct (either form above) →
`Scan` → `ScanResult.Outcomes` → `kensa.ExportOSCALScan(…)`.
