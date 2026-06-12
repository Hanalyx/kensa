# Integration

**Stub.** Content forthcoming. Until this chapter lands, the
authoritative source for this topic is:

- The relevant binary's `--help` output
- The `.spec.yaml` file(s) under `specs/` for the components
  involved
- The atomicity contract guarantees described in
  [`README.md`](../../README.md) and
  [`03-concepts.md`](03-concepts.md)

One pointer that IS current: programs importing the `api` Go package
(`github.com/Hanalyx/kensa/api`) should read a scan's compliance verdicts
from `ScanResult.Outcomes` (since v0.3.0) — one `RuleOutcome` per rule
with a `ComplianceStatus` of `pass` / `fail` / `skipped` / `error`, the
rule's severity, a human-readable detail, and the rule's normalised
compliance-framework references (`FrameworkRefs`). The check-only
`ScanResult.Transactions` entries remain for backward compatibility, but
their `committed`/`rolled_back` statuses are a legacy encoding of
compliant/non-compliant — prefer `Outcomes` for an unambiguous verdict.
The doc comments in `api/scan.go` are the authoritative reference.

Loading the rule corpus from a consuming program is public surface too
(package `github.com/Hanalyx/kensa/pkg/kensa`):

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
