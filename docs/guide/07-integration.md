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
