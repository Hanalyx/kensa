package api

// ComplianceStatus is the per-rule verdict of a read-only [Kensa.Scan].
//
// It is deliberately distinct from [TransactionStatus]. A
// [TransactionStatus] describes the terminal state of a *remediation
// transaction* (committed / rolled_back / partially_applied / errored) — it
// answers "what did the apply do?". A ComplianceStatus answers the orthogonal
// question "is the host in the rule's desired state?" with no apply, no
// rollback, and no signed envelope.
//
// Consumers mapping Kensa results into a compliance model (e.g. OpenWatch's
// host_rule_state) MUST read [ScanResult.Outcomes]; they should NOT reinterpret
// the [TransactionStatus] of the check-only [ScanResult.Transactions], whose
// committed/rolled_back values are reused there to mean compliant/non-compliant
// for backward compatibility and whose doc comments describe apply-path
// semantics that do not hold for a scan.
type ComplianceStatus string

// The four compliance verdicts a [Kensa.Scan] can report for a rule. Every
// [RuleOutcome] carries exactly one of these.
const (
	// CompliancePass: the rule's check confirmed the host is already in the
	// rule's desired state.
	CompliancePass ComplianceStatus = "pass"

	// ComplianceFail: the check ran successfully and the host is NOT in the
	// rule's desired state. This is the canonical "rule X is non-compliant".
	ComplianceFail ComplianceStatus = "fail"

	// ComplianceSkipped: the rule had no implementation applicable to the host
	// — no gated implementation matched the host's capabilities AND the rule
	// declared no default implementation. The rule was not evaluated; this is
	// an absence of verdict, NOT a failure, and is distinguished from
	// [ComplianceError] so consumers do not record a not-applicable rule as an
	// error.
	//
	// Note: a validated corpus rule always carries a default implementation
	// (the rule validator requires exactly one), so a capability-mismatched
	// rule normally falls through to its default and yields pass/fail/error
	// rather than skipped. ComplianceSkipped therefore fires only for rules
	// that declare implementations without a default, or none at all.
	ComplianceSkipped ComplianceStatus = "skipped"

	// ComplianceError: the check could not run — a transport error, an
	// unsupported check method, or a structurally invalid rule. The host's
	// compliance with the rule is unknown. [RuleOutcome.Err] carries the cause.
	ComplianceError ComplianceStatus = "error"
)

// RuleOutcome is the canonical per-rule result of a [Kensa.Scan]: a single
// compliance verdict for one rule against one host. It is the result-side
// counterpart to [Check] (which is only the check *definition*).
//
// One RuleOutcome is produced per rule passed to [Kensa.Scan], in the same
// order, and surfaced on [ScanResult.Outcomes].
type RuleOutcome struct {
	// RuleID is the canonical rule this verdict is for.
	RuleID string
	// Status is the compliance verdict — exactly one [ComplianceStatus].
	Status ComplianceStatus
	// Severity is the rule severity (critical, high, medium, low), copied
	// from the rule so a consumer can weight a non-compliant result without a
	// rule join. Empty when the rule did not declare one.
	Severity string
	// Detail is human-readable context for the verdict, suitable for logs and
	// UI (for example the check's explanation of why the host failed).
	Detail string
	// FrameworkRefs are the rule's compliance-framework references (CIS, NIST
	// 800-53, STIG, …), normalised from the rule's References block. They are
	// carried on every outcome so a consumer can attribute or filter a verdict
	// by framework without re-deriving the mapping from the rule corpus. Empty
	// when the rule maps to no framework.
	FrameworkRefs []FrameworkRef
	// Err is non-nil if and only if Status is [ComplianceError]. It identifies
	// why the check could not run.
	Err error
}
