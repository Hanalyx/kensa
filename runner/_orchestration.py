"""Top-level rule evaluation and remediation orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._checks import run_check
from runner._remediation import run_remediation
from runner._rollback import _execute_rollback
from runner._selection import select_implementation
from runner._types import RuleResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _extract_framework_refs(rule: dict) -> dict[str, str]:
    """Extract flattened framework references from a rule.

    Converts nested reference structures into flat key-value pairs
    for easy lookup and display. For example: "cis_rhel9_v2" -> "5.1.12",
    "stig_rhel9_v2r7" -> "V-123456", "nist_800_53" -> "AU-2, AU-3".

    Args:
        rule: Rule definition with optional references section.

    Returns:
        Dict mapping framework keys to their primary identifiers.

    """
    refs: dict[str, str] = {}
    references = rule.get("references", {})

    for framework, value in references.items():
        if framework == "nist_800_53" and isinstance(value, list):
            # NIST controls are a flat list
            refs["nist_800_53"] = ", ".join(value)
        elif isinstance(value, dict):
            # Nested framework (cis, stig, pci_dss, etc.)
            for version, details in value.items():
                key = f"{framework}_{version}"
                if isinstance(details, dict):
                    # Extract primary identifier
                    if "section" in details:
                        refs[key] = details["section"]
                    elif "vuln_id" in details:
                        refs[key] = details["vuln_id"]
                    elif "requirement" in details:
                        refs[key] = details["requirement"]
                    elif "control" in details:
                        refs[key] = details["control"]
                elif isinstance(details, str):
                    refs[key] = details

    return refs


def evaluate_rule(
    ssh: SSHSession, rule: dict, capabilities: dict[str, bool]
) -> RuleResult:
    """Evaluate a single rule: select implementation and run its check."""
    rule_id = rule["id"]
    title = rule.get("title", rule_id)
    severity = rule.get("severity", "unknown")
    framework_refs = _extract_framework_refs(rule)

    impl = select_implementation(rule, capabilities)
    if impl is None:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            skipped=True,
            skip_reason="No matching implementation",
            framework_refs=framework_refs,
        )

    check = impl.get("check")
    if check is None:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            skipped=True,
            skip_reason="Implementation has no check",
            framework_refs=framework_refs,
        )

    try:
        cr = run_check(ssh, check)
    except Exception as exc:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            detail=f"Error: {exc}",
            framework_refs=framework_refs,
        )

    return RuleResult(
        rule_id=rule_id,
        title=title,
        severity=severity,
        passed=cr.passed,
        detail=cr.detail,
        evidence=cr.evidence,
        framework_refs=framework_refs,
    )


def remediate_rule(
    ssh: SSHSession,
    rule: dict,
    capabilities: dict[str, bool],
    *,
    dry_run: bool = False,
    rollback_on_failure: bool = False,
) -> RuleResult:
    """Check a rule, remediate if failing, then re-check."""
    # Initial check
    result = evaluate_rule(ssh, rule, capabilities)
    if result.passed or result.skipped:
        return result

    impl = select_implementation(rule, capabilities)
    if impl is None:
        result.remediation_detail = "No matching implementation"
        return result

    assert impl is not None  # mypy type narrowing
    remediation = impl.get("remediation")
    if remediation is None:
        result.remediation_detail = "No remediation defined"
        return result

    check = impl.get("check")

    try:
        ok, detail, step_results = run_remediation(
            ssh,
            remediation,
            dry_run=dry_run,
            check=check,
        )
    except Exception as exc:
        result.remediation_detail = f"Error: {exc}"
        return result

    result.remediated = True
    result.remediation_detail = detail
    result.step_results = step_results

    if not ok:
        if rollback_on_failure and not dry_run:
            result.rollback_results = _execute_rollback(ssh, step_results)
            result.rolled_back = True
        return result

    if dry_run:
        return result

    # Re-check after remediation
    if check:
        try:
            cr = run_check(ssh, check)
            result.passed = cr.passed
            result.detail = cr.detail
            result.evidence = cr.evidence
        except Exception as exc:
            result.detail = f"Re-check error: {exc}"

    # Rollback if re-check failed
    if rollback_on_failure and not result.passed:
        result.rollback_results = _execute_rollback(ssh, step_results)
        result.rolled_back = True

    return result
