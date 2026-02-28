"""Evidence output formatter for OpenWatch integration.

Produces structured JSON with full evidence for each check result,
designed for machine parsing, audit trails, and compliance reporting.

The evidence format includes:
- Raw command output (stdout/stderr/exit_code)
- Expected vs actual values for verification
- Framework mappings (CIS, STIG, NIST, etc.)
- Timestamps for audit trails

Output is per-host, conforming to evidence_schema.json.

Example:
-------
    >>> from runner.output import RunResult, format_evidence
    >>> result = RunResult(command="check")
    >>> for host in result.hosts:
    ...     evidence_json = format_evidence(result, host)
    ...     # Each host gets its own evidence export

"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from runner.output import HostResult, RunResult


def format_evidence(run_result: RunResult, host: HostResult | None = None) -> str:
    """Format results with full evidence for OpenWatch consumption.

    Produces structured JSON including raw command output, expected/actual
    values, and framework references for audit and compliance purposes.

    Args:
        run_result: Aggregated results from a compliance run.
        host: Specific host to format. If None, formats first host.

    Returns:
        JSON string conforming to evidence_schema.json.

    Note:
        For multi-host runs, call this once per host to get separate
        evidence files. The schema is designed for per-host exports.

    """
    # Use first host if none specified
    if host is None:
        if not run_result.hosts:
            return json.dumps({"error": "No hosts in results"}, indent=2)
        host = run_result.hosts[0]

    # Generate a session ID if not available
    session_id = str(uuid.uuid4())[:8]

    output: dict[str, Any] = {
        "version": "1.0.0",
        "session": {
            "id": session_id,
            "timestamp": run_result.timestamp.isoformat(),
            "rules_path": "",  # Would need to be passed in
            "command": run_result.command,
        },
        "host": {
            "hostname": host.hostname,
            "groups": host.groups,
            "effective_variables": host.effective_variables,
            "platform": {
                "family": host.platform_family,
                "version": host.platform_version_id or host.platform_version,
            }
            if host.platform_family
            else None,
            "capabilities": host.capabilities,
        },
        "results": [],
        "summary": {
            "total": len(host.results),
            "pass": host.pass_count,
            "fail": host.fail_count,
            "error": host.error_count,
            "skip": host.skip_count,
        },
    }

    if run_result.command == "remediate":
        output["summary"]["fixed"] = host.fixed_count

    if host.error:
        output["host"]["error"] = host.error

    for result in host.results:
        result_data: dict[str, Any] = {
            "rule_id": result.rule_id,
            "title": result.title,
            "severity": result.severity,
            "passed": result.passed,
            "skipped": result.skipped,
            "error": result.error,
            "error_detail": result.error_detail,
            "detail": result.detail,
        }

        # Add evidence timestamp from evidence object or use run timestamp
        if result.evidence:
            result_data["timestamp"] = result.evidence.timestamp.isoformat()
            result_data["evidence"] = {
                "method": result.evidence.method,
                "command": result.evidence.command,
                "stdout": result.evidence.stdout,
                "stderr": result.evidence.stderr,
                "exit_code": result.evidence.exit_code,
                "expected": result.evidence.expected,
                "actual": result.evidence.actual,
            }
        else:
            result_data["timestamp"] = run_result.timestamp.isoformat()

        # Add skip reason if applicable
        if result.skipped and result.skip_reason:
            result_data["skip_reason"] = result.skip_reason

        # Add framework references
        if result.framework_refs:
            result_data["frameworks"] = result.framework_refs

        # Add remediation info if applicable
        if run_result.command == "remediate":
            result_data["remediated"] = result.remediated
            if result.remediation_detail:
                result_data["remediation_detail"] = result.remediation_detail
            if result.rolled_back:
                result_data["rolled_back"] = result.rolled_back

        output["results"].append(result_data)

    return json.dumps(output, indent=2)


def format_evidence_all(run_result: RunResult) -> str:
    """Format all hosts into a single evidence export.

    For multi-host runs, wraps each host's evidence in an array.

    Args:
        run_result: Aggregated results from a compliance run.

    Returns:
        JSON string with array of per-host evidence objects.

    """
    if len(run_result.hosts) == 1:
        return format_evidence(run_result, run_result.hosts[0])

    all_evidence = []
    for host in run_result.hosts:
        host_evidence = json.loads(format_evidence(run_result, host))
        all_evidence.append(host_evidence)

    return json.dumps(all_evidence, indent=2)
