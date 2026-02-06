"""JSON output formatter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.output import RunResult


def format_json(run_result: RunResult) -> str:
    """Format results as JSON.

    Produces a structured JSON document with:
    - timestamp
    - command (check/remediate)
    - hosts[] with capabilities and results
    - summary totals
    """
    data = {
        "timestamp": run_result.timestamp.isoformat(),
        "command": run_result.command,
        "hosts": [],
        "summary": {
            "hosts": run_result.host_count,
            "total": run_result.total_pass
            + run_result.total_fail
            + run_result.total_skip,
            "pass": run_result.total_pass,
            "fail": run_result.total_fail,
            "skip": run_result.total_skip,
        },
    }

    if run_result.command == "remediate":
        data["summary"]["fixed"] = run_result.total_fixed

    for host in run_result.hosts:
        host_data = {
            "hostname": host.hostname,
            "platform": {
                "family": host.platform_family,
                "version": host.platform_version,
            }
            if host.platform_family
            else None,
            "capabilities": host.capabilities,
            "results": [],
            "summary": {
                "total": len(host.results),
                "pass": host.pass_count,
                "fail": host.fail_count,
                "skip": host.skip_count,
            },
        }

        if host.error:
            host_data["error"] = host.error

        if run_result.command == "remediate":
            host_data["summary"]["fixed"] = host.fixed_count

        for result in host.results:
            result_data = {
                "rule_id": result.rule_id,
                "title": result.title,
                "severity": result.severity,
                "passed": result.passed,
                "skipped": result.skipped,
                "detail": result.detail,
            }

            if result.skipped:
                result_data["skip_reason"] = result.skip_reason

            # Include implementation if available
            if hasattr(result, "implementation") and result.implementation:
                result_data["implementation"] = result.implementation

            if run_result.command == "remediate":
                result_data["remediated"] = result.remediated
                if result.remediation_detail:
                    result_data["remediation_detail"] = result.remediation_detail
                if result.rolled_back:
                    result_data["rolled_back"] = result.rolled_back

            host_data["results"].append(result_data)

        data["hosts"].append(host_data)

    return json.dumps(data, indent=2)
