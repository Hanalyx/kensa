"""CSV output formatter."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.output import RunResult


def format_csv(run_result: RunResult) -> str:
    """Format results as CSV.

    Produces a flat CSV with one row per host+rule combination.
    Columns vary slightly between check and remediate commands.
    """
    output = io.StringIO()

    # Define columns based on command type
    if run_result.command == "remediate":
        fieldnames = [
            "host",
            "platform",
            "rule_id",
            "title",
            "severity",
            "passed",
            "skipped",
            "remediated",
            "detail",
        ]
    else:
        fieldnames = [
            "host",
            "platform",
            "rule_id",
            "title",
            "severity",
            "passed",
            "skipped",
            "detail",
        ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for host in run_result.hosts:
        if host.error:
            # Write error row for failed hosts
            row = {
                "host": host.hostname,
                "platform": "",
                "rule_id": "",
                "title": "",
                "severity": "",
                "passed": "",
                "skipped": "",
                "detail": f"Connection error: {host.error}",
            }
            if run_result.command == "remediate":
                row["remediated"] = ""
            writer.writerow(row)
            continue

        platform_str = ""
        if host.platform_family:
            platform_str = f"{host.platform_family} {host.platform_version or ''}"

        for result in host.results:
            row = {
                "host": host.hostname,
                "platform": platform_str,
                "rule_id": result.rule_id,
                "title": result.title,
                "severity": result.severity,
                "passed": str(result.passed).lower(),
                "skipped": str(result.skipped).lower(),
                "detail": result.detail or result.skip_reason or "",
            }

            if run_result.command == "remediate":
                row["remediated"] = str(result.remediated).lower()

            writer.writerow(row)

    return output.getvalue()
