"""Markdown and JSON report generation for benchmark comparisons."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scripts.benchmark.compare import (
    ComparisonSummary,
    ControlComparison,
    CoverageDimension,
    HostComparison,
    MultiHostResult,
)


def generate_markdown(
    comparisons: list[ControlComparison],
    summary: ComparisonSummary,
    *,
    title: str = "Benchmark Comparison",
    host: str = "",
    tool_versions: dict[str, str] | None = None,
) -> str:
    """Generate a Markdown benchmark report.

    Args:
        comparisons: List of ControlComparison records.
        summary: Aggregate metrics.
        title: Report title.
        host: Hostname for the report header.
        tool_versions: Map of tool_name -> version string.

    Returns:
        Markdown-formatted report string.

    """
    tool_versions = tool_versions or {}
    lines: list[str] = []

    # Header
    lines.append(f"# {title}")
    if host:
        tool_info = ", ".join(
            f"{t} {tool_versions.get(t, '')}" for t in sorted(summary.per_tool_coverage)
        )
        lines.append(f"## Host: {host} | Tools: {tool_info.strip()}")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Executive summary table
    lines.append("## Executive Summary")
    lines.append("")
    tool_names = sorted(summary.per_tool_coverage.keys())

    lines.append("| Dimension | " + " | ".join(tool_names) + " | Notes |")
    lines.append("|-----------|" + "|".join("------" for _ in tool_names) + "|-------|")

    # Coverage row
    cov_cells = []
    for t in tool_names:
        count = summary.per_tool_coverage.get(t, 0)
        total = summary.total_controls
        pct = (count / total * 100) if total > 0 else 0
        cov_cells.append(f"{count}/{total} ({pct:.1f}%)")
    best_cov = max(summary.per_tool_coverage.values()) if summary.per_tool_coverage else 0
    worst_cov = min(summary.per_tool_coverage.values()) if summary.per_tool_coverage else 0
    diff = best_cov - worst_cov
    lines.append(
        f"| Coverage | {' | '.join(cov_cells)} | delta: {diff} controls |"
    )

    # Agreement row
    commonly = summary.agree_count + summary.disagree_count
    lines.append(
        f"| Agreement | {summary.agreement_rate:.1%} on {commonly} common controls "
        f"| | {summary.disagree_count} disagreements |"
    )

    # Exclusive coverage
    exc_cells = []
    for t in tool_names:
        exc_cells.append(str(summary.exclusive_coverage.get(t, 0)))
    lines.append(f"| Exclusive controls | {' | '.join(exc_cells)} | |")
    lines.append("")

    # Categorize comparisons
    agreements = [c for c in comparisons if c.agreement == "agree"]
    disagreements = [c for c in comparisons if c.agreement == "disagree"]
    partial = [c for c in comparisons if c.agreement == "partial"]

    agree_pass = [c for c in agreements if _any_pass(c)]
    agree_fail = [c for c in agreements if not _any_pass(c)]

    # Disagreements section
    if disagreements:
        lines.append(f"## Disagreements ({len(disagreements)})")
        lines.append("")
        lines.append(
            "| Control | "
            + " | ".join(tool_names)
            + " | "
            + " | ".join(f"{t} rules" for t in tool_names)
            + " |"
        )
        lines.append(
            "|---------|"
            + "|".join("------" for _ in tool_names)
            + "|"
            + "|".join("------" for _ in tool_names)
            + "|"
        )
        for comp in disagreements:
            status_cells = []
            rule_cells = []
            for t in tool_names:
                r = comp.tool_results.get(t)
                if r and r.passed is not None:
                    status_cells.append("PASS" if r.passed else "FAIL")
                    rule_cells.append(str(len(r.rule_ids)))
                else:
                    status_cells.append("—")
                    rule_cells.append("—")
            title = f" {comp.title}" if comp.title else ""
            lines.append(
                f"| {comp.control_id}{title} | "
                + " | ".join(status_cells)
                + " | "
                + " | ".join(rule_cells)
                + " |"
            )
        lines.append("")

        # Disagreement details
        lines.append("### Disagreement Details")
        lines.append("")
        for comp in disagreements:
            lines.append(f"#### {comp.control_id}")
            if comp.title:
                lines.append(f"*{comp.title}*")
            lines.append("")
            for t in tool_names:
                r = comp.tool_results.get(t)
                if r and r.passed is not None:
                    status = "PASS" if r.passed else "FAIL"
                    lines.append(f"**{t}:** {status}")
                    for rid in r.rule_ids[:5]:
                        lines.append(f"- `{rid}`")
                    if len(r.rule_ids) > 5:
                        lines.append(f"- ... and {len(r.rule_ids) - 5} more")
                    if r.detail:
                        lines.append(f"- Detail: {r.detail[:100]}")
                    lines.append("")
            lines.append("---")
            lines.append("")

    # Both fail
    if agree_fail:
        lines.append(f"## Both Fail ({len(agree_fail)} controls)")
        lines.append("")
        lines.append("| Control | Title |")
        lines.append("|---------|-------|")
        for comp in agree_fail:
            lines.append(f"| {comp.control_id} | {comp.title} |")
        lines.append("")

    # Exclusive coverage
    if partial:
        lines.append(f"## Exclusive Coverage ({len(partial)} controls)")
        lines.append("")
        # Group by tool
        for t in tool_names:
            tool_exclusive = [
                c for c in partial if c.covered_by == [t]
            ]
            if tool_exclusive:
                pass_count = sum(
                    1
                    for c in tool_exclusive
                    if c.tool_results[t].passed
                )
                fail_count = len(tool_exclusive) - pass_count
                lines.append(
                    f"### {t} only ({len(tool_exclusive)} controls: "
                    f"{pass_count} pass, {fail_count} fail)"
                )
                lines.append("")
                lines.append("<details><summary>Click to expand</summary>")
                lines.append("")
                for c in tool_exclusive:
                    r = c.tool_results[t]
                    status = "PASS" if r.passed else "FAIL"
                    rules = ", ".join(r.rule_ids[:3])
                    lines.append(f"- {c.control_id}: {status} — {rules}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

    # Both pass (collapsed)
    if agree_pass:
        lines.append(f"## Both Pass ({len(agree_pass)} controls)")
        lines.append("")
        lines.append("<details><summary>Click to expand</summary>")
        lines.append("")
        for comp in agree_pass:
            rule_counts = " / ".join(
                f"{t}({len(comp.tool_results[t].rule_ids)})"
                for t in tool_names
                if t in comp.tool_results
            )
            lines.append(f"- {comp.control_id}: {rule_counts}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def generate_json(
    comparisons: list[ControlComparison],
    summary: ComparisonSummary,
) -> str:
    """Generate a JSON benchmark report.

    Args:
        comparisons: List of ControlComparison records.
        summary: Aggregate metrics.

    Returns:
        JSON-formatted string.

    """
    data = {
        "framework": summary.framework,
        "generated": datetime.now().isoformat(),
        "summary": {
            "total_controls": summary.total_controls,
            "per_tool_coverage": summary.per_tool_coverage,
            "agreement_rate": round(summary.agreement_rate, 4),
            "agree_count": summary.agree_count,
            "disagree_count": summary.disagree_count,
            "exclusive_coverage": summary.exclusive_coverage,
        },
        "controls": [],
    }

    for comp in comparisons:
        entry: dict = {
            "control_id": comp.control_id,
            "title": comp.title,
            "agreement": comp.agreement,
            "tools": {},
        }
        for tool_name, r in comp.tool_results.items():
            entry["tools"][tool_name] = {
                "passed": r.passed,
                "rule_ids": r.rule_ids,
                "has_evidence": r.has_evidence,
                "has_remediation": r.has_remediation,
                "detail": r.detail,
            }
        if comp.ground_truth is not None:
            entry["ground_truth"] = comp.ground_truth
        data["controls"].append(entry)

    return json.dumps(data, indent=2)


def write_report(
    content: str,
    path: str,
) -> None:
    """Write report content to a file.

    Args:
        content: Report content (Markdown or JSON).
        path: Output file path.

    """
    Path(path).write_text(content)


def generate_multihost_markdown(
    result: MultiHostResult,
    *,
    title: str = "Multi-Host Benchmark Comparison",
) -> str:
    """Generate a Markdown report for multi-host comparison.

    Args:
        result: MultiHostResult with per-host and aggregate data.
        title: Report title.

    Returns:
        Markdown-formatted report string.

    """
    lines: list[str] = []
    s = result.aggregate_summary
    tool_names = sorted(s.per_tool_coverage.keys())

    # Header
    lines.append(f"# {title}")
    lines.append(f"**Framework:** {result.framework}")
    lines.append(
        f"**Hosts:** {len(result.hosts)} | "
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    lines.append("")

    # Aggregate summary
    lines.append("## Aggregate Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total controls (union) | {s.total_controls} |")
    for t in tool_names:
        count = s.per_tool_coverage.get(t, 0)
        pct = (count / s.total_controls * 100) if s.total_controls > 0 else 0
        lines.append(f"| {t} coverage | {count}/{s.total_controls} ({pct:.1f}%) |")
    commonly = s.agree_count + s.disagree_count
    lines.append(f"| Agreement rate | {s.agreement_rate:.1%} on {commonly} common |")
    lines.append(f"| Disagreements | {s.disagree_count} |")
    lines.append("")

    # Coverage dimension
    if result.aggregate_coverage:
        lines.append("## Framework Coverage")
        lines.append("")
        lines.append(
            "| Tool | Controls Covered | Framework Total "
            "| Coverage % | Exclusive |"
        )
        lines.append("|------|-----------------|----------------|-----------|-----------|")
        for t in tool_names:
            cov = result.aggregate_coverage.get(t)
            if cov:
                lines.append(
                    f"| {t} | {cov.controls_covered} | {cov.total_framework} "
                    f"| {cov.coverage_percent:.1f}% | {cov.exclusive_controls} |"
                )
        lines.append("")

    # Per-host sections
    lines.append("## Per-Host Results")
    lines.append("")
    for hc in result.hosts:
        hs = hc.summary
        lines.append(f"### {hc.host_name} ({hc.platform})")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Controls | {hs.total_controls} |")
        commonly_h = hs.agree_count + hs.disagree_count
        lines.append(f"| Agreement | {hs.agreement_rate:.1%} on {commonly_h} common |")
        lines.append(f"| Disagreements | {hs.disagree_count} |")
        lines.append("")

        # Host disagreements
        host_disagreements = [
            c for c in hc.comparisons if c.agreement == "disagree"
        ]
        if host_disagreements:
            lines.append(
                f"**Disagreements ({len(host_disagreements)}):**"
            )
            lines.append("")
            for comp in host_disagreements:
                parts = []
                for t in tool_names:
                    r = comp.tool_results.get(t)
                    if r and r.passed is not None:
                        parts.append(f"{t}={'PASS' if r.passed else 'FAIL'}")
                lines.append(f"- {comp.control_id}: {', '.join(parts)}")
            lines.append("")

    # Cross-platform table
    lines.append("## Cross-Platform Table")
    lines.append("")
    _append_crossplatform_table(lines, result, tool_names)

    # Cross-platform consistency
    lines.append("## Cross-Platform Consistency")
    lines.append("")
    _append_consistency_section(lines, result, tool_names)

    return "\n".join(lines)


def _append_crossplatform_table(
    lines: list[str],
    result: MultiHostResult,
    tool_names: list[str],
) -> None:
    """Append cross-platform comparison table to lines."""
    # Collect all control IDs across all hosts
    all_controls: dict[str, str] = {}  # control_id -> title
    for hc in result.hosts:
        for comp in hc.comparisons:
            if comp.control_id not in all_controls:
                all_controls[comp.control_id] = comp.title

    if not all_controls:
        lines.append("*No controls to display.*")
        lines.append("")
        return

    # Build header: Control | host1-tool1 | host1-tool2 | host2-tool1 | ...
    host_tool_headers = []
    for hc in result.hosts:
        for t in tool_names:
            host_tool_headers.append(f"{hc.host_name}/{t}")

    lines.append("| Control | " + " | ".join(host_tool_headers) + " |")
    lines.append("|---------|" + "|".join("------" for _ in host_tool_headers) + "|")

    # Build lookup: (host_name, control_id) -> ControlComparison
    lookup: dict[tuple[str, str], ControlComparison] = {}
    for hc in result.hosts:
        for comp in hc.comparisons:
            lookup[(hc.host_name, comp.control_id)] = comp

    from scripts.benchmark.compare import _section_sort_key

    for cid in sorted(all_controls.keys(), key=_section_sort_key):
        cells = []
        for hc in result.hosts:
            comp = lookup.get((hc.host_name, cid))
            for t in tool_names:
                if comp:
                    r = comp.tool_results.get(t)
                    if r and r.passed is not None:
                        cells.append("PASS" if r.passed else "FAIL")
                    else:
                        cells.append("—")
                else:
                    cells.append("—")
        lines.append(f"| {cid} | " + " | ".join(cells) + " |")
    lines.append("")


def _append_consistency_section(
    lines: list[str],
    result: MultiHostResult,
    tool_names: list[str],
) -> None:
    """Append cross-platform consistency analysis."""
    # For each control, check if results are consistent across all hosts
    from scripts.benchmark.compare import _section_sort_key

    all_controls: set[str] = set()
    for hc in result.hosts:
        for comp in hc.comparisons:
            all_controls.add(comp.control_id)

    lookup: dict[tuple[str, str], ControlComparison] = {}
    for hc in result.hosts:
        for comp in hc.comparisons:
            lookup[(hc.host_name, comp.control_id)] = comp

    consistent: list[str] = []
    inconsistent: list[tuple[str, dict[str, list[str]]]] = []

    for cid in sorted(all_controls, key=_section_sort_key):
        # Collect (tool, result) across hosts for this control
        per_tool_results: dict[str, list[str]] = {t: [] for t in tool_names}
        for hc in result.hosts:
            comp = lookup.get((hc.host_name, cid))
            for t in tool_names:
                if comp:
                    r = comp.tool_results.get(t)
                    if r and r.passed is not None:
                        per_tool_results[t].append(
                            "PASS" if r.passed else "FAIL"
                        )

        # Check consistency: all hosts agree for each tool
        is_consistent = True
        for t in tool_names:
            vals = per_tool_results[t]
            if vals and len(set(vals)) > 1:
                is_consistent = False
                break

        if is_consistent:
            consistent.append(cid)
        else:
            inconsistent.append((cid, per_tool_results))

    lines.append(f"- **Consistent across hosts:** {len(consistent)} controls")
    lines.append(f"- **Differ across hosts:** {len(inconsistent)} controls")
    lines.append("")

    if inconsistent:
        lines.append("### Controls differing across hosts")
        lines.append("")
        for cid, per_tool in inconsistent:
            parts = []
            for t in tool_names:
                vals = per_tool[t]
                if vals:
                    parts.append(f"{t}: {'/'.join(vals)}")
            lines.append(f"- {cid}: {', '.join(parts)}")
        lines.append("")


def generate_multihost_json(
    result: MultiHostResult,
) -> str:
    """Generate a JSON report for multi-host comparison.

    Args:
        result: MultiHostResult with per-host and aggregate data.

    Returns:
        JSON-formatted string.

    """
    data: dict = {
        "framework": result.framework,
        "generated": datetime.now().isoformat(),
        "hosts": [],
        "aggregate": _summary_to_dict(result.aggregate_summary),
    }

    if result.aggregate_coverage:
        data["aggregate"]["coverage"] = {
            name: _coverage_to_dict(cov)
            for name, cov in result.aggregate_coverage.items()
        }

    for hc in result.hosts:
        host_data: dict = {
            "host_name": hc.host_name,
            "platform": hc.platform,
            "summary": _summary_to_dict(hc.summary),
            "comparisons": [],
        }
        if hc.coverage:
            host_data["coverage"] = {
                name: _coverage_to_dict(cov)
                for name, cov in hc.coverage.items()
            }
        for comp in hc.comparisons:
            entry: dict = {
                "control_id": comp.control_id,
                "title": comp.title,
                "agreement": comp.agreement,
                "tools": {},
            }
            for tool_name, r in comp.tool_results.items():
                entry["tools"][tool_name] = {
                    "passed": r.passed,
                    "rule_ids": r.rule_ids,
                    "has_evidence": r.has_evidence,
                    "has_remediation": r.has_remediation,
                    "detail": r.detail,
                }
            host_data["comparisons"].append(entry)
        data["hosts"].append(host_data)

    return json.dumps(data, indent=2)


def _summary_to_dict(s: ComparisonSummary) -> dict:
    """Convert ComparisonSummary to a serializable dict."""
    return {
        "framework": s.framework,
        "total_controls": s.total_controls,
        "per_tool_coverage": s.per_tool_coverage,
        "agreement_rate": round(s.agreement_rate, 4),
        "agree_count": s.agree_count,
        "disagree_count": s.disagree_count,
        "exclusive_coverage": s.exclusive_coverage,
    }


def _coverage_to_dict(cov: CoverageDimension) -> dict:
    """Convert CoverageDimension to a serializable dict."""
    return {
        "tool_name": cov.tool_name,
        "controls_covered": cov.controls_covered,
        "total_framework": cov.total_framework,
        "coverage_percent": cov.coverage_percent,
        "exclusive_controls": cov.exclusive_controls,
    }


def _any_pass(comp: ControlComparison) -> bool:
    """Check if any tool reports this control as passing."""
    return any(
        r.passed for r in comp.tool_results.values() if r.passed is not None
    )
