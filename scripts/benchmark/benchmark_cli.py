#!/usr/bin/env python3
"""CLI entry point for the Aegis benchmarking framework.

Usage:
    python -m scripts.benchmark.benchmark_cli \\
        --aegis results/aegis-211.json \\
        --openscap results/openscap/rhel9-211.xml \\
        --framework cis-rhel9-v2.0.0 \\
        --output benchmark-report.md

    # JSON output
    python -m scripts.benchmark.benchmark_cli \\
        --aegis results/aegis-211.json \\
        --openscap results/openscap/rhel9-211.xml \\
        --format json \\
        --output benchmark-report.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from project root
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from scripts.benchmark.adapters.aegis_adapter import AegisAdapter
from scripts.benchmark.adapters.base import ToolControlResult
from scripts.benchmark.adapters.openscap_adapter import OpenSCAPAdapter
from scripts.benchmark.compare import compare_at_control_level, summarize
from scripts.benchmark.report import generate_json, generate_markdown, write_report


def _load_control_titles(framework: str) -> dict[str, str]:
    """Load control titles from a framework mapping file.

    Args:
        framework: Framework mapping ID (e.g., "cis-rhel9-v2.0.0").

    Returns:
        Dict mapping control_id -> title.

    """
    try:
        from runner.mappings import load_all_mappings

        mappings = load_all_mappings()
        mapping = mappings.get(framework)
        if mapping:
            titles: dict[str, str] = {}
            for section_id, entry in mapping.sections.items():
                titles[section_id] = entry.title
            for section_id, entry in mapping.unimplemented.items():
                titles[section_id] = entry.title
            return titles
    except ImportError:
        pass
    return {}


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark comparison CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 on success).

    """
    parser = argparse.ArgumentParser(
        description="Aegis Benchmarking Framework — Control-level comparison",
    )
    parser.add_argument(
        "--aegis",
        required=True,
        help="Path to Aegis JSON results file",
    )
    parser.add_argument(
        "--openscap",
        required=True,
        help="Path to OpenSCAP XCCDF XML results file",
    )
    parser.add_argument(
        "--framework",
        default="",
        help="Framework mapping ID (e.g., cis-rhel9-v2.0.0) for control titles",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--host",
        default="",
        help="Hostname for report header",
    )
    args = parser.parse_args(argv)

    # Parse results
    print("Parsing Aegis results...", file=sys.stderr)
    aegis = AegisAdapter()
    aegis_results = aegis.parse(args.aegis)
    print(f"  {len(aegis_results)} controls", file=sys.stderr)

    print("Parsing OpenSCAP results...", file=sys.stderr)
    openscap = OpenSCAPAdapter()
    openscap_results = openscap.parse(args.openscap)
    print(f"  {len(openscap_results)} controls", file=sys.stderr)

    # Load titles
    control_titles = _load_control_titles(args.framework) if args.framework else {}

    # Compare
    tool_results: dict[str, dict[str, ToolControlResult]] = {
        "aegis": aegis_results,
        "openscap": openscap_results,
    }
    comparisons = compare_at_control_level(
        tool_results,
        framework=args.framework,
        control_titles=control_titles,
    )
    summary = summarize(comparisons, framework=args.framework)

    # Report
    print(f"\nComparison complete:", file=sys.stderr)
    print(f"  Total controls: {summary.total_controls}", file=sys.stderr)
    for tool, count in sorted(summary.per_tool_coverage.items()):
        pct = count / summary.total_controls * 100 if summary.total_controls else 0
        print(f"  {tool}: {count} ({pct:.1f}%)", file=sys.stderr)
    print(f"  Agreement rate: {summary.agreement_rate:.1%}", file=sys.stderr)
    print(f"  Disagreements: {summary.disagree_count}", file=sys.stderr)

    if args.format == "json":
        content = generate_json(comparisons, summary)
    else:
        content = generate_markdown(
            comparisons,
            summary,
            title=f"{args.framework} — Benchmark Comparison"
            if args.framework
            else "Benchmark Comparison",
            host=args.host,
        )

    if args.output:
        write_report(content, args.output)
        print(f"\nReport written to {args.output}", file=sys.stderr)
    else:
        print(content)

    return 0


if __name__ == "__main__":
    sys.exit(main())
