#!/usr/bin/env python3
"""CLI entry point for the Kensa benchmarking framework.

Usage:
    # Single-host mode (backward compatible)
    python -m scripts.benchmark.benchmark_cli \\
        --kensa results/kensa-211.json \\
        --openscap results/openscap/rhel9-211.xml \\
        --framework cis-rhel9 \\
        --output benchmark-report.md

    # Multi-host mode
    python -m scripts.benchmark.benchmark_cli \\
        --pair rhel9-211:results/kensa-211.json:results/openscap/rhel9-211.xml \\
        --pair rhel9-213:results/kensa-213.json:results/openscap/rhel9-213.xml \\
        --framework cis-rhel9 \\
        --output benchmark-multihost.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from project root
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from scripts.benchmark.adapters.kensa_adapter import KensaAdapter
from scripts.benchmark.adapters.base import ToolControlResult
from scripts.benchmark.adapters.openscap_adapter import OpenSCAPAdapter
from scripts.benchmark.compare import (
    HostComparison,
    MultiHostResult,
    aggregate_hosts,
    compare_at_control_level,
    compute_coverage,
    detect_mapping_errors,
    load_known_mapping_errors,
    summarize,
)
from scripts.benchmark.report import (
    generate_json,
    generate_markdown,
    generate_multihost_json,
    generate_multihost_markdown,
    write_report,
)


def _load_control_titles(framework: str) -> dict[str, str]:
    """Load control titles from a framework mapping file.

    Args:
        framework: Framework mapping ID (e.g., "cis-rhel9").

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


def _load_framework_total(framework: str) -> int:
    """Load total control count from a framework mapping.

    Args:
        framework: Framework mapping ID.

    Returns:
        Total controls in the framework, or 0 if not loadable.

    """
    try:
        from runner.mappings import load_all_mappings

        mappings = load_all_mappings()
        mapping = mappings.get(framework)
        if mapping:
            return mapping.total_controls
    except ImportError:
        pass
    return 0


def _parse_pair(pair_str: str) -> tuple[str, str, str]:
    """Parse a --pair argument into (name, kensa_path, openscap_path).

    Args:
        pair_str: Colon-separated string "name:kensa_path:openscap_path".

    Returns:
        Tuple of (name, kensa_path, openscap_path).

    Raises:
        argparse.ArgumentTypeError: If format is invalid.

    """
    parts = pair_str.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"Invalid --pair format: '{pair_str}'. "
            "Expected name:kensa_path:openscap_path"
        )
    return parts[0], parts[1], parts[2]


def _run_single_host(args: argparse.Namespace) -> int:
    """Run single-host comparison (Phase 1 backward compat)."""
    print("Parsing Kensa results...", file=sys.stderr)
    kensa = KensaAdapter()
    kensa_results = kensa.parse(args.kensa)
    print(f"  {len(kensa_results)} controls", file=sys.stderr)

    print("Parsing OpenSCAP results...", file=sys.stderr)
    openscap = OpenSCAPAdapter()
    openscap_results = openscap.parse(args.openscap)
    print(f"  {len(openscap_results)} controls", file=sys.stderr)

    control_titles = _load_control_titles(args.framework) if args.framework else {}

    tool_results: dict[str, dict[str, ToolControlResult]] = {
        "kensa": kensa_results,
        "openscap": openscap_results,
    }
    comparisons = compare_at_control_level(
        tool_results,
        framework=args.framework,
        control_titles=control_titles,
    )

    known_errors = _load_known_errors(args.known_errors)
    detect_mapping_errors(comparisons, known_errors)

    summary = summarize(comparisons, framework=args.framework)

    _print_summary(summary)

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

    _write_output(content, args.output)
    return 0


def _run_multi_host(args: argparse.Namespace) -> int:
    """Run multi-host comparison (Phase 2)."""
    pairs = [_parse_pair(p) for p in args.pair]
    control_titles = _load_control_titles(args.framework) if args.framework else {}
    framework_total = _load_framework_total(args.framework) if args.framework else 0

    known_errors = _load_known_errors(args.known_errors)

    kensa = KensaAdapter()
    openscap = OpenSCAPAdapter()
    host_comparisons: list[HostComparison] = []

    for name, kensa_path, openscap_path in pairs:
        print(f"Processing {name}...", file=sys.stderr)

        kensa_results = kensa.parse(kensa_path)
        print(f"  Kensa: {len(kensa_results)} controls", file=sys.stderr)

        openscap_results = openscap.parse(openscap_path)
        print(f"  OpenSCAP: {len(openscap_results)} controls", file=sys.stderr)

        tool_results: dict[str, dict[str, ToolControlResult]] = {
            "kensa": kensa_results,
            "openscap": openscap_results,
        }
        comparisons = compare_at_control_level(
            tool_results,
            framework=args.framework,
            control_titles=control_titles,
        )
        detect_mapping_errors(comparisons, known_errors)
        summary = summarize(comparisons, framework=args.framework)

        # Compute coverage if framework total is available
        coverage: dict = {}
        if framework_total > 0:
            # Determine exclusive IDs
            kensa_ids = set(kensa_results.keys())
            openscap_ids = set(openscap_results.keys())
            coverage["kensa"] = compute_coverage(
                kensa_results,
                framework_total,
                "kensa",
                exclusive_ids=kensa_ids - openscap_ids,
            )
            coverage["openscap"] = compute_coverage(
                openscap_results,
                framework_total,
                "openscap",
                exclusive_ids=openscap_ids - kensa_ids,
            )

        # Derive platform from name (e.g., "rhel9-211" -> "rhel9")
        platform = name.rsplit("-", 1)[0] if "-" in name else name

        host_comparisons.append(
            HostComparison(
                host_name=name,
                platform=platform,
                comparisons=comparisons,
                summary=summary,
                coverage=coverage,
            )
        )

    # Aggregate
    agg_summary = aggregate_hosts(host_comparisons, framework=args.framework)

    # Aggregate coverage (union across hosts)
    agg_coverage: dict = {}
    if framework_total > 0:
        all_kensa: dict[str, ToolControlResult] = {}
        all_openscap: dict[str, ToolControlResult] = {}
        for name, kensa_path, _ in pairs:
            for cid, r in kensa.parse(kensa_path).items():
                if cid not in all_kensa:
                    all_kensa[cid] = r
        for name, _, openscap_path in pairs:
            for cid, r in openscap.parse(openscap_path).items():
                if cid not in all_openscap:
                    all_openscap[cid] = r
        agg_coverage["kensa"] = compute_coverage(
            all_kensa,
            framework_total,
            "kensa",
            exclusive_ids=set(all_kensa.keys()) - set(all_openscap.keys()),
        )
        agg_coverage["openscap"] = compute_coverage(
            all_openscap,
            framework_total,
            "openscap",
            exclusive_ids=set(all_openscap.keys()) - set(all_kensa.keys()),
        )

    result = MultiHostResult(
        framework=args.framework,
        hosts=host_comparisons,
        aggregate_summary=agg_summary,
        aggregate_coverage=agg_coverage,
    )

    _print_summary(agg_summary)

    if args.format == "json":
        content = generate_multihost_json(result)
    else:
        content = generate_multihost_markdown(
            result,
            title=f"{args.framework} — Multi-Host Benchmark"
            if args.framework
            else "Multi-Host Benchmark Comparison",
        )

    _write_output(content, args.output)
    return 0


def _load_known_errors(path: str) -> dict | None:
    """Load known mapping errors from a YAML file.

    Args:
        path: Path to the known errors YAML, or empty string to auto-detect.

    Returns:
        Dict of known errors keyed by control_id, or None if not available.

    """
    if not path:
        # Auto-detect default location
        default = Path(__file__).parent / "known_mapping_errors.yaml"
        if default.exists():
            path = str(default)
        else:
            return None

    p = Path(path)
    if not p.exists():
        print(f"Warning: known errors file not found: {path}", file=sys.stderr)
        return None

    errors = load_known_mapping_errors(str(p))
    print(f"  Loaded {len(errors)} known mapping errors", file=sys.stderr)
    return errors


def _print_summary(summary: "ComparisonSummary") -> None:
    """Print summary metrics to stderr."""
    from scripts.benchmark.compare import ComparisonSummary

    print(f"\nComparison complete:", file=sys.stderr)
    print(f"  Total controls: {summary.total_controls}", file=sys.stderr)
    for tool, count in sorted(summary.per_tool_coverage.items()):
        pct = count / summary.total_controls * 100 if summary.total_controls else 0
        print(f"  {tool}: {count} ({pct:.1f}%)", file=sys.stderr)
    print(f"  Agreement rate: {summary.agreement_rate:.1%}", file=sys.stderr)
    print(f"  Disagreements: {summary.disagree_count}", file=sys.stderr)
    if summary.mapping_error_count > 0:
        print(
            f"  Mapping errors: {summary.mapping_error_count} (excluded)",
            file=sys.stderr,
        )


def _write_output(content: str, output: str) -> None:
    """Write content to file or stdout."""
    if output:
        write_report(content, output)
        print(f"\nReport written to {output}", file=sys.stderr)
    else:
        print(content)


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark comparison CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 on success).

    """
    parser = argparse.ArgumentParser(
        description="Kensa Benchmarking Framework — Control-level comparison",
    )
    # Single-host args (backward compatible)
    parser.add_argument(
        "--kensa",
        default="",
        help="Path to Kensa JSON results file (single-host mode)",
    )
    parser.add_argument(
        "--openscap",
        default="",
        help="Path to OpenSCAP XCCDF XML results file (single-host mode)",
    )
    # Multi-host args
    parser.add_argument(
        "--pair",
        action="append",
        default=[],
        help=(
            "Host pair as name:kensa_path:openscap_path (repeatable, multi-host mode)"
        ),
    )
    # Common args
    parser.add_argument(
        "--framework",
        default="",
        help="Framework mapping ID (e.g., cis-rhel9) for control titles",
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
        help="Hostname for report header (single-host mode)",
    )
    parser.add_argument(
        "--known-errors",
        default="",
        dest="known_errors",
        help=(
            "Path to known mapping errors YAML "
            "(default: auto-detect scripts/benchmark/known_mapping_errors.yaml)"
        ),
    )
    args = parser.parse_args(argv)

    # Validate: --pair and --kensa/--openscap are mutually exclusive
    has_single = bool(args.kensa or args.openscap)
    has_multi = bool(args.pair)

    if has_single and has_multi:
        parser.error("--pair and --kensa/--openscap are mutually exclusive")

    if has_multi:
        return _run_multi_host(args)

    if has_single:
        if not args.kensa or not args.openscap:
            parser.error("--kensa and --openscap are both required in single-host mode")
        return _run_single_host(args)

    parser.error("Either --pair or --kensa/--openscap is required")
    return 1  # unreachable


if __name__ == "__main__":
    sys.exit(main())
