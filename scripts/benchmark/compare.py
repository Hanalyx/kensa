"""Core comparison engine for control-level benchmarking."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from scripts.benchmark.adapters.base import ToolControlResult

# Stop words excluded from heuristic keyword matching
_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "in",
        "is",
        "it",
        "not",
        "of",
        "on",
        "or",
        "set",
        "the",
        "to",
        "was",
        "with",
        "ensure",
        "configured",
        "properly",
    }
)


@dataclass
class KnownMappingError:
    """A known incorrect mapping from OpenSCAP rules to a CIS control.

    Attributes:
        control_id: CIS control identifier.
        reason: Human-readable explanation of the mapping error.
        rules: OpenSCAP rule IDs that are incorrectly mapped.

    """

    control_id: str
    reason: str
    rules: list[str] = field(default_factory=list)


@dataclass
class ControlComparison:
    """Comparison record for a single framework control across tools.

    Attributes:
        control_id: Framework control identifier (e.g., CIS "5.1.20").
        framework: Framework name (e.g., "cis-rhel9-v2.0.0").
        title: Control title from the framework mapping.
        tool_results: Map of tool_name -> ToolControlResult.
        ground_truth: Verified ground truth, if available.

    """

    control_id: str
    framework: str
    title: str = ""
    tool_results: dict[str, ToolControlResult] = field(default_factory=dict)
    ground_truth: bool | None = None
    mapping_error: str = ""
    mapping_error_reason: str = ""

    @property
    def agreement(self) -> str:
        """Determine agreement status across tools.

        Returns:
            "agree" if all tools with results agree on pass/fail,
            "disagree" if any tools disagree,
            "partial" if only some tools cover this control,
            "none" if no tools cover this control.

        """
        results = {
            name: r.passed
            for name, r in self.tool_results.items()
            if r.passed is not None
        }
        if not results:
            return "none"
        if len(results) == 1:
            return "partial"

        values = list(results.values())
        if all(v == values[0] for v in values):
            return "agree"
        return "disagree"

    @property
    def covered_by(self) -> list[str]:
        """Tool names that cover this control."""
        return [name for name, r in self.tool_results.items() if r.passed is not None]


@dataclass
class ComparisonSummary:
    """Aggregate metrics from a comparison run.

    Attributes:
        framework: Framework identifier.
        total_controls: Total unique controls across all tools.
        per_tool_coverage: Map of tool_name -> number of controls covered.
        agree_count: Controls where all tools agree.
        disagree_count: Controls where tools disagree.
        exclusive_coverage: Map of tool_name -> controls only that tool covers.
        agreement_rate: Fraction of commonly-covered controls that agree.

    """

    framework: str
    total_controls: int = 0
    per_tool_coverage: dict[str, int] = field(default_factory=dict)
    agree_count: int = 0
    disagree_count: int = 0
    mapping_error_count: int = 0
    exclusive_coverage: dict[str, int] = field(default_factory=dict)
    agreement_rate: float = 0.0


def compare_at_control_level(
    tool_results: dict[str, dict[str, ToolControlResult]],
    framework: str = "",
    control_titles: dict[str, str] | None = None,
) -> list[ControlComparison]:
    """Compare multiple tools at the framework control level.

    Args:
        tool_results: Map of tool_name -> {control_id -> ToolControlResult}.
        framework: Framework identifier for the comparison.
        control_titles: Optional map of control_id -> title.

    Returns:
        List of ControlComparison records, sorted by control ID.

    """
    control_titles = control_titles or {}

    # Collect all control IDs across tools
    all_controls: set[str] = set()
    for results in tool_results.values():
        all_controls.update(results.keys())

    comparisons: list[ControlComparison] = []
    for control_id in sorted(all_controls, key=_section_sort_key):
        comp = ControlComparison(
            control_id=control_id,
            framework=framework,
            title=control_titles.get(control_id, ""),
        )
        for tool_name, results in tool_results.items():
            if control_id in results:
                comp.tool_results[tool_name] = results[control_id]

        comparisons.append(comp)

    return comparisons


def summarize(
    comparisons: list[ControlComparison],
    framework: str = "",
) -> ComparisonSummary:
    """Compute aggregate metrics from comparison records.

    Args:
        comparisons: List of ControlComparison records.
        framework: Framework identifier.

    Returns:
        ComparisonSummary with aggregate metrics.

    """
    tool_names: set[str] = set()
    for comp in comparisons:
        tool_names.update(comp.tool_results.keys())

    per_tool: dict[str, int] = dict.fromkeys(tool_names, 0)
    exclusive: dict[str, int] = dict.fromkeys(tool_names, 0)
    agree = 0
    disagree = 0
    mapping_errors = 0
    commonly_covered = 0

    for comp in comparisons:
        covered = comp.covered_by
        for t in covered:
            per_tool[t] += 1

        if len(covered) == 1:
            exclusive[covered[0]] += 1

        if comp.agreement == "agree":
            agree += 1
            commonly_covered += 1
        elif comp.agreement == "disagree":
            if comp.mapping_error:
                mapping_errors += 1
            else:
                disagree += 1
            commonly_covered += 1

    effective_common = commonly_covered - mapping_errors
    rate = agree / effective_common if effective_common > 0 else 0.0

    return ComparisonSummary(
        framework=framework,
        total_controls=len(comparisons),
        per_tool_coverage=per_tool,
        agree_count=agree,
        disagree_count=disagree,
        mapping_error_count=mapping_errors,
        exclusive_coverage=exclusive,
        agreement_rate=rate,
    )


@dataclass
class CoverageDimension:
    """Framework coverage metrics for a tool.

    Attributes:
        tool_name: Name of the tool (e.g., "aegis", "openscap").
        controls_covered: Controls with results from this tool.
        total_framework: Total controls in framework mapping.
        coverage_percent: Percentage of framework controls covered.
        exclusive_controls: Controls only this tool covers.

    """

    tool_name: str
    controls_covered: int
    total_framework: int
    coverage_percent: float
    exclusive_controls: int = 0


@dataclass
class HostComparison:
    """Complete comparison result for a single host.

    Attributes:
        host_name: Identifier for this host (e.g., "rhel9-211").
        platform: Platform string (e.g., "rhel9", "rhel8").
        comparisons: Per-control comparison records.
        summary: Aggregate metrics for this host.
        coverage: Per-tool coverage dimensions.

    """

    host_name: str
    platform: str
    comparisons: list[ControlComparison]
    summary: ComparisonSummary
    coverage: dict[str, CoverageDimension] = field(default_factory=dict)


@dataclass
class MultiHostResult:
    """Aggregate results across multiple hosts.

    Attributes:
        framework: Framework identifier.
        hosts: Per-host comparison results.
        aggregate_summary: Merged metrics across all hosts.
        aggregate_coverage: Merged coverage across all hosts.

    """

    framework: str
    hosts: list[HostComparison]
    aggregate_summary: ComparisonSummary
    aggregate_coverage: dict[str, CoverageDimension] = field(default_factory=dict)


def compute_coverage(
    tool_results: dict[str, ToolControlResult],
    total_framework: int,
    tool_name: str,
    exclusive_ids: set[str] | None = None,
) -> CoverageDimension:
    """Compute coverage metrics for a tool against a framework.

    Args:
        tool_results: Map of control_id -> ToolControlResult for this tool.
        total_framework: Total controls in the framework mapping.
        tool_name: Name of the tool.
        exclusive_ids: Control IDs only this tool covers (optional).

    Returns:
        CoverageDimension with coverage metrics.

    """
    covered = sum(1 for r in tool_results.values() if r.passed is not None)
    pct = (covered / total_framework * 100) if total_framework > 0 else 0.0
    exclusive = len(exclusive_ids) if exclusive_ids else 0

    return CoverageDimension(
        tool_name=tool_name,
        controls_covered=covered,
        total_framework=total_framework,
        coverage_percent=round(pct, 2),
        exclusive_controls=exclusive,
    )


def aggregate_hosts(
    host_comparisons: list[HostComparison],
    framework: str = "",
) -> ComparisonSummary:
    """Merge per-host comparisons into an aggregate summary.

    Uses union of all controls across hosts. For each control, agreement
    is determined by the most common per-host result (any-disagree: if any
    host shows a disagreement on that control, aggregate is disagree).

    Args:
        host_comparisons: List of per-host HostComparison results.
        framework: Framework identifier.

    Returns:
        ComparisonSummary with aggregate metrics.

    """
    if not host_comparisons:
        return ComparisonSummary(framework=framework)

    # Collect all unique control comparisons across hosts, merging tool results
    merged: dict[str, ControlComparison] = {}
    for hc in host_comparisons:
        for comp in hc.comparisons:
            if comp.control_id not in merged:
                merged[comp.control_id] = ControlComparison(
                    control_id=comp.control_id,
                    framework=comp.framework,
                    title=comp.title,
                    tool_results=dict(comp.tool_results),
                )
            else:
                # Merge tool results: keep existing, but if a tool disagrees
                # across hosts, mark as fail (conservative)
                existing = merged[comp.control_id]
                for tool_name, result in comp.tool_results.items():
                    if tool_name not in existing.tool_results:
                        existing.tool_results[tool_name] = result
                    else:
                        # If any host fails for this tool, aggregate fails
                        prev = existing.tool_results[tool_name]
                        if prev.passed is True and result.passed is False:
                            existing.tool_results[tool_name] = result

    all_comparisons = sorted(
        merged.values(), key=lambda c: _section_sort_key(c.control_id)
    )
    return summarize(all_comparisons, framework=framework)


def load_known_mapping_errors(path: str) -> dict[str, KnownMappingError]:
    """Load known mapping errors from a YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        Dict mapping control_id -> KnownMappingError.

    """
    data = yaml.safe_load(Path(path).read_text())
    result: dict[str, KnownMappingError] = {}
    for entry in data.get("errors", []):
        cid = entry["control_id"]
        result[cid] = KnownMappingError(
            control_id=cid,
            reason=entry.get("reason", ""),
            rules=entry.get("rules", []),
        )
    return result


def detect_mapping_errors(
    comparisons: list[ControlComparison],
    known_errors: dict[str, KnownMappingError] | None = None,
) -> None:
    """Flag mapping errors on disagreement comparisons (mutates in place).

    Step 1: Check against allowlist (known_errors) — sets mapping_error="known".
    Step 2: For remaining disagreements, run heuristic — sets mapping_error="suspected".

    The heuristic tokenizes the CIS control title and each OpenSCAP rule_id,
    then flags controls where NO rule has any keyword overlap with the title.

    Args:
        comparisons: List of ControlComparison records to check.
        known_errors: Optional dict of known mapping errors keyed by control_id.

    """
    known_errors = known_errors or {}

    for comp in comparisons:
        if comp.agreement != "disagree":
            continue

        # Step 1: Check allowlist
        if comp.control_id in known_errors:
            comp.mapping_error = "known"
            comp.mapping_error_reason = known_errors[comp.control_id].reason
            continue

        # Step 2: Heuristic — keyword overlap between title and rule IDs
        if not comp.title:
            continue

        title_keywords = _tokenize_title(comp.title)
        if not title_keywords:
            continue

        # Check all rule_ids across all tools
        all_rule_ids: list[str] = []
        for r in comp.tool_results.values():
            all_rule_ids.extend(r.rule_ids)

        if not all_rule_ids:
            continue

        # If NO rule has ANY keyword overlap with the title, flag as suspected
        has_any_overlap = False
        for rule_id in all_rule_ids:
            rule_keywords = _tokenize_rule_id(rule_id)
            overlap = title_keywords & rule_keywords
            if overlap:
                has_any_overlap = True
                break

        if not has_any_overlap:
            comp.mapping_error = "suspected"
            comp.mapping_error_reason = (
                f"Zero keyword overlap between title and {len(all_rule_ids)} rule(s)"
            )


def _tokenize_title(title: str) -> set[str]:
    """Extract keywords from a CIS control title.

    Args:
        title: CIS control title string.

    Returns:
        Set of lowercase keywords with stop words removed.

    """
    words = set()
    for word in title.lower().split():
        # Strip punctuation
        cleaned = word.strip(".,;:()[]\"'")
        if cleaned and cleaned not in _STOP_WORDS and len(cleaned) > 1:
            words.add(cleaned)
    return words


def _tokenize_rule_id(rule_id: str) -> set[str]:
    """Extract keywords from an OpenSCAP rule ID by splitting on underscores.

    Args:
        rule_id: OpenSCAP rule ID (e.g., "package_firewalld_installed").

    Returns:
        Set of lowercase keyword tokens.

    """
    return {tok.lower() for tok in rule_id.split("_") if len(tok) > 1}


def _section_sort_key(section: str) -> tuple:
    """Sort key for framework section IDs (e.g., 1.1.1 < 1.1.2 < 5.2.3)."""
    parts: list[tuple[int, int | str]] = []
    for part in section.replace("-", ".").split("."):
        try:
            parts.append((0, int(part)))
        except ValueError:
            parts.append((1, part))
    return tuple(parts)
