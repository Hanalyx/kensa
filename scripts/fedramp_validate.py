#!/usr/bin/env python3
"""FedRAMP baseline validation and gap analysis (development tool).

Compares the current Aegis FedRAMP mapping against the official Rev 5
baseline reference to identify gaps, validate completeness, and generate
reports. Not a user-facing CLI command.

Usage:
    python scripts/fedramp_validate.py                # Full gap analysis
    python scripts/fedramp_validate.py --json          # Machine-readable output
    python scripts/fedramp_validate.py --family AC     # Single family
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Project root (assumes script is in scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Default file paths
DEFAULT_BASELINE = PROJECT_ROOT / "context" / "fedramp" / "moderate-rev5-baseline.yaml"
DEFAULT_MAPPING = PROJECT_ROOT / "mappings" / "fedramp" / "moderate.yaml"
RULES_DIR = PROJECT_ROOT / "rules"


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class BaselineControl:
    """A single control from the FedRAMP baseline reference."""

    id: str
    title: str
    family: str
    applicability: str  # "technical", "semi-technical", "procedural"
    notes: str = ""


@dataclass
class FamilyCoverage:
    """Coverage statistics for a single control family."""

    family_id: str
    family_title: str
    total: int
    implemented: int
    unimplemented: int
    unaccounted: int

    @property
    def coverage_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.implemented / self.total) * 100

    @property
    def accounted_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return ((self.implemented + self.unimplemented) / self.total) * 100


@dataclass
class GapAnalysisResult:
    """Result of comparing baseline against current mapping."""

    total_baseline: int
    total_mapped: int  # implemented + unimplemented
    total_implemented: int
    total_unimplemented: int
    total_unaccounted: int
    unaccounted_controls: list[BaselineControl]
    missing_rules: list[str]  # referenced rules that don't exist
    technical_gaps: list[BaselineControl]  # technical controls without rules
    coverage_by_family: dict[str, FamilyCoverage] = field(default_factory=dict)

    @property
    def is_complete(self) -> bool:
        return self.total_unaccounted == 0

    @property
    def coverage_percent(self) -> float:
        if self.total_baseline == 0:
            return 0.0
        return (self.total_implemented / self.total_baseline) * 100

    @property
    def accounted_percent(self) -> float:
        if self.total_baseline == 0:
            return 0.0
        return (self.total_mapped / self.total_baseline) * 100


# ── Loaders ──────────────────────────────────────────────────────────────────


def load_baseline(path: Path | None = None) -> list[BaselineControl]:
    """Load the official FedRAMP baseline reference."""
    path = path or DEFAULT_BASELINE
    data = yaml.safe_load(path.read_text())

    controls = []
    for family_id, family_data in data.get("families", {}).items():
        family_title = family_data.get("title", family_id)
        for ctrl in family_data.get("controls", []):
            controls.append(
                BaselineControl(
                    id=ctrl["id"],
                    title=ctrl.get("title", ""),
                    family=family_id,
                    applicability=ctrl.get("applicability", "procedural"),
                    notes=ctrl.get("notes", ""),
                )
            )

    return controls


def load_mapping_data(path: Path | None = None) -> dict:
    """Load raw mapping YAML data."""
    path = path or DEFAULT_MAPPING
    return yaml.safe_load(path.read_text())


def get_available_rules(rules_dir: Path | None = None) -> set[str]:
    """Get set of all available rule IDs from the rules directory."""
    rules_dir = rules_dir or RULES_DIR
    rules = set()
    for yml_file in rules_dir.rglob("*.yml"):
        if yml_file.name == "defaults.yml":
            continue
        rules.add(yml_file.stem)
    for yaml_file in rules_dir.rglob("*.yaml"):
        rules.add(yaml_file.stem)
    return rules


# ── Gap analysis ─────────────────────────────────────────────────────────────


def gap_analysis(
    baseline: list[BaselineControl],
    mapping_data: dict,
    available_rules: set[str],
    *,
    family_filter: str | None = None,
) -> GapAnalysisResult:
    """Compare baseline against current mapping."""
    # Build lookup for baseline controls
    baseline_by_id = {ctrl.id: ctrl for ctrl in baseline}

    # Apply family filter if specified
    if family_filter:
        family_filter = family_filter.upper()
        baseline = [c for c in baseline if c.family == family_filter]
        baseline_by_id = {c.id: c for c in baseline}

    # Get implemented controls from mapping
    implemented_ids = set()
    controls_data = mapping_data.get("controls", {})
    if controls_data:
        for control_id in controls_data:
            implemented_ids.add(str(control_id))

    # Get unimplemented controls from mapping
    unimplemented_ids = set()
    unimplemented_data = mapping_data.get("unimplemented", {})
    if unimplemented_data:
        for control_id in unimplemented_data:
            unimplemented_ids.add(str(control_id))

    # Find all rules referenced in the mapping
    referenced_rules = set()
    if controls_data:
        for entry in controls_data.values():
            if isinstance(entry, dict):
                for rule_id in entry.get("rules", []):
                    referenced_rules.add(rule_id)

    # Find missing rules (referenced but don't exist)
    missing_rules = sorted(referenced_rules - available_rules)

    # Find unaccounted controls (in baseline but not in mapping)
    all_accounted = implemented_ids | unimplemented_ids
    unaccounted_controls = []
    for ctrl in baseline:
        if ctrl.id not in all_accounted:
            unaccounted_controls.append(ctrl)

    # Find technical gaps (technical controls not implemented)
    technical_gaps = []
    for ctrl in baseline:
        if ctrl.applicability == "technical" and ctrl.id not in implemented_ids:
            technical_gaps.append(ctrl)

    # Coverage by family
    families: dict[str, FamilyCoverage] = {}
    for ctrl in baseline:
        if ctrl.family not in families:
            families[ctrl.family] = FamilyCoverage(
                family_id=ctrl.family,
                family_title="",
                total=0,
                implemented=0,
                unimplemented=0,
                unaccounted=0,
            )
        fc = families[ctrl.family]
        fc.total += 1
        if ctrl.id in implemented_ids:
            fc.implemented += 1
        elif ctrl.id in unimplemented_ids:
            fc.unimplemented += 1
        else:
            fc.unaccounted += 1

    # Set family titles from baseline
    for ctrl in baseline:
        if ctrl.family in families:
            # Use first control's family as source for the title lookup
            families[ctrl.family].family_title = _family_title(ctrl.family, baseline)

    return GapAnalysisResult(
        total_baseline=len(baseline),
        total_mapped=len(implemented_ids & set(baseline_by_id.keys()))
        + len(unimplemented_ids & set(baseline_by_id.keys())),
        total_implemented=len(implemented_ids & set(baseline_by_id.keys())),
        total_unimplemented=len(unimplemented_ids & set(baseline_by_id.keys())),
        total_unaccounted=len(unaccounted_controls),
        unaccounted_controls=unaccounted_controls,
        missing_rules=missing_rules,
        technical_gaps=technical_gaps,
        coverage_by_family=families,
    )


def _family_title(family_id: str, baseline: list[BaselineControl]) -> str:
    """Look up a family title from the baseline YAML data."""
    titles = {
        "AC": "Access Control",
        "AT": "Awareness and Training",
        "AU": "Audit and Accountability",
        "CA": "Assessment, Authorization, and Monitoring",
        "CM": "Configuration Management",
        "CP": "Contingency Planning",
        "IA": "Identification and Authentication",
        "IR": "Incident Response",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PE": "Physical and Environmental Protection",
        "PL": "Planning",
        "PS": "Personnel Security",
        "RA": "Risk Assessment",
        "SA": "System and Services Acquisition",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SR": "Supply Chain Risk Management",
    }
    return titles.get(family_id, family_id)


# ── Formatters ───────────────────────────────────────────────────────────────


def format_gap_report(result: GapAnalysisResult, *, json_output: bool = False) -> str:
    """Format gap analysis as text or JSON."""
    if json_output:
        return _format_json(result)
    return _format_text(result)


def _format_json(result: GapAnalysisResult) -> str:
    """Format gap analysis as JSON."""
    data = {
        "summary": {
            "total_baseline": result.total_baseline,
            "total_mapped": result.total_mapped,
            "total_implemented": result.total_implemented,
            "total_unimplemented": result.total_unimplemented,
            "total_unaccounted": result.total_unaccounted,
            "coverage_percent": round(result.coverage_percent, 1),
            "accounted_percent": round(result.accounted_percent, 1),
            "is_complete": result.is_complete,
        },
        "missing_rules": result.missing_rules,
        "unaccounted_controls": [
            {
                "id": c.id,
                "title": c.title,
                "family": c.family,
                "applicability": c.applicability,
            }
            for c in result.unaccounted_controls
        ],
        "technical_gaps": [
            {
                "id": c.id,
                "title": c.title,
                "family": c.family,
                "notes": c.notes,
            }
            for c in result.technical_gaps
        ],
        "coverage_by_family": {
            fid: {
                "family_title": fc.family_title,
                "total": fc.total,
                "implemented": fc.implemented,
                "unimplemented": fc.unimplemented,
                "unaccounted": fc.unaccounted,
                "coverage_percent": round(fc.coverage_percent, 1),
                "accounted_percent": round(fc.accounted_percent, 1),
            }
            for fid, fc in sorted(result.coverage_by_family.items())
        },
    }
    return json.dumps(data, indent=2)


def _format_text(result: GapAnalysisResult) -> str:
    """Format gap analysis as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("FedRAMP Moderate Rev 5 — Gap Analysis Report")
    lines.append("=" * 70)
    lines.append("")

    # Summary
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Baseline controls:     {result.total_baseline}")
    lines.append(f"  Implemented (rules):   {result.total_implemented}")
    lines.append(f"  Unimplemented (noted): {result.total_unimplemented}")
    lines.append(f"  Unaccounted (gaps):    {result.total_unaccounted}")
    lines.append(f"  Coverage:              {result.coverage_percent:.1f}%")
    lines.append(f"  Accounted:             {result.accounted_percent:.1f}%")
    lines.append(f"  Complete:              {'YES' if result.is_complete else 'NO'}")
    lines.append("")

    # Coverage by family
    lines.append("COVERAGE BY FAMILY")
    lines.append("-" * 70)
    lines.append(
        f"  {'Family':<6} {'Title':<40} {'Impl':>5} {'Unimp':>6} {'Gap':>4} {'Total':>6}"
    )
    lines.append(f"  {'─' * 6} {'─' * 40} {'─' * 5} {'─' * 6} {'─' * 4} {'─' * 6}")
    for fid in sorted(result.coverage_by_family):
        fc = result.coverage_by_family[fid]
        title = fc.family_title[:40]
        lines.append(
            f"  {fid:<6} {title:<40} {fc.implemented:>5} {fc.unimplemented:>6} "
            f"{fc.unaccounted:>4} {fc.total:>6}"
        )
    lines.append("")

    # Missing rules
    if result.missing_rules:
        lines.append("MISSING RULES (referenced but don't exist)")
        lines.append("-" * 40)
        for rule_id in result.missing_rules:
            lines.append(f"  - {rule_id}")
        lines.append("")

    # Unaccounted controls
    if result.unaccounted_controls:
        lines.append("UNACCOUNTED CONTROLS (in baseline, not in mapping)")
        lines.append("-" * 70)
        for ctrl in result.unaccounted_controls:
            tag = f"[{ctrl.applicability}]"
            lines.append(f"  {ctrl.id:<12} {tag:<16} {ctrl.title}")
        lines.append("")

    # Technical gaps
    if result.technical_gaps:
        lines.append("TECHNICAL GAPS (technical controls without rules)")
        lines.append("-" * 70)
        for ctrl in result.technical_gaps:
            lines.append(f"  {ctrl.id:<12} {ctrl.title}")
            if ctrl.notes:
                lines.append(f"               Notes: {ctrl.notes}")
        lines.append("")

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FedRAMP baseline validation and gap analysis"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    parser.add_argument(
        "--family",
        type=str,
        default=None,
        help="Filter to a single family (e.g., AC, SC, SI)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Path to baseline reference YAML",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=None,
        help="Path to FedRAMP mapping YAML",
    )
    args = parser.parse_args()

    # Load data
    baseline = load_baseline(args.baseline)
    mapping_data = load_mapping_data(args.mapping)
    available_rules = get_available_rules()

    # Run analysis
    result = gap_analysis(
        baseline,
        mapping_data,
        available_rules,
        family_filter=args.family,
    )

    # Output
    report = format_gap_report(result, json_output=args.json)
    print(report)

    # Exit code: 0 if complete, 1 if gaps exist
    return 0 if result.is_complete and not result.missing_rules else 1


if __name__ == "__main__":
    sys.exit(main())
