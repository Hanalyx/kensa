#!/usr/bin/env python3
"""CIS benchmark validation and gap analysis (development tool).

Compares Aegis CIS mappings against their declared control_ids manifests
to identify gaps, validate completeness, and generate reports.  Works with
or without external baseline files — when no baseline is present it falls
back to extracting data directly from the mapping YAML.

Usage:
    python scripts/cis_validate.py                              # All CIS mappings
    python scripts/cis_validate.py --mapping cis-rhel9-v2.0.0   # Specific benchmark
    python scripts/cis_validate.py --json                        # Machine-readable
    python scripts/cis_validate.py --chapter 5                   # Single chapter
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

# Default directories
MAPPINGS_DIR = PROJECT_ROOT / "mappings" / "cis"
BASELINES_DIR = PROJECT_ROOT / "context" / "cis"
RULES_DIR = PROJECT_ROOT / "rules"

# CIS chapter titles
CHAPTER_TITLES: dict[int, str] = {
    1: "Initial Setup",
    2: "Services",
    3: "Network Configuration",
    4: "Host Based Firewall",
    5: "Access Control",
    6: "Logging and Auditing",
    7: "System Maintenance",
}


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class CISControl:
    """A single CIS benchmark control (section)."""

    id: str
    title: str
    level: str  # "L1" or "L2"
    type: str  # "Automated" or "Manual"
    chapter: int
    rule_id: str | None = None


@dataclass
class ChapterCoverage:
    """Coverage statistics for a single CIS chapter."""

    chapter_id: int
    chapter_title: str
    total: int = 0
    implemented: int = 0
    unimplemented: int = 0
    unaccounted: int = 0
    missing_rules: list[str] = field(default_factory=list)
    l1_count: int = 0
    l2_count: int = 0
    auto_count: int = 0
    manual_count: int = 0

    @property
    def coverage_percent(self) -> float:
        """Percentage of controls with implemented rules."""
        if self.total == 0:
            return 0.0
        return (self.implemented / self.total) * 100

    @property
    def accounted_percent(self) -> float:
        """Percentage of controls accounted for (implemented + unimplemented)."""
        if self.total == 0:
            return 0.0
        return ((self.implemented + self.unimplemented) / self.total) * 100


@dataclass
class CISGapAnalysisResult:
    """Result of validating a CIS mapping against its control manifest."""

    mapping_id: str
    mapping_title: str
    total_controls: int
    total_implemented: int
    total_unimplemented: int
    total_unaccounted: int
    total_missing_rules: int
    missing_rules: list[str]
    dangling_rules: list[str]
    unaccounted_controls: list[CISControl]
    coverage_by_chapter: dict[int, ChapterCoverage]
    l1_total: int = 0
    l1_implemented: int = 0
    l2_total: int = 0
    l2_implemented: int = 0
    auto_total: int = 0
    auto_implemented: int = 0
    manual_total: int = 0
    manual_implemented: int = 0

    @property
    def is_complete(self) -> bool:
        """True when every declared control_id is accounted for."""
        return self.total_unaccounted == 0

    @property
    def coverage_percent(self) -> float:
        """Percentage of controls with implemented rules."""
        if self.total_controls == 0:
            return 0.0
        return (self.total_implemented / self.total_controls) * 100

    @property
    def accounted_percent(self) -> float:
        """Percentage of controls accounted for (implemented + unimplemented)."""
        if self.total_controls == 0:
            return 0.0
        return (
            (self.total_implemented + self.total_unimplemented)
            / self.total_controls
            * 100
        )


# ── Helpers ──────────────────────────────────────────────────────────────────


def _chapter_from_id(section_id: str) -> int:
    """Extract the top-level chapter number from a dotted section ID."""
    try:
        return int(section_id.split(".")[0])
    except (ValueError, IndexError):
        return 0


def _sortable_id(section_id: str) -> list[int]:
    """Convert dotted section ID to list of ints for natural sorting."""
    parts = []
    for part in section_id.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return parts


# ── Loaders ──────────────────────────────────────────────────────────────────


def discover_mappings() -> list[Path]:
    """Auto-discover all CIS mapping YAML files."""
    if not MAPPINGS_DIR.is_dir():
        return []
    return sorted(MAPPINGS_DIR.glob("*.yaml")) + sorted(MAPPINGS_DIR.glob("*.yml"))


def resolve_mapping_path(mapping_id: str) -> Path | None:
    """Resolve a mapping ID like 'cis-rhel9-v2.0.0' to a file path.

    Checks the 'id' field inside each mapping YAML, then falls back to
    filename-based matching.
    """
    for path in discover_mappings():
        data = yaml.safe_load(path.read_text())
        if data.get("id") == mapping_id:
            return path
    # Fall back to filename-based matching
    stem = mapping_id.replace("cis-", "")
    for suffix in [".yaml", ".yml"]:
        for candidate_stem in [
            stem,
            stem.replace("-", "_"),
            stem.replace(".", "_"),
            stem.replace("-", "_").replace(".", "_"),
        ]:
            candidate = MAPPINGS_DIR / f"{candidate_stem}{suffix}"
            if candidate.exists():
                return candidate
    return None


def load_mapping_data(path: Path) -> dict:
    """Load raw CIS mapping YAML data."""
    return yaml.safe_load(path.read_text())


def load_baseline(mapping_id: str) -> dict | None:
    """Try to load a CIS baseline file from context/cis/.

    Baseline filenames follow the pattern: rhel9-v2.0.0-baseline.yaml
    Returns None if no baseline file exists.
    """
    if not BASELINES_DIR.is_dir():
        return None
    # Derive baseline filename from mapping ID
    # cis-rhel9-v2.0.0 -> rhel9-v2.0.0-baseline.yaml
    stem = mapping_id.replace("cis-", "")
    baseline_path = BASELINES_DIR / f"{stem}-baseline.yaml"
    if baseline_path.exists():
        return yaml.safe_load(baseline_path.read_text())
    return None


def get_available_rules(rules_dir: Path | None = None) -> set[str]:
    """Get set of all available rule IDs from the rules directory."""
    rules_dir = rules_dir or RULES_DIR
    rules: set[str] = set()
    for yml_file in rules_dir.rglob("*.yml"):
        if yml_file.name == "defaults.yml":
            continue
        rules.add(yml_file.stem)
    for yaml_file in rules_dir.rglob("*.yaml"):
        rules.add(yaml_file.stem)
    return rules


def build_controls_from_mapping(mapping_data: dict) -> list[CISControl]:
    """Build a list of CISControl objects from mapping data.

    Merges data from sections, unimplemented, and control_ids to produce
    a complete view.  When a baseline file is unavailable this is the
    primary source of truth.
    """
    controls: dict[str, CISControl] = {}

    # Implemented controls (have rules)
    for section_id, entry in mapping_data.get("controls", {}).items():
        sid = str(section_id)
        rules = entry.get("rules", [])
        controls[sid] = CISControl(
            id=sid,
            title=entry.get("title", ""),
            level=entry.get("level", "L1"),
            type=entry.get("type", "Automated"),
            chapter=_chapter_from_id(sid),
            rule_id=rules[0] if rules else None,
        )

    # Unimplemented sections (no rule)
    for section_id, entry in mapping_data.get("unimplemented", {}).items():
        sid = str(section_id)
        controls[sid] = CISControl(
            id=sid,
            title=entry.get("title", ""),
            level=entry.get("level", "L1"),
            type=entry.get("type", "Manual"),
            chapter=_chapter_from_id(sid),
            rule_id=None,
        )

    # Any control_ids not yet in sections or unimplemented are unaccounted
    for cid in mapping_data.get("control_ids", []):
        sid = str(cid)
        if sid not in controls:
            controls[sid] = CISControl(
                id=sid,
                title="(unknown — not in sections or unimplemented)",
                level="L1",
                type="Automated",
                chapter=_chapter_from_id(sid),
                rule_id=None,
            )

    return sorted(controls.values(), key=lambda c: _sortable_id(c.id))


# ── Gap analysis ─────────────────────────────────────────────────────────────


def gap_analysis(
    mapping_data: dict,
    available_rules: set[str],
    *,
    chapter_filter: int | None = None,
) -> CISGapAnalysisResult:
    """Run CIS gap analysis for a single mapping."""
    mapping_id = mapping_data.get("id", "unknown")
    mapping_title = mapping_data.get("title", mapping_id)

    controls = build_controls_from_mapping(mapping_data)

    # Apply chapter filter
    if chapter_filter is not None:
        controls = [c for c in controls if c.chapter == chapter_filter]

    # Determine implemented vs unimplemented vs unaccounted
    controls_map = mapping_data.get("controls", {})
    unimplemented = mapping_data.get("unimplemented", {})
    implemented_ids = {str(k) for k in controls_map}
    unimplemented_ids = {str(k) for k in unimplemented}

    # Collect referenced rule IDs from controls
    referenced_rules: set[str] = set()
    for entry in controls_map.values():
        for rule_id in entry.get("rules", []):
            if rule_id:
                referenced_rules.add(rule_id)

    # Missing rules: referenced in mapping but don't exist in rules/
    missing_rules = sorted(referenced_rules - available_rules)

    # Dangling rules: same as missing (rule referenced but file doesn't exist)
    dangling_rules = sorted(referenced_rules - available_rules)

    # Build chapter coverage
    chapters: dict[int, ChapterCoverage] = {}
    unaccounted_controls: list[CISControl] = []

    # Aggregate counters
    l1_total = l1_impl = l2_total = l2_impl = 0
    auto_total = auto_impl = manual_total = manual_impl = 0

    for ctrl in controls:
        ch = ctrl.chapter
        if ch not in chapters:
            chapters[ch] = ChapterCoverage(
                chapter_id=ch,
                chapter_title=CHAPTER_TITLES.get(ch, f"Chapter {ch}"),
            )
        cc = chapters[ch]
        cc.total += 1

        is_impl = ctrl.id in implemented_ids
        is_unimp = ctrl.id in unimplemented_ids

        if is_impl:
            cc.implemented += 1
        elif is_unimp:
            cc.unimplemented += 1
        else:
            cc.unaccounted += 1
            unaccounted_controls.append(ctrl)

        # Level breakdown
        if ctrl.level == "L1":
            cc.l1_count += 1
            l1_total += 1
            if is_impl:
                l1_impl += 1
        elif ctrl.level == "L2":
            cc.l2_count += 1
            l2_total += 1
            if is_impl:
                l2_impl += 1

        # Type breakdown
        if ctrl.type == "Automated":
            cc.auto_count += 1
            auto_total += 1
            if is_impl:
                auto_impl += 1
        elif ctrl.type == "Manual":
            cc.manual_count += 1
            manual_total += 1
            if is_impl:
                manual_impl += 1

        # Track missing rules per chapter
        if is_impl:
            rule_id = ctrl.rule_id
            if not rule_id:
                section_entry = controls_map.get(ctrl.id)
                if section_entry:
                    rules = section_entry.get("rules", [])
                    rule_id = rules[0] if rules else None
            if rule_id and rule_id not in available_rules:
                cc.missing_rules.append(rule_id)

    total_impl = sum(c.implemented for c in chapters.values())
    total_unimp = sum(c.unimplemented for c in chapters.values())
    total_unacc = sum(c.unaccounted for c in chapters.values())

    return CISGapAnalysisResult(
        mapping_id=mapping_id,
        mapping_title=mapping_title,
        total_controls=len(controls),
        total_implemented=total_impl,
        total_unimplemented=total_unimp,
        total_unaccounted=total_unacc,
        total_missing_rules=len(missing_rules),
        missing_rules=missing_rules,
        dangling_rules=dangling_rules,
        unaccounted_controls=unaccounted_controls,
        coverage_by_chapter=chapters,
        l1_total=l1_total,
        l1_implemented=l1_impl,
        l2_total=l2_total,
        l2_implemented=l2_impl,
        auto_total=auto_total,
        auto_implemented=auto_impl,
        manual_total=manual_total,
        manual_implemented=manual_impl,
    )


# ── Formatters ───────────────────────────────────────────────────────────────


def format_gap_report(
    results: list[CISGapAnalysisResult], *, json_output: bool = False
) -> str:
    """Format one or more gap analysis results as text or JSON."""
    if json_output:
        return _format_json(results)
    return _format_text(results)


def _format_json(results: list[CISGapAnalysisResult]) -> str:
    """Format gap analysis results as JSON."""
    output = []
    for result in results:
        data = {
            "mapping_id": result.mapping_id,
            "mapping_title": result.mapping_title,
            "summary": {
                "total_controls": result.total_controls,
                "total_implemented": result.total_implemented,
                "total_unimplemented": result.total_unimplemented,
                "total_unaccounted": result.total_unaccounted,
                "total_missing_rules": result.total_missing_rules,
                "coverage_percent": round(result.coverage_percent, 1),
                "accounted_percent": round(result.accounted_percent, 1),
                "is_complete": result.is_complete,
            },
            "level_breakdown": {
                "L1": {
                    "total": result.l1_total,
                    "implemented": result.l1_implemented,
                },
                "L2": {
                    "total": result.l2_total,
                    "implemented": result.l2_implemented,
                },
            },
            "type_breakdown": {
                "Automated": {
                    "total": result.auto_total,
                    "implemented": result.auto_implemented,
                },
                "Manual": {
                    "total": result.manual_total,
                    "implemented": result.manual_implemented,
                },
            },
            "missing_rules": result.missing_rules,
            "dangling_rules": result.dangling_rules,
            "unaccounted_controls": [
                {
                    "id": c.id,
                    "title": c.title,
                    "level": c.level,
                    "type": c.type,
                    "chapter": c.chapter,
                }
                for c in result.unaccounted_controls
            ],
            "coverage_by_chapter": {
                str(ch_id): {
                    "chapter_title": cc.chapter_title,
                    "total": cc.total,
                    "implemented": cc.implemented,
                    "unimplemented": cc.unimplemented,
                    "unaccounted": cc.unaccounted,
                    "l1_count": cc.l1_count,
                    "l2_count": cc.l2_count,
                    "auto_count": cc.auto_count,
                    "manual_count": cc.manual_count,
                    "coverage_percent": round(cc.coverage_percent, 1),
                    "accounted_percent": round(cc.accounted_percent, 1),
                    "missing_rules": cc.missing_rules,
                }
                for ch_id, cc in sorted(result.coverage_by_chapter.items())
            },
        }
        output.append(data)

    if len(output) == 1:
        return json.dumps(output[0], indent=2)
    return json.dumps(output, indent=2)


def _format_text(results: list[CISGapAnalysisResult]) -> str:
    """Format gap analysis results as human-readable text."""
    lines: list[str] = []

    for result in results:
        lines.append("=" * 70)
        lines.append(f"CIS Gap Analysis — {result.mapping_title}")
        lines.append("=" * 70)
        lines.append("")

        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Total controls:        {result.total_controls}")
        lines.append(f"  Implemented (rules):   {result.total_implemented}")
        lines.append(f"  Unimplemented (noted): {result.total_unimplemented}")
        lines.append(f"  Unaccounted (gaps):    {result.total_unaccounted}")
        lines.append(f"  Coverage:              {result.coverage_percent:.1f}%")
        lines.append(f"  Accounted:             {result.accounted_percent:.1f}%")
        lines.append(
            f"  Complete:              {'YES' if result.is_complete else 'NO'}"
        )
        lines.append("")

        # Level breakdown
        lines.append("LEVEL BREAKDOWN")
        lines.append("-" * 40)
        l1_pct = (
            (result.l1_implemented / result.l1_total * 100)
            if result.l1_total
            else 0.0
        )
        l2_pct = (
            (result.l2_implemented / result.l2_total * 100)
            if result.l2_total
            else 0.0
        )
        lines.append(
            f"  L1:  {result.l1_implemented:>4} / {result.l1_total:<4}"
            f"  ({l1_pct:.1f}%)"
        )
        lines.append(
            f"  L2:  {result.l2_implemented:>4} / {result.l2_total:<4}"
            f"  ({l2_pct:.1f}%)"
        )
        lines.append("")

        # Type breakdown
        lines.append("TYPE BREAKDOWN")
        lines.append("-" * 40)
        auto_pct = (
            (result.auto_implemented / result.auto_total * 100)
            if result.auto_total
            else 0.0
        )
        manual_pct = (
            (result.manual_implemented / result.manual_total * 100)
            if result.manual_total
            else 0.0
        )
        lines.append(
            f"  Automated:  {result.auto_implemented:>4} / {result.auto_total:<4}"
            f"  ({auto_pct:.1f}%)"
        )
        lines.append(
            f"  Manual:     {result.manual_implemented:>4} / {result.manual_total:<4}"
            f"  ({manual_pct:.1f}%)"
        )
        lines.append("")

        # Coverage by chapter
        lines.append("COVERAGE BY CHAPTER")
        lines.append("-" * 70)
        lines.append(
            f"  {'Ch':>2}  {'Title':<28} {'Impl':>5} {'Unimp':>6} {'Gap':>4}"
            f" {'Total':>6}  {'L1':>3} {'L2':>3}  {'Auto':>4} {'Man':>4}"
        )
        lines.append(
            f"  {'──':>2}  {'─' * 28} {'─' * 5} {'─' * 6} {'─' * 4}"
            f" {'─' * 6}  {'─' * 3} {'─' * 3}  {'─' * 4} {'─' * 4}"
        )
        for ch_id in sorted(result.coverage_by_chapter):
            cc = result.coverage_by_chapter[ch_id]
            title = cc.chapter_title[:28]
            lines.append(
                f"  {ch_id:>2}  {title:<28} {cc.implemented:>5}"
                f" {cc.unimplemented:>6} {cc.unaccounted:>4} {cc.total:>6}"
                f"  {cc.l1_count:>3} {cc.l2_count:>3}"
                f"  {cc.auto_count:>4} {cc.manual_count:>4}"
            )
        lines.append("")

        # Missing rules
        if result.missing_rules:
            lines.append(
                "MISSING RULES (referenced in mapping but not in rules/)"
            )
            lines.append("-" * 40)
            for rule_id in result.missing_rules:
                lines.append(f"  - {rule_id}")
            lines.append("")

        # Unaccounted controls
        if result.unaccounted_controls:
            lines.append(
                "UNACCOUNTED CONTROLS (in control_ids but not in mapping)"
            )
            lines.append("-" * 70)
            for ctrl in result.unaccounted_controls:
                tag = f"[{ctrl.level}/{ctrl.type}]"
                lines.append(f"  {ctrl.id:<14} {tag:<18} {ctrl.title}")
            lines.append("")

        lines.append("")

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> int:
    """Entry point for CIS gap analysis."""
    parser = argparse.ArgumentParser(
        description="CIS benchmark validation and gap analysis"
    )
    parser.add_argument(
        "--mapping",
        type=str,
        default=None,
        help="Mapping ID (e.g. cis-rhel9-v2.0.0) or path to mapping YAML",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    parser.add_argument(
        "--chapter",
        type=int,
        default=None,
        help="Filter to a single chapter (1-7)",
    )
    args = parser.parse_args()

    available_rules = get_available_rules()

    # Resolve mapping paths
    mapping_paths: list[Path] = []
    if args.mapping:
        # Could be a file path or a mapping ID
        candidate = Path(args.mapping)
        if candidate.exists():
            mapping_paths.append(candidate)
        else:
            resolved = resolve_mapping_path(args.mapping)
            if resolved:
                mapping_paths.append(resolved)
            else:
                print(
                    f"Error: Could not find mapping '{args.mapping}'",
                    file=sys.stderr,
                )
                print(
                    f"  Searched: {MAPPINGS_DIR}",
                    file=sys.stderr,
                )
                available = discover_mappings()
                if available:
                    print("  Available mappings:", file=sys.stderr)
                    for p in available:
                        data = yaml.safe_load(p.read_text())
                        mid = data.get("id", p.stem)
                        print(f"    - {mid}", file=sys.stderr)
                return 2
    else:
        # Auto-discover all CIS mappings
        mapping_paths = discover_mappings()
        if not mapping_paths:
            print(
                f"Error: No CIS mappings found in {MAPPINGS_DIR}",
                file=sys.stderr,
            )
            return 2

    # Run analysis for each mapping
    results: list[CISGapAnalysisResult] = []
    for path in mapping_paths:
        mapping_data = load_mapping_data(path)
        result = gap_analysis(
            mapping_data,
            available_rules,
            chapter_filter=args.chapter,
        )
        results.append(result)

    # Output
    report = format_gap_report(results, json_output=args.json)
    print(report)

    # Exit code: 0 if all mappings complete with no missing rules, 1 otherwise
    all_complete = all(r.is_complete and not r.missing_rules for r in results)
    return 0 if all_complete else 1


if __name__ == "__main__":
    sys.exit(main())
