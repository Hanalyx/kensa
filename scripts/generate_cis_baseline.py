#!/usr/bin/env python3
"""Generate CIS baseline reference YAML files from mapping data.

Reads CIS mapping files and produces authoritative baseline YAML files
in context/cis/ that mirror the structure of the FedRAMP baseline.

Usage:
    python scripts/generate_cis_baseline.py
"""

from __future__ import annotations

import sys
from collections import OrderedDict
from datetime import date
from pathlib import Path

import yaml


# ── Chapter title definitions ──────────────────────────────────────────────

CHAPTER_TITLES = {
    "1": "Initial Setup",
    "2": "Services",
    "3": "Network Configuration",
    "4": "Host Based Firewall",
    "5": "Access Control",
    "6": "Logging and Auditing",
    "7": "System Maintenance",
}


# ── YAML representer helpers ───────────────────────────────────────────────


class _BaselineDumper(yaml.SafeDumper):
    """Custom dumper that handles ordered output and None values."""


def _represent_none(dumper: yaml.SafeDumper, _data: None) -> yaml.ScalarNode:
    """Represent None as the literal string null."""
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    """Use quoted style for strings that look like numbers."""
    if data and (data[0].isdigit() or data in ("null", "true", "false")):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def _represent_ordered_dict(
    dumper: yaml.SafeDumper, data: OrderedDict
) -> yaml.MappingNode:
    """Preserve insertion order for OrderedDict."""
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())


_BaselineDumper.add_representer(type(None), _represent_none)
_BaselineDumper.add_representer(str, _represent_str)
_BaselineDumper.add_representer(OrderedDict, _represent_ordered_dict)


# ── Core logic ─────────────────────────────────────────────────────────────


def _top_chapter(section_id: str) -> str:
    """Extract the top-level chapter number from a section ID."""
    return section_id.split(".")[0]


def _build_control_entry(
    section_id: str,
    title: str,
    level: str | None,
    control_type: str | None,
    rule_id: str | None,
    reason: str | None = None,
) -> OrderedDict:
    """Build a single control entry dict."""
    entry: OrderedDict = OrderedDict()
    entry["id"] = section_id
    entry["title"] = title
    if level:
        entry["level"] = level
    if control_type:
        entry["type"] = control_type
    entry["rule_id"] = rule_id
    if reason:
        entry["reason"] = reason
    return entry


def generate_baseline(mapping_path: Path, output_path: Path) -> int:
    """Generate a CIS baseline YAML from a mapping file.

    Returns the total control count.
    """
    with open(mapping_path) as f:
        mapping = yaml.safe_load(f)

    framework_id: str = mapping["id"]
    title: str = mapping["title"]
    control_ids: list[str] = [str(cid) for cid in mapping["control_ids"]]
    sections: dict = mapping.get("sections", {})
    unimplemented: dict = mapping.get("unimplemented", {})

    total_controls = len(control_ids)

    # Build chapters structure: collect controls per chapter
    chapters: OrderedDict[str, list[OrderedDict]] = OrderedDict()

    for cid in control_ids:
        chapter = _top_chapter(str(cid))
        if chapter not in chapters:
            chapters[chapter] = []

        cid_str = str(cid)

        if cid_str in sections:
            sec = sections[cid_str]
            entry = _build_control_entry(
                section_id=cid_str,
                title=sec.get("title", ""),
                level=sec.get("level"),
                control_type=sec.get("type"),
                rule_id=sec.get("rule"),
            )
        elif cid_str in unimplemented:
            unimp = unimplemented[cid_str]
            entry = _build_control_entry(
                section_id=cid_str,
                title=unimp.get("title", ""),
                level=unimp.get("level"),
                control_type=unimp.get("type"),
                rule_id=None,
                reason=unimp.get("reason"),
            )
        else:
            # Control ID listed but not in sections or unimplemented
            entry = _build_control_entry(
                section_id=cid_str,
                title="",
                level=None,
                control_type=None,
                rule_id=None,
                reason="missing from mapping",
            )

        chapters[chapter].append(entry)

    # Build final YAML structure
    today = date.today().isoformat()

    chapters_dict: OrderedDict = OrderedDict()
    for chapter_num, controls in chapters.items():
        chapter_title = CHAPTER_TITLES.get(chapter_num, f"Chapter {chapter_num}")
        chapters_dict[chapter_num] = OrderedDict(
            [("title", chapter_title), ("controls", controls)]
        )

    baseline = OrderedDict(
        [
            ("id", framework_id),
            ("total_controls", total_controls),
            ("source", title),
            ("chapters", chapters_dict),
        ]
    )

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build header comment
    source_name = title
    header_lines = [
        f"# {source_name} — Authoritative Control List",
        f"# Source: {source_name}",
        f"# Last synced: {today}",
        "",
    ]
    header = "\n".join(header_lines) + "\n"

    yaml_body = yaml.dump(
        baseline,
        Dumper=_BaselineDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    )

    with open(output_path, "w") as f:
        f.write(header)
        f.write(yaml_body)

    return total_controls


# ── CLI entry point ────────────────────────────────────────────────────────


def main() -> int:
    """Generate CIS baseline files from mapping data."""
    project_root = Path(__file__).resolve().parent.parent

    configs = [
        {
            "mapping": project_root / "mappings" / "cis" / "rhel9_v2.0.0.yaml",
            "output": project_root / "context" / "cis" / "rhel9-v2.0.0-baseline.yaml",
            "label": "CIS RHEL 9 v2.0.0",
        },
        {
            "mapping": project_root / "mappings" / "cis" / "rhel8_v4.0.0.yaml",
            "output": project_root / "context" / "cis" / "rhel8-v4.0.0-baseline.yaml",
            "label": "CIS RHEL 8 v4.0.0",
        },
    ]

    errors = 0
    for cfg in configs:
        mapping_path = cfg["mapping"]
        output_path = cfg["output"]
        label = cfg["label"]

        if not mapping_path.exists():
            print(f"ERROR: Mapping file not found: {mapping_path}")
            errors += 1
            continue

        try:
            count = generate_baseline(mapping_path, output_path)
            print(f"Generated {output_path.name}: {count} controls ({label})")
        except Exception as e:
            print(f"ERROR generating {label}: {e}")
            errors += 1

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
