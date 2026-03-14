#!/usr/bin/env python3
"""Rebuild the CIS RHEL 9 v2.0.0 SOT baseline from the benchmark PDF."""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import date
from pathlib import Path
from subprocess import run

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PDF_PATH = PROJECT_ROOT / "SOT" / "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf"
BASELINE_PATH = PROJECT_ROOT / "context" / "cis" / "rhel9-v2.0.0-baseline.yaml"
TMP_DIR = Path("/tmp/cis_rhel9_extract")
BODY_TXT = TMP_DIR / "body.txt"

BODY_PAGE_START = 17
BODY_PAGE_END = 989


class _Dumper(yaml.SafeDumper):
    """Custom dumper for stable, readable SOT output."""


def _repr_none(dumper: yaml.SafeDumper, _data: None) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")


def _repr_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    if data and (data[0].isdigit() or data in {"null", "true", "false"}):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def _repr_ordered_dict(dumper: yaml.SafeDumper, data: OrderedDict) -> yaml.MappingNode:
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())


_Dumper.add_representer(type(None), _repr_none)
_Dumper.add_representer(str, _repr_str)
_Dumper.add_representer(OrderedDict, _repr_ordered_dict)


def _run_pdftotext(start: int, end: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "pdftotext",
            "-f",
            str(start),
            "-l",
            str(end),
            "-layout",
            str(PDF_PATH),
            str(output),
        ],
        check=True,
    )


def _clean_page(page: str) -> str:
    lines = page.splitlines()
    cleaned: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            cleaned.append("")
            continue
        if re.fullmatch(r"Page \d+", stripped):
            continue
        cleaned.append(line.rstrip())
    return "\n".join(cleaned).strip("\n")


def _clean_pdf_text(raw: str) -> str:
    return "\n\f\n".join(
        page for page in (_clean_page(page) for page in raw.split("\f")) if page.strip()
    )


def _strip_common_indent(text: str) -> str:
    lines = text.splitlines()
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return ""
    trim = min(len(line) - len(line.lstrip(" ")) for line in non_empty)
    return "\n".join(line[trim:] if len(line) >= trim else "" for line in lines)


def _normalize_block(text: str) -> str:
    lines = _strip_common_indent(text.replace("\f", "\n")).splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(line.rstrip() for line in lines).strip()


def _section_map(segment: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in segment.splitlines():
        line = raw_line.rstrip()
        marker = re.match(
            r"^\s*(Profile Applicability|Description|Rationale|Impact|Audit|Notes|"
            r"Remediation|Default Value|References|Additional Information|"
            r"CIS Controls|MITRE ATT&CK Mappings):\s*(.*)$",
            line,
        )
        if marker:
            current = marker.group(1)
            sections.setdefault(current, [])
            rest = marker.group(2)
            if rest:
                sections[current].append(rest)
            continue
        if current:
            sections[current].append(line)
    return {key: _normalize_block("\n".join(value)) for key, value in sections.items()}


def _parse_profiles(text: str) -> list[str]:
    profiles: list[str] = []
    for line in text.splitlines():
        match = re.search(r"(Level [12] - (?:Server|Workstation))", line)
        if match:
            profiles.append(match.group(1))
    return profiles


def _parse_references(text: str) -> list[str]:
    refs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = re.match(r"^\d+\.\s+(.*)$", stripped)
        if match:
            if current:
                refs.append(" ".join(current).strip())
            current = [match.group(1).strip()]
        elif current:
            current.append(stripped)
    if current:
        refs.append(" ".join(current).strip())
    return refs


def _parse_cis_controls(text: str) -> OrderedDict:
    mappings: OrderedDict[str, str] = OrderedDict()
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and (
            stripped in {"Controls", "Control", "Version"} or "IG 1" in line
        ):
            continue
        lines.append(line.rstrip())

    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        blocks.append(current)

    for block in blocks:
        version: str | None = None
        title_lines: list[str] = []
        collecting_title = False
        control_number: str | None = None
        for raw_line in block:
            stripped = raw_line.strip()
            if not version:
                version_match = re.match(r"^(v[78])\b", stripped)
                if version_match:
                    version = version_match.group(1)
            control_match = re.match(r"^(\d+\.\d+)\s+(.*)$", stripped)
            if control_match and control_number is None:
                control_number = control_match.group(1)
                title_lines.append(control_match.group(2).strip())
                collecting_title = True
                continue
            if collecting_title:
                if re.match(r"^v[78]\b", stripped):
                    collecting_title = False
                    continue
                title_lines.append(stripped)
        if version and control_number and title_lines:
            value = f"{control_number} {' '.join(title_lines).strip()}"
            if version in mappings:
                mappings[version] = f"{mappings[version]}; {value}"
            else:
                mappings[version] = value
    return mappings


def _control_segments(body_text: str, ids: list[str]) -> dict[str, str]:
    starts: list[tuple[int, str]] = []
    for control_id in ids:
        match = re.search(rf"(?m)^\s*{re.escape(control_id)}\b", body_text)
        if not match:
            raise ValueError(f"Unable to locate control header for {control_id}")
        starts.append((match.start(), control_id))
    starts.sort()

    segments: dict[str, str] = {}
    for idx, (start, control_id) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(body_text)
        segments[control_id] = body_text[start:end]
    return segments


def _load_manifest() -> tuple[OrderedDict[str, str], list[dict]]:
    baseline = yaml.safe_load(BASELINE_PATH.read_text())
    chapter_titles = OrderedDict(
        (chapter_id, chapter["title"])
        for chapter_id, chapter in baseline["chapters"].items()
    )
    controls: list[dict] = []
    for chapter in baseline["chapters"].values():
        controls.extend(chapter["controls"])
    return chapter_titles, controls


def _build_control(manifest: dict, segment: str) -> OrderedDict:
    sections = _section_map(segment)
    profiles = _parse_profiles(sections.get("Profile Applicability", ""))
    entry: OrderedDict = OrderedDict()
    entry["id"] = manifest["id"]
    entry["title"] = manifest["title"]
    entry["level"] = (
        manifest["level"]
        if "level" in manifest
        else ("L1" if any(p.startswith("Level 1") for p in profiles) else "L2")
    )
    entry["type"] = manifest["type"]
    entry["profiles"] = profiles
    entry["description"] = sections.get("Description", "")
    entry["rationale"] = sections.get("Rationale", "")
    entry["audit"] = sections.get("Audit", "")
    entry["remediation"] = sections.get("Remediation", "")
    if sections.get("Default Value", ""):
        entry["default_value"] = sections["Default Value"]
    references = _parse_references(sections.get("References", ""))
    if references:
        entry["references"] = references
    cis_controls = _parse_cis_controls(sections.get("CIS Controls", ""))
    if cis_controls:
        entry["cis_controls"] = cis_controls
    return entry


def _build_baseline(
    chapter_titles: OrderedDict[str, str], controls: list[OrderedDict]
) -> OrderedDict:
    chapters: OrderedDict[str, OrderedDict] = OrderedDict(
        (chapter_id, OrderedDict([("title", title), ("controls", [])]))
        for chapter_id, title in chapter_titles.items()
    )
    for control in controls:
        chapter_id = control["id"].split(".")[0]
        chapters[chapter_id]["controls"].append(control)
    return OrderedDict(
        [
            ("id", "cis-rhel9"),
            ("version", "2.0.0"),
            ("platform", "Red Hat Enterprise Linux 9"),
            ("total_controls", len(controls)),
            ("source", "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0"),
            ("last_synced", date.today().isoformat()),
            ("chapters", chapters),
        ]
    )


def _write_yaml(baseline: OrderedDict) -> None:
    header = "\n".join(
        [
            "# CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 — Full Baseline Extract",
            "# Source: CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 (PDF)",
            f"# Extracted: {date.today().isoformat()}",
            "# Contains full audit procedures, remediation procedures, descriptions,",
            "# rationale, CIS Controls mappings, and references for every control.",
            "#",
            "# This file replaces the previous lightweight baseline that only had",
            "# id/title/level/type. It serves as the authoritative SOT for CIS reviews.",
            "",
        ]
    )
    yaml_body = yaml.dump(
        baseline,
        Dumper=_Dumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=1000,
    )
    BASELINE_PATH.write_text(header + yaml_body)


def main() -> int:
    _run_pdftotext(BODY_PAGE_START, BODY_PAGE_END, BODY_TXT)
    body_text = _clean_pdf_text(BODY_TXT.read_text())
    chapter_titles, manifest_controls = _load_manifest()
    segments = _control_segments(
        body_text, [control["id"] for control in manifest_controls]
    )
    controls = [
        _build_control(control, segments[control["id"]])
        for control in manifest_controls
    ]
    baseline = _build_baseline(chapter_titles, controls)
    _write_yaml(baseline)
    print(f"Extracted {len(controls)} controls to {BASELINE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
