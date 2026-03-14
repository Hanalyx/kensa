#!/usr/bin/env python3
"""Extract a full CIS RHEL 8 v4.0.0 SOT baseline from the benchmark PDF."""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from subprocess import run

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PDF_PATH = PROJECT_ROOT / "SOT" / "CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.pdf"
OUTPUT_PATH = PROJECT_ROOT / "context" / "cis" / "rhel8-v4.0.0-baseline.yaml"
TMP_DIR = Path("/tmp/cis_rhel8_extract")
BODY_TXT = TMP_DIR / "body.txt"
SUMMARY_TXT = TMP_DIR / "summary.txt"

BODY_PAGE_START = 21
BODY_PAGE_END = 1057
SUMMARY_PAGE_START = 1058
SUMMARY_PAGE_END = 1081

CHAPTER_TITLES = {
    "1": "Initial Setup",
    "2": "Services",
    "3": "Network Configuration",
    "4": "Host Based Firewall",
    "5": "Access Control",
    "6": "Logging and Auditing",
    "7": "System Maintenance",
}

SECTION_MARKERS = {
    "Profile Applicability",
    "Description",
    "Rationale",
    "Impact",
    "Audit",
    "Notes",
    "Remediation",
    "Default Value",
    "References",
    "Additional Information",
    "CIS Controls",
}


@dataclass
class SummaryControl:
    id: str
    title: str
    type: str


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


def _load_pdf_text(start: int, end: int, cache_path: Path) -> str:
    _run_pdftotext(start, end, cache_path)
    return cache_path.read_text()


def _clean_page(page: str) -> str:
    lines = page.splitlines()
    cleaned: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            cleaned.append("")
            continue
        if stripped == "Internal Only - General":
            continue
        if re.fullmatch(r"Page \d+", stripped):
            continue
        cleaned.append(line.rstrip())
    return "\n".join(cleaned).strip("\n")


def _clean_pdf_text(raw: str) -> str:
    pages = raw.split("\f")
    cleaned_pages = [_clean_page(page) for page in pages]
    return "\n\f\n".join(page for page in cleaned_pages if page.strip())


def _strip_common_indent(text: str) -> str:
    lines = text.splitlines()
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return ""
    indents = [len(line) - len(line.lstrip(" ")) for line in non_empty]
    trim = min(indents)
    return "\n".join(line[trim:] if len(line) >= trim else "" for line in lines)


def _normalize_block(text: str) -> str:
    text = text.replace("\f", "\n")
    text = text.replace("\u2022", "•")
    lines = _strip_common_indent(text).splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(line.rstrip() for line in lines).strip()


def _parse_summary(summary_text: str) -> list[SummaryControl]:
    lines = summary_text.splitlines()
    controls: list[SummaryControl] = []
    current_id: str | None = None
    title_parts: list[str] = []
    current_type: str | None = None

    def flush() -> None:
        nonlocal current_id, title_parts, current_type
        if current_id and current_type:
            title = " ".join(part.strip() for part in title_parts if part.strip())
            title = re.sub(r"\s+", " ", title).strip()
            controls.append(SummaryControl(current_id, title, current_type))
        current_id = None
        title_parts = []
        current_type = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Appendix: Summary Table"):
            continue
        if stripped.startswith("Appendix: CIS Controls"):
            break
        if stripped.startswith("CIS Benchmark Recommendation"):
            continue
        if stripped.startswith("Set Correctly"):
            continue
        if stripped in {"Recommendation", "Recommendations", "Correctly"}:
            continue
        if re.fullmatch(r"Yes\s+No", stripped):
            continue
        if stripped in {"Yes", "No"}:
            continue
        if "" in stripped:
            stripped = stripped.replace("", "").rstrip()
        match = re.match(r"^(\d+(?:\.\d+)+)\s+(.*)$", stripped)
        if match:
            flush()
            current_id = match.group(1)
            remainder = match.group(2).strip()
            type_match = re.search(r"\((Automated|Manual)\)$", remainder)
            if type_match:
                current_type = type_match.group(1)
                remainder = re.sub(r"\((Automated|Manual)\)$", "", remainder).strip()
            if remainder:
                title_parts.append(remainder)
            continue
        if current_id:
            type_match = re.search(r"\((Automated|Manual)\)$", stripped)
            if type_match:
                current_type = type_match.group(1)
                stripped = re.sub(r"\((Automated|Manual)\)$", "", stripped).strip()
                if stripped:
                    title_parts.append(stripped)
            else:
                title_parts.append(stripped)
    flush()
    return controls


def _section_map(segment: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in segment.splitlines():
        line = raw_line.rstrip()
        marker = re.match(
            r"^\s*(Profile Applicability|Description|Rationale|Impact|Audit|Notes|"
            r"Remediation|Default Value|References|Additional Information|CIS Controls):\s*(.*)$",
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
        match = re.search(
            r"(Level [12] - (?:Server|Workstation))",
            line,
        )
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


def _build_control(summary: SummaryControl, segment: str) -> OrderedDict:
    sections = _section_map(segment)
    profiles = _parse_profiles(sections.get("Profile Applicability", ""))
    level = "L1" if any(profile.startswith("Level 1") for profile in profiles) else "L2"

    entry: OrderedDict = OrderedDict()
    entry["id"] = summary.id
    entry["title"] = summary.title
    entry["level"] = level
    entry["type"] = summary.type
    entry["profiles"] = profiles
    entry["description"] = sections.get("Description", "")
    entry["rationale"] = sections.get("Rationale", "")
    entry["audit"] = sections.get("Audit", "")
    entry["remediation"] = sections.get("Remediation", "")
    default_value = sections.get("Default Value", "")
    if default_value:
        entry["default_value"] = default_value
    references = _parse_references(sections.get("References", ""))
    if references:
        entry["references"] = references
    cis_controls = _parse_cis_controls(sections.get("CIS Controls", ""))
    if cis_controls:
        entry["cis_controls"] = cis_controls
    return entry


def _build_baseline(controls: list[OrderedDict]) -> OrderedDict:
    chapters: OrderedDict[str, OrderedDict] = OrderedDict()
    for chapter_id, title in CHAPTER_TITLES.items():
        chapters[chapter_id] = OrderedDict([("title", title), ("controls", [])])

    for control in controls:
        chapter_id = control["id"].split(".")[0]
        chapters[chapter_id]["controls"].append(control)

    return OrderedDict(
        [
            ("id", "cis-rhel8"),
            ("version", "4.0.0"),
            ("platform", "Red Hat Enterprise Linux 8"),
            ("total_controls", len(controls)),
            ("source", "CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0"),
            ("last_synced", date.today().isoformat()),
            ("chapters", chapters),
        ]
    )


def _write_yaml(baseline: OrderedDict) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    header = "\n".join(
        [
            "# CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 — Full Baseline Extract",
            "# Source: CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 (PDF)",
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
    OUTPUT_PATH.write_text(header + yaml_body)


def main() -> int:
    body_raw = _load_pdf_text(BODY_PAGE_START, BODY_PAGE_END, BODY_TXT)
    summary_raw = _load_pdf_text(SUMMARY_PAGE_START, SUMMARY_PAGE_END, SUMMARY_TXT)

    body_text = _clean_pdf_text(body_raw)
    summary_text = _clean_pdf_text(summary_raw)

    summary_controls = _parse_summary(summary_text)
    if not summary_controls:
        raise ValueError("No controls parsed from appendix summary")

    segments = _control_segments(
        body_text, [control.id for control in summary_controls]
    )
    controls = [
        _build_control(control, segments[control.id]) for control in summary_controls
    ]
    baseline = _build_baseline(controls)
    _write_yaml(baseline)
    print(f"Extracted {len(controls)} controls to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
