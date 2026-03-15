#!/usr/bin/env python3
"""Verify extracted CIS RHEL 9 audit/remediation blocks against the PDF text."""

from __future__ import annotations

import json
import re
from pathlib import Path
from subprocess import run

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PDF_PATH = PROJECT_ROOT / "SOT" / "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf"
BASELINE_PATH = PROJECT_ROOT / "context" / "cis" / "rhel9-v2.0.0-baseline.yaml"
TMP_DIR = Path("/tmp/cis_rhel9_verify")
BODY_TXT = TMP_DIR / "body.txt"
REPORT_PATH = PROJECT_ROOT / "tmp" / "cis_rhel9_verification_report.json"

BODY_PAGE_START = 17
BODY_PAGE_END = 989


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


def _normalize(text: str | None) -> str:
    if not text:
        return ""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def main() -> int:
    _run_pdftotext(BODY_PAGE_START, BODY_PAGE_END, BODY_TXT)
    body_text = _clean_pdf_text(BODY_TXT.read_text())

    baseline = yaml.safe_load(BASELINE_PATH.read_text())
    controls = []
    for chapter in baseline["chapters"].values():
        controls.extend(chapter["controls"])

    ids = [control["id"] for control in controls]
    segments = _control_segments(body_text, ids)

    results = []
    for control in controls:
        control_id = control["id"]
        sections = _section_map(segments[control_id])
        expected_audit = _normalize(sections.get("Audit", ""))
        expected_remediation = _normalize(sections.get("Remediation", ""))
        actual_audit = _normalize(control.get("audit", ""))
        actual_remediation = _normalize(control.get("remediation", ""))

        entry = {
            "id": control_id,
            "audit_match": expected_audit == actual_audit,
            "remediation_match": expected_remediation == actual_remediation,
        }
        if not entry["audit_match"]:
            entry["audit_expected_head"] = expected_audit[:400]
            entry["audit_actual_head"] = actual_audit[:400]
        if not entry["remediation_match"]:
            entry["remediation_expected_head"] = expected_remediation[:400]
            entry["remediation_actual_head"] = actual_remediation[:400]
        results.append(entry)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(results, indent=2))

    mismatch_entries = sum(
        1
        for entry in results
        if not entry["audit_match"] or not entry["remediation_match"]
    )
    print(
        json.dumps(
            {
                "controls_checked": len(results),
                "mismatch_entries": mismatch_entries,
                "report": str(REPORT_PATH),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
