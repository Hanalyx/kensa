#!/usr/bin/env python3
"""Verify extracted CIS RHEL 8 audit/remediation blocks against the PDF text."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from extract_cis_rhel8_sot import (
    BODY_PAGE_END,
    BODY_PAGE_START,
    BODY_TXT,
    OUTPUT_PATH,
    _clean_pdf_text,
    _control_segments,
    _load_pdf_text,
    _parse_summary,
    _section_map,
    SUMMARY_PAGE_END,
    SUMMARY_PAGE_START,
    SUMMARY_TXT,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = PROJECT_ROOT / "tmp" / "cis_rhel8_verification_report.json"


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
    body_text = _clean_pdf_text(
        _load_pdf_text(BODY_PAGE_START, BODY_PAGE_END, BODY_TXT)
    )
    summary_text = _clean_pdf_text(
        _load_pdf_text(SUMMARY_PAGE_START, SUMMARY_PAGE_END, SUMMARY_TXT)
    )
    summary_controls = _parse_summary(summary_text)
    segments = _control_segments(
        body_text, [control.id for control in summary_controls]
    )

    baseline = yaml.safe_load(OUTPUT_PATH.read_text())
    controls = {}
    for chapter in baseline["chapters"].values():
        for control in chapter["controls"]:
            controls[control["id"]] = control

    results = []
    mismatch_count = 0
    for summary in summary_controls:
        control = controls.get(summary.id)
        if not control:
            results.append({"id": summary.id, "status": "missing_from_yaml"})
            mismatch_count += 1
            continue
        sections = _section_map(segments[summary.id])
        expected_audit = _normalize(sections.get("Audit", ""))
        expected_remediation = _normalize(sections.get("Remediation", ""))
        actual_audit = _normalize(control.get("audit", ""))
        actual_remediation = _normalize(control.get("remediation", ""))

        entry = {
            "id": summary.id,
            "audit_match": expected_audit == actual_audit,
            "remediation_match": expected_remediation == actual_remediation,
        }
        if not entry["audit_match"]:
            entry["audit_expected_head"] = expected_audit[:400]
            entry["audit_actual_head"] = actual_audit[:400]
            mismatch_count += 1
        if not entry["remediation_match"]:
            entry["remediation_expected_head"] = expected_remediation[:400]
            entry["remediation_actual_head"] = actual_remediation[:400]
            mismatch_count += 1
        results.append(entry)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(results, indent=2))
    print(
        json.dumps(
            {
                "controls_checked": len(summary_controls),
                "mismatch_entries": sum(
                    1
                    for entry in results
                    if not entry.get("audit_match", True)
                    or not entry.get("remediation_match", True)
                    or entry.get("status") == "missing_from_yaml"
                ),
                "report": str(REPORT_PATH),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
