#!/usr/bin/env python3
"""Compare KENSA and OpenSCAP at the CIS section level.

Since KENSA consolidates multiple OpenSCAP rules into single rules by security
intent, rule-to-rule comparison is invalid. Instead, we compare at the CIS
section level - the common denominator both tools reference.

Usage:
    python3 scripts/cis_section_compare.py \
        --kensa results/kensa-results.json \
        --openscap results/openscap-results.xml \
        --output CIS_SECTION_COMPARISON.md
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}


@dataclass
class SectionResult:
    """Aggregated result for a CIS section."""

    section: str
    kensa_rules: list[tuple[str, bool, str]] = field(default_factory=list)  # (id, passed, detail)
    openscap_rules: list[tuple[str, bool]] = field(default_factory=list)  # (id, passed)

    @property
    def kensa_pass(self) -> bool | None:
        """Section passes if ALL kensa rules pass."""
        if not self.kensa_rules:
            return None
        return all(passed for _, passed, _ in self.kensa_rules)

    @property
    def openscap_pass(self) -> bool | None:
        """Section passes if ALL openscap rules pass."""
        if not self.openscap_rules:
            return None
        return all(passed for _, passed in self.openscap_rules)

    @property
    def agreement(self) -> str:
        """Compare results."""
        if self.kensa_pass is None and self.openscap_pass is None:
            return "neither"
        if self.kensa_pass is None:
            return "openscap-only"
        if self.openscap_pass is None:
            return "kensa-only"
        if self.kensa_pass == self.openscap_pass:
            return "agree"
        return "disagree"


def extract_cis_section(rule_id: str, ident_refs: list[str]) -> str | None:
    """Extract CIS section number from OpenSCAP rule."""
    # Try to find CIS reference in ident elements
    for ref in ident_refs:
        # Match patterns like "CIS-1.2.3" or just section numbers
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", ref)
        if match:
            return match.group(1)
    return None


def parse_openscap_with_sections(xml_path: str) -> dict[str, list[tuple[str, bool]]]:
    """Parse OpenSCAP results grouped by CIS section.

    Returns dict mapping CIS section -> list of (rule_id, passed).
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # First, build a map of rule_id -> CIS sections from Rule definitions
    rule_to_sections: dict[str, list[str]] = defaultdict(list)

    for rule in root.findall(".//xccdf:Rule", NS):
        rule_id = rule.get("id", "").replace("xccdf_org.ssgproject.content_rule_", "")

        # Look for CIS references in ident elements
        for ident in rule.findall("xccdf:ident", NS):
            system = ident.get("system", "")
            text = ident.text or ""
            if "cis" in system.lower() or text.startswith("CIS"):
                # Extract section number
                match = re.search(r"(\d+\.\d+(?:\.\d+)*)", text)
                if match:
                    rule_to_sections[rule_id].append(match.group(1))

        # Also check reference elements
        for ref in rule.findall("xccdf:reference", NS):
            href = ref.get("href", "")
            text = ref.text or ""
            if "cis" in href.lower() or "cis" in text.lower():
                match = re.search(r"(\d+\.\d+(?:\.\d+)*)", text)
                if match:
                    rule_to_sections[rule_id].append(match.group(1))

    # Now parse results
    sections: dict[str, list[tuple[str, bool]]] = defaultdict(list)

    for test_result in root.findall(".//xccdf:TestResult", NS):
        for rule_result in test_result.findall("xccdf:rule-result", NS):
            idref = rule_result.get("idref", "")
            short_id = idref.replace("xccdf_org.ssgproject.content_rule_", "")

            result_elem = rule_result.find("xccdf:result", NS)
            result_text = result_elem.text if result_elem is not None else "unknown"

            if result_text not in ("pass", "fail"):
                continue

            passed = result_text == "pass"

            # Get CIS sections for this rule
            cis_sections = rule_to_sections.get(short_id, [])
            if cis_sections:
                for section in cis_sections:
                    sections[section].append((short_id, passed))
            else:
                # No CIS mapping - put in "unmapped"
                sections["unmapped"].append((short_id, passed))

    return dict(sections)


def parse_kensa_with_sections(json_path: str) -> dict[str, list[tuple[str, bool, str]]]:
    """Parse KENSA results grouped by CIS section.

    Returns dict mapping CIS section -> list of (rule_id, passed, detail).
    """
    with open(json_path) as f:
        data = json.load(f)

    sections: dict[str, list[tuple[str, bool, str]]] = defaultdict(list)

    hosts = data.get("hosts", [data]) if "hosts" in data else [data]

    for host in hosts:
        for rule in host.get("results", []):
            if rule.get("skipped"):
                continue

            rule_id = rule.get("rule_id", "")
            passed = rule.get("passed", False)
            detail = rule.get("detail", "")
            section = rule.get("framework_section", "")

            if section:
                sections[section].append((rule_id, passed, detail))
            else:
                sections["unmapped"].append((rule_id, passed, detail))

    return dict(sections)


def generate_report(
    kensa_sections: dict[str, list[tuple[str, bool, str]]],
    openscap_sections: dict[str, list[tuple[str, bool]]],
    output_path: str,
) -> None:
    """Generate CIS section comparison report."""
    # Merge all sections
    all_sections = set(kensa_sections.keys()) | set(openscap_sections.keys())
    all_sections.discard("unmapped")

    results: dict[str, SectionResult] = {}
    for section in sorted(all_sections, key=lambda s: [int(x) for x in s.split(".")]):
        sr = SectionResult(section=section)
        if section in kensa_sections:
            sr.kensa_rules = kensa_sections[section]
        if section in openscap_sections:
            sr.openscap_rules = openscap_sections[section]
        results[section] = sr

    # Categorize
    both_pass = []
    both_fail = []
    disagree = []
    kensa_only = []
    openscap_only = []

    for section, sr in results.items():
        if sr.agreement == "agree":
            if sr.kensa_pass:
                both_pass.append(sr)
            else:
                both_fail.append(sr)
        elif sr.agreement == "disagree":
            disagree.append(sr)
        elif sr.agreement == "kensa-only":
            kensa_only.append(sr)
        elif sr.agreement == "openscap-only":
            openscap_only.append(sr)

    # Generate report
    report = []
    report.append("# CIS Section-Level Comparison: KENSA vs OpenSCAP\n")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    report.append("## Methodology")
    report.append("")
    report.append("This comparison aggregates results at the **CIS section level** rather than")
    report.append("comparing individual rules. This accounts for the different philosophies:")
    report.append("- **OpenSCAP**: Multiple granular rules per CIS section (e.g., 15 rules for DAC auditing)")
    report.append("- **KENSA**: Consolidated rules by security intent (e.g., 1 rule for DAC auditing)")
    report.append("")
    report.append("A CIS section **passes** if ALL rules covering it pass.")
    report.append("")
    report.append("---\n")

    # Summary
    total_sections = len(results)
    report.append("## Executive Summary\n")
    report.append(f"**CIS Sections Analyzed:** {total_sections}\n")
    report.append("| Category | Count | % |")
    report.append("|----------|-------|---|")
    report.append(f"| Both tools agree: PASS | {len(both_pass)} | {100*len(both_pass)//total_sections}% |")
    report.append(f"| Both tools agree: FAIL | {len(both_fail)} | {100*len(both_fail)//total_sections}% |")
    report.append(f"| **Disagreement** | {len(disagree)} | {100*len(disagree)//total_sections}% |")
    report.append(f"| KENSA only (no OpenSCAP mapping) | {len(kensa_only)} | {100*len(kensa_only)//total_sections}% |")
    report.append(f"| OpenSCAP only (no KENSA mapping) | {len(openscap_only)} | {100*len(openscap_only)//total_sections}% |")
    report.append("")

    agreement_rate = (len(both_pass) + len(both_fail)) / max(1, len(both_pass) + len(both_fail) + len(disagree))
    report.append(f"**Agreement Rate (where both cover):** {100*agreement_rate:.1f}%")
    report.append("")
    report.append("---\n")

    # Disagreements - most important
    if disagree:
        report.append("## Disagreements (Requires Investigation)\n")
        report.append("These CIS sections have different pass/fail outcomes between tools.\n")
        report.append("| CIS Section | KENSA | OpenSCAP | KENSA Rules | OpenSCAP Rules |")
        report.append("|-------------|-------|----------|-------------|----------------|")
        for sr in disagree:
            kensa_status = "PASS" if sr.kensa_pass else "FAIL"
            openscap_status = "PASS" if sr.openscap_pass else "FAIL"
            kensa_count = len(sr.kensa_rules)
            openscap_count = len(sr.openscap_rules)
            report.append(f"| {sr.section} | {kensa_status} | {openscap_status} | {kensa_count} | {openscap_count} |")
        report.append("")

        # Detail on disagreements
        report.append("### Disagreement Details\n")
        for sr in disagree:
            report.append(f"#### CIS {sr.section}\n")
            if sr.kensa_rules:
                report.append("**KENSA:**")
                for rule_id, passed, detail in sr.kensa_rules:
                    status = "PASS" if passed else "FAIL"
                    report.append(f"- `{rule_id}`: {status} - {detail[:50]}")
            if sr.openscap_rules:
                report.append("")
                report.append("**OpenSCAP:**")
                for rule_id, passed in sr.openscap_rules[:5]:  # Limit to 5
                    status = "pass" if passed else "fail"
                    report.append(f"- `{rule_id}`: {status}")
                if len(sr.openscap_rules) > 5:
                    report.append(f"- ... and {len(sr.openscap_rules) - 5} more")
            report.append("")
        report.append("---\n")

    # Both fail - action needed
    if both_fail:
        report.append("## Both Fail (Action Required)\n")
        report.append("| CIS Section | KENSA Rules | OpenSCAP Rules | KENSA Detail |")
        report.append("|-------------|-------------|----------------|--------------|")
        for sr in both_fail:
            kensa_detail = sr.kensa_rules[0][2][:40] if sr.kensa_rules else ""
            report.append(f"| {sr.section} | {len(sr.kensa_rules)} | {len(sr.openscap_rules)} | {kensa_detail} |")
        report.append("")
        report.append("---\n")

    # Coverage gaps
    if kensa_only or openscap_only:
        report.append("## Coverage Gaps\n")
        if openscap_only:
            report.append(f"### OpenSCAP covers but KENSA doesn't ({len(openscap_only)} sections)\n")
            pass_count = sum(1 for sr in openscap_only if sr.openscap_pass)
            fail_count = len(openscap_only) - pass_count
            report.append(f"- Passing in OpenSCAP: {pass_count}")
            report.append(f"- **Failing in OpenSCAP (priority):** {fail_count}")
            report.append("")
            if fail_count > 0:
                report.append("**Failing sections (need KENSA rules):**")
                for sr in openscap_only:
                    if not sr.openscap_pass:
                        rules = ", ".join(r[0] for r in sr.openscap_rules[:3])
                        report.append(f"- CIS {sr.section}: {rules}")
            report.append("")

        if kensa_only:
            report.append(f"### KENSA covers but OpenSCAP doesn't ({len(kensa_only)} sections)\n")
            report.append("These may be KENSA-specific rules or CIS sections not in OpenSCAP's profile.\n")
            report.append("<details><summary>Click to expand</summary>\n")
            for sr in kensa_only:
                status = "PASS" if sr.kensa_pass else "FAIL"
                rules = ", ".join(r[0] for r in sr.kensa_rules)
                report.append(f"- CIS {sr.section}: {status} - {rules}")
            report.append("</details>\n")

    report.append("---\n")

    # Agreement details
    report.append(f"## Both Pass ({len(both_pass)} sections)\n")
    report.append("<details><summary>Click to expand</summary>\n")
    for sr in both_pass:
        kensa_rules = ", ".join(r[0] for r in sr.kensa_rules)
        report.append(f"- CIS {sr.section}: KENSA({len(sr.kensa_rules)}) / OpenSCAP({len(sr.openscap_rules)})")
    report.append("</details>\n")

    # Write report
    output = Path(output_path)
    output.write_text("\n".join(report))
    print(f"Report written to {output_path}")
    print(f"\nSummary:")
    print(f"  Total CIS sections: {total_sections}")
    print(f"  Both pass: {len(both_pass)}")
    print(f"  Both fail: {len(both_fail)}")
    print(f"  Disagree: {len(disagree)}")
    print(f"  Agreement rate: {100*agreement_rate:.1f}%")


def main():
    parser = argparse.ArgumentParser(description="CIS section-level comparison")
    parser.add_argument("--kensa", required=True, help="Path to KENSA JSON results")
    parser.add_argument("--openscap", required=True, help="Path to OpenSCAP XML results")
    parser.add_argument("--output", default="CIS_SECTION_COMPARISON.md", help="Output file")
    args = parser.parse_args()

    print(f"Parsing KENSA results...")
    kensa_sections = parse_kensa_with_sections(args.kensa)
    print(f"  Found {len(kensa_sections)} CIS sections")

    print(f"Parsing OpenSCAP results...")
    openscap_sections = parse_openscap_with_sections(args.openscap)
    print(f"  Found {len(openscap_sections)} CIS sections")

    generate_report(kensa_sections, openscap_sections, args.output)


if __name__ == "__main__":
    main()
