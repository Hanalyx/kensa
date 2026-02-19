"""Adapter for parsing OpenSCAP XCCDF XML results into control-level results.

Refactored from ``scripts/cis_section_compare.py`` to generalise the
CIS-section extraction and result aggregation logic.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict

from scripts.benchmark.adapters.base import ToolAdapter, ToolControlResult

XCCDF_NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}


class OpenSCAPAdapter(ToolAdapter):
    """Parse OpenSCAP XCCDF XML into control-level results.

    Extracts CIS section references from Rule definitions, then maps
    rule-result pass/fail outcomes to those sections.  A section passes
    only when ALL contributing rules pass.
    """

    @property
    def tool_name(self) -> str:
        return "openscap"

    def parse(self, path: str) -> dict[str, ToolControlResult]:
        """Parse XCCDF XML and aggregate by CIS section.

        Args:
            path: Path to OpenSCAP XCCDF XML file.

        Returns:
            Dict mapping control_id -> ToolControlResult.

        """
        tree = ET.parse(path)
        root = tree.getroot()

        rule_to_sections = self._build_rule_section_map(root)
        section_rules = self._aggregate_results(root, rule_to_sections)

        controls: dict[str, ToolControlResult] = {}
        for section, rules in section_rules.items():
            if section == "unmapped":
                continue
            all_pass = all(passed for _, passed in rules)
            rule_ids = [rid for rid, _ in rules]

            controls[section] = ToolControlResult(
                tool_name="openscap",
                control_id=section,
                passed=all_pass,
                rule_ids=rule_ids,
                has_evidence=False,  # XCCDF provides pass/fail only
                has_remediation=False,  # Checked separately in Phase 3
                evidence_fields=[],
                detail=f"{len(rules)} rules evaluated",
            )

        return controls

    def count_mapped_sections(self, path: str) -> int:
        """Count unique CIS sections present in an XCCDF file.

        Useful for coverage dimension without full result parsing.

        Args:
            path: Path to OpenSCAP XCCDF XML file.

        Returns:
            Number of unique CIS sections found.

        """
        tree = ET.parse(path)
        root = tree.getroot()
        rule_to_sections = self._build_rule_section_map(root)
        all_sections: set[str] = set()
        for sections in rule_to_sections.values():
            all_sections.update(sections)
        return len(all_sections)

    @staticmethod
    def _build_rule_section_map(
        root: ET.Element,
    ) -> dict[str, list[str]]:
        """Build mapping from OpenSCAP rule_id to CIS section numbers.

        Checks both ``<ident>`` and ``<reference>`` elements for CIS
        section references.
        """
        rule_to_sections: dict[str, list[str]] = defaultdict(list)

        for rule in root.findall(".//xccdf:Rule", XCCDF_NS):
            rule_id = rule.get("id", "").replace(
                "xccdf_org.ssgproject.content_rule_", ""
            )

            # Check ident elements
            for ident in rule.findall("xccdf:ident", XCCDF_NS):
                system = ident.get("system", "")
                text = ident.text or ""
                if "cis" in system.lower() or text.startswith("CIS"):
                    match = re.search(r"(\d+\.\d+(?:\.\d+)*)", text)
                    if match:
                        rule_to_sections[rule_id].append(match.group(1))

            # Check reference elements — match cisecurity.org only,
            # not pcisecuritystandards.org (which also contains "cis").
            for ref in rule.findall("xccdf:reference", XCCDF_NS):
                href = ref.get("href", "")
                text = ref.text or ""
                if "cisecurity.org" in href.lower():
                    match = re.search(r"(\d+\.\d+(?:\.\d+)*)", text)
                    if match:
                        rule_to_sections[rule_id].append(match.group(1))

        return dict(rule_to_sections)

    @staticmethod
    def _aggregate_results(
        root: ET.Element,
        rule_to_sections: dict[str, list[str]],
    ) -> dict[str, list[tuple[str, bool]]]:
        """Parse TestResult elements and group by CIS section."""
        sections: dict[str, list[tuple[str, bool]]] = defaultdict(list)

        for test_result in root.findall(".//xccdf:TestResult", XCCDF_NS):
            for rule_result in test_result.findall("xccdf:rule-result", XCCDF_NS):
                idref = rule_result.get("idref", "")
                short_id = idref.replace(
                    "xccdf_org.ssgproject.content_rule_", ""
                )

                result_elem = rule_result.find("xccdf:result", XCCDF_NS)
                result_text = (
                    result_elem.text if result_elem is not None else "unknown"
                )

                if result_text not in ("pass", "fail"):
                    continue

                passed = result_text == "pass"
                cis_sections = rule_to_sections.get(short_id, [])
                if cis_sections:
                    for section in cis_sections:
                        sections[section].append((short_id, passed))
                else:
                    sections["unmapped"].append((short_id, passed))

        return dict(sections)
