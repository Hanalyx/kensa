"""SpecDerived tests for README accuracy.

See specs/internal/readme_accuracy.spec.yaml for specification.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestReadmeAccuracySpecDerived:
    """Spec-derived tests for README accuracy."""

    def test_ac1_rule_count_matches_actual(self):
        """AC-1: README rule count matches the actual number of .yml files under rules/."""
        rules_dir = REPO_ROOT / "rules"
        actual_count = len(list(rules_dir.rglob("*.yml")))

        readme = (REPO_ROOT / "README.md").read_text()
        # Match pattern like `630 rules` in the badge line
        match = re.search(r"`(\d+) rules`", readme)
        assert match, "README must contain a rule count in `N rules` format"
        readme_count = int(match.group(1))

        assert (
            readme_count == actual_count
        ), f"README claims {readme_count} rules but repo has {actual_count}"

    def test_ac2_mechanism_count_matches_actual(self):
        """AC-2: README mechanism count matches actual distinct mechanisms in rules."""
        rules_dir = REPO_ROOT / "rules"
        mechanisms = set()
        for rule_file in rules_dir.rglob("*.yml"):
            try:
                data = yaml.safe_load(rule_file.read_text())
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue
            for impl in data.get("implementations", []):
                rem = impl.get("remediation", {})
                if isinstance(rem, dict):
                    if "mechanism" in rem:
                        mechanisms.add(rem["mechanism"])
                    for step in rem.get("steps", []):
                        if isinstance(step, dict) and "mechanism" in step:
                            mechanisms.add(step["mechanism"])

        readme = (REPO_ROOT / "README.md").read_text()
        # Match pattern like `19 remediation mechanisms`
        match = re.search(r"`(\d+) remediation mechanisms`", readme)
        assert (
            match
        ), "README must contain mechanism count in `N remediation mechanisms` format"
        readme_count = int(match.group(1))

        assert (
            readme_count == len(mechanisms)
        ), f"README claims {readme_count} mechanisms but rules use {len(mechanisms)}: {sorted(mechanisms)}"

    def test_ac3_support_boundary_section_exists(self):
        """AC-3: README contains a support boundary section."""
        readme = (REPO_ROOT / "README.md").read_text()
        assert re.search(
            r"##\s+(Supported Platforms|Support Boundary|Platform Support)", readme
        ), "README must contain a support boundary section"

    def test_ac4_framework_coverage_table_present(self):
        """AC-4: README contains framework coverage table with control counts."""
        readme = (REPO_ROOT / "README.md").read_text()
        assert (
            "Framework Coverage" in readme
        ), "README must contain Framework Coverage section"
        # Should have a table with actual data
        assert "cis-rhel9" in readme.lower() or "CIS RHEL 9" in readme

    def test_ac5_cis_rhel8_coverage_matches_mapping(self):
        """AC-5: README CIS RHEL 8 coverage percentage matches actual mapping."""
        mapping_path = REPO_ROOT / "mappings" / "cis" / "rhel8.yaml"
        mapping = yaml.safe_load(mapping_path.read_text())

        total = len(mapping.get("control_ids", []))
        unimplemented = len(mapping.get("unimplemented", {}))
        mapped = total - unimplemented

        readme = (REPO_ROOT / "README.md").read_text()
        # Match pipe-separated table row: | CIS RHEL 8 ... | id | 322 | 293 | 91.0% |
        match = re.search(
            r"CIS RHEL 8[^|]*\|[^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%",
            readme,
        )
        assert match, "README must contain CIS RHEL 8 coverage table row"
        readme_total = int(match.group(1))
        readme_mapped = int(match.group(2))

        assert (
            readme_total == total
        ), f"README CIS RHEL 8 total is {readme_total} but mapping has {total}"
        assert (
            readme_mapped == mapped
        ), f"README CIS RHEL 8 mapped is {readme_mapped} but mapping has {mapped}"

    def test_ac6_cis_rhel9_coverage_matches_mapping(self):
        """AC-6: README CIS RHEL 9 coverage percentage matches actual mapping."""
        mapping_path = REPO_ROOT / "mappings" / "cis" / "rhel9.yaml"
        mapping = yaml.safe_load(mapping_path.read_text())

        total = len(mapping.get("control_ids", []))
        unimplemented = len(mapping.get("unimplemented", {}))
        mapped = total - unimplemented

        readme = (REPO_ROOT / "README.md").read_text()
        match = re.search(
            r"CIS RHEL 9[^|]*\|[^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%",
            readme,
        )
        assert match, "README must contain CIS RHEL 9 coverage table row"
        readme_total = int(match.group(1))
        readme_mapped = int(match.group(2))

        assert (
            readme_total == total
        ), f"README CIS RHEL 9 total is {readme_total} but mapping has {total}"
        assert (
            readme_mapped == mapped
        ), f"README CIS RHEL 9 mapped is {readme_mapped} but mapping has {mapped}"

    def test_ac7_check_methods_exist_in_registry(self):
        """AC-7: Every check method referenced in a rule exists in CHECK_HANDLERS."""
        from runner.handlers.checks import CHECK_HANDLERS

        rules_dir = REPO_ROOT / "rules"
        invalid = []
        for rule_file in sorted(rules_dir.rglob("*.yml")):
            try:
                data = yaml.safe_load(rule_file.read_text())
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue
            for impl in data.get("implementations", []):
                check = impl.get("check", {})
                if isinstance(check, dict):
                    method = check.get("method")
                    if method and method not in CHECK_HANDLERS:
                        invalid.append(f"{rule_file.stem}: check method '{method}'")

        assert not invalid, (
            f"Rules reference {len(invalid)} unknown check methods:\n"
            + "\n".join(invalid[:20])
        )

    def test_ac8_remediation_mechanisms_exist_in_registry(self):
        """AC-8: Every remediation mechanism referenced in a rule exists in REMEDIATION_HANDLERS."""
        from runner.handlers.remediation import REMEDIATION_HANDLERS

        rules_dir = REPO_ROOT / "rules"
        invalid = []
        for rule_file in sorted(rules_dir.rglob("*.yml")):
            try:
                data = yaml.safe_load(rule_file.read_text())
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue
            for impl in data.get("implementations", []):
                rem = impl.get("remediation", {})
                if isinstance(rem, dict):
                    # Single-step
                    mech = rem.get("mechanism")
                    if mech and mech not in REMEDIATION_HANDLERS:
                        invalid.append(f"{rule_file.stem}: mechanism '{mech}'")
                    # Multi-step
                    for step in rem.get("steps", []):
                        if isinstance(step, dict):
                            smech = step.get("mechanism")
                            if smech and smech not in REMEDIATION_HANDLERS:
                                invalid.append(
                                    f"{rule_file.stem}: step mechanism '{smech}'"
                                )

        assert not invalid, (
            f"Rules reference {len(invalid)} unknown remediation mechanisms:\n"
            + "\n".join(invalid[:20])
        )
