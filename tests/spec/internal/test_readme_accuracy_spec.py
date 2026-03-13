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
                if isinstance(rem, dict) and "mechanism" in rem:
                    mechanisms.add(rem["mechanism"])

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
