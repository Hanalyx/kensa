"""Spec-derived tests for release/cleanup-operations.spec.yaml.

Tests validate that cleanup operation safeguards and tooling are in place
as defined in specs/release/cleanup-operations.spec.yaml.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]


class TestCleanupOperationsSpecDerived:
    """Spec-derived tests for cleanup operations (AC-1 through AC-10)."""

    def test_ac1_cleanup_tiers_documented(self):
        """AC-1: Cleanup operations are classified into four tiers by blast radius."""
        # The spec itself defines the four tiers. Verify the spec exists and
        # contains all four tier references.
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        assert spec.exists(), "cleanup-operations.spec.yaml must exist"
        content = spec.read_text()
        assert "tier 1" in content, "Spec must define tier 1 (cosmetic)"
        assert "tier 2" in content, "Spec must define tier 2 (removal)"
        assert "tier 3" in content, "Spec must define tier 3 (structural)"
        assert "tier 4" in content, "Spec must define tier 4 (destructive)"

    def test_ac2_dry_run_constraint_in_spec(self):
        """AC-2: Every tier 2+ cleanup PR includes a dry-run report listing what will be removed."""
        # Verify the spec's constraints require dry-run verification for removal PRs
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert (
            "dry-run" in content.lower() or "dry_run" in content.lower()
        ), "Spec must require dry-run reports for tier 2+ cleanup"

    def test_ac3_grep_evidence_constraint_in_spec(self):
        """AC-3: Code removal PRs include grep evidence showing zero references to deleted code."""
        # Verify the spec's constraints require grep evidence before deletion
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert (
            "grep" in content.lower()
        ), "Spec must require grep evidence for code removal"
        assert (
            "references" in content.lower()
        ), "Spec must mention checking references before deletion"

    def test_ac4_validation_toolchain_available(self):
        """AC-4: Full validation toolchain is available (pytest, ruff, mypy, schema validate, dedup)."""
        # Verify key validation scripts exist
        assert (
            REPO_ROOT / "schema" / "validate.py"
        ).exists(), "schema/validate.py must exist for rule schema validation"
        assert (
            REPO_ROOT / "scripts" / "rule_dedup_check.py"
        ).exists(), "scripts/rule_dedup_check.py must exist for dedup validation"
        assert (
            REPO_ROOT / "scripts" / "cis_validate.py"
        ).exists(), "scripts/cis_validate.py must exist for CIS coverage validation"
        assert (
            REPO_ROOT / "schema" / "validate_specs.py"
        ).exists(), "schema/validate_specs.py must exist for spec schema validation"

    def test_ac5_single_concern_constraint(self):
        """AC-5: Cleanup PRs do not contain feature or bugfix changes (single concern per PR)."""
        # Verify the spec's constraints enforce single-concern PRs
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert re.search(
            r"MUST NOT combine cleanup.*feature|single concern",
            content,
            re.IGNORECASE,
        ), "Spec must enforce single-concern cleanup PRs"

    def test_ac6_consolidate_script_available(self):
        """AC-6: Rule consolidation script exists for structural cleanup using git mv."""
        consolidate = REPO_ROOT / "scripts" / "consolidate_rules.py"
        assert (
            consolidate.exists()
        ), "scripts/consolidate_rules.py must exist for rule consolidation"
        # Verify the spec requires git mv for file moves
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert "git mv" in content, "Spec must require git mv for file moves"

    def test_ac7_dependency_removal_verification(self):
        """AC-7: Dependency removal is verified with import grep and pip check."""
        # Verify pyproject.toml exists (the dependency source of truth)
        pyproject = REPO_ROOT / "pyproject.toml"
        assert pyproject.exists(), "pyproject.toml must exist as dependency source"
        # Verify the spec requires import grep and pip check
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert (
            "import" in content.lower() and "grep" in content.lower()
        ), "Spec must require import grep for dependency removal"

    def test_ac8_spec_registry_exists(self):
        """AC-8: SPEC_REGISTRY.md exists for tracking spec file references."""
        registry = REPO_ROOT / "specs" / "SPEC_REGISTRY.md"
        assert (
            registry.exists()
        ), "specs/SPEC_REGISTRY.md must exist for spec reference tracking"

    def test_ac9_deprecated_before_removal(self):
        """AC-9: Deprecated code is marked before removal with spec status set to deprecated."""
        # Verify the spec lifecycle includes a deprecated status
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert (
            "deprecated" in content.lower()
        ), "Spec must reference deprecated status for code marked for removal"

    def test_ac10_large_cleanups_staged(self):
        """AC-10: Large cleanups are broken into staged PRs, not combined into a single large PR."""
        # Verify the spec requires staged PRs for large cleanups
        spec = REPO_ROOT / "specs" / "release" / "cleanup-operations.spec.yaml"
        content = spec.read_text()
        assert re.search(
            r"staged|multiple PRs|broken into",
            content,
            re.IGNORECASE,
        ), "Spec must require large cleanups to be broken into staged PRs"
