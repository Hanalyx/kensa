"""Spec-derived tests for release/cleanup-operations.spec.yaml.

Tests validate that cleanup operation safeguards and tooling are in place
as defined in specs/release/cleanup-operations.spec.yaml.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]


class TestCleanupOperationsSpecDerived:
    """Spec-derived tests for cleanup operations (AC-4, AC-6, AC-8)."""

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

    def test_ac6_consolidate_script_available(self):
        """AC-6: Rule consolidation script exists for structural cleanup."""
        consolidate = REPO_ROOT / "scripts" / "consolidate_rules.py"
        assert (
            consolidate.exists()
        ), "scripts/consolidate_rules.py must exist for rule consolidation"

    def test_ac8_spec_registry_exists(self):
        """AC-8: SPEC_REGISTRY.md exists for tracking spec file references."""
        registry = REPO_ROOT / "specs" / "SPEC_REGISTRY.md"
        assert (
            registry.exists()
        ), "specs/SPEC_REGISTRY.md must exist for spec reference tracking"
