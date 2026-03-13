"""Spec-derived tests for system.spec.yaml.

Tests validate the system-level acceptance criteria defined in
specs/system.spec.yaml — verifying that all expected registries,
handlers, CLI commands, and framework mappings exist.
"""

from __future__ import annotations

from pathlib import Path


class TestSystemSpecDerived:
    """Spec-derived tests for Kensa system context (AC-1 through AC-6)."""

    def test_ac1_capability_probes(self):
        """AC-1: 24 capability probes detect host features for implementation gating."""
        from runner.detect import CAPABILITY_PROBES

        assert len(CAPABILITY_PROBES) == 24

    def test_ac2_check_handlers(self):
        """AC-2: 21 check handler types evaluate compliance rules against remote state."""
        from runner.handlers.checks import CHECK_HANDLERS

        assert len(CHECK_HANDLERS) == 21

    def test_ac3_remediation_handlers(self):
        """AC-3: 29 remediation handler types apply fixes with pre-state capture."""
        from runner.handlers.remediation import REMEDIATION_HANDLERS

        assert len(REMEDIATION_HANDLERS) == 29

    def test_ac4_rollback_system(self):
        """AC-4: Rollback system reverses remediations from stored snapshots."""
        from runner.handlers.capture import CAPTURE_HANDLERS
        from runner.handlers.rollback import ROLLBACK_HANDLERS

        assert len(ROLLBACK_HANDLERS) > 0
        assert len(CAPTURE_HANDLERS) > 0

    def test_ac5_cli_commands(self):
        """AC-5: CLI commands provide the expected functionality."""
        from runner.cli import main

        assert len(main.commands) == 11
        expected = {
            "detect",
            "check",
            "remediate",
            "rollback",
            "history",
            "diff",
            "coverage",
            "list",
            "list-frameworks",  # deprecated alias
            "info",
            "lookup",
        }
        assert set(main.commands.keys()) == expected

    def test_ac6_framework_mappings(self):
        """AC-6: Framework mappings support CIS, STIG, NIST 800-53, PCI-DSS, and FedRAMP."""
        mappings_dir = Path(__file__).resolve().parent.parent.parent / "mappings"
        expected = {"cis", "stig", "nist", "pci-dss", "fedramp"}
        actual = {d.name for d in mappings_dir.iterdir() if d.is_dir()}
        assert expected <= actual
