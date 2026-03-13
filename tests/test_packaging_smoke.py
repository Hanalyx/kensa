"""Packaging smoke tests.

Verify that Kensa's packaging produces a working installation:
CLI entry points, subcommand discovery, data file locations, and version output.

These tests run against the *current* source tree (not an installed package)
and are designed to also work post-install in CI packaging jobs.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

PYTHON = sys.executable


class TestCLIEntryPoints:
    """Verify CLI entry points are functional."""

    def test_module_help_exits_0(self):
        """python3 -m runner --help exits 0."""
        result = subprocess.run(
            [PYTHON, "-m", "runner", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "Usage" in result.stdout

    def test_module_version_exits_0(self):
        """python3 -m runner --version exits 0."""
        result = subprocess.run(
            [PYTHON, "-m", "runner", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        # Should print a version string (e.g., "kensa, version 1.3.0" or "dev")
        output = result.stdout + result.stderr
        assert "version" in output.lower() or "dev" in output.lower()


class TestSubcommandDiscovery:
    """Verify all expected subcommands are discoverable."""

    EXPECTED_SUBCOMMANDS = [
        "check",
        "coverage",
        "detect",
        "diff",
        "history",
        "info",
        "list",
        "remediate",
        "rollback",
    ]

    def test_help_lists_all_subcommands(self):
        """--help output mentions all expected subcommands."""
        result = subprocess.run(
            [PYTHON, "-m", "runner", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        for cmd in self.EXPECTED_SUBCOMMANDS:
            assert cmd in result.stdout, f"Subcommand '{cmd}' not found in --help"

    @pytest.mark.parametrize(
        "subcommand",
        EXPECTED_SUBCOMMANDS,
    )
    def test_subcommand_help_exits_0(self, subcommand):
        """Each subcommand's --help exits 0."""
        result = subprocess.run(
            [PYTHON, "-m", "runner", subcommand, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"{subcommand} --help failed: {result.stderr}"
        assert "Usage" in result.stdout or "usage" in result.stdout.lower()


class TestDataFileLocations:
    """Verify data directories and critical files are locatable."""

    def test_rules_directory_exists(self):
        """Rules directory is found by get_rules_path()."""
        from runner.paths import get_rules_path

        rules_dir = get_rules_path()
        assert rules_dir.exists()
        assert rules_dir.is_dir()
        # Should contain at least one .yml file
        yml_files = list(rules_dir.rglob("*.yml"))
        assert len(yml_files) > 0, "Rules directory has no .yml files"

    def test_schema_file_exists(self):
        """Rule schema file is found by get_schema_path()."""
        from runner.paths import get_schema_path

        schema_path = get_schema_path("rule.schema.json")
        assert schema_path.exists()

    def test_mappings_directory_exists(self):
        """Mappings directory is found by get_mappings_path()."""
        from runner.paths import get_mappings_path

        mappings_dir = get_mappings_path()
        assert mappings_dir.exists()
        assert mappings_dir.is_dir()
        # Should contain at least one .yaml file
        yaml_files = list(mappings_dir.rglob("*.yaml"))
        assert len(yaml_files) > 0, "Mappings directory has no .yaml files"

    def test_config_directory_exists(self):
        """Config directory is found by get_config_path()."""
        from runner.paths import get_config_path

        config_dir = get_config_path()
        assert config_dir.exists()
        assert config_dir.is_dir()

    def test_defaults_yml_exists(self):
        """config/defaults.yml exists."""
        from runner.paths import get_config_path

        defaults = get_config_path("defaults.yml")
        assert defaults.exists()


class TestVersionConsistency:
    """Verify version reporting is consistent."""

    def test_get_version_returns_string(self):
        """get_version() returns a non-empty string."""
        from runner.paths import get_version

        version = get_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_cli_version_matches_get_version(self):
        """CLI --version matches get_version()."""
        from runner.paths import get_version

        expected = get_version()
        result = subprocess.run(
            [PYTHON, "-m", "runner", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert (
            expected in output
        ), f"CLI version output '{output.strip()}' doesn't contain '{expected}'"
