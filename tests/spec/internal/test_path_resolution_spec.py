"""Spec-derived tests for path_resolution.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/path_resolution.spec.yaml — verifying that Kensa
resource paths are resolved through get_rules_path() (not hardcoded
literals) and that all supported install layouts are discovered.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


class TestPathResolutionSpecDerived:
    """Spec-derived tests for path resolution (AC-1 through AC-7)."""

    def test_ac1_control_without_rules_uses_get_rules_path(self, tmp_path):
        """AC-1: --control without --rules resolves rules via get_rules_path()."""
        from runner._rule_selection import select_rules

        # Create a minimal rule so load_rules succeeds
        rules_dir = tmp_path / "rules" / "access-control"
        rules_dir.mkdir(parents=True)
        rule_file = rules_dir / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\n"
            "title: Test\n"
            "severity: medium\n"
            "category: access-control\n"
            "tags: []\n"
            "references: {}\n"
            "platforms:\n"
            "  - family: rhel\n"
            "implementations:\n"
            "  - capability: base\n"
            "    check:\n"
            "      type: command\n"
            "      run: 'true'\n"
            "      expected_exit: 0\n"
        )

        # Patch at the source module so the local import picks it up
        with patch(
            "runner.paths.get_rules_path", return_value=tmp_path / "rules"
        ) as mock_grp:
            with contextlib.suppress(ValueError, FileNotFoundError):
                select_rules(
                    rules_path=None,
                    rule_path=None,
                    severity=(),
                    tag=(),
                    category=None,
                    control="cis:99.99.99",
                )

            mock_grp.assert_called_once()

    def test_ac2_coverage_without_rules_uses_get_rules_path(self):
        """AC-2: coverage command without --rules resolves via get_rules_path()."""
        from click.testing import CliRunner

        from runner.cli import main

        runner = CliRunner()

        with patch(
            "runner.paths.get_rules_path", side_effect=FileNotFoundError("no rules")
        ) as mock_grp:
            result = runner.invoke(
                main, ["coverage", "--framework", "cis-rhel9-v2.0.0"]
            )
            mock_grp.assert_called_once()
            assert result.exit_code != 0

    def test_ac3_find_package_data_dir_user_local(self, tmp_path):
        """AC-3: _find_package_data_dir() finds ~/.local/share/kensa."""
        from runner.paths import _find_package_data_dir

        fake_home = tmp_path / "fakehome"
        kensa_data = fake_home / ".local" / "share" / "kensa"
        kensa_data.mkdir(parents=True)

        with (
            patch.object(Path, "home", return_value=fake_home),
            patch("runner.paths.sys") as mock_sys,
        ):
            mock_sys.prefix = str(tmp_path / "no-venv")
            mock_sys.base_prefix = str(tmp_path / "no-base")

            result = _find_package_data_dir()
            assert result == kensa_data

    def test_ac3_find_package_data_dir_venv_prefix(self, tmp_path):
        """AC-3: _find_package_data_dir() finds {sys.prefix}/share/kensa."""
        from runner.paths import _find_package_data_dir

        venv_data = tmp_path / "venv" / "share" / "kensa"
        venv_data.mkdir(parents=True)

        with (
            patch.object(Path, "home", return_value=tmp_path / "nohome"),
            patch("runner.paths.sys") as mock_sys,
        ):
            mock_sys.prefix = str(tmp_path / "venv")
            mock_sys.base_prefix = str(tmp_path / "no-base")

            result = _find_package_data_dir()
            assert result == venv_data

    def test_ac3_find_package_data_dir_site_packages_fallback(self, tmp_path):
        """AC-3: _find_package_data_dir() finds site-packages kensa/data/."""
        import types

        from runner.paths import _find_package_data_dir

        pkg_dir = tmp_path / "site-packages" / "kensa"
        data_dir = pkg_dir / "data"
        data_dir.mkdir(parents=True)
        init_file = pkg_dir / "__init__.py"
        init_file.write_text("")

        fake_module = types.ModuleType("kensa")
        fake_module.__file__ = str(init_file)

        with (
            patch.object(Path, "home", return_value=tmp_path / "nohome"),
            patch("runner.paths.sys") as mock_sys,
            patch.dict(sys.modules, {"kensa": fake_module}),
        ):
            mock_sys.prefix = str(tmp_path / "no-prefix")
            mock_sys.base_prefix = str(tmp_path / "no-base")

            result = _find_package_data_dir()
            assert result == data_dir

    def test_ac4_env_var_overrides_all(self, tmp_path):
        """AC-4: KENSA_RULES_PATH env var overrides all other paths."""
        from runner.paths import get_rules_path

        env_rules = tmp_path / "env-rules"
        env_rules.mkdir()

        # Also create cwd-relative rules to prove env var wins
        cwd_rules = tmp_path / "cwd" / "rules"
        cwd_rules.mkdir(parents=True)

        with (
            patch.dict(os.environ, {"KENSA_RULES_PATH": str(env_rules)}),
            patch("runner.paths.Path.cwd", return_value=tmp_path / "cwd"),
        ):
            result = get_rules_path()
            assert result == env_rules

    def test_ac5_error_messages_no_hardcoded_rules_path(self, tmp_path):
        """AC-5: Error messages don't contain hardcoded 'rules/' literal."""
        from runner.paths import get_rules_path

        # Point everything to nonexistent dirs so get_rules_path fails
        with (
            patch.dict(os.environ, {"KENSA_RULES_PATH": ""}, clear=False),
            patch("runner.paths.Path.cwd", return_value=tmp_path / "empty"),
            patch(
                "runner.paths.Path.__file__",
                new_callable=lambda: property(lambda self: str(tmp_path / "fake.py")),
            )
            if False
            else patch("runner.paths._find_package_data_dir", return_value=None),
        ):
            old = os.environ.pop("KENSA_RULES_PATH", None)
            # Also need source-relative to fail — patch __file__
            fake_runner = tmp_path / "runner" / "paths.py"
            fake_runner.parent.mkdir(parents=True, exist_ok=True)
            import runner.paths as paths_mod

            orig_file = paths_mod.__file__
            try:
                paths_mod.__file__ = str(fake_runner)
                with pytest.raises(FileNotFoundError) as exc_info:
                    get_rules_path()
                # Error message must not contain "rules/" literal
                assert "rules/" not in str(exc_info.value)
                assert "Cannot locate" in str(exc_info.value)
            finally:
                paths_mod.__file__ = orig_file
                if old is not None:
                    os.environ["KENSA_RULES_PATH"] = old

    def test_ac6_raises_file_not_found_when_no_rules(self, tmp_path):
        """AC-6: get_rules_path() raises FileNotFoundError when no rules exist."""
        from runner.paths import get_rules_path

        old = os.environ.pop("KENSA_RULES_PATH", None)
        import runner.paths as paths_mod

        orig_file = paths_mod.__file__
        try:
            fake_runner = tmp_path / "runner" / "paths.py"
            fake_runner.parent.mkdir(parents=True, exist_ok=True)
            paths_mod.__file__ = str(fake_runner)

            with (
                patch("runner.paths.Path.cwd", return_value=tmp_path / "empty"),
                patch("runner.paths._find_package_data_dir", return_value=None),
                pytest.raises(FileNotFoundError),
            ):
                get_rules_path()
        finally:
            paths_mod.__file__ = orig_file
            if old is not None:
                os.environ["KENSA_RULES_PATH"] = old

    def test_ac7_cwd_wins_over_installed(self, tmp_path):
        """AC-7: cwd-relative rules directory takes precedence over installed."""
        from runner.paths import get_rules_path

        cwd_rules = tmp_path / "cwd" / "rules"
        cwd_rules.mkdir(parents=True)

        installed_data = tmp_path / "installed" / "share" / "kensa" / "rules"
        installed_data.mkdir(parents=True)

        old = os.environ.pop("KENSA_RULES_PATH", None)
        try:
            with patch("runner.paths.Path.cwd", return_value=tmp_path / "cwd"):
                result = get_rules_path()
                assert result == cwd_rules
        finally:
            if old is not None:
                os.environ["KENSA_RULES_PATH"] = old
