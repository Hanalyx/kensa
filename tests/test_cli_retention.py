"""Tests for snapshot retention pruning during remediate startup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.cli import main
from runner.ssh import Result


class TestSnapshotPruningDuringRemediate:
    """Verify that prune_snapshots is called at the start of remediate."""

    @patch("runner.storage.ResultStore.prune_snapshots", return_value=0)
    @patch("runner._host_runner.SSHSession")
    def test_prune_snapshots_called_during_remediate(
        self, mock_session_cls, mock_prune, tmp_path
    ):
        """prune_snapshots() should be called before host processing."""
        # Set up mock SSH
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            return Result(exit_code=1, stdout="", stderr="")

        mock_ssh.run = mock_run

        # Write a test rule
        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\n"
            "title: Test rule\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 8\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '0'\n"
            "    remediation:\n"
            "      mechanism: sysctl_set\n"
            "      key: net.ipv4.ip_forward\n"
            "      value: '0'\n"
        )

        runner = CliRunner()
        runner.invoke(
            main,
            [
                "remediate",
                "--dry-run",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )

        # Verify prune_snapshots was called
        mock_prune.assert_called_once()

    @patch("runner.storage.ResultStore.prune_snapshots", return_value=0)
    @patch("runner._host_runner.SSHSession")
    def test_prune_snapshots_uses_config_archive_days(
        self, mock_session_cls, mock_prune, tmp_path
    ):
        """prune_snapshots() should use snapshot_archive_days from config."""
        # Set up mock SSH
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            return Result(exit_code=1, stdout="", stderr="")

        mock_ssh.run = mock_run

        # Write config with custom archive days
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "defaults.yml").write_text(
            "rollback:\n  snapshot_archive_days: 30\n"
        )

        # Write a test rule
        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\n"
            "title: Test rule\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 8\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '0'\n"
            "    remediation:\n"
            "      mechanism: sysctl_set\n"
            "      key: net.ipv4.ip_forward\n"
            "      value: '0'\n"
        )

        runner = CliRunner()
        runner.invoke(
            main,
            [
                "remediate",
                "--dry-run",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "--config-dir",
                str(config_dir),
            ],
        )

        # Verify prune_snapshots was called with the config value
        mock_prune.assert_called_once_with(archive_days=30)

    @patch("runner.storage.ResultStore.prune_snapshots", return_value=0)
    @patch("runner._host_runner.SSHSession")
    def test_prune_snapshots_defaults_to_90_days(
        self, mock_session_cls, mock_prune, tmp_path
    ):
        """prune_snapshots() should default to 90 days when not configured."""
        # Set up mock SSH
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            return Result(exit_code=1, stdout="", stderr="")

        mock_ssh.run = mock_run

        # Write config without rollback section
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "defaults.yml").write_text("variables:\n  some_var: value\n")

        # Write a test rule
        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\n"
            "title: Test rule\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 8\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '0'\n"
            "    remediation:\n"
            "      mechanism: sysctl_set\n"
            "      key: net.ipv4.ip_forward\n"
            "      value: '0'\n"
        )

        runner = CliRunner()
        runner.invoke(
            main,
            [
                "remediate",
                "--dry-run",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "--config-dir",
                str(config_dir),
            ],
        )

        # Verify prune_snapshots was called with default 90 days
        mock_prune.assert_called_once_with(archive_days=90)

    @patch("runner._host_runner.SSHSession")
    def test_prune_failure_does_not_block_remediation(self, mock_session_cls, tmp_path):
        """If prune_snapshots raises, remediate should still proceed."""
        # Set up mock SSH
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            return Result(exit_code=1, stdout="", stderr="")

        mock_ssh.run = mock_run

        # Write a test rule
        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\n"
            "title: Test rule\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 8\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '0'\n"
            "    remediation:\n"
            "      mechanism: sysctl_set\n"
            "      key: net.ipv4.ip_forward\n"
            "      value: '0'\n"
        )

        # Patch prune_snapshots to raise an exception
        with patch(
            "runner.storage.ResultStore.prune_snapshots",
            side_effect=Exception("DB unavailable"),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--dry-run",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )
            # Remediation should still proceed (DRY RUN output visible)
            assert "DRY RUN" in result.output
