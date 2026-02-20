"""Tests for runner/cli.py — CLI integration tests."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.cli import main
from runner.detect import PlatformInfo
from runner.ssh import Result


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text for easier testing."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


class TestCLIHelp:
    def test_main_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "detect" in result.output
        assert "check" in result.output
        assert "remediate" in result.output

    def test_detect_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["detect", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--sudo" in result.output

    def test_check_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--help"])
        assert result.exit_code == 0
        assert "--rules" in result.output
        assert "--severity" in result.output
        assert "--verbose" in result.output

    def test_remediate_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["remediate", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output
        assert "--rollback-on-failure" in result.output


class TestCLIErrors:
    @patch("runner.paths.get_inventory_path", return_value=None)
    def test_check_no_host(self, _mock_inv):
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--rule", "rules/access-control/ssh-disable-root-login.yml"]
        )
        assert result.exit_code == 1
        assert "No target hosts" in result.output

    def test_check_no_rules(self):
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--host", "10.0.0.1"])
        assert result.exit_code == 1
        assert "Specify --rules or --rule" in result.output


class TestCLICheck:
    @patch("runner._host_runner.SSHSession")
    def test_check_pass(self, mock_session_cls, tmp_path):
        """Verify check subcommand produces PASS output for a passing rule."""
        # Set up mock SSH
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_ssh.connect = MagicMock()
        mock_ssh.close = MagicMock()

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="0", stderr="")
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
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--user",
                "admin",
                "--rule",
                str(rule_file),
            ],
        )
        assert "PASS" in result.output
        clean_output = strip_ansi(result.output)
        assert "1 pass" in clean_output or (
            "1 rules" in clean_output and "pass" in clean_output
        )

    @patch("runner._host_runner.SSHSession")
    def test_check_fail(self, mock_session_cls, tmp_path):
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            return Result(exit_code=1, stdout="", stderr="")

        mock_ssh.run = mock_run

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
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--user",
                "admin",
                "--rule",
                str(rule_file),
            ],
        )
        assert "FAIL" in result.output
        clean_output = strip_ansi(result.output)
        assert "1 fail" in clean_output or (
            "1 rules" in clean_output and "fail" in clean_output
        )


class TestCLIVerbose:
    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_verbose_shows_capabilities(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_ssh.run = MagicMock(
            return_value=Result(exit_code=0, stdout="0", stderr="")
        )
        mock_detect_platform.return_value = PlatformInfo(family="rhel", version=9)

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
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "-v",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )
        assert "capabilities" in result.output
        assert "default implementation" in result.output


class TestCLIRemediate:
    @patch("runner._host_runner.SSHSession")
    def test_dry_run_shows_prefix(self, mock_session_cls, tmp_path):
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")  # Failing check
            return Result(exit_code=1, stdout="", stderr="")

        mock_ssh.run = mock_run

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
        assert "DRY RUN" in result.output


class TestCLIFilters:
    @patch("runner._host_runner.SSHSession")
    def test_severity_filter(self, mock_session_cls, tmp_path):
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_ssh.run = MagicMock(
            return_value=Result(exit_code=0, stdout="0", stderr="")
        )

        # Write two rules with different severities
        (tmp_path / "high-rule.yml").write_text(
            "id: high-rule\ntitle: High\nseverity: high\ncategory: kernel\n"
            "platforms:\n  - family: rhel\n    min_version: 8\n"
            "implementations:\n  - default: true\n    check:\n      method: sysctl_value\n      key: k\n      expected: '0'\n"
        )
        (tmp_path / "low-rule.yml").write_text(
            "id: low-rule\ntitle: Low\nseverity: low\ncategory: kernel\n"
            "platforms:\n  - family: rhel\n    min_version: 8\n"
            "implementations:\n  - default: true\n    check:\n      method: sysctl_value\n      key: k\n      expected: '0'\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--rules",
                str(tmp_path),
                "--severity",
                "high",
            ],
        )
        assert "high-rule" in result.output
        assert "low-rule" not in result.output


class TestCLIPlatformSkip:
    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_check_skips_platform_mismatch(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """Rules with min_version: 9 should be SKIP on a RHEL 8 host."""
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_ssh.run = MagicMock(
            return_value=Result(exit_code=0, stdout="0", stderr="")
        )

        # Host is RHEL 8
        mock_detect_platform.return_value = PlatformInfo(family="rhel", version=8)

        # Rule requires min_version: 9
        rule_file = tmp_path / "rhel9-only.yml"
        rule_file.write_text(
            "id: rhel9-only-rule\n"
            "title: RHEL 9 only rule\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 9\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '0'\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--user",
                "admin",
                "--rule",
                str(rule_file),
            ],
        )
        assert "SKIP" in result.output
        assert "rhel9-only-rule" in result.output
        clean_output = strip_ansi(result.output)
        assert "1 skip" in clean_output or (
            "1 rules" in clean_output and "skip" in clean_output
        )


class TestCLIRollbackFlag:
    @patch("runner._host_runner.SSHSession")
    def test_rollback_on_failure_shows_rolled_back(self, mock_session_cls, tmp_path):
        """--rollback-on-failure should produce 'rolled back' in output when triggered."""
        mock_ssh = MagicMock()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)

        call_count = {"sysctl_n": 0}

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                call_count["sysctl_n"] += 1
                # Always return wrong value so check and re-check fail
                return Result(exit_code=0, stdout="1", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            if "echo" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\n"
            "title: Test rule\n"
            "severity: medium\n"
            "category: kernel\n"
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
        result = runner.invoke(
            main,
            [
                "remediate",
                "--rollback-on-failure",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )
        assert "rolled back" in result.output
