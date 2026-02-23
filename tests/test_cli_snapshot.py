"""Tests for --no-snapshot flag on the remediate command.

Verifies Phase 6 behavior: pre-state snapshot capture is ON by default
and can be disabled with --no-snapshot.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.cli import main
from runner.ssh import Result


def _make_mock_ssh():
    """Create a mock SSH session for remediation tests."""
    mock_ssh = MagicMock()
    mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
    mock_ssh.__exit__ = MagicMock(return_value=False)
    mock_ssh.connect = MagicMock()
    mock_ssh.close = MagicMock()
    return mock_ssh


RULE_YAML = (
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


class TestSnapshotHelp:
    def test_no_snapshot_in_help(self):
        """--no-snapshot flag should appear in remediate help."""
        runner = CliRunner()
        result = runner.invoke(main, ["remediate", "--help"])
        assert result.exit_code == 0
        assert "--no-snapshot" in result.output


class TestSnapshotDefault:
    @patch("runner._host_runner.SSHSession")
    def test_default_remediate_captures_pre_state(self, mock_session_cls, tmp_path):
        """Default remediate (no --no-snapshot) should capture pre-state snapshots."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        capture_calls = []

        def mock_run(cmd, *, timeout=None):
            # Track capture-related commands (sysctl -n for capture, cat for persist check)
            if "sysctl -n" in cmd:
                capture_calls.append(cmd)
                # First call is the check, second is capture, third is re-check
                return Result(exit_code=0, stdout="1", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            if "cat /etc/sysctl" in cmd:
                capture_calls.append(cmd)
                return Result(exit_code=1, stdout="", stderr="")
            if "echo" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(RULE_YAML)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )
        assert result.exit_code == 0, result.output

        # The sysctl capture handler runs 'sysctl -n <key>' to read current value
        # and 'cat /etc/sysctl.d/99-kensa-*.conf' or similar to check persist file.
        # With snapshot enabled (default), we should see capture-related commands
        # beyond just the check/re-check calls.
        # At minimum: check sysctl -n, capture sysctl -n, capture cat, re-check sysctl -n
        assert len(capture_calls) >= 3, (
            f"Expected at least 3 sysctl/cat calls (check + capture + re-check), "
            f"got {len(capture_calls)}: {capture_calls}"
        )

    @patch("runner._host_runner.SSHSession")
    def test_no_snapshot_disables_pre_state_capture(self, mock_session_cls, tmp_path):
        """--no-snapshot should skip pre-state capture."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        capture_calls = []

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                capture_calls.append(cmd)
                return Result(exit_code=0, stdout="1", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            if "cat /etc/sysctl" in cmd:
                capture_calls.append(cmd)
                return Result(exit_code=1, stdout="", stderr="")
            if "echo" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(RULE_YAML)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--no-snapshot",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )
        assert result.exit_code == 0, result.output

        # With --no-snapshot, capture is disabled. We should see fewer calls:
        # Only check sysctl -n (initial) and re-check sysctl -n (post-remediation).
        # No capture sysctl -n or cat calls.
        # The cat /etc/sysctl calls are capture-only, so should be absent.
        cat_calls = [c for c in capture_calls if "cat /etc/sysctl" in c]
        assert len(cat_calls) == 0, (
            f"Expected no capture cat calls with --no-snapshot, "
            f"got {len(cat_calls)}: {cat_calls}"
        )


class TestSnapshotStoreIntegration:
    @patch("runner.cli._store_remediation_results")
    @patch("runner._host_runner.SSHSession")
    def test_default_passes_snapshot_mode_all(
        self, mock_session_cls, mock_store, tmp_path
    ):
        """Default remediate should pass snapshot_mode='all' to storage."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(
            return_value=Result(exit_code=0, stdout="0", stderr="")
        )

        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(RULE_YAML)

        runner = CliRunner()
        runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )

        mock_store.assert_called_once()
        _, kwargs = mock_store.call_args
        assert kwargs["snapshot_mode"] == "all"

    @patch("runner.cli._store_remediation_results")
    @patch("runner._host_runner.SSHSession")
    def test_no_snapshot_passes_snapshot_mode_none(
        self, mock_session_cls, mock_store, tmp_path
    ):
        """--no-snapshot should pass snapshot_mode='none' to storage."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(
            return_value=Result(exit_code=0, stdout="0", stderr="")
        )

        rule_file = tmp_path / "test-rule.yml"
        rule_file.write_text(RULE_YAML)

        runner = CliRunner()
        runner.invoke(
            main,
            [
                "remediate",
                "--no-snapshot",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )

        mock_store.assert_called_once()
        _, kwargs = mock_store.call_args
        assert kwargs["snapshot_mode"] == "none"


class TestSnapshotUnitLevel:
    def test_run_remediation_snapshot_true_captures(self, mock_ssh):
        """run_remediation with snapshot=True (default) should populate pre_state."""
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=0, stdout="1", stderr=""),
                "cat /etc/sysctl": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        remediation = {
            "mechanism": "sysctl_set",
            "key": "net.ipv4.ip_forward",
            "value": "0",
        }
        from runner.handlers.remediation import run_remediation

        ok, detail, steps = run_remediation(
            ssh, remediation, dry_run=False, snapshot=True
        )
        assert len(steps) == 1
        assert steps[0].pre_state is not None
        assert steps[0].pre_state.mechanism == "sysctl_set"

    def test_run_remediation_snapshot_false_skips_capture(self, mock_ssh):
        """run_remediation with snapshot=False should leave pre_state as None."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        remediation = {
            "mechanism": "sysctl_set",
            "key": "net.ipv4.ip_forward",
            "value": "0",
        }
        from runner.handlers.remediation import run_remediation

        ok, detail, steps = run_remediation(
            ssh, remediation, dry_run=False, snapshot=False
        )
        assert len(steps) == 1
        assert steps[0].pre_state is None

    def test_run_remediation_multi_step_snapshot_false(self, mock_ssh):
        """Multi-step remediation with snapshot=False should have no pre_state."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "rpm -q": Result(exit_code=0, stdout="aide-0.16", stderr=""),
            }
        )
        remediation = {
            "steps": [
                {"mechanism": "sysctl_set", "key": "k", "value": "0"},
                {"mechanism": "package_present", "name": "aide"},
            ]
        }
        from runner.handlers.remediation import run_remediation

        ok, detail, steps = run_remediation(
            ssh, remediation, dry_run=False, snapshot=False
        )
        assert len(steps) == 2
        for step in steps:
            assert step.pre_state is None
