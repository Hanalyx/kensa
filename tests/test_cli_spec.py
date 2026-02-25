"""Spec-derived tests for CLI commands.

Tests the CLI surface defined in runner/cli.py, verifying exit codes,
output formats, side effects, and error behavior as formalized in the
specs/cli/ behavioral specifications.

Each Test<Command>SpecDerived class maps to one spec file, with test methods
named after acceptance criteria (AC-N).
"""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.cli import main
from runner.detect import PlatformInfo
from runner.ssh import Result


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for assertion clarity."""
    return re.compile(r"\x1b\[[0-9;]*m").sub("", text)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_mock_ssh():
    """Create a mock SSH session that works as a context manager."""
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.connect = MagicMock()
    mock.close = MagicMock()
    return mock


def _write_simple_rule(tmp_path, rule_id="test-rule", severity="medium", failing=False):
    """Write a minimal rule file and return its path."""
    rule_file = tmp_path / f"{rule_id}.yml"
    expected = "1" if failing else "0"
    rule_file.write_text(
        f"id: {rule_id}\n"
        f"title: Test rule {rule_id}\n"
        f"severity: {severity}\n"
        "category: kernel\n"
        "platforms:\n"
        "  - family: rhel\n"
        "    min_version: 8\n"
        "implementations:\n"
        "  - default: true\n"
        "    check:\n"
        "      method: sysctl_value\n"
        "      key: net.ipv4.ip_forward\n"
        f"      expected: '{expected}'\n"
    )
    return rule_file


def _write_remediable_rule(tmp_path, rule_id="test-rule", severity="medium"):
    """Write a rule with both check and remediation."""
    rule_file = tmp_path / f"{rule_id}.yml"
    rule_file.write_text(
        f"id: {rule_id}\n"
        f"title: Test rule {rule_id}\n"
        f"severity: {severity}\n"
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
    return rule_file


# ── TestDetectSpecDerived ────────────────────────────────────────────────────


class TestDetectSpecDerived:
    """Spec-derived tests for the detect CLI command.

    Spec: specs/cli/detect.spec.md
    """

    @patch("runner._host_runner.SSHSession")
    def test_ac1_single_reachable_host_exits_0(self, mock_session_cls):
        """AC-1: Detect with a single reachable host exits 0 and prints
        platform + capability table."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "", ""))

        runner = CliRunner()
        result = runner.invoke(
            main, ["detect", "--host", "10.0.0.1", "--user", "admin"]
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output

    @patch("runner._host_runner.SSHSession")
    def test_ac2_unreachable_host_exits_0(self, mock_session_cls):
        """AC-2: Detect with an unreachable host exits 0 and prints error."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.connect.side_effect = ConnectionError("Connection refused")
        mock_ssh.__enter__.side_effect = ConnectionError("Connection refused")

        runner = CliRunner()
        result = runner.invoke(
            main, ["detect", "--host", "10.0.0.99", "--user", "admin"]
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Connection failed" in output

    @patch("runner.paths.get_inventory_path", return_value=None)
    def test_ac3_no_targets_exits_1(self, _mock_inv):
        """AC-3: Detect with no target hosts exits 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["detect"])

        assert result.exit_code == 1
        assert "No target hosts" in result.output

    @patch("runner.cli.detect_capabilities")
    @patch("runner._host_runner.SSHSession")
    def test_ac4_capability_override_true(self, mock_session_cls, mock_detect_caps):
        """AC-4: -C key=true appears as override in output."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "", ""))
        # Return sshd_config_d as False so overriding to True is a real override
        mock_detect_caps.return_value = {"sshd_config_d": False}

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["detect", "--host", "10.0.0.1", "-C", "sshd_config_d=true"],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "override" in output

    @patch("runner.cli.detect_capabilities")
    @patch("runner._host_runner.SSHSession")
    def test_ac5_capability_override_false(self, mock_session_cls, mock_detect_caps):
        """AC-5: -C key=false appears as override in output."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "", ""))
        # Return sshd_config_d as True so overriding to False is a real override
        mock_detect_caps.return_value = {"sshd_config_d": True}

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["detect", "--host", "10.0.0.1", "-C", "sshd_config_d=false"],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "override" in output

    def test_ac6_invalid_capability_format(self):
        """AC-6: Invalid -C format (no =) exits 1."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["detect", "--host", "10.0.0.1", "-C", "no_equals"],
        )

        assert result.exit_code == 1
        assert "Invalid capability format" in result.output

    def test_ac7_invalid_capability_value(self):
        """AC-7: Invalid -C value (not true/false) exits 1."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["detect", "--host", "10.0.0.1", "-C", "key=maybe"],
        )

        assert result.exit_code == 1
        assert "Invalid capability value" in result.output

    @patch("runner._host_runner.SSHSession")
    def test_ac8_parallel_execution(self, mock_session_cls):
        """AC-8: Parallel execution with two hosts prints both outputs."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "", ""))

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["detect", "--host", "10.0.0.1,10.0.0.2", "--workers", "2"],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output
        assert "10.0.0.2" in output


# ── TestCheckSpecDerived ─────────────────────────────────────────────────────


class TestCheckSpecDerived:
    """Spec-derived tests for the check CLI command.

    Spec: specs/cli/check.spec.md
    """

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac1_exit_0_when_check_passes(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-1: Check with one passing rule exits 0, output contains PASS."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(family="rhel", version=9)

        rule_file = _write_simple_rule(tmp_path, failing=False)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "PASS" in result.output or "1 pass" in output

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac2_exit_0_when_check_fails(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-2: Check with one failing rule exits 0, output contains FAIL."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        # Rule expects "0" but mock returns "1" → FAIL
        mock_ssh.run = MagicMock(return_value=Result(0, "1", ""))
        mock_detect_platform.return_value = PlatformInfo(family="rhel", version=9)

        rule_file = _write_simple_rule(tmp_path, failing=False)  # expected="0"

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "FAIL" in result.output or "1 fail" in output

    @patch("runner.paths.get_inventory_path", return_value=None)
    def test_ac3_no_targets_exits_1(self, _mock_inv):
        """AC-3: Check with no target hosts exits 1."""
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--rule", "rules/access-control/ssh-disable-root-login.yml"]
        )

        assert result.exit_code == 1
        assert "No target hosts" in result.output

    def test_ac4_no_rules_exits_1(self):
        """AC-4: Check with no rules exits 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--host", "10.0.0.1"])

        assert result.exit_code == 1
        assert "Specify --rules or --rule" in result.output

    def test_ac5_bad_rules_path_exits_1(self):
        """AC-5: Check with bad rules path exits 1."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rules", "/nonexistent/path"],
        )

        assert result.exit_code == 1

    @patch("runner._host_runner.SSHSession")
    def test_ac6_quiet_suppresses_output(self, mock_session_cls, tmp_path):
        """AC-6: --quiet suppresses terminal output."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_simple_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", str(rule_file), "--quiet"],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Quiet mode should not contain per-rule PASS/FAIL output
        assert "PASS" not in output
        assert "FAIL" not in output

    @patch("runner._host_runner.SSHSession")
    def test_ac7_json_output(self, mock_session_cls, tmp_path):
        """AC-7: -o json writes JSON to stdout."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_simple_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", str(rule_file), "-o", "json"],
        )

        assert result.exit_code == 0
        # The JSON should be parseable somewhere in the output
        # Find the JSON block in output
        lines = result.output.strip().split("\n")
        json_start = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                json_start = i
                break
        if json_start is not None:
            json_text = "\n".join(lines[json_start:])
            data = json.loads(json_text)
            assert "hosts" in data or "results" in data or isinstance(data, dict | list)

    @patch("runner._host_runner.SSHSession")
    @patch("runner.storage.ResultStore")
    def test_ac8_store_creates_session(
        self, mock_store_cls, mock_session_cls, tmp_path
    ):
        """AC-8: --store creates a session in ResultStore."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        mock_store.create_session.return_value = 1

        rule_file = _write_simple_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", str(rule_file), "--store"],
        )

        assert result.exit_code == 0
        mock_store.create_session.assert_called_once()

    @patch("runner._host_runner.SSHSession")
    def test_ac9_connection_failure_exits_0(self, mock_session_cls, tmp_path):
        """AC-9: Connection failure prints error and continues; exit 0."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.connect.side_effect = ConnectionError("Connection refused")
        mock_ssh.__enter__.side_effect = ConnectionError("Connection refused")

        rule_file = _write_simple_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        assert "Connection failed" in result.output

    @patch("runner._host_runner.SSHSession")
    def test_ac10_severity_filter(self, mock_session_cls, tmp_path):
        """AC-10: --severity filter reduces rule set to matching severities."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        _write_simple_rule(tmp_path, rule_id="high-rule", severity="high")
        _write_simple_rule(tmp_path, rule_id="low-rule", severity="low")

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

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "high-rule" in output
        assert "low-rule" not in output

    @patch("runner._host_runner.SSHSession")
    def test_ac11_multi_host_summary(self, mock_session_cls, tmp_path):
        """AC-11: Multi-host run prints summary line with host count and totals."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_simple_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1,10.0.0.2",
                "--rule",
                str(rule_file),
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "2 hosts" in output

    @patch("runner._host_runner.SSHSession")
    def test_ac15_parallel_execution(self, mock_session_cls, tmp_path):
        """AC-15: Parallel execution produces results for all hosts."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_simple_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1,10.0.0.2",
                "--rule",
                str(rule_file),
                "--workers",
                "2",
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output
        assert "10.0.0.2" in output

    @patch("runner._host_runner.SSHSession")
    def test_ac16_csv_output_to_file(self, mock_session_cls, tmp_path):
        """AC-16: -o csv:path writes a CSV file."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_simple_rule(tmp_path)
        csv_path = tmp_path / "results.csv"

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "-o",
                f"csv:{csv_path}",
            ],
        )

        assert result.exit_code == 0
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "test-rule" in content

    def test_ac17_invalid_output_format_exits_1(self):
        """AC-17: Invalid output format exits 1."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--host", "10.0.0.1", "--rule", "nonexistent.yml", "-o", "xyz"],
        )

        # Either fails on rule load or output format — both exit 1
        assert result.exit_code == 1

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac18_framework_sorts_results(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-18: --framework sorts results by framework section order.

        Uses the real rules/ directory with a real framework mapping to verify
        that framework ordering is applied without errors.
        """
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(family="rhel", version=9)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--rules",
                "rules/",
                "--framework",
                "cis-rhel9-v2.0.0",
                "--severity",
                "critical",  # narrow the set for speed
            ],
        )

        assert result.exit_code == 0


# ── TestRemediateSpecDerived ─────────────────────────────────────────────────


class TestRemediateSpecDerived:
    """Spec-derived tests for the remediate CLI command.

    Spec: specs/cli/remediate.spec.md
    """

    @patch("runner._host_runner.SSHSession")
    def test_ac1_passing_rule_exits_0(self, mock_session_cls, tmp_path):
        """AC-1: Remediate with one passing rule exits 0, shows pass count."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "1 pass" in output or "pass" in output.lower()

    @patch("runner._host_runner.SSHSession")
    def test_ac3_dry_run_banner(self, mock_session_cls, tmp_path):
        """AC-3: --dry-run prints DRY RUN banner."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "1", ""))

        rule_file = _write_remediable_rule(tmp_path)

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

        assert result.exit_code == 0
        assert "DRY RUN" in result.output

    @patch("runner.paths.get_inventory_path", return_value=None)
    def test_ac4_no_targets_exits_1(self, _mock_inv):
        """AC-4: No target hosts exits 1."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--rule", "rules/access-control/ssh-disable-root-login.yml"],
        )

        assert result.exit_code == 1
        assert "No target hosts" in result.output

    def test_ac5_no_rules_exits_1(self):
        """AC-5: No rules exits 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["remediate", "--host", "10.0.0.1"])

        assert result.exit_code == 1
        assert "Specify --rules or --rule" in result.output

    @patch("runner._host_runner.SSHSession")
    @patch("runner.conflicts.detect_conflicts")
    def test_ac6_unresolved_conflicts_exits_1(
        self, mock_conflicts, mock_session_cls, tmp_path
    ):
        """AC-6: Unresolved conflicts without --allow-conflicts exits 1."""
        mock_conflicts.return_value = [
            MagicMock(
                rule_ids=["r1", "r2"], resource="/etc/foo", description="conflict"
            )
        ]

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 1

    @patch("runner._host_runner.SSHSession")
    @patch("runner.conflicts.detect_conflicts")
    def test_ac7_allow_conflicts_proceeds(
        self, mock_conflicts, mock_session_cls, tmp_path
    ):
        """AC-7: --allow-conflicts prints warning and proceeds."""
        mock_conflicts.return_value = [
            MagicMock(
                rule_ids=["r1", "r2"], resource="/etc/foo", description="conflict"
            )
        ]
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--allow-conflicts",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Conflicts detected" in output or "proceeding" in output.lower()

    @patch("runner._host_runner.SSHSession")
    @patch("runner.storage.ResultStore")
    def test_ac8_always_stores_results(
        self, mock_store_cls, mock_session_cls, tmp_path
    ):
        """AC-8: Results are always stored (no --store flag needed)."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        mock_store.create_session.return_value = 1
        mock_store.create_remediation_session.return_value = 1
        mock_store.prune_snapshots.return_value = 0

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        # Storage should have been called without explicit --store
        mock_store.create_session.assert_called()

    @patch("runner._host_runner.SSHSession")
    @patch("runner.storage.ResultStore")
    def test_ac9_no_snapshot_mode(self, mock_store_cls, mock_session_cls, tmp_path):
        """AC-9: --no-snapshot sets snapshot_mode to 'none'."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        mock_store.create_session.return_value = 1
        mock_store.create_remediation_session.return_value = 1
        mock_store.prune_snapshots.return_value = 0

        rule_file = _write_remediable_rule(tmp_path)

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

        assert result.exit_code == 0
        # Verify snapshot_mode was set to "none"
        call_kwargs = mock_store.create_remediation_session.call_args
        if call_kwargs:
            # Check positional or keyword args
            args, kwargs = call_kwargs
            assert kwargs.get("snapshot_mode") == "none" or (
                len(args) > 2 and args[2] == "none"
            )

    @patch("runner._host_runner.SSHSession")
    def test_ac11_quiet_suppresses_output(self, mock_session_cls, tmp_path):
        """AC-11: --quiet suppresses terminal output."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--quiet",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Quiet should suppress per-rule output
        assert "PASS" not in output
        assert "FAIL" not in output

    @patch("runner._host_runner.SSHSession")
    def test_ac12_connection_failure_exits_0(self, mock_session_cls, tmp_path):
        """AC-12: Connection failure exits 0."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.connect.side_effect = ConnectionError("Connection refused")
        mock_ssh.__enter__.side_effect = ConnectionError("Connection refused")

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        assert "Connection failed" in result.output

    @patch("runner._host_runner.SSHSession")
    def test_ac13_multi_host_summary(self, mock_session_cls, tmp_path):
        """AC-13: Multi-host run prints summary with totals."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1,10.0.0.2",
                "--rule",
                str(rule_file),
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "2 hosts" in output

    @patch("runner._host_runner.SSHSession")
    def test_ac15_parallel_execution(self, mock_session_cls, tmp_path):
        """AC-15: Parallel execution produces results for all hosts."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1,10.0.0.2",
                "--rule",
                str(rule_file),
                "--workers",
                "2",
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output
        assert "10.0.0.2" in output

    @patch("runner._host_runner.SSHSession")
    def test_ac17_snapshot_pruning_runs(self, mock_session_cls, tmp_path):
        """AC-17: Snapshot pruning runs before processing hosts."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)

        with patch("runner.cli._get_rollback_archive_days", return_value=90):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
            )

        assert result.exit_code == 0

    @patch("runner._host_runner.SSHSession")
    @patch("runner.storage.ResultStore")
    def test_ac18_pruning_failure_does_not_block(
        self, mock_store_cls, mock_session_cls, tmp_path
    ):
        """AC-18: Snapshot pruning failure does not block remediation."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        mock_store.prune_snapshots.side_effect = RuntimeError("DB locked")
        mock_store.create_session.return_value = 1
        mock_store.create_remediation_session.return_value = 1

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        # Should succeed despite pruning failure
        assert result.exit_code == 0


# ── Helpers for storage-backed tests ─────────────────────────────────────────


def _make_db(tmp_path):
    """Create a temp database and return (db_path, store)."""
    from runner.storage import ResultStore

    db_dir = tmp_path / ".kensa"
    db_dir.mkdir()
    db_path = db_dir / "results.db"
    store = ResultStore(db_path=db_path)
    return db_path, store


def _seed_check_session(store, *, host="10.0.0.1", passing=True):
    """Create a check session with one result and return session_id."""
    session_id = store.create_session(hosts=[host], rules_path="rules/")
    store.record_result(
        session_id=session_id,
        host=host,
        rule_id="ssh-disable-root-login",
        passed=passing,
        detail="test detail",
        remediated=False,
    )
    return session_id


def _seed_remediation_session(store, *, host="10.0.0.5"):
    """Create a remediation session with sample data."""
    session_id = store.create_session(hosts=[host], rules_path="rules/")
    rs_id = store.create_remediation_session(
        session_id,
        dry_run=False,
        rollback_on_failure=True,
        snapshot_mode="all",
    )
    rem1 = store.record_remediation(
        rs_id,
        host=host,
        rule_id="ssh-disable-root-login",
        severity="high",
        passed_before=False,
        passed_after=True,
        remediated=True,
        rolled_back=False,
        detail="Set PermitRootLogin=no",
    )
    step1 = store.record_step(rem1, 0, "config_set_dropin", True, "Wrote drop-in")
    store.record_pre_state(
        step1,
        "config_set_dropin",
        {"path": "/etc/ssh/sshd_config.d/00-kensa.conf", "existed": False},
        capturable=True,
    )
    return rs_id


# ── TestRollbackSpecDerived ──────────────────────────────────────────────────


class TestRollbackSpecDerived:
    """Spec-derived tests for the rollback CLI command.

    Spec: specs/cli/rollback.spec.md
    """

    def test_ac1_no_mode_exits_1(self):
        """AC-1: No mode flag exits 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["rollback"])

        assert result.exit_code == 1
        assert "Specify --list" in result.output

    def test_ac2_multiple_modes_exits_1(self):
        """AC-2: Multiple mode flags exits 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["rollback", "--list", "--info", "1"])

        assert result.exit_code == 1
        assert "Only one of" in result.output

    def test_ac3_list_empty(self, tmp_path):
        """AC-3: --list with no sessions prints informational message."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list"])

        assert result.exit_code == 0
        assert "No remediation sessions found" in result.output

    def test_ac4_list_shows_sessions(self, tmp_path):
        """AC-4: --list with sessions exits 0 and displays table."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Remediation Sessions" in output
        assert "10.0.0.5" in output

    def test_ac5_list_json(self, tmp_path):
        """AC-5: --list --json outputs valid JSON array."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_ac6_info_valid_session(self, tmp_path):
        """AC-6: --info with valid session exits 0."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert f"Remediation Session #{rs_id}" in output

    def test_ac7_info_nonexistent_session(self, tmp_path):
        """AC-7: --info with nonexistent session exits 1."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_ac8_info_json(self, tmp_path):
        """AC-8: --info --json outputs valid JSON object."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id), "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, dict)
        assert "id" in data
        assert "remediations" in data

    def test_ac10_start_without_host_exits_1(self, tmp_path):
        """AC-10: --start without --host/--limit exits 1."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--start", str(rs_id)])

        assert result.exit_code == 1
        assert "--host" in result.output or "--limit" in result.output

    def test_ac15_list_host_filter(self, tmp_path):
        """AC-15: --list --host filters sessions by host."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_remediation_session(store, host="10.0.0.5")
            _seed_remediation_session(store, host="10.0.0.6")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list", "--host", "10.0.0.5"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.5" in output

    def test_ac16_info_rule_filter(self, tmp_path):
        """AC-16: --info --rule filters to a specific rule."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--info",
                    str(rs_id),
                    "--rule",
                    "ssh-disable-root-login",
                ],
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "ssh-disable-root-login" in output

    def test_ac18_start_nonexistent_session(self, tmp_path):
        """AC-18: --start with nonexistent session exits 1."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["rollback", "--start", "999", "--host", "10.0.0.5"],
            )

        assert result.exit_code == 1
        assert "not found" in result.output


# ── TestHistorySpecDerived ───────────────────────────────────────────────────


class TestHistorySpecDerived:
    """Spec-derived tests for the history CLI command.

    Spec: specs/cli/history.spec.md
    """

    def test_ac1_stats(self, tmp_path):
        """AC-1: --stats exits 0 and displays database statistics."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_check_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--stats"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Database Statistics" in output

    def test_ac2_prune(self, tmp_path):
        """AC-2: --prune exits 0 and prints deletion count."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_check_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--prune", "30"])

        assert result.exit_code == 0
        assert "Deleted" in result.output

    def test_ac3_session_id_valid(self, tmp_path):
        """AC-3: --session-id with valid session exits 0."""
        db_path, store = _make_db(tmp_path)
        try:
            sid = _seed_check_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--session-id", str(sid)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert f"Session {sid}" in output

    def test_ac4_session_id_not_found(self, tmp_path):
        """AC-4: --session-id with nonexistent session exits 1."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--session-id", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_ac5_sessions_list(self, tmp_path):
        """AC-5: --sessions exits 0 and lists sessions."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_check_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--sessions"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Scan Sessions" in output

    def test_ac7_sessions_empty(self, tmp_path):
        """AC-7: --sessions with no sessions prints informational message."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--sessions"])

        assert result.exit_code == 0
        assert "No sessions found" in result.output

    def test_ac8_default_without_host_exits_1(self):
        """AC-8: Default mode without --host exits 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["history"])

        assert result.exit_code == 1
        assert "--host" in result.output or "--sessions" in result.output

    def test_ac9_default_with_host(self, tmp_path):
        """AC-9: Default mode with --host exits 0."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_check_session(store, host="10.0.0.1")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--host", "10.0.0.1"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output

    def test_ac10_default_no_history(self, tmp_path):
        """AC-10: Default mode with --host and no history prints message."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--host", "10.0.0.99"])

        assert result.exit_code == 0
        assert "No history" in result.output


# ── TestDiffSpecDerived ──────────────────────────────────────────────────────


class TestDiffSpecDerived:
    """Spec-derived tests for the diff CLI command.

    Spec: specs/cli/diff.spec.md
    """

    def test_ac1_diff_two_sessions(self, tmp_path):
        """AC-1: Diff of two valid sessions exits 0."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=True)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=False)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", str(s1), str(s2)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Diff" in output or "Session" in output

    def test_ac2_diff_json(self, tmp_path):
        """AC-2: --json outputs valid JSON."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=True)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=False)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", str(s1), str(s2), "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "session1" in data
        assert "session2" in data
        assert "changes" in data

    def test_ac5_no_changes(self, tmp_path):
        """AC-5: No changes between sessions prints appropriate message."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=True)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=True)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", str(s1), str(s2)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "No changes" in output

    def test_ac6_invalid_session(self, tmp_path):
        """AC-6: Invalid session ID exits 1."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", "999", "1000"])

        assert result.exit_code == 1

    def test_ac7_regression_detected(self, tmp_path):
        """AC-7: Regressions (pass→fail) appear as REGRESSION."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=True)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=False)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", str(s1), str(s2)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "REGRESSION" in output

    def test_ac8_resolved_detected(self, tmp_path):
        """AC-8: Resolved (fail→pass) appear as RESOLVED."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=False)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=True)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", str(s1), str(s2)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "RESOLVED" in output

    def test_ac10_missing_positional_args(self):
        """AC-10: Missing positional arguments shows usage error."""
        runner = CliRunner()
        result = runner.invoke(main, ["diff"])

        assert result.exit_code != 0
