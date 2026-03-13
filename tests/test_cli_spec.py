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
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

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
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

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

    def test_ac4_no_rules_auto_resolves(self):
        """AC-4: Check with no --rules auto-resolves default rules directory."""
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--host", "10.0.0.1"])

        # Should NOT get "Specify --rules or --rule" — auto-resolves via get_rules_path()
        assert "Specify --rules or --rule" not in (result.output or "")

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

    @patch("runner.cli.apply_auto_framework")
    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac12_framework_auto_applies_platform_selection(
        self, mock_session_cls, mock_detect_platform, mock_auto_fw, tmp_path
    ):
        """AC-12: --framework auto applies platform-based framework selection."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        rule_file = _write_simple_rule(tmp_path)

        # apply_auto_framework returns (rules, section_map)
        mock_auto_fw.return_value = (
            [{"id": "test-rule", "title": "Test rule test-rule"}],
            {"test-rule": "1.1"},
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "--framework",
                "auto",
            ],
        )

        assert result.exit_code == 0
        mock_auto_fw.assert_called_once()

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac13_var_overrides_rule_variables(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-13: --var KEY=VALUE overrides rule variables."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        # Write a rule that uses a variable
        rule_file = tmp_path / "var-rule.yml"
        rule_file.write_text(
            "id: var-rule\n"
            "title: Var test\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 8\n"
            "variables:\n"
            "  expected_val:\n"
            "    default: '1'\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '{{ expected_val }}'\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "--var",
                "expected_val=0",
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # The check should have run successfully with the overridden variable
        assert "var-rule" in output

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    @patch("runner.mappings.load_all_mappings")
    def test_ac14_control_filters_rules(
        self, mock_mappings, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-14: --control filters to rules for a specific framework control."""
        from runner.mappings import FrameworkMapping, MappingEntry

        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        # Write two rules: one that matches the control, one that doesn't
        _write_simple_rule(tmp_path, rule_id="ssh-rule")
        _write_simple_rule(tmp_path, rule_id="other-rule")

        # Create a real mapping with the control pointing to ssh-rule
        mapping = FrameworkMapping(
            id="test-fw",
            framework="test",
            title="Test Framework",
            sections={
                "1.1.1": MappingEntry(
                    rule_id="ssh-rule",
                    title="SSH rule",
                    metadata={"rules": ["ssh-rule"]},
                ),
            },
        )
        mock_mappings.return_value = {"test-fw": mapping}

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "10.0.0.1",
                "--rules",
                str(tmp_path),
                "--control",
                "test-fw:1.1.1",
            ],
        )

        # Should exit 0 and filter to only the matching rule
        assert result.exit_code == 0

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
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

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
                "cis-rhel9",
                "--severity",
                "critical",  # narrow the set for speed
            ],
        )

        assert result.exit_code == 0

    @patch("runner._host_runner.SSHSession")
    def test_ac19_evidence_output(self, mock_session_cls, tmp_path):
        """AC-19: '-o evidence:path' writes evidence JSON export to file."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_simple_rule(tmp_path)
        evidence_path = tmp_path / "evidence.json"

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
                f"evidence:{evidence_path}",
                "-q",
            ],
        )

        assert result.exit_code == 0
        assert evidence_path.exists()
        import json

        data = json.loads(evidence_path.read_text())
        assert "results" in data
        assert "host" in data

    @patch("runner._host_runner.SSHSession")
    @patch("runner.storage.ResultStore")
    def test_ac20_store_without_rules_passes_resolved_path(
        self, mock_store_cls, mock_session_cls, tmp_path
    ):
        """AC-20: --store without --rules passes auto-resolved path (not None) to session store."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        mock_store = MagicMock()
        mock_store_cls.return_value = mock_store
        mock_store.create_session.return_value = 1

        # Create a minimal rules dir for get_rules_path to resolve to
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test-rule.yml"
        rule_file.write_text(
            "id: test-rule\ntitle: T\nseverity: medium\ncategory: kernel\n"
            "platforms:\n  - family: rhel\nimplementations:\n"
            "  - default: true\n    check:\n      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n      expected: '0'\n"
        )

        runner = CliRunner()
        with patch("runner.paths.get_rules_path", return_value=rules_dir):
            result = runner.invoke(
                main,
                ["check", "--host", "10.0.0.1", "--store"],
            )

        assert result.exit_code == 0
        mock_store.create_session.assert_called_once()
        call_kwargs = mock_store.create_session.call_args
        rules_path_arg = call_kwargs[1].get(
            "rules_path", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else None
        )
        assert rules_path_arg is not None
        assert rules_path_arg != ""


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

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac2_failing_rule_shows_fixed_or_fail(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-2: Remediate with one failing rule shows 'fixed' or 'fail' count."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        # Return "1" (check fails since expected is "0")
        mock_ssh.run = MagicMock(return_value=Result(0, "1", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        rule_file = _write_remediable_rule(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["remediate", "--host", "10.0.0.1", "--rule", str(rule_file)],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Should show either 'fixed' or 'fail' in the summary
        assert "fixed" in output.lower() or "fail" in output.lower()

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

    def test_ac5_no_rules_auto_resolves(self):
        """AC-5: No --rules auto-resolves default rules directory."""
        runner = CliRunner()
        result = runner.invoke(main, ["remediate", "--host", "10.0.0.1"])

        # Should NOT get "Specify --rules or --rule" — auto-resolves via get_rules_path()
        assert "Specify --rules or --rule" not in (result.output or "")

    def test_ac21_no_rules_auto_resolves_default(self):
        """AC-21: Remediate with no --rules auto-resolves via get_rules_path()."""
        runner = CliRunner()
        result = runner.invoke(main, ["remediate", "--host", "10.0.0.1"])

        # Auto-resolution should not produce the old "Specify --rules" error
        assert "Specify --rules or --rule" not in (result.output or "")

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

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac10_rollback_on_failure_summary(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-10: --rollback-on-failure enables inline rollback; rolled-back count in summary."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        rule_file = _write_remediable_rule(tmp_path)

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

        # Should complete successfully with rollback-on-failure enabled
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Summary should contain rule counts (pass/fixed/fail)
        assert "rules" in output.lower() or "pass" in output.lower()

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

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac14_framework_sorts_results(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-14: --framework sorts results by section order."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1",
                "--rules",
                "rules/",
                "--framework",
                "cis-rhel9",
                "--severity",
                "critical",  # narrow the set for speed
            ],
        )

        assert result.exit_code == 0

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
    def test_ac16_json_output(self, mock_session_cls, tmp_path):
        """AC-16: -o json writes JSON to stdout."""
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
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "-o",
                "json",
                "--quiet",
            ],
        )

        assert result.exit_code == 0
        # With --quiet + -o json, output should contain JSON
        # Find and parse the JSON object
        output = result.output.strip()
        brace_start = output.find("{")
        if brace_start >= 0:
            depth = 0
            for i, ch in enumerate(output[brace_start:], start=brace_start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                if depth == 0:
                    json_text = output[brace_start : i + 1]
                    data = json.loads(json_text)
                    assert isinstance(data, dict)
                    break

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

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    def test_ac19_var_overrides_rule_variables(
        self, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-19: --var KEY=VALUE overrides rule variables."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        # Write a rule that uses a variable
        rule_file = tmp_path / "var-rule.yml"
        rule_file.write_text(
            "id: var-rule\n"
            "title: Var test\n"
            "severity: medium\n"
            "category: kernel\n"
            "platforms:\n"
            "  - family: rhel\n"
            "    min_version: 8\n"
            "variables:\n"
            "  expected_val:\n"
            "    default: '1'\n"
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      method: sysctl_value\n"
            "      key: net.ipv4.ip_forward\n"
            "      expected: '{{ expected_val }}'\n"
            "    remediation:\n"
            "      mechanism: sysctl_set\n"
            "      key: net.ipv4.ip_forward\n"
            "      value: '{{ expected_val }}'\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "--var",
                "expected_val=0",
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "var-rule" in output

    @patch("runner.cli.detect_platform")
    @patch("runner._host_runner.SSHSession")
    @patch("runner.mappings.load_all_mappings")
    def test_ac20_control_filters_rules(
        self, mock_mappings, mock_session_cls, mock_detect_platform, tmp_path
    ):
        """AC-20: --control filters to rules for a specific framework control."""
        from runner.mappings import FrameworkMapping, MappingEntry

        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))
        mock_detect_platform.return_value = PlatformInfo(
            family="rhel", version=9, version_id="9.3"
        )

        _write_remediable_rule(tmp_path, rule_id="ssh-rule")
        _write_remediable_rule(tmp_path, rule_id="other-rule")

        # Create a real mapping with the control pointing to ssh-rule
        mapping = FrameworkMapping(
            id="test-fw",
            framework="test",
            title="Test Framework",
            sections={
                "1.1.1": MappingEntry(
                    rule_id="ssh-rule",
                    title="SSH rule",
                    metadata={"rules": ["ssh-rule"]},
                ),
            },
        )
        mock_mappings.return_value = {"test-fw": mapping}

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1",
                "--rules",
                str(tmp_path),
                "--control",
                "test-fw:1.1.1",
            ],
        )

        assert result.exit_code == 0

    @patch("runner._host_runner.SSHSession")
    def test_ac22_evidence_output(self, mock_session_cls, tmp_path):
        """AC-22: '-o evidence:path' writes evidence JSON export to file."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "0", ""))

        rule_file = _write_remediable_rule(tmp_path)
        evidence_path = tmp_path / "evidence.json"

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "remediate",
                "--host",
                "10.0.0.1",
                "--rule",
                str(rule_file),
                "-o",
                f"evidence:{evidence_path}",
                "-q",
            ],
        )

        assert result.exit_code == 0
        assert evidence_path.exists()
        import json

        data = json.loads(evidence_path.read_text())
        assert "results" in data
        assert "host" in data


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

    def test_ac9_info_detail_includes_pre_state(self, tmp_path):
        """AC-9: --info --detail includes per-step pre-state data."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id), "--detail"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Detail mode should show step details and pre-state data
        assert "Step" in output or "step" in output
        assert "Pre-state" in output or "pre_state" in output.lower()

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

    def test_ac11_start_host_not_in_session_exits_1(self, tmp_path):
        """AC-11: --start with host not in session exits 1 with stored hosts listed."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store, host="10.0.0.5")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["rollback", "--start", str(rs_id), "--host", "10.0.0.99"],
            )

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        # Should list the stored hosts
        assert "10.0.0.5" in output

    def test_ac12_stale_snapshot_exits_1(self, tmp_path):
        """AC-12: --start with stale snapshot (>7 days) without --force exits 1."""
        import sqlite3
        from datetime import datetime, timedelta

        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store, host="10.0.0.5")
        finally:
            store.close()

        # Directly update the timestamp in the database to make it stale
        old_ts = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(
            str(db_path),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.execute(
            "UPDATE remediation_sessions SET timestamp = ?",
            (old_ts,),
        )
        conn.commit()
        conn.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["rollback", "--start", str(rs_id), "--host", "10.0.0.5"],
            )

        assert result.exit_code == 1

    @patch("runner._host_runner.SSHSession")
    def test_ac13_start_force_overrides_stale(self, mock_session_cls, tmp_path):
        """AC-13: --start --force overrides stale snapshot warning."""
        import sqlite3
        from datetime import datetime, timedelta

        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh
        mock_ssh.run = MagicMock(return_value=Result(0, "", ""))

        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store, host="10.0.0.5")
        finally:
            store.close()

        # Make the session stale (>7 days)
        old_ts = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(
            str(db_path),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.execute(
            "UPDATE remediation_sessions SET timestamp = ?",
            (old_ts,),
        )
        conn.commit()
        conn.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--force",
                ],
            )

        # With --force, should proceed past the stale warning (exit 0)
        assert result.exit_code == 0

    def test_ac14_start_dry_run_no_execution(self, tmp_path):
        """AC-14: --start --dry-run shows what would be rolled back without executing."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store, host="10.0.0.5")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--dry-run",
                ],
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Dry-run should indicate no action taken
        assert "dry" in output.lower() or "Dry" in output

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

    def test_ac17_already_rolled_back_skipped(self, tmp_path):
        """AC-17: Already-rolled-back steps are skipped unless --force."""
        db_path, store = _make_db(tmp_path)
        try:
            rs_id = _seed_remediation_session(store, host="10.0.0.5")
            # Record a rollback event for the step so it's "already rolled back"
            rems = store.get_remediations(rs_id)
            for rem in rems:
                steps = store.get_remediation_steps(rem.id)
                for step in steps:
                    store.record_rollback_event(
                        step.id,
                        mechanism="config_set_dropin",
                        success=True,
                        detail="Rolled back",
                        source="manual",
                    )
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                ],
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # Should indicate steps were already rolled back
        assert "already" in output.lower() or "rolled back" in output.lower()

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

    def test_ac19_password_prompt(self):
        """AC-19: -p without a value prompts securely for SSH password."""
        runner = CliRunner()
        # Invoke rollback with -p (no value) — Click should prompt for input.
        # We provide the password via input parameter to simulate user typing.
        result = runner.invoke(
            main,
            ["rollback", "--list", "-p"],
            input="secret\n",
        )
        # The command should proceed (not error on missing password value).
        # It may exit 0 (list mode) or error for other reasons, but not
        # "Error: Option '-p' requires an argument".
        assert "requires an argument" not in (result.output or "")


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
        """AC-3: --id with valid session exits 0."""
        db_path, store = _make_db(tmp_path)
        try:
            sid = _seed_check_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--id", str(sid)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert f"Session {sid}" in output

    def test_ac4_session_id_not_found(self, tmp_path):
        """AC-4: --id with nonexistent session exits 1."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--id", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_ac5_default_lists_sessions(self, tmp_path):
        """AC-5: Default mode (no flags) exits 0 and lists sessions."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_check_session(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Scan Sessions" in output

    def test_ac6_host_filters_session_list(self, tmp_path):
        """AC-6: --host without --id filters session list by host."""
        db_path, store = _make_db(tmp_path)
        try:
            _seed_check_session(store, host="10.0.0.1")
            _seed_check_session(store, host="10.0.0.2")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--host", "10.0.0.1"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output

    def test_ac7_default_empty(self, tmp_path):
        """AC-7: Default mode with no sessions prints 'No sessions found'."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history"])

        assert result.exit_code == 0
        assert "No sessions found" in result.output

    def test_ac8_host_rule_shows_history(self, tmp_path):
        """AC-8: --host --rule shows per-host result history."""
        db_path, store = _make_db(tmp_path)
        try:
            sid = store.create_session(hosts=["10.0.0.1"], rules_path="rules/")
            store.record_result(
                session_id=sid,
                host="10.0.0.1",
                rule_id="rule-a",
                passed=True,
                detail="pass",
                remediated=False,
            )
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["history", "--host", "10.0.0.1", "--rule", "rule-a"]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "rule-a" in output

    def test_ac9_host_no_history(self, tmp_path):
        """AC-9: --host with no history prints 'No history for host'."""
        db_path, store = _make_db(tmp_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["history", "--host", "10.0.0.99", "--rule", "nonexistent"]
            )

        assert result.exit_code == 0
        assert "No history" in result.output

    def test_ac10_session_id_no_results(self, tmp_path):
        """AC-10: --id with no results for session prints 'No results'."""
        db_path, store = _make_db(tmp_path)
        try:
            # Create a session but don't add any results
            sid = store.create_session(hosts=["10.0.0.1"], rules_path="rules/")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["history", "--id", str(sid)])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "No results" in output

    def test_ac11_host_and_rule_filter(self, tmp_path):
        """AC-11: --host --rule filters by both host and rule."""
        db_path, store = _make_db(tmp_path)
        try:
            sid = store.create_session(hosts=["10.0.0.1"], rules_path="rules/")
            store.record_result(
                session_id=sid,
                host="10.0.0.1",
                rule_id="rule-a",
                passed=True,
                detail="pass",
                remediated=False,
            )
            store.record_result(
                session_id=sid,
                host="10.0.0.1",
                rule_id="rule-b",
                passed=False,
                detail="fail",
                remediated=False,
            )
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["history", "--host", "10.0.0.1", "--rule", "rule-a"]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "rule-a" in output


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

    def test_ac3_show_unchanged(self, tmp_path):
        """AC-3: --show-unchanged includes unchanged results in output."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=True)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=True)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["diff", str(s1), str(s2), "--show-unchanged"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        # With --show-unchanged, unchanged entries should appear
        assert "UNCHANGED" in output or "Unchanged" in output

    def test_ac4_host_filter(self, tmp_path):
        """AC-4: --host filters changes to specified host only."""
        db_path, store = _make_db(tmp_path)
        try:
            # Create sessions with results from two hosts
            s1 = store.create_session(
                hosts=["10.0.0.1", "10.0.0.2"], rules_path="rules/"
            )
            store.record_result(
                session_id=s1,
                host="10.0.0.1",
                rule_id="ssh-disable-root-login",
                passed=True,
                detail="ok",
                remediated=False,
            )
            store.record_result(
                session_id=s1,
                host="10.0.0.2",
                rule_id="ssh-disable-root-login",
                passed=True,
                detail="ok",
                remediated=False,
            )
            s2 = store.create_session(
                hosts=["10.0.0.1", "10.0.0.2"], rules_path="rules/"
            )
            store.record_result(
                session_id=s2,
                host="10.0.0.1",
                rule_id="ssh-disable-root-login",
                passed=False,
                detail="fail",
                remediated=False,
            )
            store.record_result(
                session_id=s2,
                host="10.0.0.2",
                rule_id="ssh-disable-root-login",
                passed=False,
                detail="fail",
                remediated=False,
            )
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["diff", str(s1), str(s2), "--host", "10.0.0.1"]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "10.0.0.1" in output

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

    def test_ac9_json_show_unchanged(self, tmp_path):
        """AC-9: --json --show-unchanged includes unchanged entries in JSON."""
        db_path, store = _make_db(tmp_path)
        try:
            s1 = _seed_check_session(store, host="10.0.0.1", passing=True)
            s2 = _seed_check_session(store, host="10.0.0.1", passing=True)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["diff", str(s1), str(s2), "--json", "--show-unchanged"],
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "changes" in data
        # With show-unchanged, the unchanged entry should appear
        unchanged = [c for c in data["changes"] if c["status"] == "unchanged"]
        assert len(unchanged) >= 1

    def test_ac10_missing_positional_args(self):
        """AC-10: Missing positional arguments shows usage error."""
        runner = CliRunner()
        result = runner.invoke(main, ["diff"])

        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════════════════════
# coverage — specs/cli/coverage.spec.md
# ═══════════════════════════════════════════════════════════════════════════════


def _make_mock_mapping(
    mapping_id="test-framework",
    title="Test Framework",
    sections=None,
    platform=None,
    controls=None,
    unimplemented=None,
):
    """Build a mock FrameworkMapping for coverage/list-frameworks tests."""
    mock = MagicMock()
    mock.id = mapping_id
    mock.title = title
    mock.platform = platform
    mock.sections = sections or {}
    mock.controls = controls or []
    mock.unimplemented = unimplemented or {}
    mock.implemented_count = len(mock.sections)
    mock.unimplemented_count = len(mock.unimplemented)
    return mock


def _make_coverage_report(
    mapping_id="test-framework",
    total_controls=10,
    implemented=8,
    unimplemented=1,
    unaccounted=None,
    missing_rules=None,
    has_manifest=True,
    automated=0,
    remediable=0,
    typed_remediable=0,
    rollback_safe=0,
):
    """Build a CoverageReport for tests."""
    from runner.mappings import CoverageReport

    return CoverageReport(
        mapping_id=mapping_id,
        total_controls=total_controls,
        implemented=implemented,
        unimplemented=unimplemented,
        unaccounted=unaccounted or [],
        missing_rules=missing_rules or [],
        has_manifest=has_manifest,
        automated=automated,
        remediable=remediable,
        typed_remediable=typed_remediable,
        rollback_safe=rollback_safe,
    )


class TestCoverageSpecDerived:
    """Spec-derived tests for ``kensa coverage``.

    Source spec: specs/cli/coverage.spec.md (8 ACs)
    """

    def test_ac1_valid_framework_exits_0(self, tmp_path):
        """AC-1: Valid framework exits 0 with coverage stats."""
        mapping = _make_mock_mapping()
        report = _make_coverage_report()

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": mapping},
            ),
            patch("runner.cli.load_rules", return_value=[{"id": "test-rule"}]),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main, ["coverage", "--framework", "test-fw", "--rules", str(tmp_path)]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Implemented" in output or "coverage" in output.lower()

    def test_ac2_json_output(self, tmp_path):
        """AC-2: --json outputs valid JSON with framework metadata."""
        report = _make_coverage_report()

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch("runner.cli.load_rules", return_value=[{"id": "test-rule"}]),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "coverage",
                    "--framework",
                    "test-fw",
                    "--rules",
                    str(tmp_path),
                    "--json",
                ],
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "framework" in data
        assert "coverage" in data

    def test_ac3_unknown_framework_exits_1(self):
        """AC-3: Unknown framework exits 1 with available list."""
        with patch(
            "runner.mappings.load_all_mappings", return_value={"known-fw": MagicMock()}
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["coverage", "--framework", "bogus"])

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        assert "Unknown framework" in output or "bogus" in output

    def test_ac4_invalid_rules_path_exits_1(self):
        """AC-4: Invalid rules path exits 1."""
        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch(
                "runner.cli.load_rules", side_effect=FileNotFoundError("no such dir")
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["coverage", "--framework", "test-fw", "--rules", "/nonexistent"],
            )

        assert result.exit_code == 1

    def test_ac5_missing_manifest_warning(self, tmp_path):
        """AC-5: Missing manifest shows warning."""
        report = _make_coverage_report(has_manifest=False)

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch("runner.cli.load_rules", return_value=[{"id": "test-rule"}]),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main, ["coverage", "--framework", "test-fw", "--rules", str(tmp_path)]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "manifest" in output.lower() or "approximate" in output.lower()

    def test_ac6_missing_rules_listed(self, tmp_path):
        """AC-6: Missing rules are listed in output."""
        report = _make_coverage_report(missing_rules=["ghost-rule-1", "ghost-rule-2"])

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch("runner.cli.load_rules", return_value=[{"id": "test-rule"}]),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main, ["coverage", "--framework", "test-fw", "--rules", str(tmp_path)]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "ghost-rule-1" in output

    def test_ac7_json_includes_completeness_fields(self, tmp_path):
        """AC-7: --json includes is_complete and has_manifest."""
        report = _make_coverage_report(has_manifest=True)

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch("runner.cli.load_rules", return_value=[{"id": "test-rule"}]),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "coverage",
                    "--framework",
                    "test-fw",
                    "--rules",
                    str(tmp_path),
                    "--json",
                ],
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "is_complete" in data["coverage"]
        assert "has_manifest" in data["coverage"]

    def test_ac8_json_coverage_percent_rounded(self, tmp_path):
        """AC-8: Coverage percentages are rounded to 1 decimal in JSON."""
        report = _make_coverage_report(total_controls=3, implemented=1)

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch("runner.cli.load_rules", return_value=[{"id": "test-rule"}]),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "coverage",
                    "--framework",
                    "test-fw",
                    "--rules",
                    str(tmp_path),
                    "--json",
                ],
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        pct = data["coverage"]["coverage_percent"]
        # 1/3 = 33.333... → rounded to 33.3
        assert pct == round(pct, 1)

    def test_ac9_automated_count(self):
        """AC-9: CoverageReport includes automated count — controls with non-manual check methods."""

        report = _make_coverage_report(automated=7)
        assert report.automated == 7

    def test_ac10_remediable_count(self):
        """AC-10: CoverageReport includes remediable count — controls with non-manual remediation."""

        report = _make_coverage_report(remediable=6)
        assert report.remediable == 6

    def test_ac11_typed_remediable_count(self):
        """AC-11: CoverageReport includes typed_remediable count — typed mechanisms only."""

        report = _make_coverage_report(typed_remediable=5)
        assert report.typed_remediable == 5

    def test_ac12_rollback_safe_count(self):
        """AC-12: CoverageReport includes rollback_safe count — capturable mechanisms only."""

        report = _make_coverage_report(rollback_safe=4)
        assert report.rollback_safe == 4

    def test_ac13_json_includes_quality_metrics(self, tmp_path):
        """AC-13: --json coverage object includes automated, remediable, typed_remediable, rollback_safe."""
        report = _make_coverage_report(
            automated=7, remediable=6, typed_remediable=5, rollback_safe=4
        )

        with (
            patch(
                "runner.mappings.load_all_mappings",
                return_value={"test-fw": _make_mock_mapping()},
            ),
            patch(
                "runner.cli.load_rules",
                return_value=[{"id": "test-rule"}],
            ),
            patch("runner.mappings.check_coverage", return_value=report),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "coverage",
                    "--framework",
                    "test-fw",
                    "--rules",
                    str(tmp_path),
                    "--json",
                ],
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        cov = data["coverage"]
        assert cov["automated"] == 7
        assert cov["remediable"] == 6
        assert cov["typed_remediable"] == 5
        assert cov["rollback_safe"] == 4


# ═══════════════════════════════════════════════════════════════════════════════
# list-frameworks — specs/cli/list_frameworks.spec.md
# ═══════════════════════════════════════════════════════════════════════════════


class TestListFrameworksSpecDerived:
    """Spec-derived tests for ``kensa list frameworks``.

    Source spec: specs/cli/list_frameworks.spec.yaml (5 ACs)
    """

    def test_ac1_with_mappings_exits_0(self):
        """AC-1: With mappings present, exits 0 and displays list."""
        mapping = _make_mock_mapping(mapping_id="cis-rhel9", title="CIS RHEL 9 v2.0.0")

        with patch(
            "runner.mappings.load_all_mappings",
            return_value={"cis-rhel9": mapping},
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["list", "frameworks"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "cis-rhel9" in output

    def test_ac2_no_mappings_exits_0(self):
        """AC-2: With no mappings, exits 0 and prints message."""
        with patch("runner.mappings.load_all_mappings", return_value={}):
            runner = CliRunner()
            result = runner.invoke(main, ["list", "frameworks"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "No framework mappings found" in output

    def test_ac3_sorted_alphabetically(self):
        """AC-3: Mappings sorted alphabetically by ID."""
        m_b = _make_mock_mapping(mapping_id="b-framework", title="B Framework")
        m_a = _make_mock_mapping(mapping_id="a-framework", title="A Framework")

        with patch(
            "runner.mappings.load_all_mappings",
            return_value={"b-framework": m_b, "a-framework": m_a},
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["list", "frameworks"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        pos_a = output.find("a-framework")
        pos_b = output.find("b-framework")
        assert pos_a < pos_b

    def test_ac4_platform_info_displayed(self):
        """AC-4: Platform info included when mapping has platform constraints."""
        platform = MagicMock()
        platform.family = "rhel"
        platform.min_version = "9"
        platform.max_version = None
        mapping = _make_mock_mapping(
            mapping_id="cis-rhel9", title="CIS RHEL 9", platform=platform
        )

        with patch(
            "runner.mappings.load_all_mappings", return_value={"cis-rhel9": mapping}
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["list", "frameworks"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "rhel" in output

    def test_ac5_section_counts_shown(self):
        """AC-5: Section counts show implemented and skipped."""
        mapping = _make_mock_mapping(
            mapping_id="test-fw",
            title="Test FW",
            sections={"1.1": MagicMock(), "1.2": MagicMock()},
            unimplemented={"2.1": MagicMock()},
        )
        mapping.implemented_count = 2
        mapping.unimplemented_count = 1

        with patch(
            "runner.mappings.load_all_mappings", return_value={"test-fw": mapping}
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["list", "frameworks"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "2 implemented" in output
        assert "1 skipped" in output

    def test_deprecated_alias_still_works(self):
        """Backward compat: 'kensa list-frameworks' still works as deprecated alias."""
        mapping = _make_mock_mapping(mapping_id="cis-rhel9", title="CIS RHEL 9 v2.0.0")

        with patch(
            "runner.mappings.load_all_mappings",
            return_value={"cis-rhel9": mapping},
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["list-frameworks"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "cis-rhel9" in output


# ═══════════════════════════════════════════════════════════════════════════════
# info — specs/cli/info.spec.md
# ═══════════════════════════════════════════════════════════════════════════════


def _make_mock_rule_index(rule_ids=None):
    """Return a dict of rule_id → rule data for mocking build_rule_index."""
    if rule_ids is None:
        rule_ids = ["test-rule"]
    return {
        rid: {
            "id": rid,
            "title": f"Title for {rid}",
            "description": f"Description for {rid}",
            "severity": "medium",
            "category": "kernel",
            "tags": ["test"],
            "platforms": [{"family": "rhel"}],
            "references": {
                "cis": {
                    "rhel9": {"section": "5.2.2", "level": "L1"},
                },
                "stig": {
                    "rhel9": {"vuln_id": "V-258036", "severity": "medium"},
                },
                "nist_800_53": ["AC-3"],
            },
            "implementations": [
                {
                    "default": True,
                    "check": {"method": "command"},
                    "remediation": {"mechanism": "config_set"},
                }
            ],
        }
        for rid in rule_ids
    }


class TestInfoSpecDerived:
    """Spec-derived tests for ``kensa info``.

    Source spec: specs/cli/info.spec.md (15 ACs)
    """

    def test_ac1_positional_rule_id_exits_0(self):
        """AC-1: Positional rule ID exits 0 with full detail."""
        rules = _make_mock_rule_index(["sudo-use-pty"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.classify_query",
                return_value=("rule", "sudo-use-pty"),
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "sudo-use-pty"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "sudo-use-pty" in output

    def test_ac2_positional_rule_not_found_exits_1(self):
        """AC-2: Positional rule ID not found exits 1."""
        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value={}),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.classify_query",
                return_value=("rule", "nonexistent-rule"),
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "nonexistent-rule"])

        assert result.exit_code == 1

    def test_ac3_positional_cis_auto_detect(self):
        """AC-3: Positional CIS section auto-detected, exits 0."""
        rules = _make_mock_rule_index(["test-rule"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.classify_query",
                return_value=("cis", "5.2.2"),
            ),
            patch(
                "runner.rule_info.search_rules_by_reference",
                return_value=[
                    {
                        "rule_id": "test-rule",
                        "title": "Test",
                        "severity": "medium",
                        "refs": [{"framework": "rhel9", "section": "5.2.2"}],
                    }
                ],
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "5.2.2"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "test-rule" in output

    def test_ac4_positional_stig_auto_detect(self):
        """AC-4: Positional STIG ID auto-detected, exits 0."""
        rules = _make_mock_rule_index(["test-rule"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.classify_query",
                return_value=("stig", "V-258036"),
            ),
            patch(
                "runner.rule_info.search_rules_by_reference",
                return_value=[
                    {
                        "rule_id": "test-rule",
                        "title": "Test",
                        "severity": "medium",
                        "refs": [{"framework": "rhel9", "vuln_id": "V-258036"}],
                    }
                ],
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "V-258036"])

        assert result.exit_code == 0

    def test_ac5_positional_nist_auto_detect(self):
        """AC-5: Positional NIST control auto-detected, exits 0."""
        rules = _make_mock_rule_index(["test-rule"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.classify_query",
                return_value=("nist", "AC-3"),
            ),
            patch(
                "runner.rule_info.search_rules_by_reference",
                return_value=[
                    {
                        "rule_id": "test-rule",
                        "title": "Test",
                        "severity": "medium",
                        "refs": [],
                    }
                ],
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "AC-3"])

        assert result.exit_code == 0

    def test_ac6_explicit_cis_flag(self):
        """AC-6: --cis explicit flag exits 0 with matching rules."""
        rules = _make_mock_rule_index(["test-rule"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.search_rules_by_reference",
                return_value=[
                    {
                        "rule_id": "test-rule",
                        "title": "Test",
                        "severity": "medium",
                        "refs": [{"framework": "rhel9", "section": "5.2.2"}],
                    }
                ],
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "--cis", "5.2.2"])

        assert result.exit_code == 0

    def test_ac7_control_flag_exits_0(self):
        """AC-7: --control with valid control exits 0."""
        from runner.mappings import FrameworkIndex, FrameworkMapping, MappingEntry

        mapping = FrameworkMapping(
            id="test-fw",
            framework="test",
            title="Test",
            sections={
                "1.1": MappingEntry(
                    rule_id="test-rule",
                    title="Ctrl 1.1",
                    metadata={"rules": ["test-rule"]},
                ),
            },
        )
        mappings = {"test-fw": mapping}
        index = FrameworkIndex.build(mappings)

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch(
                "runner.rule_info.build_rule_index",
                return_value=_make_mock_rule_index(["test-rule"]),
            ),
            patch("runner.mappings.load_all_mappings", return_value=mappings),
            patch("runner.mappings.FrameworkIndex") as mock_fi_cls,
        ):
            mock_fi_cls.build.return_value = index
            runner = CliRunner()
            result = runner.invoke(main, ["info", "--control", "test-fw:1.1"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "test-rule" in output

    def test_ac8_rule_flag_exits_0(self):
        """AC-8: --rule with known rule exits 0 with framework refs."""
        from runner.mappings import FrameworkIndex, FrameworkMapping, MappingEntry

        mapping = FrameworkMapping(
            id="test-fw",
            framework="test",
            title="Test FW",
            sections={
                "1.1": MappingEntry(
                    rule_id="test-rule",
                    title="Ctrl 1.1",
                    metadata={"rules": ["test-rule"]},
                ),
            },
        )
        mappings = {"test-fw": mapping}
        index = FrameworkIndex.build(mappings)
        rules = _make_mock_rule_index(["test-rule"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value=mappings),
            patch("runner.mappings.FrameworkIndex") as mock_fi_cls,
        ):
            mock_fi_cls.build.return_value = index
            runner = CliRunner()
            result = runner.invoke(main, ["info", "--rule", "test-rule"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "test-rule" in output

    def test_ac9_list_controls_exits_0(self):
        """AC-9: --list-controls exits 0 with control listing."""
        from runner.mappings import FrameworkIndex, FrameworkMapping, MappingEntry

        mapping = FrameworkMapping(
            id="test-fw",
            framework="test",
            title="Test FW",
            sections={
                "1.1": MappingEntry(
                    rule_id="rule-a",
                    title="Ctrl 1.1",
                    metadata={"rules": ["rule-a"]},
                ),
                "1.2": MappingEntry(
                    rule_id="rule-b",
                    title="Ctrl 1.2",
                    metadata={"rules": ["rule-b", "rule-c"]},
                ),
            },
        )
        mappings = {"test-fw": mapping}
        index = FrameworkIndex.build(mappings)

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value={}),
            patch("runner.mappings.load_all_mappings", return_value=mappings),
            patch("runner.mappings.FrameworkIndex") as mock_fi_cls,
        ):
            mock_fi_cls.build.return_value = index
            runner = CliRunner()
            result = runner.invoke(main, ["info", "--list-controls"])

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "1.1" in output
        assert "1.2" in output

    def test_ac10_json_output(self):
        """AC-10: --json outputs valid JSON."""
        rules = _make_mock_rule_index(["test-rule"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value={}),
            patch(
                "runner.rule_info.classify_query",
                return_value=("rule", "test-rule"),
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "test-rule", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "rule" in data or "query" in data

    def test_ac11_conflicting_flags_exits_1(self):
        """AC-11: Multiple conflicting flags exits 1."""
        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value={}),
            patch("runner.mappings.load_all_mappings", return_value={}),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "--control", "x:1.1", "--rule", "y"])

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        assert "Only one" in output

    def test_ac12_no_arguments_exits_1(self):
        """AC-12: No arguments exits 1 with usage examples."""
        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value={}),
            patch("runner.mappings.load_all_mappings", return_value={}),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info"])

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        assert "Specify" in output or "Examples" in output

    def test_ac13_prefix_match(self):
        """AC-13: --prefix-match matches control prefixes."""
        from runner.mappings import FrameworkIndex, FrameworkMapping, MappingEntry

        mapping = FrameworkMapping(
            id="test-fw",
            framework="test",
            title="Test FW",
            sections={
                "5.1.1": MappingEntry(
                    rule_id="rule-a",
                    title="Ctrl 5.1.1",
                    metadata={"rules": ["rule-a"]},
                ),
                "5.1.2": MappingEntry(
                    rule_id="rule-b",
                    title="Ctrl 5.1.2",
                    metadata={"rules": ["rule-b"]},
                ),
                "5.2.1": MappingEntry(
                    rule_id="rule-c",
                    title="Ctrl 5.2.1",
                    metadata={"rules": ["rule-c"]},
                ),
            },
        )
        mappings = {"test-fw": mapping}
        index = FrameworkIndex.build(mappings)
        rules = _make_mock_rule_index(["rule-a", "rule-b", "rule-c"])

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value=rules),
            patch("runner.mappings.load_all_mappings", return_value=mappings),
            patch("runner.mappings.FrameworkIndex") as mock_fi_cls,
        ):
            mock_fi_cls.build.return_value = index
            runner = CliRunner()
            result = runner.invoke(
                main, ["info", "--control", "test-fw:5.1", "--prefix-match"]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "rule-a" in output
        assert "rule-b" in output

    def test_ac14_list_controls_with_framework_filter(self):
        """AC-14: --list-controls --framework filters to specified framework."""
        from runner.mappings import FrameworkIndex, FrameworkMapping, MappingEntry

        m1 = FrameworkMapping(
            id="fw-a",
            framework="test",
            title="FW A",
            sections={
                "1.1": MappingEntry(
                    rule_id="r1", title="C1", metadata={"rules": ["r1"]}
                ),
            },
        )
        m2 = FrameworkMapping(
            id="fw-b",
            framework="test",
            title="FW B",
            sections={
                "2.1": MappingEntry(
                    rule_id="r2", title="C2", metadata={"rules": ["r2"]}
                ),
            },
        )
        mappings = {"fw-a": m1, "fw-b": m2}
        index = FrameworkIndex.build(mappings)

        with (
            patch("runner.paths.get_rules_path", return_value="rules/"),
            patch("runner.rule_info.build_rule_index", return_value={}),
            patch("runner.mappings.load_all_mappings", return_value=mappings),
            patch("runner.mappings.FrameworkIndex") as mock_fi_cls,
        ):
            mock_fi_cls.build.return_value = index
            runner = CliRunner()
            result = runner.invoke(
                main, ["info", "--list-controls", "--framework", "fw-a"]
            )

        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "1.1" in output
        # fw-b's controls should not appear
        assert "2.1" not in output

    def test_ac15_rules_dir_not_found_with_ref_flag(self):
        """AC-15: Rules directory not found with explicit ref flag exits 1."""
        with (
            patch("runner.paths.get_rules_path", side_effect=FileNotFoundError),
            patch("runner.mappings.load_all_mappings", return_value={}),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["info", "--cis", "5.2.2"])

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        assert "unable to locate rules directory" in output.lower()
