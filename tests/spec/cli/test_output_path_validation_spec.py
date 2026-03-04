"""Spec-derived tests for output_path_validation.spec.yaml.

Tests validate the acceptance criteria defined in
specs/cli/output_path_validation.spec.yaml — verifying that output file paths
are validated before SSH connections and that I/O errors are displayed as
human-readable messages rather than Python tracebacks.

These tests will FAIL until the implementation is written. That is correct.
"""

from __future__ import annotations

import re
import stat
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.cli import main


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for assertion clarity."""
    return re.compile(r"\x1b\[[0-9;]*m").sub("", text)


def _write_simple_rule(tmp_path, rule_id: str = "test-rule") -> str:
    """Write a minimal passable rule and return its path."""
    rule_file = tmp_path / f"{rule_id}.yml"
    rule_file.write_text(
        f"id: {rule_id}\n"
        f"title: Test rule {rule_id}\n"
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
    return str(rule_file)


def _make_mock_ssh():
    """Create a mock SSH session that works as a context manager."""
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.connect = MagicMock()
    mock.close = MagicMock()
    return mock


class TestOutputPathValidationSpecDerived:
    """Spec-derived tests for output path validation (AC-1 through AC-7)."""

    def test_ac1_nonexistent_parent_exits_before_ssh(self, tmp_path):
        """AC-1: Non-existent parent dir exits 1 with human-readable error before SSH."""
        rule_file = _write_simple_rule(tmp_path)
        invalid_output = str(tmp_path / "nonexistent_dir" / "output.json")

        runner = CliRunner()
        with patch("runner.ssh.SSHSession") as mock_ssh:
            result = runner.invoke(
                main,
                [
                    "check",
                    "--host",
                    "fake-host",
                    "--rule",
                    rule_file,
                    "-o",
                    f"evidence:{invalid_output}",
                ],
            )

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        assert "nonexistent_dir" in output
        assert "Traceback" not in output
        mock_ssh.assert_not_called()

    def test_ac2_non_writable_parent_exits_before_ssh(self, tmp_path):
        """AC-2: Non-writable parent dir exits 1 with human-readable error before SSH."""
        rule_file = _write_simple_rule(tmp_path)
        locked_dir = tmp_path / "locked"
        locked_dir.mkdir()
        # Remove write permission
        locked_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        output_path = str(locked_dir / "output.json")

        runner = CliRunner()
        try:
            with patch("runner.ssh.SSHSession") as mock_ssh:
                result = runner.invoke(
                    main,
                    [
                        "check",
                        "--host",
                        "fake-host",
                        "--rule",
                        rule_file,
                        "-o",
                        f"evidence:{output_path}",
                    ],
                )

            assert result.exit_code == 1
            output = strip_ansi(result.output)
            assert "locked" in output
            assert "Traceback" not in output
            mock_ssh.assert_not_called()
        finally:
            # Restore permissions so tmp_path cleanup succeeds
            locked_dir.chmod(stat.S_IRWXU)

    def test_ac3_valid_path_scan_proceeds(self, tmp_path):
        """AC-3: Valid output path allows scan to proceed without early exit."""
        from runner.detect import PlatformInfo
        from runner.ssh import Result

        rule_file = _write_simple_rule(tmp_path)
        output_dir = tmp_path / "results"
        output_dir.mkdir()
        output_path = str(output_dir / "output.json")

        mock_ssh = _make_mock_ssh()
        mock_ssh.run.return_value = Result(exit_code=0, stdout="0", stderr="")

        platform = PlatformInfo(family="rhel", version=9, version_id="9.0")

        runner = CliRunner()
        with (
            patch("runner.ssh.SSHSession", return_value=mock_ssh),
            patch("runner.detect.detect_platform", return_value=platform),
            patch("runner.detect.detect_capabilities", return_value=set()),
        ):
            result = runner.invoke(
                main,
                [
                    "check",
                    "--host",
                    "fake-host",
                    "--rule",
                    rule_file,
                    "-o",
                    f"json:{output_path}",
                ],
            )

        # Should not exit early; scan ran (exit 0 or reached host processing)
        assert result.exit_code == 0
        assert "Traceback" not in strip_ansi(result.output)

    def test_ac4_error_has_no_traceback_and_includes_path(self, tmp_path):
        """AC-4: Error output has no traceback and includes the invalid path."""
        rule_file = _write_simple_rule(tmp_path)
        bad_dir = "does_not_exist_xyz"
        invalid_output = f"{bad_dir}/output.json"

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--host",
                "fake-host",
                "--rule",
                rule_file,
                "-o",
                f"csv:{invalid_output}",
            ],
        )

        output = strip_ansi(result.output)
        assert result.exit_code == 1
        assert "Traceback" not in output
        assert bad_dir in output

    def test_ac5_multiple_outputs_invalid_one_exits_before_scan(self, tmp_path):
        """AC-5: Multiple -o specs with one invalid path exits 1 before scanning."""
        rule_file = _write_simple_rule(tmp_path)
        valid_dir = tmp_path / "valid"
        valid_dir.mkdir()
        valid_output = str(valid_dir / "out.json")
        invalid_output = str(tmp_path / "no_such_dir" / "out.csv")

        runner = CliRunner()
        with patch("runner.ssh.SSHSession") as mock_ssh:
            result = runner.invoke(
                main,
                [
                    "check",
                    "--host",
                    "fake-host",
                    "--rule",
                    rule_file,
                    "-o",
                    f"json:{valid_output}",
                    "-o",
                    f"csv:{invalid_output}",
                ],
            )

        assert result.exit_code == 1
        assert "no_such_dir" in strip_ansi(result.output)
        mock_ssh.assert_not_called()

    def test_ac6_runtime_io_error_is_human_readable(self, tmp_path):
        """AC-6: OSError during write is caught and shown as human-readable error."""
        from runner.detect import PlatformInfo
        from runner.ssh import Result

        rule_file = _write_simple_rule(tmp_path)
        output_dir = tmp_path / "results"
        output_dir.mkdir()
        output_path = str(output_dir / "output.json")

        mock_ssh = _make_mock_ssh()
        mock_ssh.run.return_value = Result(exit_code=0, stdout="0", stderr="")

        platform = PlatformInfo(family="rhel", version=9, version_id="9.0")

        runner = CliRunner()
        with (
            patch("runner.ssh.SSHSession", return_value=mock_ssh),
            patch("runner.detect.detect_platform", return_value=platform),
            patch("runner.detect.detect_capabilities", return_value=set()),
            patch(
                "runner.cli.write_output",
                side_effect=OSError("No space left on device"),
            ),
        ):
            result = runner.invoke(
                main,
                [
                    "check",
                    "--host",
                    "fake-host",
                    "--rule",
                    rule_file,
                    "-o",
                    f"json:{output_path}",
                ],
            )

        output = strip_ansi(result.output)
        assert result.exit_code == 1
        assert "No space left on device" in output
        assert "Traceback" not in output

    def test_ac7_remediate_also_validates_output_paths(self, tmp_path):
        """AC-7: Output path validation also applies to the remediate command."""
        rule_file = _write_simple_rule(tmp_path)
        invalid_output = str(tmp_path / "missing_dir" / "report.json")

        runner = CliRunner()
        with patch("runner.ssh.SSHSession") as mock_ssh:
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "fake-host",
                    "--rule",
                    rule_file,
                    "-o",
                    f"json:{invalid_output}",
                ],
            )

        assert result.exit_code == 1
        output = strip_ansi(result.output)
        assert "missing_dir" in output
        assert "Traceback" not in output
        mock_ssh.assert_not_called()
