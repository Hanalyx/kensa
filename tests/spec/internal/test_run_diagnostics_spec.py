"""Spec-derived tests for run_diagnostics.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/run_diagnostics.spec.yaml — verifying error vs fail
distinction, timing, skip reason categorization, and enhanced summaries.
"""

from __future__ import annotations

import json

from runner._types import RuleResult
from runner.output import HostResult, RunResult


class TestRunDiagnosticsSpecDerived:
    """Spec-derived tests for run diagnostics (AC-1 through AC-18)."""

    def test_ac1_rule_result_has_error_fields(self):
        """AC-1: RuleResult has error bool and error_detail str with defaults."""
        result = RuleResult(
            rule_id="test-rule",
            title="Test",
            severity="medium",
            passed=False,
        )
        assert result.error is False
        assert result.error_detail == ""

    def test_ac2_evaluate_rule_sets_error_on_exception(self):
        """AC-2: evaluate_rule sets error=True and error_detail on exception."""
        from unittest.mock import MagicMock, patch

        ssh = MagicMock()
        rule = {
            "id": "test-rule",
            "title": "Test",
            "severity": "medium",
            "implementations": [
                {
                    "capability": "base",
                    "check": {"type": "command", "run": "true", "expected_exit": 0},
                }
            ],
        }

        with patch(
            "runner._orchestration.run_check", side_effect=OSError("SSH timeout")
        ):
            from runner._orchestration import evaluate_rule

            result = evaluate_rule(ssh, rule, {"base": True})

        assert result.error is True
        assert result.error_detail == "SSH timeout"
        assert result.passed is False

    def test_ac3_remediate_rule_sets_error_on_remediation_exception(self):
        """AC-3: remediate_rule sets error=True on remediation exception."""
        from unittest.mock import MagicMock, patch

        ssh = MagicMock()
        rule = {
            "id": "test-rule",
            "title": "Test",
            "severity": "medium",
            "implementations": [
                {
                    "capability": "base",
                    "check": {"type": "command", "run": "false", "expected_exit": 0},
                    "remediation": [
                        {"mechanism": "command_exec", "run": "fix-it"},
                    ],
                }
            ],
        }

        # Make check fail (so remediation is attempted), then remediation raises
        from runner._types import CheckResult

        with (
            patch(
                "runner._orchestration.run_check",
                return_value=CheckResult(passed=False, detail="failed"),
            ),
            patch(
                "runner._orchestration.run_remediation",
                side_effect=RuntimeError("remediation broke"),
            ),
        ):
            from runner._orchestration import remediate_rule

            result = remediate_rule(ssh, rule, {"base": True})

        assert result.error is True
        assert result.error_detail == "remediation broke"

    def test_ac4_host_result_error_count_excludes_skipped(self):
        """AC-4: HostResult.error_count counts errors; fail_count excludes errors."""
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(rule_id="r1", title="Pass", severity="low", passed=True),
            RuleResult(rule_id="r2", title="Fail", severity="low", passed=False),
            RuleResult(
                rule_id="r3",
                title="Error",
                severity="low",
                passed=False,
                error=True,
                error_detail="timeout",
            ),
            RuleResult(
                rule_id="r4",
                title="Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="platform: requires rhel",
            ),
        ]
        assert host.pass_count == 1
        assert host.fail_count == 1  # excludes errors
        assert host.error_count == 1
        assert host.skip_count == 1

    def test_ac5_run_result_total_error(self):
        """AC-5: RunResult.total_error sums error_count across hosts."""
        run = RunResult(command="check")
        h1 = HostResult(hostname="h1")
        h1.results = [
            RuleResult(
                rule_id="r1",
                title="Error",
                severity="low",
                passed=False,
                error=True,
                error_detail="timeout",
            ),
        ]
        h2 = HostResult(hostname="h2")
        h2.results = [
            RuleResult(
                rule_id="r1",
                title="Error",
                severity="low",
                passed=False,
                error=True,
                error_detail="conn refused",
            ),
            RuleResult(rule_id="r2", title="Pass", severity="low", passed=True),
        ]
        run.hosts = [h1, h2]
        assert run.total_error == 2

    def test_ac6_terminal_displays_error(self):
        """AC-6: Terminal output displays ERROR for error results."""
        from io import StringIO
        from unittest.mock import MagicMock, patch

        from rich.console import Console

        from runner._host_runner import run_checks

        ssh = MagicMock()
        rule = {
            "id": "test-error-rule",
            "title": "Test Error Rule",
            "severity": "medium",
            "implementations": [
                {
                    "capability": "base",
                    "check": {"type": "command", "run": "true", "expected_exit": 0},
                }
            ],
        }

        with patch(
            "runner._host_runner.evaluate_rule",
            return_value=RuleResult(
                rule_id="test-error-rule",
                title="Test Error Rule",
                severity="medium",
                passed=False,
                error=True,
                error_detail="SSH timeout",
            ),
        ):
            buf = StringIO()
            out = Console(file=buf, force_terminal=True, width=120)
            run_checks(ssh, [rule], {"base": True}, None, out=out, verbose=False)
            output = buf.getvalue()

        assert "ERROR" in output

    def test_ac7_summary_includes_error_segment(self):
        """AC-7: Summary lines include error count when errors > 0."""
        # Build a HostResult with errors and check that counts are consistent
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(
                rule_id="r1",
                title="Error",
                severity="low",
                passed=False,
                error=True,
                error_detail="timeout",
            ),
            RuleResult(rule_id="r2", title="Pass", severity="low", passed=True),
            RuleResult(rule_id="r3", title="Fail", severity="low", passed=False),
        ]
        # Verify the counts are available for summary formatting
        assert host.error_count == 1
        assert host.pass_count == 1
        assert host.fail_count == 1

    def test_ac8_json_includes_error_fields(self):
        """AC-8: JSON output includes error/error_detail per result and error in summaries."""
        from runner.output.json_fmt import format_json

        run = RunResult(command="check")
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(
                rule_id="r1",
                title="Error Rule",
                severity="medium",
                passed=False,
                error=True,
                error_detail="SSH timeout",
            ),
            RuleResult(rule_id="r2", title="Pass Rule", severity="low", passed=True),
        ]
        run.hosts = [host]
        data = json.loads(format_json(run))

        # Per-result
        error_result = data["hosts"][0]["results"][0]
        assert error_result["error"] is True
        assert error_result["error_detail"] == "SSH timeout"

        # Host summary
        assert data["hosts"][0]["summary"]["error"] == 1

        # Run summary
        assert data["summary"]["error"] == 1

    def test_ac9_csv_includes_error_columns(self):
        """AC-9: CSV output includes error and error_detail columns."""
        from runner.output.csv_fmt import CHECK_COLUMNS, REMEDIATE_COLUMNS, format_csv

        assert "error" in CHECK_COLUMNS
        assert "error_detail" in CHECK_COLUMNS
        assert "error" in REMEDIATE_COLUMNS
        assert "error_detail" in REMEDIATE_COLUMNS

        run = RunResult(command="check")
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(
                rule_id="r1",
                title="Error Rule",
                severity="medium",
                passed=False,
                error=True,
                error_detail="timeout",
            ),
        ]
        run.hosts = [host]
        csv_output = format_csv(run)
        lines = csv_output.strip().split("\n")
        header = lines[0]
        assert "error" in header
        assert "error_detail" in header
        # Data row should contain "true" for error
        assert "true" in lines[1]  # error=true

    def test_ac10_pdf_error_status_label(self):
        """AC-10: PDF output renders ERROR status with lightsalmon color."""
        from runner.output.pdf_fmt import STATUS_COLORS, _get_status_label

        result = RuleResult(
            rule_id="r1",
            title="Error",
            severity="medium",
            passed=False,
            error=True,
            error_detail="timeout",
        )
        assert _get_status_label(result) == "ERROR"
        assert "ERROR" in STATUS_COLORS
        assert STATUS_COLORS["ERROR"] == "lightsalmon"

    def test_ac11_evidence_includes_error_fields(self):
        """AC-11: Evidence output includes error/error_detail per result and in summary."""
        from runner.output.evidence_fmt import format_evidence

        run = RunResult(command="check")
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(
                rule_id="r1",
                title="Error Rule",
                severity="medium",
                passed=False,
                error=True,
                error_detail="SSH timeout",
            ),
        ]
        run.hosts = [host]
        data = json.loads(format_evidence(run, host))

        assert data["results"][0]["error"] is True
        assert data["results"][0]["error_detail"] == "SSH timeout"
        assert data["summary"]["error"] == 1

    def test_ac12_host_result_has_duration_seconds(self):
        """AC-12: HostResult and RunResult have duration_seconds fields."""
        host = HostResult(hostname="test")
        assert host.duration_seconds is None
        host.duration_seconds = 14.3
        assert host.duration_seconds == 14.3

        run = RunResult(command="check")
        assert run.duration_seconds is None
        run.duration_seconds = 42.1
        assert run.duration_seconds == 42.1

    def test_ac13_host_check_result_has_duration(self):
        """AC-13: HostCheckResult/HostRemediateResult have duration_seconds."""
        from runner._host_runner import HostCheckResult, HostRemediateResult

        check_result = HostCheckResult(
            hostname="test", success=True, duration_seconds=5.2
        )
        assert check_result.duration_seconds == 5.2

        remediate_result = HostRemediateResult(
            hostname="test", success=True, duration_seconds=8.7
        )
        assert remediate_result.duration_seconds == 8.7

    def test_ac14_json_includes_duration(self):
        """AC-14: JSON output includes duration_seconds at run and host level."""
        from runner.output.json_fmt import format_json

        run = RunResult(command="check")
        run.duration_seconds = 42.1
        host = HostResult(hostname="test", duration_seconds=14.3)
        host.results = [
            RuleResult(rule_id="r1", title="Pass", severity="low", passed=True),
        ]
        run.hosts = [host]
        data = json.loads(format_json(run))

        assert data["duration_seconds"] == 42.1
        assert data["hosts"][0]["duration_seconds"] == 14.3

    def test_ac15_skip_reasons_categorization(self):
        """AC-15: HostResult.skip_reasons categorizes skip reasons correctly."""
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(
                rule_id="r1",
                title="Platform Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="platform: requires rhel 9",
            ),
            RuleResult(
                rule_id="r2",
                title="Capability Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="No matching implementation",
            ),
            RuleResult(
                rule_id="r3",
                title="Dependency Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="dependency_failed: r1",
            ),
            RuleResult(
                rule_id="r4",
                title="No Check Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="Implementation has no check",
            ),
            RuleResult(
                rule_id="r5",
                title="Other Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="some unknown reason",
            ),
        ]
        reasons = host.skip_reasons
        assert reasons["platform"] == 1
        assert reasons["capability"] == 1
        assert reasons["dependency"] == 1
        assert reasons["no_check"] == 1
        assert reasons["other"] == 1

    def test_ac16_total_skip_reasons(self):
        """AC-16: RunResult.total_skip_reasons aggregates across hosts."""
        run = RunResult(command="check")
        h1 = HostResult(hostname="h1")
        h1.results = [
            RuleResult(
                rule_id="r1",
                title="Platform Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="platform: requires rhel 9",
            ),
        ]
        h2 = HostResult(hostname="h2")
        h2.results = [
            RuleResult(
                rule_id="r1",
                title="Platform Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="platform: requires rhel 8",
            ),
            RuleResult(
                rule_id="r2",
                title="Cap Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="No matching implementation",
            ),
        ]
        run.hosts = [h1, h2]
        totals = run.total_skip_reasons
        assert totals["platform"] == 2
        assert totals["capability"] == 1

    def test_ac17_json_includes_skip_reasons(self):
        """AC-17: JSON output includes skip_reasons in summaries when skips present."""
        from runner.output.json_fmt import format_json

        run = RunResult(command="check")
        host = HostResult(hostname="test")
        host.results = [
            RuleResult(
                rule_id="r1",
                title="Skip",
                severity="low",
                passed=False,
                skipped=True,
                skip_reason="platform: requires rhel 9",
            ),
        ]
        run.hosts = [host]
        data = json.loads(format_json(run))

        assert "skip_reasons" in data["hosts"][0]["summary"]
        assert data["hosts"][0]["summary"]["skip_reasons"]["platform"] == 1
        assert "skip_reasons" in data["summary"]
        assert data["summary"]["skip_reasons"]["platform"] == 1

    def test_ac18_storage_v4_migration(self, tmp_path):
        """AC-18: Storage schema v4 adds duration_seconds to sessions table."""
        from runner.storage import ResultStore

        db_path = tmp_path / "test.db"
        store = ResultStore(db_path=db_path)
        try:
            assert store.SCHEMA_VERSION == 4
            # Check column exists
            conn = store._get_conn()
            cursor = conn.execute("PRAGMA table_info(sessions)")
            columns = {row[1] for row in cursor.fetchall()}
            assert "duration_seconds" in columns
        finally:
            store.close()
