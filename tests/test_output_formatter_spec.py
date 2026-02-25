"""SpecDerived tests for output formatter module."""

from __future__ import annotations

import csv
import io
import json
import sys
from unittest import mock

from runner._types import RuleResult
from runner.output import HostResult, RunResult, parse_output_spec, write_output


def _make_rule_result(**kwargs) -> RuleResult:
    """Helper to create a RuleResult with sensible defaults."""
    defaults = {
        "rule_id": "test-rule",
        "title": "Test Rule",
        "severity": "high",
        "passed": True,
        "skipped": False,
        "detail": "check passed",
    }
    defaults.update(kwargs)
    return RuleResult(**defaults)


def _make_run_result(command: str = "check", hosts: list | None = None) -> RunResult:
    """Helper to create a RunResult."""
    run = RunResult(command=command)
    if hosts:
        run.hosts = hosts
    return run


class TestOutputFormatterSpecDerived:
    """Spec-derived tests for output formatter.

    See specs/internal/output_formatter.spec.yaml for specification.
    """

    def test_ac1_json_pretty_printed(self):
        """AC-1: write_output with fmt='json' returns pretty-printed JSON."""
        host = HostResult(hostname="server1")
        run = _make_run_result(hosts=[host])

        output = write_output(run, "json")
        data = json.loads(output)

        assert "timestamp" in data
        assert data["command"] == "check"
        assert "hosts" in data
        assert "summary" in data
        # Check pretty-printing (2-space indent)
        assert "\n" in output
        assert "  " in output

    def test_ac2_json_includes_per_host_details(self):
        """AC-2: JSON includes per-host platform, capabilities, per-rule results."""
        result = _make_rule_result(
            rule_id="ssh-check", severity="high", passed=False, detail="failed"
        )
        host = HostResult(
            hostname="server1",
            platform_family="rhel",
            platform_version=9,
            capabilities={"sshd": True, "systemd": True},
            results=[result],
        )
        run = _make_run_result(hosts=[host])

        output = write_output(run, "json")
        data = json.loads(output)

        host_data = data["hosts"][0]
        assert host_data["hostname"] == "server1"
        assert host_data["platform"]["family"] == "rhel"
        assert host_data["platform"]["version"] == 9
        assert host_data["capabilities"]["sshd"] is True
        assert len(host_data["results"]) == 1
        r = host_data["results"][0]
        assert r["rule_id"] == "ssh-check"
        assert r["severity"] == "high"
        assert r["passed"] is False
        assert r["detail"] == "failed"

    def test_ac3_json_remediate_fields(self):
        """AC-3: JSON for remediate includes summary.fixed, remediated, remediation_detail, rolled_back."""
        result = _make_rule_result(
            passed=True,
            remediated=True,
            remediation_detail="Set PermitRootLogin to no",
            rolled_back=False,
        )
        host = HostResult(hostname="server1", results=[result])
        run = _make_run_result(command="remediate", hosts=[host])

        output = write_output(run, "json")
        data = json.loads(output)

        assert "fixed" in data["summary"]
        r = data["hosts"][0]["results"][0]
        assert r["remediated"] is True
        assert r["remediation_detail"] == "Set PermitRootLogin to no"

    def test_ac4_csv_header_row(self):
        """AC-4: write_output with fmt='csv' returns CSV with header row."""
        result = _make_rule_result()
        host = HostResult(
            hostname="server1",
            platform_family="rhel",
            platform_version=9,
            results=[result],
        )
        run = _make_run_result(hosts=[host])

        output = write_output(run, "csv")
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        # First row is header
        header = rows[0]
        assert "host" in header
        assert "platform" in header
        assert "rule_id" in header
        assert "severity" in header
        assert "passed" in header
        assert "skipped" in header
        assert "detail" in header

    def test_ac5_csv_remediate_adds_column(self):
        """AC-5: CSV remediate adds 'remediated' column."""
        result = _make_rule_result(remediated=True)
        host = HostResult(hostname="server1", results=[result])
        run = _make_run_result(command="remediate", hosts=[host])

        output = write_output(run, "csv")
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        header = rows[0]
        assert "remediated" in header

    def test_ac6_csv_connection_error_single_row(self):
        """AC-6: CSV hosts with connection errors produce single row with error in detail."""
        host = HostResult(hostname="server1", error="Connection refused")
        run = _make_run_result(hosts=[host])

        output = write_output(run, "csv")
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        # Header + 1 error row
        assert len(rows) == 2
        error_row = dict(zip(rows[0], rows[1], strict=False))
        assert error_row["host"] == "server1"
        assert "Connection error:" in error_row["detail"]
        assert error_row["rule_id"] == ""

    def test_ac7_pdf_requires_filepath(self):
        """AC-7: write_output with fmt='pdf' requires filepath; raises ValueError if None."""
        run = _make_run_result()

        import pytest

        with pytest.raises(ValueError, match="PDF format requires a filepath"):
            write_output(run, "pdf")

    def test_ac8_pdf_raises_importerror_without_reportlab(self):
        """AC-8: PDF raises ImportError when reportlab not installed."""
        run = _make_run_result()

        with (
            mock.patch.dict(sys.modules, {"reportlab": None}),
            mock.patch("runner.output.pdf_fmt.REPORTLAB_AVAILABLE", False),
        ):
            import pytest

            with pytest.raises(ImportError, match="reportlab"):
                write_output(run, "pdf", filepath="/tmp/test.pdf")

    def test_ac9_evidence_returns_structured_json(self):
        """AC-9: write_output with fmt='evidence' returns structured JSON."""
        result = _make_rule_result()
        host = HostResult(
            hostname="server1",
            platform_family="rhel",
            platform_version=9,
            results=[result],
        )
        run = _make_run_result(hosts=[host])

        output = write_output(run, "evidence")
        data = json.loads(output)

        # Evidence format includes host, session, results, summary
        assert "host" in data
        assert "results" in data
        assert "summary" in data

    def test_ac10_unknown_format_raises_valueerror(self):
        """AC-10: Unknown format raises ValueError listing valid formats."""
        run = _make_run_result()

        import pytest

        with pytest.raises(ValueError, match="Unknown output format"):
            write_output(run, "xml")

    def test_ac11_parse_output_spec(self):
        """AC-11: parse_output_spec('json') returns ('json', None); parse_output_spec('csv:out.csv') returns ('csv', 'out.csv')."""
        assert parse_output_spec("json") == ("json", None)
        assert parse_output_spec("csv:out.csv") == ("csv", "out.csv")
        assert parse_output_spec("PDF:Report.pdf") == ("pdf", "Report.pdf")
        assert parse_output_spec("JSON") == ("json", None)

    def test_ac12_filepath_writes_and_returns(self, tmp_path):
        """AC-12: When filepath provided for text formats, output is written to file and returned."""
        result = _make_rule_result()
        host = HostResult(hostname="server1", results=[result])
        run = _make_run_result(hosts=[host])

        outfile = tmp_path / "output.json"
        output = write_output(run, "json", filepath=str(outfile))

        # Output returned as string
        assert output != ""
        data = json.loads(output)
        assert data["command"] == "check"

        # Also written to file
        file_contents = outfile.read_text()
        assert file_contents == output
