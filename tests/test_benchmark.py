"""Tests for the benchmarking framework."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from scripts.benchmark.adapters.aegis_adapter import AegisAdapter
from scripts.benchmark.adapters.base import ToolAdapter, ToolControlResult
from scripts.benchmark.adapters.openscap_adapter import OpenSCAPAdapter
from scripts.benchmark.compare import (
    ControlComparison,
    compare_at_control_level,
    summarize,
)
from scripts.benchmark.report import generate_json, generate_markdown

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def aegis_flat_json(tmp_path: Path) -> Path:
    """Aegis flat-format JSON with framework_section."""
    data = {
        "results": [
            {
                "rule_id": "ssh-disable-root-login",
                "title": "Disable SSH root login",
                "severity": "high",
                "passed": True,
                "skipped": False,
                "detail": "PermitRootLogin: no",
                "framework_section": "5.1.20",
            },
            {
                "rule_id": "ssh-max-auth-tries",
                "title": "Set SSH MaxAuthTries",
                "severity": "medium",
                "passed": False,
                "skipped": False,
                "detail": "MaxAuthTries: 6 (expected <= 4)",
                "framework_section": "5.1.5",
            },
            {
                "rule_id": "passwd-max-days",
                "title": "Password max days",
                "severity": "medium",
                "passed": True,
                "skipped": False,
                "detail": "PASS_MAX_DAYS: 365",
                "framework_section": "5.5.1.1",
            },
            {
                "rule_id": "skipped-rule",
                "title": "A skipped rule",
                "severity": "low",
                "passed": False,
                "skipped": True,
                "detail": "",
                "framework_section": "9.9.9",
            },
            {
                "rule_id": "unmapped-rule",
                "title": "Unmapped rule",
                "severity": "low",
                "passed": True,
                "skipped": False,
                "detail": "ok",
                "framework_section": "",
            },
        ]
    }
    p = tmp_path / "aegis.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture()
def aegis_multihost_json(tmp_path: Path) -> Path:
    """Aegis multi-host JSON."""
    data = {
        "timestamp": "2026-02-19T00:00:00",
        "command": "check",
        "hosts": [
            {
                "hostname": "host1",
                "platform": {"family": "rhel", "version": 9},
                "capabilities": {},
                "results": [
                    {
                        "rule_id": "ssh-disable-root-login",
                        "title": "Disable SSH root login",
                        "severity": "high",
                        "passed": True,
                        "skipped": False,
                        "detail": "PermitRootLogin: no",
                        "framework_section": "5.1.20",
                    },
                ],
                "summary": {"total": 1, "pass": 1, "fail": 0, "skip": 0},
            },
            {
                "hostname": "host2",
                "platform": {"family": "rhel", "version": 9},
                "capabilities": {},
                "results": [
                    {
                        "rule_id": "ssh-disable-root-login",
                        "title": "Disable SSH root login",
                        "severity": "high",
                        "passed": False,
                        "skipped": False,
                        "detail": "PermitRootLogin: yes",
                        "framework_section": "5.1.20",
                    },
                ],
                "summary": {"total": 1, "pass": 0, "fail": 1, "skip": 0},
            },
        ],
        "summary": {"hosts": 2, "total": 2, "pass": 1, "fail": 1, "skip": 0},
    }
    p = tmp_path / "aegis-multi.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture()
def openscap_xml(tmp_path: Path) -> Path:
    """Minimal OpenSCAP XCCDF XML with CIS references."""
    xml = textwrap.dedent("""\
        <?xml version="1.0" encoding="UTF-8"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test">
          <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
            <ident system="https://www.cisecurity.org">CIS-5.1.20</ident>
          </Rule>
          <Rule id="xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny">
            <reference href="https://www.cisecurity.org/benchmark/cis">5.5.1.1</reference>
          </Rule>
          <Rule id="xccdf_org.ssgproject.content_rule_sshd_set_maxauthtries">
            <ident system="https://www.cisecurity.org">CIS-5.1.5</ident>
          </Rule>
          <Rule id="xccdf_org.ssgproject.content_rule_no_cis_ref">
          </Rule>
          <TestResult id="tr1">
            <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
              <result>pass</result>
            </rule-result>
            <rule-result idref="xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny">
              <result>fail</result>
            </rule-result>
            <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_set_maxauthtries">
              <result>pass</result>
            </rule-result>
            <rule-result idref="xccdf_org.ssgproject.content_rule_no_cis_ref">
              <result>pass</result>
            </rule-result>
            <rule-result idref="xccdf_org.ssgproject.content_rule_skipped_rule">
              <result>notselected</result>
            </rule-result>
          </TestResult>
        </Benchmark>
    """)
    p = tmp_path / "openscap.xml"
    p.write_text(xml)
    return p


# ── ToolControlResult tests ───────────────────────────────────────────────────


class TestToolControlResult:
    def test_basic_fields(self):
        r = ToolControlResult(
            tool_name="test",
            control_id="1.1.1",
            passed=True,
            rule_ids=["r1"],
        )
        assert r.tool_name == "test"
        assert r.control_id == "1.1.1"
        assert r.passed is True
        assert r.rule_ids == ["r1"]
        assert r.has_evidence is False
        assert r.has_remediation is False

    def test_none_passed_means_not_covered(self):
        r = ToolControlResult(
            tool_name="test",
            control_id="1.1.1",
            passed=None,
        )
        assert r.passed is None


# ── AegisAdapter tests ────────────────────────────────────────────────────────


class TestAegisAdapter:
    def test_tool_name(self):
        assert AegisAdapter().tool_name == "aegis"

    def test_is_tool_adapter(self):
        assert isinstance(AegisAdapter(), ToolAdapter)

    def test_parse_flat_format(self, aegis_flat_json: Path):
        adapter = AegisAdapter()
        results = adapter.parse(str(aegis_flat_json))

        # 3 controls (skipped and unmapped excluded)
        assert len(results) == 3
        assert "5.1.20" in results
        assert "5.1.5" in results
        assert "5.5.1.1" in results
        assert "9.9.9" not in results  # skipped

    def test_pass_fail_values(self, aegis_flat_json: Path):
        results = AegisAdapter().parse(str(aegis_flat_json))

        assert results["5.1.20"].passed is True
        assert results["5.1.5"].passed is False
        assert results["5.5.1.1"].passed is True

    def test_rule_ids_populated(self, aegis_flat_json: Path):
        results = AegisAdapter().parse(str(aegis_flat_json))

        assert results["5.1.20"].rule_ids == ["ssh-disable-root-login"]
        assert results["5.1.5"].rule_ids == ["ssh-max-auth-tries"]

    def test_detail_populated(self, aegis_flat_json: Path):
        results = AegisAdapter().parse(str(aegis_flat_json))

        assert "PermitRootLogin" in results["5.1.20"].detail

    def test_multihost_format(self, aegis_multihost_json: Path):
        adapter = AegisAdapter()
        results = adapter.parse(str(aegis_multihost_json))

        # Both hosts have 5.1.20; merged, one passes one fails → control fails
        assert "5.1.20" in results
        assert results["5.1.20"].passed is False

    def test_list_hosts(self, aegis_multihost_json: Path):
        adapter = AegisAdapter()
        hosts = adapter.list_hosts(str(aegis_multihost_json))
        assert hosts == ["host1", "host2"]

    def test_list_hosts_flat(self, aegis_flat_json: Path):
        adapter = AegisAdapter()
        hosts = adapter.list_hosts(str(aegis_flat_json))
        assert hosts == ["default"]

    def test_parse_host(self, aegis_multihost_json: Path):
        adapter = AegisAdapter()
        results = adapter.parse_host(str(aegis_multihost_json), "host1")
        assert results["5.1.20"].passed is True

        results2 = adapter.parse_host(str(aegis_multihost_json), "host2")
        assert results2["5.1.20"].passed is False

    def test_parse_host_not_found(self, aegis_multihost_json: Path):
        adapter = AegisAdapter()
        results = adapter.parse_host(str(aegis_multihost_json), "nonexistent")
        assert results == {}

    def test_unmapped_rules_excluded(self, aegis_flat_json: Path):
        results = AegisAdapter().parse(str(aegis_flat_json))
        # Rules without framework_section are excluded
        for r in results.values():
            assert r.control_id != ""

    def test_multi_rule_per_section(self, tmp_path: Path):
        """Multiple rules mapping to the same section: all must pass."""
        data = {
            "results": [
                {
                    "rule_id": "rule-a",
                    "title": "A",
                    "severity": "high",
                    "passed": True,
                    "skipped": False,
                    "detail": "ok",
                    "framework_section": "1.1.1",
                },
                {
                    "rule_id": "rule-b",
                    "title": "B",
                    "severity": "high",
                    "passed": False,
                    "skipped": False,
                    "detail": "fail",
                    "framework_section": "1.1.1",
                },
            ]
        }
        p = tmp_path / "multi.json"
        p.write_text(json.dumps(data))

        results = AegisAdapter().parse(str(p))
        assert results["1.1.1"].passed is False
        assert len(results["1.1.1"].rule_ids) == 2


# ── OpenSCAPAdapter tests ────────────────────────────────────────────────────


class TestOpenSCAPAdapter:
    def test_tool_name(self):
        assert OpenSCAPAdapter().tool_name == "openscap"

    def test_is_tool_adapter(self):
        assert isinstance(OpenSCAPAdapter(), ToolAdapter)

    def test_parse_sections(self, openscap_xml: Path):
        results = OpenSCAPAdapter().parse(str(openscap_xml))

        assert "5.1.20" in results
        assert "5.1.5" in results
        assert "5.5.1.1" in results

    def test_pass_fail_values(self, openscap_xml: Path):
        results = OpenSCAPAdapter().parse(str(openscap_xml))

        assert results["5.1.20"].passed is True
        assert results["5.5.1.1"].passed is False  # pam_faillock fails
        assert results["5.1.5"].passed is True

    def test_rule_ids(self, openscap_xml: Path):
        results = OpenSCAPAdapter().parse(str(openscap_xml))

        assert "sshd_disable_root_login" in results["5.1.20"].rule_ids

    def test_unmapped_excluded(self, openscap_xml: Path):
        results = OpenSCAPAdapter().parse(str(openscap_xml))
        # no_cis_ref should be in unmapped, not in results
        for r in results.values():
            assert "no_cis_ref" not in r.rule_ids

    def test_notselected_skipped(self, openscap_xml: Path):
        results = OpenSCAPAdapter().parse(str(openscap_xml))
        # notselected rules should not appear
        for r in results.values():
            assert "skipped_rule" not in r.rule_ids

    def test_no_evidence(self, openscap_xml: Path):
        results = OpenSCAPAdapter().parse(str(openscap_xml))
        for r in results.values():
            assert r.has_evidence is False
            assert r.evidence_fields == []


# ── Comparison engine tests ───────────────────────────────────────────────────


class TestControlComparison:
    def test_agreement_both_pass(self):
        comp = ControlComparison(
            control_id="1.1",
            framework="cis",
            tool_results={
                "a": ToolControlResult("a", "1.1", passed=True),
                "b": ToolControlResult("b", "1.1", passed=True),
            },
        )
        assert comp.agreement == "agree"

    def test_agreement_both_fail(self):
        comp = ControlComparison(
            control_id="1.1",
            framework="cis",
            tool_results={
                "a": ToolControlResult("a", "1.1", passed=False),
                "b": ToolControlResult("b", "1.1", passed=False),
            },
        )
        assert comp.agreement == "agree"

    def test_disagreement(self):
        comp = ControlComparison(
            control_id="1.1",
            framework="cis",
            tool_results={
                "a": ToolControlResult("a", "1.1", passed=True),
                "b": ToolControlResult("b", "1.1", passed=False),
            },
        )
        assert comp.agreement == "disagree"

    def test_partial_one_tool(self):
        comp = ControlComparison(
            control_id="1.1",
            framework="cis",
            tool_results={
                "a": ToolControlResult("a", "1.1", passed=True),
            },
        )
        assert comp.agreement == "partial"

    def test_none_no_results(self):
        comp = ControlComparison(control_id="1.1", framework="cis")
        assert comp.agreement == "none"

    def test_covered_by(self):
        comp = ControlComparison(
            control_id="1.1",
            framework="cis",
            tool_results={
                "a": ToolControlResult("a", "1.1", passed=True),
                "b": ToolControlResult("b", "1.1", passed=None),
            },
        )
        assert comp.covered_by == ["a"]


class TestCompareAtControlLevel:
    def test_basic_comparison(self):
        tool_a = {
            "1.1": ToolControlResult("a", "1.1", passed=True, rule_ids=["r1"]),
            "1.2": ToolControlResult("a", "1.2", passed=False, rule_ids=["r2"]),
        }
        tool_b = {
            "1.1": ToolControlResult("b", "1.1", passed=True, rule_ids=["r3"]),
            "1.3": ToolControlResult("b", "1.3", passed=True, rule_ids=["r4"]),
        }
        comparisons = compare_at_control_level({"a": tool_a, "b": tool_b})

        assert len(comparisons) == 3  # 1.1, 1.2, 1.3
        ids = [c.control_id for c in comparisons]
        assert ids == ["1.1", "1.2", "1.3"]

    def test_sorted_output(self):
        tool_a = {
            "5.1.20": ToolControlResult("a", "5.1.20", passed=True),
            "1.1.1": ToolControlResult("a", "1.1.1", passed=True),
            "2.3": ToolControlResult("a", "2.3", passed=True),
        }
        comparisons = compare_at_control_level({"a": tool_a})
        ids = [c.control_id for c in comparisons]
        assert ids == ["1.1.1", "2.3", "5.1.20"]

    def test_titles_applied(self):
        tool_a = {
            "1.1": ToolControlResult("a", "1.1", passed=True),
        }
        titles = {"1.1": "Test Control"}
        comparisons = compare_at_control_level({"a": tool_a}, control_titles=titles)
        assert comparisons[0].title == "Test Control"


class TestSummarize:
    def test_basic_summary(self):
        comparisons = [
            ControlComparison(
                control_id="1.1",
                framework="cis",
                tool_results={
                    "a": ToolControlResult("a", "1.1", passed=True),
                    "b": ToolControlResult("b", "1.1", passed=True),
                },
            ),
            ControlComparison(
                control_id="1.2",
                framework="cis",
                tool_results={
                    "a": ToolControlResult("a", "1.2", passed=True),
                    "b": ToolControlResult("b", "1.2", passed=False),
                },
            ),
            ControlComparison(
                control_id="1.3",
                framework="cis",
                tool_results={
                    "a": ToolControlResult("a", "1.3", passed=True),
                },
            ),
        ]
        summary = summarize(comparisons, framework="cis")

        assert summary.total_controls == 3
        assert summary.per_tool_coverage["a"] == 3
        assert summary.per_tool_coverage["b"] == 2
        assert summary.agree_count == 1
        assert summary.disagree_count == 1
        assert summary.exclusive_coverage["a"] == 1
        assert summary.exclusive_coverage["b"] == 0
        assert summary.agreement_rate == 0.5

    def test_empty_comparisons(self):
        summary = summarize([])
        assert summary.total_controls == 0
        assert summary.agreement_rate == 0.0

    def test_all_agree(self):
        comparisons = [
            ControlComparison(
                control_id="1.1",
                framework="cis",
                tool_results={
                    "a": ToolControlResult("a", "1.1", passed=True),
                    "b": ToolControlResult("b", "1.1", passed=True),
                },
            ),
        ]
        summary = summarize(comparisons)
        assert summary.agreement_rate == 1.0


# ── Report generation tests ───────────────────────────────────────────────────


class TestReport:
    @pytest.fixture()
    def sample_data(self):
        comparisons = [
            ControlComparison(
                control_id="1.1",
                framework="cis",
                title="Test Control A",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis", "1.1", passed=True, rule_ids=["r1"]
                    ),
                    "openscap": ToolControlResult(
                        "openscap", "1.1", passed=True, rule_ids=["r2"]
                    ),
                },
            ),
            ControlComparison(
                control_id="1.2",
                framework="cis",
                title="Test Control B",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis", "1.2", passed=True, rule_ids=["r3"]
                    ),
                    "openscap": ToolControlResult(
                        "openscap", "1.2", passed=False, rule_ids=["r4"]
                    ),
                },
            ),
            ControlComparison(
                control_id="1.3",
                framework="cis",
                title="Test Control C",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis", "1.3", passed=True, rule_ids=["r5"]
                    ),
                },
            ),
        ]
        summary = summarize(comparisons, framework="cis")
        return comparisons, summary

    def test_markdown_contains_header(self, sample_data):
        comparisons, summary = sample_data
        md = generate_markdown(comparisons, summary, title="Test Report")
        assert "# Test Report" in md

    def test_markdown_contains_summary_table(self, sample_data):
        comparisons, summary = sample_data
        md = generate_markdown(comparisons, summary)
        assert "Executive Summary" in md
        assert "Coverage" in md
        assert "Agreement" in md

    def test_markdown_contains_disagreements(self, sample_data):
        comparisons, summary = sample_data
        md = generate_markdown(comparisons, summary)
        assert "Disagreement" in md
        assert "1.2" in md

    def test_markdown_contains_exclusive(self, sample_data):
        comparisons, summary = sample_data
        md = generate_markdown(comparisons, summary)
        assert "Exclusive Coverage" in md

    def test_json_structure(self, sample_data):
        comparisons, summary = sample_data
        raw = generate_json(comparisons, summary)
        data = json.loads(raw)

        assert "framework" in data
        assert "summary" in data
        assert "controls" in data
        assert data["summary"]["total_controls"] == 3
        assert data["summary"]["agree_count"] == 1
        assert data["summary"]["disagree_count"] == 1

    def test_json_controls(self, sample_data):
        comparisons, summary = sample_data
        data = json.loads(generate_json(comparisons, summary))

        ctrl = data["controls"][0]
        assert ctrl["control_id"] == "1.1"
        assert ctrl["agreement"] == "agree"
        assert "aegis" in ctrl["tools"]

    def test_markdown_host_header(self, sample_data):
        comparisons, summary = sample_data
        md = generate_markdown(
            comparisons,
            summary,
            host="192.168.1.211",
            tool_versions={"aegis": "v1.9.0", "openscap": "1.3.x"},
        )
        assert "192.168.1.211" in md
        assert "v1.9.0" in md


# ── Integration: adapters → compare → report ─────────────────────────────────


class TestIntegration:
    def test_full_pipeline(self, aegis_flat_json: Path, openscap_xml: Path):
        """End-to-end: parse both → compare → summarize → report."""
        aegis_results = AegisAdapter().parse(str(aegis_flat_json))
        openscap_results = OpenSCAPAdapter().parse(str(openscap_xml))

        comparisons = compare_at_control_level(
            {"aegis": aegis_results, "openscap": openscap_results},
            framework="cis-test",
        )
        summary = summarize(comparisons, framework="cis-test")

        # Both tools cover 5.1.20, 5.1.5, 5.5.1.1
        assert summary.total_controls == 3

        # Check agreement on 5.1.20 (both pass)
        c_5120 = next(c for c in comparisons if c.control_id == "5.1.20")
        assert c_5120.agreement == "agree"

        # Check disagreement on 5.5.1.1 (aegis pass, openscap fail)
        c_5511 = next(c for c in comparisons if c.control_id == "5.5.1.1")
        assert c_5511.agreement == "disagree"

        # Check disagreement on 5.1.5 (aegis fail, openscap pass)
        c_515 = next(c for c in comparisons if c.control_id == "5.1.5")
        assert c_515.agreement == "disagree"

        # Generate reports (just ensure no crash)
        md = generate_markdown(comparisons, summary)
        assert len(md) > 0

        js = generate_json(comparisons, summary)
        data = json.loads(js)
        assert data["summary"]["total_controls"] == 3

    def test_write_report(self, tmp_path: Path):
        """Test file writing."""
        from scripts.benchmark.report import write_report

        out = tmp_path / "report.md"
        write_report("# Test", str(out))
        assert out.read_text() == "# Test"


# ── CLI tests ─────────────────────────────────────────────────────────────────


class TestCLI:
    def test_main_markdown(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "report.md"
        rc = main(
            [
                "--aegis",
                str(aegis_flat_json),
                "--openscap",
                str(openscap_xml),
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        assert output.exists()
        content = output.read_text()
        assert "Benchmark Comparison" in content

    def test_main_json(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "report.json"
        rc = main(
            [
                "--aegis",
                str(aegis_flat_json),
                "--openscap",
                str(openscap_xml),
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        data = json.loads(output.read_text())
        assert "summary" in data
        assert "controls" in data

    def test_main_stdout(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        capsys,
    ):
        from scripts.benchmark.benchmark_cli import main

        rc = main(
            [
                "--aegis",
                str(aegis_flat_json),
                "--openscap",
                str(openscap_xml),
            ]
        )
        assert rc == 0
        captured = capsys.readouterr()
        assert "Benchmark Comparison" in captured.out
