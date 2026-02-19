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
    CoverageDimension,
    HostComparison,
    MultiHostResult,
    aggregate_hosts,
    compare_at_control_level,
    compute_coverage,
    detect_mapping_errors,
    load_known_mapping_errors,
    summarize,
)
from scripts.benchmark.report import (
    generate_json,
    generate_markdown,
    generate_multihost_json,
    generate_multihost_markdown,
)

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


# ── Phase 2: Multi-host + Coverage tests ─────────────────────────────────────


def _make_host_comparison(
    host_name: str,
    platform: str,
    aegis_results: dict[str, ToolControlResult],
    openscap_results: dict[str, ToolControlResult],
    framework: str = "cis",
) -> HostComparison:
    """Helper to build a HostComparison from tool results."""
    tool_results = {"aegis": aegis_results, "openscap": openscap_results}
    comparisons = compare_at_control_level(tool_results, framework=framework)
    summary = summarize(comparisons, framework=framework)
    return HostComparison(
        host_name=host_name,
        platform=platform,
        comparisons=comparisons,
        summary=summary,
    )


class TestCoverageDimension:
    def test_basic_coverage(self):
        results = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True),
            "1.2": ToolControlResult("aegis", "1.2", passed=False),
        }
        cov = compute_coverage(results, total_framework=10, tool_name="aegis")
        assert cov.tool_name == "aegis"
        assert cov.controls_covered == 2
        assert cov.total_framework == 10
        assert cov.coverage_percent == 20.0

    def test_zero_total(self):
        results = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True),
        }
        cov = compute_coverage(results, total_framework=0, tool_name="aegis")
        assert cov.coverage_percent == 0.0

    def test_none_passed_excluded(self):
        results = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True),
            "1.2": ToolControlResult("aegis", "1.2", passed=None),
        }
        cov = compute_coverage(results, total_framework=5, tool_name="aegis")
        assert cov.controls_covered == 1

    def test_exclusive_controls(self):
        results = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True),
            "1.2": ToolControlResult("aegis", "1.2", passed=True),
        }
        cov = compute_coverage(
            results,
            total_framework=10,
            tool_name="aegis",
            exclusive_ids={"1.2"},
        )
        assert cov.exclusive_controls == 1

    def test_empty_results(self):
        cov = compute_coverage({}, total_framework=10, tool_name="aegis")
        assert cov.controls_covered == 0
        assert cov.coverage_percent == 0.0


class TestHostComparison:
    def test_host_comparison_fields(self):
        aegis = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}
        hc = _make_host_comparison("rhel9-211", "rhel9", aegis, openscap)

        assert hc.host_name == "rhel9-211"
        assert hc.platform == "rhel9"
        assert len(hc.comparisons) == 1
        assert hc.summary.agree_count == 1

    def test_host_with_coverage(self):
        aegis = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}
        hc = _make_host_comparison("rhel9-211", "rhel9", aegis, openscap)
        hc.coverage["aegis"] = compute_coverage(aegis, 5, "aegis")
        hc.coverage["openscap"] = compute_coverage(openscap, 5, "openscap")

        assert hc.coverage["aegis"].controls_covered == 1
        assert hc.coverage["openscap"].coverage_percent == 20.0


class TestMultiHostResult:
    def test_multihost_structure(self):
        aegis = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}
        hc1 = _make_host_comparison("rhel9-211", "rhel9", aegis, openscap)
        hc2 = _make_host_comparison("rhel9-213", "rhel9", aegis, openscap)

        agg = aggregate_hosts([hc1, hc2], framework="cis")
        result = MultiHostResult(
            framework="cis",
            hosts=[hc1, hc2],
            aggregate_summary=agg,
        )

        assert len(result.hosts) == 2
        assert result.aggregate_summary.total_controls == 1
        assert result.framework == "cis"


class TestAggregateHosts:
    def test_union_of_controls(self):
        """Aggregate should include union of all controls across hosts."""
        aegis1 = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True),
        }
        openscap1 = {
            "1.1": ToolControlResult("openscap", "1.1", passed=True),
        }
        aegis2 = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True),
            "1.2": ToolControlResult("aegis", "1.2", passed=False),
        }
        openscap2 = {
            "1.1": ToolControlResult("openscap", "1.1", passed=True),
            "1.2": ToolControlResult("openscap", "1.2", passed=False),
        }

        hc1 = _make_host_comparison("h1", "rhel9", aegis1, openscap1)
        hc2 = _make_host_comparison("h2", "rhel9", aegis2, openscap2)

        agg = aggregate_hosts([hc1, hc2], framework="cis")
        assert agg.total_controls == 2

    def test_empty_hosts(self):
        agg = aggregate_hosts([], framework="cis")
        assert agg.total_controls == 0

    def test_any_fail_aggregates_conservative(self):
        """If any host fails a tool on a control, aggregate shows fail."""
        aegis1 = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap1 = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}
        aegis2 = {"1.1": ToolControlResult("aegis", "1.1", passed=False)}
        openscap2 = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}

        hc1 = _make_host_comparison("h1", "rhel9", aegis1, openscap1)
        hc2 = _make_host_comparison("h2", "rhel9", aegis2, openscap2)

        agg = aggregate_hosts([hc1, hc2], framework="cis")
        # aegis pass on h1, fail on h2 → aggregate fail
        # openscap pass on both → aggregate pass
        # Result: disagree
        assert agg.disagree_count == 1

    def test_agreement_recalculated(self):
        """Aggregate recalculates agreement from merged results."""
        aegis1 = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap1 = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}

        hc1 = _make_host_comparison("h1", "rhel9", aegis1, openscap1)
        hc2 = _make_host_comparison("h2", "rhel9", aegis1, openscap1)

        agg = aggregate_hosts([hc1, hc2])
        assert agg.agree_count == 1
        assert agg.agreement_rate == 1.0


class TestMultiHostReport:
    @pytest.fixture()
    def multihost_result(self) -> MultiHostResult:
        aegis1 = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True, rule_ids=["r1"]),
            "1.2": ToolControlResult("aegis", "1.2", passed=True, rule_ids=["r2"]),
        }
        openscap1 = {
            "1.1": ToolControlResult("openscap", "1.1", passed=True, rule_ids=["r3"]),
            "1.2": ToolControlResult("openscap", "1.2", passed=False, rule_ids=["r4"]),
        }
        aegis2 = {
            "1.1": ToolControlResult("aegis", "1.1", passed=True, rule_ids=["r1"]),
            "1.2": ToolControlResult("aegis", "1.2", passed=False, rule_ids=["r2"]),
        }
        openscap2 = {
            "1.1": ToolControlResult("openscap", "1.1", passed=False, rule_ids=["r3"]),
            "1.2": ToolControlResult("openscap", "1.2", passed=False, rule_ids=["r4"]),
        }

        hc1 = _make_host_comparison("rhel9-211", "rhel9", aegis1, openscap1)
        hc2 = _make_host_comparison("rhel8-202", "rhel8", aegis2, openscap2)

        agg = aggregate_hosts([hc1, hc2], framework="cis")
        return MultiHostResult(
            framework="cis",
            hosts=[hc1, hc2],
            aggregate_summary=agg,
        )

    def test_markdown_contains_aggregate_summary(self, multihost_result):
        md = generate_multihost_markdown(multihost_result)
        assert "Aggregate Summary" in md
        assert "Total controls (union)" in md

    def test_markdown_contains_per_host(self, multihost_result):
        md = generate_multihost_markdown(multihost_result)
        assert "rhel9-211" in md
        assert "rhel8-202" in md
        assert "Per-Host Results" in md

    def test_markdown_contains_crossplatform(self, multihost_result):
        md = generate_multihost_markdown(multihost_result)
        assert "Cross-Platform Table" in md

    def test_markdown_contains_consistency(self, multihost_result):
        md = generate_multihost_markdown(multihost_result)
        assert "Cross-Platform Consistency" in md
        assert "Consistent across hosts" in md

    def test_json_structure(self, multihost_result):
        raw = generate_multihost_json(multihost_result)
        data = json.loads(raw)

        assert "hosts" in data
        assert len(data["hosts"]) == 2
        assert "aggregate" in data
        assert data["hosts"][0]["host_name"] == "rhel9-211"
        assert data["hosts"][1]["host_name"] == "rhel8-202"

    def test_json_per_host_comparisons(self, multihost_result):
        data = json.loads(generate_multihost_json(multihost_result))

        host0 = data["hosts"][0]
        assert "comparisons" in host0
        assert "summary" in host0
        assert host0["platform"] == "rhel9"

    def test_markdown_with_coverage(self, multihost_result):
        multihost_result.aggregate_coverage = {
            "aegis": CoverageDimension("aegis", 2, 10, 20.0, 0),
            "openscap": CoverageDimension("openscap", 2, 10, 20.0, 0),
        }
        md = generate_multihost_markdown(multihost_result)
        assert "Framework Coverage" in md
        assert "20.0%" in md

    def test_json_with_coverage(self, multihost_result):
        multihost_result.aggregate_coverage = {
            "aegis": CoverageDimension("aegis", 2, 10, 20.0, 1),
        }
        data = json.loads(generate_multihost_json(multihost_result))
        assert "coverage" in data["aggregate"]
        assert data["aggregate"]["coverage"]["aegis"]["controls_covered"] == 2


class TestCrossplatformTable:
    def test_table_rows(self):
        """Cross-platform table has a row per control, column per host/tool."""
        aegis1 = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap1 = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}
        aegis2 = {"1.1": ToolControlResult("aegis", "1.1", passed=False)}
        openscap2 = {"1.1": ToolControlResult("openscap", "1.1", passed=False)}

        hc1 = _make_host_comparison("h1", "rhel9", aegis1, openscap1)
        hc2 = _make_host_comparison("h2", "rhel8", aegis2, openscap2)

        agg = aggregate_hosts([hc1, hc2], framework="cis")
        result = MultiHostResult(
            framework="cis",
            hosts=[hc1, hc2],
            aggregate_summary=agg,
        )
        md = generate_multihost_markdown(result)

        # Headers should include host/tool combos
        assert "h1/aegis" in md
        assert "h2/openscap" in md
        # Control row
        assert "1.1" in md
        assert "PASS" in md
        assert "FAIL" in md

    def test_missing_control_shows_dash(self):
        """Controls not present on a host show '—'."""
        aegis1 = {"1.1": ToolControlResult("aegis", "1.1", passed=True)}
        openscap1 = {"1.1": ToolControlResult("openscap", "1.1", passed=True)}
        aegis2 = {"1.2": ToolControlResult("aegis", "1.2", passed=False)}
        openscap2 = {"1.2": ToolControlResult("openscap", "1.2", passed=False)}

        hc1 = _make_host_comparison("h1", "rhel9", aegis1, openscap1)
        hc2 = _make_host_comparison("h2", "rhel8", aegis2, openscap2)

        agg = aggregate_hosts([hc1, hc2], framework="cis")
        result = MultiHostResult(
            framework="cis",
            hosts=[hc1, hc2],
            aggregate_summary=agg,
        )
        md = generate_multihost_markdown(result)
        # Control 1.1 only on h1, so h2 columns should show —
        assert "\u2014" in md  # em dash


class TestOpenSCAPCountMappedSections:
    def test_count_sections(self, openscap_xml: Path):
        adapter = OpenSCAPAdapter()
        count = adapter.count_mapped_sections(str(openscap_xml))
        # Fixture has 3 CIS sections: 5.1.20, 5.1.5, 5.5.1.1
        assert count == 3


class TestCLIMultiHost:
    def test_pair_markdown(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "multihost.md"
        rc = main(
            [
                "--pair",
                f"rhel9-211:{aegis_flat_json}:{openscap_xml}",
                "--pair",
                f"rhel9-213:{aegis_flat_json}:{openscap_xml}",
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        content = output.read_text()
        assert "Multi-Host" in content
        assert "rhel9-211" in content
        assert "rhel9-213" in content

    def test_pair_json(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "multihost.json"
        rc = main(
            [
                "--pair",
                f"rhel9-211:{aegis_flat_json}:{openscap_xml}",
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        data = json.loads(output.read_text())
        assert "hosts" in data
        assert "aggregate" in data
        assert data["hosts"][0]["host_name"] == "rhel9-211"

    def test_pair_mutual_exclusion(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        with pytest.raises(SystemExit):
            main(
                [
                    "--aegis",
                    str(aegis_flat_json),
                    "--openscap",
                    str(openscap_xml),
                    "--pair",
                    f"h1:{aegis_flat_json}:{openscap_xml}",
                ]
            )

    def test_no_args_errors(self):
        from scripts.benchmark.benchmark_cli import main

        with pytest.raises(SystemExit):
            main([])


class TestCLIBackwardCompat:
    def test_single_host_still_works(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "compat.md"
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
        content = output.read_text()
        assert "Benchmark Comparison" in content

    def test_single_host_json_still_works(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "compat.json"
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

    def test_aegis_only_errors(self, aegis_flat_json: Path):
        from scripts.benchmark.benchmark_cli import main

        with pytest.raises(SystemExit):
            main(["--aegis", str(aegis_flat_json)])


# ── Phase 3: Mapping Error Detection tests ───────────────────────────────────


@pytest.fixture()
def known_errors_yaml(tmp_path: Path) -> Path:
    """Create a sample known mapping errors YAML file."""
    content = textwrap.dedent("""\
        version: 1
        errors:
          - control_id: "1.2.1"
            reason: "Firewall rules mapped to GPG check"
            rules:
              - package_firewalld_installed
              - service_firewalld_enabled
          - control_id: "1.4.3"
            reason: "Sysctl rules mapped to GRUB config"
            rules:
              - sysctl_net_ipv6_conf_default_accept_source_route
    """)
    p = tmp_path / "known_errors.yaml"
    p.write_text(content)
    return p


class TestKnownMappingErrors:
    def test_load_known_errors(self, known_errors_yaml: Path):
        errors = load_known_mapping_errors(str(known_errors_yaml))
        assert len(errors) == 2
        assert "1.2.1" in errors
        assert "1.4.3" in errors

    def test_error_fields(self, known_errors_yaml: Path):
        errors = load_known_mapping_errors(str(known_errors_yaml))
        e = errors["1.2.1"]
        assert e.control_id == "1.2.1"
        assert "Firewall" in e.reason
        assert "package_firewalld_installed" in e.rules
        assert len(e.rules) == 2

    def test_match_against_comparisons(self, known_errors_yaml: Path):
        errors = load_known_mapping_errors(str(known_errors_yaml))
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                title="Enable GPG signature checking",
                tool_results={
                    "aegis": ToolControlResult("aegis", "1.2.1", passed=True),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                        rule_ids=["package_firewalld_installed"],
                    ),
                },
            ),
        ]
        detect_mapping_errors(comps, errors)
        assert comps[0].mapping_error == "known"
        assert "Firewall" in comps[0].mapping_error_reason

    def test_unknown_control_ignored(self, known_errors_yaml: Path):
        errors = load_known_mapping_errors(str(known_errors_yaml))
        comps = [
            ControlComparison(
                control_id="9.9.9",
                framework="cis",
                title="Unknown control",
                tool_results={
                    "aegis": ToolControlResult("aegis", "9.9.9", passed=True),
                    "openscap": ToolControlResult(
                        "openscap",
                        "9.9.9",
                        passed=False,
                        rule_ids=["unknown_rule"],
                    ),
                },
            ),
        ]
        detect_mapping_errors(comps, errors)
        # Not in allowlist, and heuristic checks keyword overlap
        assert comps[0].mapping_error != "known"


class TestMappingHeuristic:
    def test_zero_overlap_flagged(self):
        """Rules with no keyword overlap to title are flagged as suspected."""
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                title="Enable GPG signature checking for packages",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "1.2.1",
                        passed=True,
                        rule_ids=["gpgcheck_enabled"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                        rule_ids=["service_firewalld_enabled"],
                    ),
                },
            ),
        ]
        detect_mapping_errors(comps)
        assert comps[0].mapping_error == "suspected"

    def test_partial_overlap_not_flagged(self):
        """Rules with some keyword overlap to title are NOT flagged."""
        comps = [
            ControlComparison(
                control_id="5.1.5",
                framework="cis",
                title="Ensure sshd KexAlgorithms is configured",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "5.1.5",
                        passed=True,
                        rule_ids=["ssh_approved_kex"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "5.1.5",
                        passed=False,
                        rule_ids=["sshd_use_strong_kex"],
                    ),
                },
            ),
        ]
        detect_mapping_errors(comps)
        assert comps[0].mapping_error == ""

    def test_non_disagreement_skipped(self):
        """Controls that agree are not checked for mapping errors."""
        comps = [
            ControlComparison(
                control_id="1.1",
                framework="cis",
                title="Test control",
                tool_results={
                    "aegis": ToolControlResult("aegis", "1.1", passed=True),
                    "openscap": ToolControlResult("openscap", "1.1", passed=True),
                },
            ),
        ]
        detect_mapping_errors(comps)
        assert comps[0].mapping_error == ""

    def test_no_title_skips_heuristic(self):
        """Controls without a title skip the heuristic."""
        comps = [
            ControlComparison(
                control_id="1.1",
                framework="cis",
                title="",
                tool_results={
                    "aegis": ToolControlResult("aegis", "1.1", passed=True),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.1",
                        passed=False,
                        rule_ids=["unrelated_rule"],
                    ),
                },
            ),
        ]
        detect_mapping_errors(comps)
        assert comps[0].mapping_error == ""


class TestDetectMappingErrors:
    def test_combined_allowlist_and_heuristic(self, known_errors_yaml: Path):
        """Allowlist takes precedence; heuristic catches remaining."""
        errors = load_known_mapping_errors(str(known_errors_yaml))
        comps = [
            # Known error (in allowlist)
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                title="Enable GPG signature checking",
                tool_results={
                    "aegis": ToolControlResult("aegis", "1.2.1", passed=True),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                        rule_ids=["package_firewalld_installed"],
                    ),
                },
            ),
            # Suspected error (zero keyword overlap)
            ControlComparison(
                control_id="1.5.1",
                framework="cis",
                title="Restrict core dumps",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "1.5.1",
                        passed=False,
                        rule_ids=["coredump_restricted"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.5.1",
                        passed=True,
                        rule_ids=["sysctl_kernel_randomize_va_space"],
                    ),
                },
            ),
            # Real disagreement (keyword overlap exists)
            ControlComparison(
                control_id="5.1.5",
                framework="cis",
                title="Ensure sshd KexAlgorithms is configured",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "5.1.5",
                        passed=True,
                        rule_ids=["ssh_approved_kex"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "5.1.5",
                        passed=False,
                        rule_ids=["sshd_use_strong_kex"],
                    ),
                },
            ),
        ]
        detect_mapping_errors(comps, errors)
        assert comps[0].mapping_error == "known"
        assert comps[1].mapping_error == "suspected"
        assert comps[2].mapping_error == ""

    def test_summarize_excludes_mapping_errors(self):
        """Mapping errors are excluded from disagree_count and agreement_rate."""
        comps = [
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
                mapping_error="known",
                mapping_error_reason="bad mapping",
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
                    "b": ToolControlResult("b", "1.3", passed=False),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        assert summary.agree_count == 1
        assert summary.disagree_count == 1  # Only 1.3, not 1.2
        assert summary.mapping_error_count == 1
        # agreement_rate = 1 agree / (1 agree + 1 disagree) = 0.5
        assert summary.agreement_rate == 0.5


class TestMappingErrorReport:
    def test_markdown_has_known_errors_section(self):
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                title="Enable GPG checking",
                mapping_error="known",
                mapping_error_reason="Firewall rules mapped to GPG",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "1.2.1",
                        passed=True,
                        rule_ids=["r1"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                        rule_ids=["package_firewalld_installed"],
                    ),
                },
            ),
            ControlComparison(
                control_id="5.1.5",
                framework="cis",
                title="Ensure sshd KexAlgorithms",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "5.1.5",
                        passed=True,
                        rule_ids=["r2"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "5.1.5",
                        passed=False,
                        rule_ids=["sshd_use_strong_kex"],
                    ),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        md = generate_markdown(comps, summary)

        assert "Known Mapping Errors (1)" in md
        assert "Firewall rules mapped to GPG" in md
        # The real disagreement is still in the Disagreements section
        assert "Disagreements (1)" in md

    def test_markdown_has_suspected_errors_section(self):
        comps = [
            ControlComparison(
                control_id="2.2.4",
                framework="cis",
                title="Ensure telnet client is not installed",
                mapping_error="suspected",
                mapping_error_reason="Zero keyword overlap",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "2.2.4",
                        passed=True,
                        rule_ids=["r1"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "2.2.4",
                        passed=False,
                        rule_ids=["package_dhcp_removed"],
                    ),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        md = generate_markdown(comps, summary)

        assert "Suspected Mapping Errors (1)" in md
        assert "2.2.4" in md

    def test_markdown_disagreement_count_reduced(self):
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                title="GPG check",
                mapping_error="known",
                mapping_error_reason="bad",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "1.2.1",
                        passed=True,
                        rule_ids=["r1"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                        rule_ids=["r2"],
                    ),
                },
            ),
            ControlComparison(
                control_id="5.1.5",
                framework="cis",
                title="KexAlgorithms",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "5.1.5",
                        passed=True,
                        rule_ids=["r3"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "5.1.5",
                        passed=False,
                        rule_ids=["r4"],
                    ),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        md = generate_markdown(comps, summary)

        # Only the real disagreement shows in Disagreements section
        assert "Disagreements (1)" in md
        # Known errors in their own section
        assert "Known Mapping Errors (1)" in md


class TestMappingErrorJSON:
    def test_json_includes_mapping_error_fields(self):
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                title="GPG check",
                mapping_error="known",
                mapping_error_reason="Firewall mapped to GPG",
                tool_results={
                    "aegis": ToolControlResult(
                        "aegis",
                        "1.2.1",
                        passed=True,
                        rule_ids=["r1"],
                    ),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                        rule_ids=["r2"],
                    ),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        data = json.loads(generate_json(comps, summary))

        ctrl = data["controls"][0]
        assert ctrl["mapping_error"] == "known"
        assert ctrl["mapping_error_reason"] == "Firewall mapped to GPG"

    def test_json_summary_has_mapping_error_count(self):
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                mapping_error="known",
                mapping_error_reason="bad",
                tool_results={
                    "aegis": ToolControlResult("aegis", "1.2.1", passed=True),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                    ),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        data = json.loads(generate_json(comps, summary))

        assert data["summary"]["mapping_error_count"] == 1
        assert data["summary"]["disagree_count"] == 0

    def test_multihost_json_includes_mapping_error(self):
        comps = [
            ControlComparison(
                control_id="1.2.1",
                framework="cis",
                mapping_error="known",
                mapping_error_reason="bad mapping",
                tool_results={
                    "aegis": ToolControlResult("aegis", "1.2.1", passed=True),
                    "openscap": ToolControlResult(
                        "openscap",
                        "1.2.1",
                        passed=False,
                    ),
                },
            ),
        ]
        summary = summarize(comps, framework="cis")
        hc = HostComparison(
            host_name="h1",
            platform="rhel9",
            comparisons=comps,
            summary=summary,
        )
        agg = aggregate_hosts([hc], framework="cis")
        result = MultiHostResult(
            framework="cis",
            hosts=[hc],
            aggregate_summary=agg,
        )
        data = json.loads(generate_multihost_json(result))

        entry = data["hosts"][0]["comparisons"][0]
        assert entry["mapping_error"] == "known"
        assert entry["mapping_error_reason"] == "bad mapping"


class TestCLIKnownErrors:
    def test_cli_with_known_errors_flag(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        known_errors_yaml: Path,
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
                "--known-errors",
                str(known_errors_yaml),
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        content = output.read_text()
        assert "Benchmark Comparison" in content

    def test_cli_known_errors_json(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        known_errors_yaml: Path,
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
                "--known-errors",
                str(known_errors_yaml),
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        data = json.loads(output.read_text())
        assert "mapping_error_count" in data["summary"]

    def test_cli_multihost_with_known_errors(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        known_errors_yaml: Path,
        tmp_path: Path,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "multihost.md"
        rc = main(
            [
                "--pair",
                f"rhel9-211:{aegis_flat_json}:{openscap_xml}",
                "--known-errors",
                str(known_errors_yaml),
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        content = output.read_text()
        assert "Multi-Host" in content

    def test_cli_missing_known_errors_warns(
        self,
        aegis_flat_json: Path,
        openscap_xml: Path,
        tmp_path: Path,
        capsys,
    ):
        from scripts.benchmark.benchmark_cli import main

        output = tmp_path / "report.md"
        rc = main(
            [
                "--aegis",
                str(aegis_flat_json),
                "--openscap",
                str(openscap_xml),
                "--known-errors",
                "/nonexistent/path.yaml",
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        captured = capsys.readouterr()
        assert "not found" in captured.err
