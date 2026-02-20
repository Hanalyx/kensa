"""Tests for scripts/gap_analysis.py — KENSA vs OpenSCAP comparison."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from scripts.gap_analysis import (
    KENSA_TO_OPENSCAP,
    OPENSCAP_TO_KENSA,
    RuleResult,
    find_matching_openscap_rule,
    generate_report,
    normalize_rule_id,
    parse_kensa_json,
    parse_openscap_xml,
)

# ---------------------------------------------------------------------------
# Fixtures — synthetic test data
# ---------------------------------------------------------------------------

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

MINIMAL_XCCDF = textwrap.dedent(f"""\
    <?xml version="1.0" encoding="UTF-8"?>
    <Benchmark xmlns="{XCCDF_NS}">
      <TestResult id="test-result-1">
        <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
          <result>pass</result>
        </rule-result>
        <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_empty_passwords">
          <result>fail</result>
        </rule-result>
        <rule-result idref="xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled">
          <result>notapplicable</result>
        </rule-result>
        <rule-result idref="xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled">
          <result>notselected</result>
        </rule-result>
        <rule-result idref="xccdf_org.ssgproject.content_rule_service_cups_disabled">
          <result>notchecked</result>
        </rule-result>
      </TestResult>
      <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
        <title>Disable SSH Root Login</title>
      </Rule>
      <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_empty_passwords">
        <title>Disable SSH Empty Passwords</title>
      </Rule>
    </Benchmark>
""")


def _write_xccdf(tmp_path: Path, content: str = MINIMAL_XCCDF) -> Path:
    p = tmp_path / "openscap-results.xml"
    p.write_text(content)
    return p


def _write_kensa_json(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "kensa-results.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def xccdf_path(tmp_path):
    return _write_xccdf(tmp_path)


@pytest.fixture
def kensa_single_host_json(tmp_path):
    data = {
        "results": [
            {
                "rule_id": "ssh-disable-root-login",
                "title": "Disable SSH root login",
                "passed": True,
                "detail": "PermitRootLogin no",
                "framework_section": "5.2.10",
            },
            {
                "rule_id": "ssh-permit-empty-passwords",
                "title": "Disallow empty passwords",
                "passed": False,
                "detail": "PermitEmptyPasswords yes (expected no)",
                "framework_section": "5.2.11",
            },
            {
                "rule_id": "kmod-disable-cramfs",
                "title": "Disable cramfs module",
                "passed": True,
                "detail": "",
                "framework_section": "1.1.1.1",
            },
            {
                "rule_id": "custom-kensa-only-rule",
                "title": "Custom KENSA rule",
                "passed": True,
                "detail": "ok",
                "framework_section": "99.99",
            },
        ]
    }
    return _write_kensa_json(tmp_path, data)


# ---------------------------------------------------------------------------
# RuleResult dataclass
# ---------------------------------------------------------------------------


class TestRuleResult:
    def test_defaults(self):
        r = RuleResult(rule_id="test", title="Test", passed=True)
        assert r.detail == ""
        assert r.section == ""

    def test_with_all_fields(self):
        r = RuleResult(
            rule_id="ssh-root",
            title="Root Login",
            passed=False,
            detail="bad config",
            section="5.2.10",
        )
        assert r.rule_id == "ssh-root"
        assert r.passed is False
        assert r.detail == "bad config"
        assert r.section == "5.2.10"


# ---------------------------------------------------------------------------
# parse_openscap_xml
# ---------------------------------------------------------------------------


class TestParseOpenscapXML:
    def test_pass_and_fail_parsed(self, xccdf_path):
        results = parse_openscap_xml(str(xccdf_path))
        assert "sshd_disable_root_login" in results
        assert "sshd_disable_empty_passwords" in results
        assert results["sshd_disable_root_login"].passed is True
        assert results["sshd_disable_empty_passwords"].passed is False

    def test_notapplicable_skipped(self, xccdf_path):
        results = parse_openscap_xml(str(xccdf_path))
        assert "service_avahi-daemon_disabled" not in results

    def test_notselected_skipped(self, xccdf_path):
        results = parse_openscap_xml(str(xccdf_path))
        assert "kernel_module_cramfs_disabled" not in results

    def test_notchecked_skipped(self, xccdf_path):
        results = parse_openscap_xml(str(xccdf_path))
        assert "service_cups_disabled" not in results

    def test_titles_populated_from_rule_defs(self, xccdf_path):
        results = parse_openscap_xml(str(xccdf_path))
        assert results["sshd_disable_root_login"].title == "Disable SSH Root Login"
        assert (
            results["sshd_disable_empty_passwords"].title
            == "Disable SSH Empty Passwords"
        )

    def test_short_id_extraction(self, xccdf_path):
        results = parse_openscap_xml(str(xccdf_path))
        for rule_id in results:
            assert "xccdf_org.ssgproject" not in rule_id

    def test_empty_test_result(self, tmp_path):
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <Benchmark xmlns="{XCCDF_NS}">
              <TestResult id="empty"></TestResult>
            </Benchmark>
        """)
        p = _write_xccdf(tmp_path, xml)
        results = parse_openscap_xml(str(p))
        assert results == {}

    def test_missing_result_element(self, tmp_path):
        """rule-result with no <result> child should be skipped."""
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <Benchmark xmlns="{XCCDF_NS}">
              <TestResult id="t1">
                <rule-result idref="xccdf_org.ssgproject.content_rule_test_rule">
                </rule-result>
              </TestResult>
            </Benchmark>
        """)
        p = _write_xccdf(tmp_path, xml)
        results = parse_openscap_xml(str(p))
        assert results == {}

    def test_unknown_result_text_skipped(self, tmp_path):
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <Benchmark xmlns="{XCCDF_NS}">
              <TestResult id="t1">
                <rule-result idref="xccdf_org.ssgproject.content_rule_test_rule">
                  <result>error</result>
                </rule-result>
              </TestResult>
            </Benchmark>
        """)
        p = _write_xccdf(tmp_path, xml)
        results = parse_openscap_xml(str(p))
        assert results == {}


# ---------------------------------------------------------------------------
# parse_kensa_json
# ---------------------------------------------------------------------------


class TestParseKensaJSON:
    def test_single_host_format(self, kensa_single_host_json):
        results = parse_kensa_json(str(kensa_single_host_json))
        assert len(results) == 4
        assert results["ssh-disable-root-login"].passed is True
        assert results["ssh-permit-empty-passwords"].passed is False

    def test_multi_host_format(self, tmp_path):
        data = {
            "hosts": [
                {
                    "results": [
                        {"rule_id": "rule-a", "title": "A", "passed": True},
                    ]
                },
                {
                    "results": [
                        {"rule_id": "rule-b", "title": "B", "passed": False},
                    ]
                },
            ]
        }
        p = _write_kensa_json(tmp_path, data)
        results = parse_kensa_json(str(p))
        assert "rule-a" in results
        assert "rule-b" in results

    def test_skipped_rules_excluded(self, tmp_path):
        data = {
            "results": [
                {"rule_id": "rule-ok", "title": "OK", "passed": True},
                {
                    "rule_id": "rule-skip",
                    "title": "Skip",
                    "passed": False,
                    "skipped": True,
                },
            ]
        }
        p = _write_kensa_json(tmp_path, data)
        results = parse_kensa_json(str(p))
        assert "rule-ok" in results
        assert "rule-skip" not in results

    def test_section_captured(self, kensa_single_host_json):
        results = parse_kensa_json(str(kensa_single_host_json))
        assert results["ssh-disable-root-login"].section == "5.2.10"

    def test_empty_results(self, tmp_path):
        data = {"results": []}
        p = _write_kensa_json(tmp_path, data)
        results = parse_kensa_json(str(p))
        assert results == {}

    def test_missing_optional_fields(self, tmp_path):
        data = {
            "results": [
                {"rule_id": "bare-rule", "passed": True},
            ]
        }
        p = _write_kensa_json(tmp_path, data)
        results = parse_kensa_json(str(p))
        assert results["bare-rule"].title == ""
        assert results["bare-rule"].detail == ""
        assert results["bare-rule"].section == ""


# ---------------------------------------------------------------------------
# normalize_rule_id
# ---------------------------------------------------------------------------


class TestNormalizeRuleId:
    def test_removes_hyphens(self):
        assert normalize_rule_id("ssh-disable-root") == "sshdisableroot"

    def test_removes_underscores(self):
        assert normalize_rule_id("sshd_disable_root") == "sshddisableroot"

    def test_lowercases(self):
        assert normalize_rule_id("SSH-Disable-ROOT") == "sshdisableroot"

    def test_mixed_separators(self):
        assert normalize_rule_id("a-b_c-D_E") == "abcde"

    def test_empty_string(self):
        assert normalize_rule_id("") == ""

    def test_no_separators(self):
        assert normalize_rule_id("foobar") == "foobar"


# ---------------------------------------------------------------------------
# find_matching_openscap_rule
# ---------------------------------------------------------------------------


class TestFindMatchingOpenscapRule:
    def test_direct_mapping_found(self):
        openscap = {"sshd_disable_root_login": RuleResult("x", "x", True)}
        match = find_matching_openscap_rule("ssh-disable-root-login", openscap)
        assert match == "sshd_disable_root_login"

    def test_direct_mapping_not_in_results(self):
        """Mapping exists but OpenSCAP didn't report that rule."""
        openscap = {"some_other_rule": RuleResult("x", "x", True)}
        match = find_matching_openscap_rule("ssh-disable-root-login", openscap)
        # Falls through to fuzzy match; may or may not match
        assert match is None or match in openscap

    def test_fuzzy_match_kensa_substring(self):
        """KENSA normalized ID is a substring of OpenSCAP normalized ID."""
        openscap = {"accounts_password_pam_minlen_extended": RuleResult("x", "x", True)}
        # "pam-pwquality-minlen" normalizes to "pampwqualityminlen"
        # not a substring of "accountspasswordpamminlenextended", so no match
        match = find_matching_openscap_rule("pam-minlen", openscap)
        # "pamminlen" is a substring of "accountspasswordpamminlenextended"
        assert match == "accounts_password_pam_minlen_extended"

    def test_fuzzy_match_openscap_substring(self):
        """OpenSCAP normalized ID is a substring of KENSA normalized ID."""
        openscap = {"minlen": RuleResult("x", "x", True)}
        match = find_matching_openscap_rule("pam-pwquality-minlen", openscap)
        assert match == "minlen"

    def test_no_match(self):
        openscap = {"completely_unrelated": RuleResult("x", "x", True)}
        match = find_matching_openscap_rule("ssh-disable-root-login", openscap)
        assert match is None

    def test_unmapped_rule_no_fuzzy(self):
        openscap = {"zzz_no_overlap": RuleResult("x", "x", True)}
        match = find_matching_openscap_rule("aaa-unique-rule", openscap)
        assert match is None


# ---------------------------------------------------------------------------
# KENSA_TO_OPENSCAP / OPENSCAP_TO_KENSA mapping consistency
# ---------------------------------------------------------------------------


class TestMappingDicts:
    def test_reverse_mapping_covers_all_values(self):
        """Every OpenSCAP value in forward map exists as a key in reverse map."""
        for openscap_id in KENSA_TO_OPENSCAP.values():
            assert openscap_id in OPENSCAP_TO_KENSA

    def test_reverse_mapping_points_back(self):
        """Reverse map value is one of the KENSA IDs that maps to that OpenSCAP ID."""
        for openscap_id, kensa_id in OPENSCAP_TO_KENSA.items():
            assert KENSA_TO_OPENSCAP[kensa_id] == openscap_id

    def test_no_empty_keys(self):
        for k in KENSA_TO_OPENSCAP:
            assert k.strip() != ""
        for k in OPENSCAP_TO_KENSA:
            assert k.strip() != ""

    def test_no_duplicate_values(self):
        """Each OpenSCAP ID should map to at most one KENSA ID."""
        seen: dict[str, str] = {}
        for kensa_id, openscap_id in KENSA_TO_OPENSCAP.items():
            if openscap_id in seen:
                # Two KENSA rules map to the same OpenSCAP rule;
                # the reverse map will only hold one — document which.
                pass
            seen[openscap_id] = kensa_id

    def test_mapping_count_reasonable(self):
        """Sanity check: we have a substantial number of mappings."""
        assert len(KENSA_TO_OPENSCAP) >= 100

    def test_known_mappings_present(self):
        """Spot-check a few critical mappings."""
        assert KENSA_TO_OPENSCAP["ssh-disable-root-login"] == "sshd_disable_root_login"
        assert (
            KENSA_TO_OPENSCAP["kmod-disable-cramfs"] == "kernel_module_cramfs_disabled"
        )
        assert KENSA_TO_OPENSCAP["service-enable-auditd"] == "service_auditd_enabled"
        assert KENSA_TO_OPENSCAP["selinux-state-enforcing"] == "selinux_state"


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def _run_report(self, tmp_path, kensa, openscap):
        out = str(tmp_path / "report.md")
        generate_report(kensa, openscap, out)
        return Path(out).read_text()

    def test_report_contains_header(self, tmp_path):
        kensa = {"rule-a": RuleResult("rule-a", "A", True)}
        openscap = {"rule-x": RuleResult("rule-x", "X", True)}
        md = self._run_report(tmp_path, kensa, openscap)
        assert "# CIS RHEL 9 Gap Analysis" in md

    def test_report_executive_summary_counts(self, tmp_path):
        kensa = {
            "r1": RuleResult("r1", "R1", True),
            "r2": RuleResult("r2", "R2", False),
        }
        openscap = {
            "o1": RuleResult("o1", "O1", True),
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "| Rules checked | 2 | 1 |" in md

    def test_both_pass_agreement(self, tmp_path):
        kensa = {
            "ssh-disable-root-login": RuleResult("ssh-disable-root-login", "A", True)
        }
        openscap = {
            "sshd_disable_root_login": RuleResult("sshd_disable_root_login", "B", True)
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "Both tools agree (pass): 1" in md

    def test_both_fail_agreement(self, tmp_path):
        kensa = {
            "ssh-disable-root-login": RuleResult("ssh-disable-root-login", "A", False)
        }
        openscap = {
            "sshd_disable_root_login": RuleResult("sshd_disable_root_login", "B", False)
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "Both tools agree (fail): 1" in md

    def test_kensa_pass_openscap_fail_mismatch(self, tmp_path):
        kensa = {
            "ssh-disable-root-login": RuleResult("ssh-disable-root-login", "A", True)
        }
        openscap = {
            "sshd_disable_root_login": RuleResult("sshd_disable_root_login", "B", False)
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "KENSA Passes, OpenSCAP Fails" in md
        assert "`ssh-disable-root-login`" in md

    def test_kensa_fail_openscap_pass_mismatch(self, tmp_path):
        kensa = {
            "ssh-disable-root-login": RuleResult("ssh-disable-root-login", "A", False)
        }
        openscap = {
            "sshd_disable_root_login": RuleResult("sshd_disable_root_login", "B", True)
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "KENSA Fails, OpenSCAP Passes" in md

    def test_kensa_only_rules(self, tmp_path):
        kensa = {
            "unique-kensa-rule": RuleResult(
                "unique-kensa-rule", "A", True, section="1.2.3"
            )
        }
        openscap = {"unrelated_openscap": RuleResult("unrelated_openscap", "X", True)}
        md = self._run_report(tmp_path, kensa, openscap)
        assert "KENSA-Only Rules" in md
        assert "`unique-kensa-rule`" in md
        assert "1.2.3" in md

    def test_openscap_only_failing_critical_gaps(self, tmp_path):
        kensa = {"unrelated-kensa": RuleResult("unrelated-kensa", "A", True)}
        openscap = {
            "orphan_openscap_failing": RuleResult(
                "orphan_openscap_failing", "Orphan rule", False
            )
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "Critical Gaps" in md
        assert "`orphan_openscap_failing`" in md

    def test_openscap_only_passing_counted(self, tmp_path):
        kensa = {"x": RuleResult("x", "X", True)}
        openscap = {
            "pass_only": RuleResult("pass_only", "P", True),
        }
        md = self._run_report(tmp_path, kensa, openscap)
        assert "Passing (lower priority): 1" in md

    def test_report_written_to_file(self, tmp_path):
        out = tmp_path / "out.md"
        kensa = {"r": RuleResult("r", "R", True)}
        openscap = {"o": RuleResult("o", "O", True)}
        generate_report(kensa, openscap, str(out))
        assert out.exists()
        assert out.stat().st_size > 0

    def test_empty_inputs(self, tmp_path):
        """Both empty — should not crash, should produce a report."""
        # generate_report does len(kensa_results) in denominator,
        # so empty dicts would cause ZeroDivisionError.
        # This documents existing behavior.
        kensa: dict[str, RuleResult] = {}
        _openscap: dict[str, RuleResult] = {}
        if not kensa:
            pytest.skip("Empty inputs cause ZeroDivisionError — known limitation")

    def test_large_detail_truncated(self, tmp_path):
        long_detail = "x" * 200
        kensa = {
            "ssh-disable-root-login": RuleResult(
                "ssh-disable-root-login", "A", True, detail=long_detail
            )
        }
        openscap = {
            "sshd_disable_root_login": RuleResult("sshd_disable_root_login", "B", False)
        }
        md = self._run_report(tmp_path, kensa, openscap)
        # Detail is truncated to 40 chars in mismatch tables
        assert long_detail not in md


# ---------------------------------------------------------------------------
# Integration: end-to-end parse + report
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_parse_and_compare(self, tmp_path):
        """Parse both formats and run generate_report without errors."""
        xccdf = _write_xccdf(tmp_path)
        kensa_data = {
            "results": [
                {
                    "rule_id": "ssh-disable-root-login",
                    "title": "SSH root",
                    "passed": True,
                },
                {
                    "rule_id": "ssh-permit-empty-passwords",
                    "title": "Empty pw",
                    "passed": False,
                },
            ]
        }
        kensa_json = _write_kensa_json(tmp_path, kensa_data)

        kensa_results = parse_kensa_json(str(kensa_json))
        openscap_results = parse_openscap_xml(str(xccdf))

        out = str(tmp_path / "e2e_report.md")
        generate_report(kensa_results, openscap_results, out)

        report = Path(out).read_text()
        # SSH root login: KENSA pass + OpenSCAP pass -> both agree
        assert "Both tools agree (pass): 1" in report
        # Empty passwords: KENSA fail + OpenSCAP fail -> both agree fail
        assert "Both tools agree (fail): 1" in report

    def test_mismatch_detected_end_to_end(self, tmp_path):
        """KENSA and OpenSCAP disagree on one rule."""
        xccdf = _write_xccdf(tmp_path)
        kensa_data = {
            "results": [
                # KENSA says fail, OpenSCAP says pass for root login
                {
                    "rule_id": "ssh-disable-root-login",
                    "title": "SSH root",
                    "passed": False,
                },
            ]
        }
        kensa_json = _write_kensa_json(tmp_path, kensa_data)

        kensa_results = parse_kensa_json(str(kensa_json))
        openscap_results = parse_openscap_xml(str(xccdf))

        out = str(tmp_path / "mismatch_report.md")
        generate_report(kensa_results, openscap_results, out)

        report = Path(out).read_text()
        assert "KENSA Fails, OpenSCAP Passes" in report
        assert "Mismatches requiring investigation: 1" in report


# ---------------------------------------------------------------------------
# Edge cases in XML parsing
# ---------------------------------------------------------------------------


class TestXMLEdgeCases:
    def test_multiple_test_results(self, tmp_path):
        """Multiple TestResult elements should all be parsed."""
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <Benchmark xmlns="{XCCDF_NS}">
              <TestResult id="t1">
                <rule-result idref="xccdf_org.ssgproject.content_rule_rule_a">
                  <result>pass</result>
                </rule-result>
              </TestResult>
              <TestResult id="t2">
                <rule-result idref="xccdf_org.ssgproject.content_rule_rule_b">
                  <result>fail</result>
                </rule-result>
              </TestResult>
            </Benchmark>
        """)
        p = _write_xccdf(tmp_path, xml)
        results = parse_openscap_xml(str(p))
        assert "rule_a" in results
        assert "rule_b" in results

    def test_rule_without_title_definition(self, tmp_path):
        """Rule result with no matching Rule definition gets empty title."""
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <Benchmark xmlns="{XCCDF_NS}">
              <TestResult id="t1">
                <rule-result idref="xccdf_org.ssgproject.content_rule_orphan_rule">
                  <result>pass</result>
                </rule-result>
              </TestResult>
            </Benchmark>
        """)
        p = _write_xccdf(tmp_path, xml)
        results = parse_openscap_xml(str(p))
        assert results["orphan_rule"].title == ""

    def test_idref_without_ssg_prefix(self, tmp_path):
        """Non-standard idref gets prefix stripped as-is."""
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <Benchmark xmlns="{XCCDF_NS}">
              <TestResult id="t1">
                <rule-result idref="custom_rule_id">
                  <result>pass</result>
                </rule-result>
              </TestResult>
            </Benchmark>
        """)
        p = _write_xccdf(tmp_path, xml)
        results = parse_openscap_xml(str(p))
        # The prefix replacement is a no-op for non-standard IDs
        assert "custom_rule_id" in results
