"""Spec-derived tests for evaluate_rule orchestration pipeline.

Tests the orchestration logic in runner/_orchestration.py:evaluate_rule(),
isolating it from check handlers and implementation selection by mocking
select_implementation and run_check.

Spec: specs/orchestration/evaluate_rule.spec.md
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from runner._orchestration import _extract_framework_refs, evaluate_rule
from runner._types import CheckResult, Evidence, RuleResult

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def minimal_rule():
    """Minimal rule dict with only required fields."""
    return {
        "id": "test-rule-001",
        "title": "Test Rule",
        "severity": "high",
        "implementations": [
            {
                "default": True,
                "check": {"method": "command", "run": "echo ok"},
            }
        ],
    }


@pytest.fixture
def rule_with_refs():
    """Rule with comprehensive framework references."""
    return {
        "id": "test-rule-refs",
        "title": "Rule With References",
        "severity": "medium",
        "references": {
            "cis": {
                "rhel9": {
                    "section": "5.1.12",
                    "level": "1",
                },
            },
            "stig": {
                "rhel9": {
                    "vuln_id": "V-257844",
                    "rule_id": "SV-257844r925618",
                },
            },
            "nist_800_53": ["AU-2", "AU-3", "AU-12"],
            "pci_dss": {
                "v4_0": {
                    "requirement": "10.2.1",
                },
            },
        },
        "implementations": [
            {
                "default": True,
                "check": {"method": "command", "run": "echo ok"},
            }
        ],
    }


@pytest.fixture
def mock_ssh():
    """Simple mock SSH session."""
    return MagicMock()


@pytest.fixture
def sample_evidence():
    """Sample Evidence object for check results."""
    return Evidence(
        method="command",
        command="echo ok",
        stdout="ok",
        stderr="",
        exit_code=0,
        expected=None,
        actual="ok",
        timestamp=datetime.now(tz=timezone.utc),
    )


@pytest.fixture
def empty_caps():
    """Empty capabilities dict."""
    return {}


# ── TestEvaluateRuleSpecDerived ──────────────────────────────────────────────


class TestEvaluateRuleSpecDerived:
    """Spec-derived tests for evaluate_rule orchestration pipeline.

    Each test corresponds to an acceptance criterion from
    specs/orchestration/evaluate_rule.spec.md.
    """

    def test_check_passes(self, mock_ssh, minimal_rule, sample_evidence, empty_caps):
        """AC-1: Check passes -> RuleResult.passed=True with evidence and detail."""
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "echo ok"}}
            mock_check.return_value = CheckResult(
                passed=True,
                detail="Value matches expected",
                evidence=sample_evidence,
            )

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert isinstance(result, RuleResult)
            assert result.passed is True
            assert result.skipped is False
            assert result.detail == "Value matches expected"
            assert result.evidence is sample_evidence
            assert result.rule_id == "test-rule-001"

    def test_check_fails(self, mock_ssh, minimal_rule, sample_evidence, empty_caps):
        """AC-2: Check fails -> RuleResult.passed=False with detail and evidence."""
        fail_evidence = Evidence(
            method="command",
            command="echo ok",
            stdout="not-ok",
            stderr="",
            exit_code=1,
            expected="ok",
            actual="not-ok",
            timestamp=datetime.now(tz=timezone.utc),
        )
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "echo ok"}}
            mock_check.return_value = CheckResult(
                passed=False,
                detail="Expected 'ok', got 'not-ok'",
                evidence=fail_evidence,
            )

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert result.passed is False
            assert result.skipped is False
            assert result.detail == "Expected 'ok', got 'not-ok'"
            assert result.evidence is fail_evidence

    def test_no_matching_implementation(self, mock_ssh, minimal_rule, empty_caps):
        """AC-3: No matching implementation -> skipped with reason."""
        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = None

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert result.passed is False
            assert result.skipped is True
            assert result.skip_reason == "No matching implementation"
            assert result.evidence is None

    def test_no_check_block(self, mock_ssh, minimal_rule, empty_caps):
        """AC-4: Implementation has no check block -> skipped with reason."""
        with patch("runner._orchestration.select_implementation") as mock_sel:
            # Implementation exists but has no "check" key
            mock_sel.return_value = {
                "remediation": {"mechanism": "config_set", "path": "/etc/conf"}
            }

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert result.passed is False
            assert result.skipped is True
            assert result.skip_reason == "Implementation has no check"
            assert result.evidence is None

    def test_check_handler_exception(self, mock_ssh, minimal_rule, empty_caps):
        """AC-5: Check handler throws -> passed=False, detail starts with 'Error: '."""
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "fail"}}
            mock_check.side_effect = RuntimeError("SSH connection lost")

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert result.passed is False
            assert result.skipped is False
            assert result.detail.startswith("Error: ")
            assert "SSH connection lost" in result.detail
            assert result.evidence is None

    def test_framework_refs_attached_on_pass(
        self, mock_ssh, rule_with_refs, sample_evidence, empty_caps
    ):
        """AC-6: Framework refs extracted and attached on pass path."""
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "echo ok"}}
            mock_check.return_value = CheckResult(
                passed=True, detail="ok", evidence=sample_evidence
            )

            result = evaluate_rule(mock_ssh, rule_with_refs, empty_caps)

            assert result.framework_refs != {}
            assert "cis_rhel9" in result.framework_refs
            assert result.framework_refs["cis_rhel9"] == "5.1.12"
            assert "stig_rhel9" in result.framework_refs
            assert "nist_800_53" in result.framework_refs

    def test_framework_refs_attached_on_skip(
        self, mock_ssh, rule_with_refs, empty_caps
    ):
        """AC-6: Framework refs extracted and attached on skip path."""
        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = None

            result = evaluate_rule(mock_ssh, rule_with_refs, empty_caps)

            assert result.skipped is True
            assert result.framework_refs != {}
            assert "cis_rhel9" in result.framework_refs

    def test_framework_refs_attached_on_error(
        self, mock_ssh, rule_with_refs, empty_caps
    ):
        """AC-6: Framework refs extracted and attached on error path."""
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "fail"}}
            mock_check.side_effect = RuntimeError("timeout")

            result = evaluate_rule(mock_ssh, rule_with_refs, empty_caps)

            assert result.passed is False
            assert result.framework_refs != {}
            assert "cis_rhel9" in result.framework_refs

    def test_rule_metadata_propagated_on_all_paths(self, mock_ssh, empty_caps):
        """AC-7: Rule metadata (id, title, severity) propagated on all paths."""
        rule = {
            "id": "meta-check-rule",
            "title": "Metadata Propagation Test",
            "severity": "critical",
            "implementations": [],
        }

        # Skip path (no implementations -> select_implementation returns None)
        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = None
            result = evaluate_rule(mock_ssh, rule, empty_caps)

            assert result.rule_id == "meta-check-rule"
            assert result.title == "Metadata Propagation Test"
            assert result.severity == "critical"

    def test_title_defaults_to_rule_id(self, mock_ssh, empty_caps):
        """AC-8: Title defaults to rule_id when title key is absent."""
        rule = {
            "id": "no-title-rule",
            "severity": "low",
            "implementations": [],
        }
        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = None
            result = evaluate_rule(mock_ssh, rule, empty_caps)

            assert result.title == "no-title-rule"

    def test_severity_defaults_to_unknown(self, mock_ssh, empty_caps):
        """AC-9: Severity defaults to 'unknown' when severity key is absent."""
        rule = {
            "id": "no-severity-rule",
            "implementations": [],
        }
        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = None
            result = evaluate_rule(mock_ssh, rule, empty_caps)

            assert result.severity == "unknown"

    def test_evidence_none_on_skip_path(self, mock_ssh, minimal_rule, empty_caps):
        """AC-14: Evidence is None on skip paths."""
        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = None
            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)
            assert result.evidence is None

        with patch("runner._orchestration.select_implementation") as mock_sel:
            mock_sel.return_value = {"remediation": {"mechanism": "manual"}}
            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)
            assert result.evidence is None

    def test_evidence_none_on_error_path(self, mock_ssh, minimal_rule, empty_caps):
        """AC-14: Evidence is None on error path."""
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "fail"}}
            mock_check.side_effect = OSError("connection refused")

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert result.evidence is None

    def test_select_implementation_receives_correct_args(
        self, mock_ssh, minimal_rule, sample_evidence
    ):
        """Verify select_implementation called with rule and capabilities."""
        caps = {"sshd_config_d": True, "authselect": False}
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "command", "run": "echo ok"}}
            mock_check.return_value = CheckResult(
                passed=True, detail="ok", evidence=sample_evidence
            )

            evaluate_rule(mock_ssh, minimal_rule, caps)

            mock_sel.assert_called_once_with(minimal_rule, caps)

    def test_run_check_receives_check_block(
        self, mock_ssh, minimal_rule, sample_evidence, empty_caps
    ):
        """Verify run_check called with ssh and the check block from implementation."""
        check_block = {"method": "sysctl_value", "key": "net.ipv4.ip_forward"}
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": check_block}
            mock_check.return_value = CheckResult(
                passed=True, detail="ok", evidence=sample_evidence
            )

            evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            mock_check.assert_called_once_with(mock_ssh, check_block)

    def test_run_check_not_called_on_skip(self, mock_ssh, minimal_rule, empty_caps):
        """run_check must not be called when implementation is None or has no check."""
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = None
            evaluate_rule(mock_ssh, minimal_rule, empty_caps)
            mock_check.assert_not_called()

        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"remediation": {"mechanism": "manual"}}
            evaluate_rule(mock_ssh, minimal_rule, empty_caps)
            mock_check.assert_not_called()

    def test_check_result_detail_and_evidence_forwarded(
        self, mock_ssh, minimal_rule, empty_caps
    ):
        """CheckResult detail and evidence are forwarded to RuleResult verbatim."""
        evidence = Evidence(
            method="file_content",
            command="cat /etc/conf",
            stdout="key=value",
            stderr="",
            exit_code=0,
            expected="key=value",
            actual="key=value",
            timestamp=datetime.now(tz=timezone.utc),
        )
        with (
            patch("runner._orchestration.select_implementation") as mock_sel,
            patch("runner._orchestration.run_check") as mock_check,
        ):
            mock_sel.return_value = {"check": {"method": "file_content"}}
            mock_check.return_value = CheckResult(
                passed=True,
                detail="Content matches",
                evidence=evidence,
            )

            result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

            assert result.detail == "Content matches"
            assert result.evidence is evidence
            assert result.evidence.method == "file_content"

    def test_exception_types_caught(self, mock_ssh, minimal_rule, empty_caps):
        """AC-5: Various exception types are caught and converted to Error detail."""
        exceptions = [
            ValueError("bad value"),
            TimeoutError("command timed out"),
            KeyError("missing_key"),
            OSError("network error"),
        ]
        for exc in exceptions:
            with (
                patch("runner._orchestration.select_implementation") as mock_sel,
                patch("runner._orchestration.run_check") as mock_check,
            ):
                mock_sel.return_value = {"check": {"method": "command", "run": "x"}}
                mock_check.side_effect = exc

                result = evaluate_rule(mock_ssh, minimal_rule, empty_caps)

                assert result.passed is False
                assert result.detail.startswith("Error: ")
                assert str(exc) in result.detail


# ── TestExtractFrameworkRefs ─────────────────────────────────────────────────


class TestExtractFrameworkRefs:
    """Tests for _extract_framework_refs helper.

    Covers AC-10 through AC-13 from the spec.
    """

    def test_nist_comma_join(self):
        """AC-10: NIST controls joined with ', ' separator."""
        rule = {
            "references": {
                "nist_800_53": ["AU-2", "AU-3", "AU-12"],
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["nist_800_53"] == "AU-2, AU-3, AU-12"

    def test_nist_single_control(self):
        """AC-10: NIST with single control still works."""
        rule = {
            "references": {
                "nist_800_53": ["AC-1"],
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["nist_800_53"] == "AC-1"

    def test_cis_section_extraction(self):
        """AC-11: CIS section extracted from nested dict."""
        rule = {
            "references": {
                "cis": {
                    "rhel9": {
                        "section": "5.1.12",
                        "level": "1",
                    }
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["cis_rhel9"] == "5.1.12"

    def test_stig_vuln_id_extraction(self):
        """AC-11: STIG vuln_id extracted from nested dict."""
        rule = {
            "references": {
                "stig": {
                    "rhel9": {
                        "vuln_id": "V-257844",
                        "rule_id": "SV-257844r925618",
                    }
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["stig_rhel9"] == "V-257844"

    def test_pci_dss_requirement_extraction(self):
        """AC-11: PCI-DSS requirement extracted from nested dict."""
        rule = {
            "references": {
                "pci_dss": {
                    "v4_0": {
                        "requirement": "10.2.1",
                    }
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["pci_dss_v4_0"] == "10.2.1"

    def test_generic_control_extraction(self):
        """AC-11: Generic 'control' key extracted from nested dict."""
        rule = {
            "references": {
                "fedramp": {
                    "moderate_rev5": {
                        "control": "AC-2",
                    }
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["fedramp_moderate_rev5"] == "AC-2"

    def test_string_valued_version_entry(self):
        """AC-12: String-valued framework version entries handled."""
        rule = {
            "references": {
                "custom_framework": {
                    "v1": "CTRL-001",
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["custom_framework_v1"] == "CTRL-001"

    def test_no_references_key(self):
        """AC-13: Empty dict when rule has no references key."""
        rule = {"id": "no-refs"}
        refs = _extract_framework_refs(rule)
        assert refs == {}

    def test_empty_references(self):
        """AC-13: Empty dict when references is empty."""
        rule = {"references": {}}
        refs = _extract_framework_refs(rule)
        assert refs == {}

    def test_multiple_frameworks(self):
        """Multiple frameworks in a single rule are all extracted."""
        rule = {
            "references": {
                "cis": {
                    "rhel9": {"section": "1.2.3"},
                    "rhel8": {"section": "1.2.4"},
                },
                "stig": {
                    "rhel9": {"vuln_id": "V-100000"},
                },
                "nist_800_53": ["AC-1", "AC-2"],
            }
        }
        refs = _extract_framework_refs(rule)
        assert refs["cis_rhel9"] == "1.2.3"
        assert refs["cis_rhel8"] == "1.2.4"
        assert refs["stig_rhel9"] == "V-100000"
        assert refs["nist_800_53"] == "AC-1, AC-2"

    def test_nested_dict_without_known_keys_skipped(self):
        """Nested dict without section/vuln_id/requirement/control is skipped."""
        rule = {
            "references": {
                "unknown": {
                    "v1": {
                        "some_other_key": "value",
                    }
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert "unknown_v1" not in refs

    def test_framework_key_composition(self):
        """Framework key is composed as {framework}_{version}."""
        rule = {
            "references": {
                "cis": {
                    "rhel9": {"section": "5.1.1"},
                }
            }
        }
        refs = _extract_framework_refs(rule)
        assert "cis_rhel9" in refs
        assert "cis" not in refs  # Parent key alone is not a valid ref
