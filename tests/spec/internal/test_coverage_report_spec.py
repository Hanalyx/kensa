"""Spec-derived tests for coverage_report.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/coverage_report.spec.yaml — verifying that the coverage
report generator includes full rule detail data, loads review sidecar
YAML, renders flagged rules, and supports review filtering.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Add project root so we can import the script module
ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.coverage_report import compute_data  # noqa: E402, I001
from scripts.coverage_report import load_reviews  # noqa: E402, I001
from scripts.coverage_report import render_html  # noqa: E402, I001


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_rule(rule_id: str, **overrides) -> dict:
    """Create a minimal rule dict with defaults."""
    defaults = {
        "id": rule_id,
        "title": f"Test rule {rule_id}",
        "description": f"Description for {rule_id}.",
        "rationale": f"Rationale for {rule_id}.",
        "severity": "medium",
        "category": "audit",
        "tags": ["test", "audit"],
        "references": {
            "cis": {"rhel9": {"section": "1.1.1", "level": "L1"}},
            "stig": {"rhel8": {"vuln_id": "V-999999", "severity": "CAT II"}},
            "nist_800_53": ["AC-1", "SC-1"],
        },
        "platforms": [{"family": "rhel", "min_version": 8}],
        "implementations": [
            {
                "default": True,
                "check": {
                    "method": "package_state",
                    "name": "test-pkg",
                    "state": "present",
                },
                "remediation": {"mechanism": "package_present", "name": "test-pkg"},
            }
        ],
    }
    defaults.update(overrides)
    return defaults


def _make_mapping(fw_id: str, rules_map: dict[str, list[str]]) -> dict:
    """Create a minimal framework mapping dict."""
    controls = {}
    control_ids = []
    for ctrl_id, rule_ids in rules_map.items():
        controls[ctrl_id] = {"rules": rule_ids, "title": f"Control {ctrl_id}"}
        control_ids.append(ctrl_id)
    return {
        "id": fw_id,
        "title": f"Test Framework {fw_id}",
        "framework": "test",
        "controls": controls,
        "control_ids": control_ids,
        "unimplemented": {},
    }


def _make_review_yaml(reviews: dict) -> str:
    """Render a review dict to YAML string."""
    return yaml.dump({"reviews": reviews}, default_flow_style=False)


def _build_data(
    rules: dict[str, dict] | None = None,
    mappings: dict[str, dict] | None = None,
    reviews: dict | None = None,
) -> dict:
    """Build compute_data output with sensible defaults."""
    if rules is None:
        rules = {"test-rule": _make_rule("test-rule")}
    if mappings is None:
        mappings = {"cis-rhel9": _make_mapping("cis-rhel9", {"1.1.1": ["test-rule"]})}
    if reviews is None:
        reviews = {}
    return compute_data(mappings, rules, {}, reviews)


# ── Rule Detail Tests (AC-1 through AC-7) ────────────────────────────────────


class TestCoverageReportRuleDetail:
    """Spec-derived tests for rule detail panel (AC-1 through AC-7)."""

    def test_ac1_rule_ids_are_clickable_in_html(self):
        """AC-1: Rule IDs in the Rules tab are rendered as clickable links."""
        data = _build_data()
        html = render_html(data, [])
        # Rule ID should be wrapped in an anchor or clickable element
        assert 'onclick="showRuleDetail(' in html or "showRuleDetail" in html
        assert "test-rule" in html

    def test_ac2_detail_displays_rule_metadata(self):
        """AC-2: Detail panel displays id, title, description, rationale, severity, category, tags."""
        data = _build_data()
        rules = data["rules"]
        assert len(rules) >= 1
        rule = rules[0]
        assert rule["id"] == "test-rule"
        assert rule["title"] == "Test rule test-rule"
        assert "description" in rule
        assert "rationale" in rule
        assert rule["severity"] == "medium"
        assert rule["category"] == "audit"
        assert "tags" in rule
        assert isinstance(rule["tags"], list)

    def test_ac3_detail_displays_framework_references(self):
        """AC-3: Detail panel displays all framework references from the rule YAML."""
        data = _build_data()
        rule = data["rules"][0]
        refs = rule.get("references", {})
        assert "cis" in refs
        assert "stig" in refs
        assert "nist_800_53" in refs

    def test_ac4_detail_displays_platform_constraints(self):
        """AC-4: Detail panel displays platform constraints."""
        data = _build_data()
        rule = data["rules"][0]
        platforms = rule.get("platforms", [])
        assert len(platforms) >= 1
        assert platforms[0]["family"] == "rhel"
        assert platforms[0]["min_version"] == 8

    def test_ac5_detail_displays_implementation_details(self):
        """AC-5: Detail panel displays check method, remediation mechanism, capability gates."""
        rules = {
            "gated-rule": _make_rule(
                "gated-rule",
                implementations=[
                    {
                        "when": "rsyslog_active",
                        "check": {"method": "command", "run": "grep test /etc/foo"},
                        "remediation": {"mechanism": "manual", "note": "Fix manually"},
                    },
                    {
                        "default": True,
                        "check": {"method": "package_state", "name": "pkg"},
                        "remediation": {"mechanism": "package_present", "name": "pkg"},
                    },
                ],
            )
        }
        data = _build_data(rules=rules, mappings={})
        rule = data["rules"][0]
        impls = rule.get("implementations", [])
        assert len(impls) == 2
        assert impls[0].get("when") == "rsyslog_active"
        assert impls[0]["check"]["method"] == "command"
        assert impls[1].get("default") is True

    def test_ac6_detail_panel_close_mechanism_in_html(self):
        """AC-6: Detail panel has a close mechanism."""
        data = _build_data()
        html = render_html(data, [])
        assert "closeRuleDetail" in html or "close-detail" in html

    def test_ac7_compute_data_includes_full_rule_fields(self):
        """AC-7: compute_data() includes full rule detail fields in the embedded JSON."""
        data = _build_data()
        rule = data["rules"][0]
        required_fields = [
            "id",
            "title",
            "description",
            "rationale",
            "severity",
            "category",
            "tags",
            "references",
            "platforms",
            "implementations",
        ]
        for field in required_fields:
            assert field in rule, f"Missing field: {field}"


# ── Review Workflow Tests (AC-8 through AC-16) ───────────────────────────────


class TestCoverageReportReviewWorkflow:
    """Spec-derived tests for review YAML sidecar (AC-8 through AC-16)."""

    def test_ac8_loads_review_yaml(self, tmp_path):
        """AC-8: coverage_report.py loads reports/review.yaml when it exists."""
        review_file = tmp_path / "review.yaml"
        review_data = {
            "reviews": {
                "test-rule": [
                    {
                        "date": "2026-03-08",
                        "reviewer": "ai",
                        "flag": "verify",
                        "note": "Check this rule.",
                    }
                ]
            }
        }
        review_file.write_text(yaml.dump(review_data))
        result = load_reviews(review_file)
        assert "test-rule" in result
        assert len(result["test-rule"]) == 1
        assert result["test-rule"][0]["flag"] == "verify"

    def test_ac9_missing_review_yaml_handled(self, tmp_path):
        """AC-9: Missing or empty review.yaml is handled gracefully."""
        # Missing file
        result = load_reviews(tmp_path / "nonexistent.yaml")
        assert result == {}

        # Empty file
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        result = load_reviews(empty_file)
        assert result == {}

        # Malformed YAML
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{{not yaml")
        result = load_reviews(bad_file)
        assert result == {}

    def test_ac10_flagged_rules_show_indicator_in_data(self):
        """AC-10: Rules with active flags have flag_status in the data."""
        reviews = {
            "test-rule": [
                {
                    "date": "2026-03-08",
                    "reviewer": "ai",
                    "flag": "incorrect-check",
                    "note": "Wrong check.",
                }
            ]
        }
        data = _build_data(reviews=reviews)
        rule = data["rules"][0]
        assert rule.get("flag_status") == "incorrect-check"

    def test_ac11_review_history_in_rule_detail(self):
        """AC-11: Rule detail includes full review history with date, reviewer, flag, note."""
        reviews = {
            "test-rule": [
                {
                    "date": "2026-03-07",
                    "reviewer": "ai",
                    "flag": "verify",
                    "note": "First note.",
                },
                {
                    "date": "2026-03-08",
                    "reviewer": "remy",
                    "flag": "cleared",
                    "note": "Confirmed OK.",
                },
            ]
        }
        data = _build_data(reviews=reviews)
        rule = data["rules"][0]
        assert "reviews" in rule
        assert len(rule["reviews"]) == 2
        assert rule["reviews"][0]["date"] == "2026-03-07"
        assert rule["reviews"][1]["date"] == "2026-03-08"
        for entry in rule["reviews"]:
            assert "date" in entry
            assert "reviewer" in entry
            assert "flag" in entry
            assert "note" in entry

    def test_ac12_summary_includes_flagged_count(self):
        """AC-12: Summary data includes count of flagged rules."""
        reviews = {
            "test-rule": [
                {
                    "date": "2026-03-08",
                    "reviewer": "ai",
                    "flag": "verify",
                    "note": "Check.",
                }
            ]
        }
        data = _build_data(reviews=reviews)
        summary = data.get("review_summary", {})
        assert summary.get("total_flagged", 0) >= 1

    def test_ac13_filter_by_flag_status_in_html(self):
        """AC-13: Rules tab supports filtering by flag status."""
        reviews = {
            "test-rule": [
                {
                    "date": "2026-03-08",
                    "reviewer": "ai",
                    "flag": "verify",
                    "note": "Check.",
                }
            ]
        }
        data = _build_data(reviews=reviews)
        html = render_html(data, [])
        # Filter dropdown should include flag options
        assert "Flagged" in html
        assert "Unflagged" in html

    def test_ac14_flag_types_have_distinct_colors(self):
        """AC-14: Flag types are visually differentiated by color."""
        data = _build_data()
        html = render_html(data, [])
        # Check that the flag color mapping is present in the JS
        assert "incorrect-check" in html
        assert "verify" in html
        assert "stale-reference" in html
        assert "missing-coverage" in html
        assert "cleared" in html

    def test_ac15_review_entries_chronological_order(self):
        """AC-15: Review entries are in chronological order (oldest first)."""
        reviews = {
            "test-rule": [
                {
                    "date": "2026-03-09",
                    "reviewer": "remy",
                    "flag": "cleared",
                    "note": "Later.",
                },
                {
                    "date": "2026-03-07",
                    "reviewer": "ai",
                    "flag": "verify",
                    "note": "Earlier.",
                },
            ]
        }
        data = _build_data(reviews=reviews)
        rule = data["rules"][0]
        dates = [r["date"] for r in rule["reviews"]]
        assert dates == sorted(dates), "Reviews should be sorted chronologically"

    def test_ac16_review_yaml_not_overwritten(self, tmp_path):
        """AC-16: The script never writes to review.yaml — read-only."""
        review_file = tmp_path / "review.yaml"
        original = _make_review_yaml(
            {
                "test-rule": [
                    {
                        "date": "2026-03-08",
                        "reviewer": "ai",
                        "flag": "verify",
                        "note": "Original.",
                    }
                ]
            }
        )
        review_file.write_text(original)
        original_mtime = review_file.stat().st_mtime

        # Load reviews and build data — should not modify the file
        load_reviews(review_file)
        _build_data(
            reviews=load_reviews(review_file),
        )

        assert review_file.read_text() == original
        assert review_file.stat().st_mtime == original_mtime
