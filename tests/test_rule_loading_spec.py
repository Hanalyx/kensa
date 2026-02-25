"""SpecDerived tests for rule loading module."""

from __future__ import annotations

import yaml

from runner._loading import load_rules, rule_applies_to_platform


class TestRuleLoadingSpecDerived:
    """Spec-derived tests for rule loading.

    See specs/internal/rule_loading.spec.yaml for specification.
    """

    def test_ac1_single_file_loads_one_rule(self, tmp_path):
        """AC-1: load_rules with a file path loads that single file and returns a list with one rule dict."""
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(
            yaml.dump({"id": "test-rule", "title": "Test", "severity": "high"})
        )

        result = load_rules(str(rule_file))
        assert len(result) == 1
        assert result[0]["id"] == "test-rule"

    def test_ac2_directory_recursive_discovery(self, tmp_path):
        """AC-2: load_rules with a directory path recursively discovers all .yml/.yaml files sorted by path."""
        sub = tmp_path / "sub"
        sub.mkdir()

        (tmp_path / "b_rule.yml").write_text(yaml.dump({"id": "b-rule", "title": "B"}))
        (sub / "a_rule.yaml").write_text(yaml.dump({"id": "a-rule", "title": "A"}))
        (tmp_path / "c_rule.yml").write_text(yaml.dump({"id": "c-rule", "title": "C"}))

        result = load_rules(str(tmp_path))
        assert len(result) >= 2
        # Check that all rules were loaded
        ids = [r["id"] for r in result]
        assert "a-rule" in ids
        assert "b-rule" in ids
        assert "c-rule" in ids

    def test_ac3_invalid_yaml_silently_skipped(self, tmp_path):
        """AC-3: Files that fail YAML parsing are silently skipped."""
        good = tmp_path / "good.yml"
        good.write_text(yaml.dump({"id": "good-rule", "title": "Good"}))

        bad = tmp_path / "bad.yml"
        bad.write_text("{{invalid: yaml: [unclosed")

        result = load_rules(str(tmp_path))
        assert len(result) == 1
        assert result[0]["id"] == "good-rule"

    def test_ac4_non_dict_or_missing_id_skipped(self, tmp_path):
        """AC-4: Files that parse to non-dict or lack 'id' key are silently skipped."""
        # A file that parses to a list (non-dict)
        list_file = tmp_path / "list.yml"
        list_file.write_text(yaml.dump(["item1", "item2"]))

        # A file that parses to a dict but lacks "id"
        no_id_file = tmp_path / "no_id.yml"
        no_id_file.write_text(yaml.dump({"title": "No ID", "severity": "low"}))

        # A valid file
        valid = tmp_path / "valid.yml"
        valid.write_text(yaml.dump({"id": "valid", "title": "Valid"}))

        result = load_rules(str(tmp_path))
        assert len(result) == 1
        assert result[0]["id"] == "valid"

    def test_ac5_severity_filter_case_insensitive(self, tmp_path):
        """AC-5: severity filter is case-insensitive."""
        (tmp_path / "high.yml").write_text(yaml.dump({"id": "r1", "severity": "High"}))
        (tmp_path / "low.yml").write_text(yaml.dump({"id": "r2", "severity": "low"}))
        (tmp_path / "med.yml").write_text(yaml.dump({"id": "r3", "severity": "MEDIUM"}))

        result = load_rules(str(tmp_path), severity=["high"])
        assert len(result) == 1
        assert result[0]["id"] == "r1"

        # Filter with uppercase input matching lowercase rule
        result = load_rules(str(tmp_path), severity=["LOW"])
        assert len(result) == 1
        assert result[0]["id"] == "r2"

    def test_ac6_tags_filter_case_insensitive_intersection(self, tmp_path):
        """AC-6: tags filter is case-insensitive intersection."""
        (tmp_path / "r1.yml").write_text(
            yaml.dump({"id": "r1", "tags": ["SSH", "auth"]})
        )
        (tmp_path / "r2.yml").write_text(yaml.dump({"id": "r2", "tags": ["Network"]}))
        (tmp_path / "r3.yml").write_text(
            yaml.dump({"id": "r3", "tags": ["ssh", "crypto"]})
        )

        # Filter for "ssh" should match both r1 (SSH) and r3 (ssh)
        result = load_rules(str(tmp_path), tags=["ssh"])
        ids = {r["id"] for r in result}
        assert ids == {"r1", "r3"}

    def test_ac7_category_filter_case_insensitive(self, tmp_path):
        """AC-7: category filter is case-insensitive exact match."""
        (tmp_path / "r1.yml").write_text(
            yaml.dump({"id": "r1", "category": "Access-Control"})
        )
        (tmp_path / "r2.yml").write_text(yaml.dump({"id": "r2", "category": "audit"}))

        result = load_rules(str(tmp_path), category="access-control")
        assert len(result) == 1
        assert result[0]["id"] == "r1"

        result = load_rules(str(tmp_path), category="AUDIT")
        assert len(result) == 1
        assert result[0]["id"] == "r2"

    def test_ac8_no_platforms_returns_true(self):
        """AC-8: rule_applies_to_platform returns True when no platforms field."""
        rule = {"id": "test", "title": "Test"}
        assert rule_applies_to_platform(rule, "rhel", 9) is True

    def test_ac9_matching_platform_returns_true(self):
        """AC-9: rule_applies_to_platform returns True when platform entry matches family and version range."""
        rule = {
            "id": "test",
            "platforms": [
                {"family": "rhel", "min_version": 8, "max_version": 9},
            ],
        }
        assert rule_applies_to_platform(rule, "rhel", 8) is True
        assert rule_applies_to_platform(rule, "rhel", 9) is True

    def test_ac10_empty_or_no_match_returns_false(self):
        """AC-10: rule_applies_to_platform returns False when platforms is empty list or no match."""
        # Empty platforms list
        rule_empty = {"id": "test", "platforms": []}
        assert rule_applies_to_platform(rule_empty, "rhel", 9) is False

        # No matching entry
        rule_no_match = {
            "id": "test",
            "platforms": [
                {"family": "debian", "min_version": 10, "max_version": 12},
            ],
        }
        assert rule_applies_to_platform(rule_no_match, "rhel", 9) is False

        # Version out of range
        rule_version = {
            "id": "test",
            "platforms": [
                {"family": "rhel", "min_version": 8, "max_version": 8},
            ],
        }
        assert rule_applies_to_platform(rule_version, "rhel", 9) is False
