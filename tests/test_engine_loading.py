"""Tests for rule loading, filtering, and implementation selection."""

from __future__ import annotations

import pytest

from runner.engine import (
    evaluate_when,
    load_rules,
    rule_applies_to_platform,
    select_implementation,
)


class TestLoadRules:
    def test_load_single_file(self, tmp_rule_file, sample_rule):
        path = tmp_rule_file(sample_rule)
        rules = load_rules(str(path))
        assert len(rules) == 1
        assert rules[0]["id"] == "test-sysctl-rule"

    def test_load_directory(self, tmp_rule_dir, sample_rule, sample_rule_gated):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d))
        assert len(rules) == 2

    def test_skip_non_rule_yaml_lenient(self, tmp_path):
        # File without an 'id' field — lenient mode skips it
        (tmp_path / "not-a-rule.yml").write_text("some_key: some_value\n")
        rules = load_rules(str(tmp_path), strict=False)
        assert len(rules) == 0

    def test_reject_non_rule_yaml_strict(self, tmp_path):
        # File without an 'id' field — strict mode raises
        from runner._loading import RuleLoadError

        (tmp_path / "not-a-rule.yml").write_text("some_key: some_value\n")
        with pytest.raises(RuleLoadError):
            load_rules(str(tmp_path))

    def test_skip_malformed_yaml_lenient(self, tmp_path):
        (tmp_path / "bad.yml").write_text(": : : not valid yaml [[[")
        rules = load_rules(str(tmp_path), strict=False)
        assert len(rules) == 0

    def test_reject_malformed_yaml_strict(self, tmp_path):
        from runner._loading import RuleLoadError

        (tmp_path / "bad.yml").write_text(": : : not valid yaml [[[")
        with pytest.raises(RuleLoadError):
            load_rules(str(tmp_path))

    def test_filter_severity(self, tmp_rule_dir, sample_rule, sample_rule_gated):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d), severity=["high"])
        assert len(rules) == 1
        assert rules[0]["id"] == "test-gated-rule"

    def test_filter_severity_multiple(
        self, tmp_rule_dir, sample_rule, sample_rule_gated
    ):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d), severity=["high", "medium"])
        assert len(rules) == 2

    def test_filter_tags(self, tmp_rule_dir, sample_rule, sample_rule_gated):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d), tags=["ssh"])
        assert len(rules) == 1
        assert rules[0]["id"] == "test-gated-rule"

    def test_filter_tags_or_semantics(
        self, tmp_rule_dir, sample_rule, sample_rule_gated
    ):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d), tags=["sysctl", "ssh"])
        assert len(rules) == 2

    def test_filter_category(self, tmp_rule_dir, sample_rule, sample_rule_gated):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d), category="kernel")
        assert len(rules) == 1
        assert rules[0]["id"] == "test-sysctl-rule"

    def test_combined_filters(self, tmp_rule_dir, sample_rule, sample_rule_gated):
        d = tmp_rule_dir([sample_rule, sample_rule_gated])
        rules = load_rules(str(d), severity=["medium"], category="kernel")
        assert len(rules) == 1

    def test_no_path_raises(self):
        with pytest.raises(ValueError):
            load_rules(None)

    def test_nonexistent_path_raises(self):
        with pytest.raises(FileNotFoundError):
            load_rules("/nonexistent/path")

    def test_loads_real_rules(self):
        """Smoke test against actual rules directory."""
        rules = load_rules("rules/")
        assert len(rules) >= 30  # We know there are 35


class TestEvaluateWhen:
    def test_none_always_true(self, sample_caps):
        assert evaluate_when(None, sample_caps) is True

    def test_string_present(self, sample_caps):
        assert evaluate_when("sshd_config_d", sample_caps) is True

    def test_string_absent(self, sample_caps):
        assert evaluate_when("fips_mode", sample_caps) is False

    def test_string_unknown(self, sample_caps):
        assert evaluate_when("nonexistent", sample_caps) is False

    def test_all_true(self, sample_caps):
        assert (
            evaluate_when({"all": ["authselect", "pam_faillock"]}, sample_caps) is True
        )

    def test_all_false(self, sample_caps):
        assert evaluate_when({"all": ["authselect", "fips_mode"]}, sample_caps) is False

    def test_any_true(self, sample_caps):
        assert (
            evaluate_when({"any": ["fips_mode", "sshd_config_d"]}, sample_caps) is True
        )

    def test_any_false(self, sample_caps):
        assert evaluate_when({"any": ["fips_mode", "tpm2"]}, sample_caps) is False

    def test_empty_all(self, sample_caps):
        assert evaluate_when({"all": []}, sample_caps) is True

    def test_empty_any(self, sample_caps):
        assert evaluate_when({"any": []}, sample_caps) is False


class TestSelectImplementation:
    def test_selects_matching_gate(self, sample_rule_gated, sample_caps):
        impl = select_implementation(sample_rule_gated, sample_caps)
        assert impl.get("when") == "sshd_config_d"

    def test_falls_back_to_default(self, sample_rule_gated):
        no_caps = {"sshd_config_d": False}
        impl = select_implementation(sample_rule_gated, no_caps)
        assert impl.get("default") is True

    def test_default_only_rule(self, sample_rule, sample_caps):
        impl = select_implementation(sample_rule, sample_caps)
        assert impl.get("default") is True

    def test_no_implementations(self, sample_caps):
        rule = {"id": "empty", "implementations": []}
        impl = select_implementation(rule, sample_caps)
        assert impl is None

    def test_first_matching_gate_wins(self, sample_caps):
        rule = {
            "id": "multi-gate",
            "implementations": [
                {"when": "fips_mode", "check": {"method": "command", "run": "fips"}},
                {
                    "when": "sshd_config_d",
                    "check": {"method": "command", "run": "sshd"},
                },
                {"default": True, "check": {"method": "command", "run": "default"}},
            ],
        }
        impl = select_implementation(rule, sample_caps)
        # fips_mode is False, sshd_config_d is True → picks sshd_config_d
        assert impl["check"]["run"] == "sshd"


class TestRuleAppliesToPlatform:
    def test_matching_version(self):
        rule = {"platforms": [{"family": "rhel", "min_version": 8}]}
        assert rule_applies_to_platform(rule, "rhel", 9) is True

    def test_exact_min(self):
        rule = {"platforms": [{"family": "rhel", "min_version": 9}]}
        assert rule_applies_to_platform(rule, "rhel", 9) is True

    def test_skipped_below_min(self):
        rule = {"platforms": [{"family": "rhel", "min_version": 9}]}
        assert rule_applies_to_platform(rule, "rhel", 8) is False

    def test_skipped_above_max(self):
        rule = {"platforms": [{"family": "rhel", "max_version": 9}]}
        assert rule_applies_to_platform(rule, "rhel", 10) is False

    def test_no_platforms_always_applies(self):
        rule = {"id": "no-platform-constraint"}
        assert rule_applies_to_platform(rule, "rhel", 9) is True

    def test_wrong_family(self):
        rule = {"platforms": [{"family": "debian", "min_version": 12}]}
        assert rule_applies_to_platform(rule, "rhel", 9) is False

    def test_min_and_max_range(self):
        rule = {"platforms": [{"family": "rhel", "min_version": 8, "max_version": 9}]}
        assert rule_applies_to_platform(rule, "rhel", 8) is True
        assert rule_applies_to_platform(rule, "rhel", 9) is True
        assert rule_applies_to_platform(rule, "rhel", 10) is False
        assert rule_applies_to_platform(rule, "rhel", 7) is False

    def test_multiple_platform_entries(self):
        rule = {
            "platforms": [
                {"family": "rhel", "min_version": 9},
                {"family": "debian", "min_version": 12},
            ]
        }
        assert rule_applies_to_platform(rule, "rhel", 9) is True
        assert rule_applies_to_platform(rule, "debian", 12) is True
        assert rule_applies_to_platform(rule, "rhel", 8) is False

    def test_empty_platforms_list(self):
        rule = {"platforms": []}
        assert rule_applies_to_platform(rule, "rhel", 9) is False
