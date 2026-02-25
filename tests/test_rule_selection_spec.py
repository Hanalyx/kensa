"""SpecDerived tests for rule_selection module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from runner._rule_selection import RuleSelection, select_rules
from runner.ordering import OrderingResult


def _make_rule(rule_id: str, **kwargs) -> dict:
    """Create a minimal rule dict for testing."""
    rule = {
        "id": rule_id,
        "title": f"Test rule {rule_id}",
        "severity": "medium",
        "category": "test",
        "tags": [],
    }
    rule.update(kwargs)
    return rule


def _make_ordering_result(rules: list[dict]) -> OrderingResult:
    """Create a simple OrderingResult with no cycles."""
    return OrderingResult(
        ordered=rules,
        cycles=[],
        conflicts=[],
        superseded={},
        skipped=[],
    )


def _make_ordering_result_with_cycles(rules: list[dict]) -> OrderingResult:
    """Create an OrderingResult with a cycle."""
    return OrderingResult(
        ordered=rules,
        cycles=[["rule-a", "rule-b", "rule-a"]],
        conflicts=[],
        superseded={},
        skipped=[],
    )


# Patch targets: load_rules and order_rules are imported at module level in
# _rule_selection, so patch on that module. load_config, parse_var_overrides,
# FrameworkIndex, load_all_mappings etc. are locally imported inside functions,
# so patch at their source modules.
_P_LOAD_RULES = "runner._rule_selection.load_rules"
_P_ORDER_RULES = "runner._rule_selection.order_rules"
_P_LOAD_CONFIG = "runner._config.load_config"
_P_PARSE_VAR = "runner._config.parse_var_overrides"
_P_FW_INDEX = "runner.mappings.FrameworkIndex"
_P_LOAD_ALL_MAPPINGS = "runner.mappings.load_all_mappings"
_P_RULES_FOR_FW = "runner.mappings.rules_for_framework"
_P_BUILD_MAP = "runner.mappings.build_rule_to_section_map"


class TestRuleSelectionSpecDerived:
    """Spec-derived tests for rule_selection.

    See specs/internal/rule_selection.spec.yaml for specification.
    """

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    def test_ac1_rules_path_loads_all_matching(
        self, mock_load_rules, mock_order_rules, mock_parse_var, mock_load_config
    ):
        """AC-1: select_rules with --rules path loads all matching rules."""
        rules = [_make_rule("rule-1"), _make_rule("rule-2")]
        mock_load_rules.return_value = rules
        mock_order_rules.return_value = _make_ordering_result(rules)
        mock_load_config.return_value = MagicMock()

        result = select_rules(
            rules_path="rules/",
            rule_path=None,
            severity=(),
            tag=(),
            category=None,
        )

        assert isinstance(result, RuleSelection)
        mock_load_rules.assert_called_once_with(
            "rules/", severity=None, tags=None, category=None
        )
        assert len(result.rules) == 2

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    def test_ac2_rule_path_loads_single_file(
        self, mock_load_rules, mock_order_rules, mock_parse_var, mock_load_config
    ):
        """AC-2: select_rules with --rule path loads a single rule file."""
        rule = _make_rule("single-rule")
        mock_load_rules.return_value = [rule]
        mock_order_rules.return_value = _make_ordering_result([rule])
        mock_load_config.return_value = MagicMock()

        result = select_rules(
            rules_path=None,
            rule_path="rules/access-control/single-rule.yml",
            severity=(),
            tag=(),
            category=None,
        )

        assert isinstance(result, RuleSelection)
        mock_load_rules.assert_called_once_with(
            "rules/access-control/single-rule.yml",
            severity=None,
            tags=None,
            category=None,
        )
        assert len(result.rules) == 1

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    @patch(_P_LOAD_ALL_MAPPINGS)
    @patch(_P_FW_INDEX)
    @patch(_P_RULES_FOR_FW)
    @patch(_P_BUILD_MAP)
    def test_ac3_no_path_with_control_defaults_to_rules(
        self,
        mock_build_map,
        mock_rules_for_fw,
        mock_fw_index_cls,
        mock_load_all_mappings,
        mock_load_rules,
        mock_order_rules,
        mock_parse_var,
        mock_load_config,
    ):
        """AC-3: When no path and --control set, defaults rules_path to 'rules/'."""
        rules = [_make_rule("rule-1")]
        mock_load_rules.return_value = rules
        mock_order_rules.return_value = _make_ordering_result(rules)
        mock_load_config.return_value = MagicMock()

        # Mock framework index for control resolution
        mock_index = MagicMock()
        mock_index.query_by_control.return_value = ["rule-1"]
        mock_index.controls_to_rules = {}
        mock_fw_index_cls.build.return_value = mock_index

        mock_mapping = MagicMock()
        mock_mapping.title = "CIS RHEL 9 v2.0.0"
        mock_mapping.implemented_count = 100
        mock_load_all_mappings.return_value = {"cis-rhel9-v2.0.0": mock_mapping}
        mock_rules_for_fw.return_value = rules
        mock_build_map.return_value = {"rule-1": "1.1.1"}

        result = select_rules(
            rules_path=None,
            rule_path=None,
            severity=(),
            tag=(),
            category=None,
            control="cis-rhel9-v2.0.0:1.1.1",
        )

        # Should have used "rules/" as the default path
        mock_load_rules.assert_called_once_with(
            "rules/", severity=None, tags=None, category=None
        )
        assert isinstance(result, RuleSelection)

    def test_ac4_no_path_no_control_raises_valueerror(self):
        """AC-4: When no path and no --control, raises ValueError."""
        with pytest.raises(ValueError, match="Specify --rules or --rule"):
            select_rules(
                rules_path=None,
                rule_path=None,
                severity=(),
                tag=(),
                category=None,
            )

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    @patch(_P_LOAD_ALL_MAPPINGS)
    @patch(_P_FW_INDEX)
    def test_ac5_control_and_rule_mutually_exclusive(
        self,
        mock_fw_index_cls,
        mock_load_all_mappings,
        mock_load_rules,
        mock_order_rules,
        mock_parse_var,
        mock_load_config,
    ):
        """AC-5: --control and --rule mutually exclusive; raises ValueError."""
        rules = [_make_rule("rule-1")]
        mock_load_rules.return_value = rules
        mock_order_rules.return_value = _make_ordering_result(rules)
        mock_load_config.return_value = MagicMock()

        mock_index = MagicMock()
        mock_fw_index_cls.build.return_value = mock_index
        mock_load_all_mappings.return_value = {"cis-rhel9-v2.0.0": MagicMock()}

        with pytest.raises(ValueError, match="mutually exclusive"):
            select_rules(
                rules_path=None,
                rule_path="rules/test-rule.yml",
                severity=(),
                tag=(),
                category=None,
                control="cis:1.1.1",
            )

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    @patch(_P_LOAD_ALL_MAPPINGS)
    @patch(_P_FW_INDEX)
    @patch(_P_RULES_FOR_FW)
    @patch(_P_BUILD_MAP)
    def test_ac6_control_with_prefix_resolves_via_framework_index(
        self,
        mock_build_map,
        mock_rules_for_fw,
        mock_fw_index_cls,
        mock_load_all_mappings,
        mock_load_rules,
        mock_order_rules,
        mock_parse_var,
        mock_load_config,
    ):
        """AC-6: --control with 'prefix:section' resolves via FrameworkIndex."""
        rules = [_make_rule("rule-1"), _make_rule("rule-2")]
        filtered = [rules[0]]
        mock_load_rules.return_value = rules
        mock_order_rules.return_value = _make_ordering_result(filtered)
        mock_load_config.return_value = MagicMock()

        mock_index = MagicMock()
        mock_index.query_by_control.return_value = ["rule-1"]
        mock_index.controls_to_rules = {}
        mock_fw_index_cls.build.return_value = mock_index

        mock_mapping = MagicMock()
        mock_mapping.title = "CIS RHEL 9 v2.0.0"
        mock_mapping.implemented_count = 100
        mock_load_all_mappings.return_value = {"cis-rhel9-v2.0.0": mock_mapping}
        mock_rules_for_fw.return_value = filtered
        mock_build_map.return_value = {"rule-1": "1.1.2.4"}

        result = select_rules(
            rules_path="rules/",
            rule_path=None,
            severity=(),
            tag=(),
            category=None,
            control="cis-rhel9-v2.0.0:1.1.2.4",
        )

        mock_index.query_by_control.assert_called()
        assert isinstance(result, RuleSelection)
        # Framework should be inferred from the control prefix
        assert result.framework == "cis-rhel9-v2.0.0"

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    @patch(_P_LOAD_ALL_MAPPINGS)
    @patch(_P_FW_INDEX)
    def test_ac7_control_no_colon_resolves_across_all(
        self,
        mock_fw_index_cls,
        mock_load_all_mappings,
        mock_load_rules,
        mock_order_rules,
        mock_parse_var,
        mock_load_config,
    ):
        """AC-7: --control with no ':' resolves across all mappings."""
        rules = [_make_rule("rule-1")]
        mock_load_rules.return_value = rules
        mock_order_rules.return_value = _make_ordering_result(rules)
        mock_load_config.return_value = MagicMock()

        mock_index = MagicMock()
        mock_index.query_by_control.return_value = ["rule-1"]
        mock_index.controls_to_rules = {}
        mock_fw_index_cls.build.return_value = mock_index
        mock_load_all_mappings.return_value = {"cis-rhel9-v2.0.0": MagicMock()}

        result = select_rules(
            rules_path="rules/",
            rule_path=None,
            severity=(),
            tag=(),
            category=None,
            control="1.1.2.4",
        )

        assert isinstance(result, RuleSelection)
        # Ambiguous resolution sets ControlContext
        assert result.control_ctx is not None

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    @patch(_P_LOAD_ALL_MAPPINGS)
    @patch(_P_FW_INDEX)
    def test_ac8_control_resolving_zero_rules_raises(
        self,
        mock_fw_index_cls,
        mock_load_all_mappings,
        mock_load_rules,
        mock_order_rules,
        mock_parse_var,
        mock_load_config,
    ):
        """AC-8: --control resolving to zero rules raises ValueError."""
        rules = [_make_rule("rule-1")]
        mock_load_rules.return_value = rules
        mock_load_config.return_value = MagicMock()

        mock_index = MagicMock()
        mock_index.query_by_control.return_value = []
        mock_index.controls_to_rules = {}
        mock_fw_index_cls.build.return_value = mock_index
        mock_load_all_mappings.return_value = {"cis-rhel9-v2.0.0": MagicMock()}

        with pytest.raises(ValueError, match="No rules found for control"):
            select_rules(
                rules_path="rules/",
                rule_path=None,
                severity=(),
                tag=(),
                category=None,
                control="cis-rhel9-v2.0.0:99.99.99",
            )

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    @patch(_P_LOAD_ALL_MAPPINGS)
    @patch(_P_RULES_FOR_FW)
    @patch(_P_BUILD_MAP)
    def test_ac9_framework_filters_rules(
        self,
        mock_build_map,
        mock_rules_for_fw,
        mock_load_all_mappings,
        mock_load_rules,
        mock_order_rules,
        mock_parse_var,
        mock_load_config,
    ):
        """AC-9: --framework filters to specified mapping rules; unknown raises ValueError."""
        rules = [_make_rule("rule-1"), _make_rule("rule-2")]
        filtered = [rules[0]]
        mock_load_rules.return_value = rules
        mock_order_rules.return_value = _make_ordering_result(filtered)
        mock_load_config.return_value = MagicMock()

        mock_mapping = MagicMock()
        mock_mapping.title = "CIS RHEL 9 v2.0.0"
        mock_mapping.implemented_count = 100
        mock_load_all_mappings.return_value = {"cis-rhel9-v2.0.0": mock_mapping}
        mock_rules_for_fw.return_value = filtered
        mock_build_map.return_value = {"rule-1": "1.1.1"}

        result = select_rules(
            rules_path="rules/",
            rule_path=None,
            severity=(),
            tag=(),
            category=None,
            framework="cis-rhel9-v2.0.0",
        )

        assert isinstance(result, RuleSelection)
        assert result.framework == "cis-rhel9-v2.0.0"
        mock_rules_for_fw.assert_called_once_with(mock_mapping, rules)

        # Unknown framework raises ValueError
        with pytest.raises(ValueError, match="Unknown framework"):
            select_rules(
                rules_path="rules/",
                rule_path=None,
                severity=(),
                tag=(),
                category=None,
                framework="nonexistent-framework",
            )

    @patch(_P_LOAD_CONFIG)
    @patch(_P_PARSE_VAR, return_value={})
    @patch(_P_ORDER_RULES)
    @patch(_P_LOAD_RULES)
    def test_ac10_ordering_always_applied_cycles_raise(
        self, mock_load_rules, mock_order_rules, mock_parse_var, mock_load_config
    ):
        """AC-10: Dependency ordering via order_rules always applied; cycles cause ValueError."""
        rules = [_make_rule("rule-a"), _make_rule("rule-b")]
        mock_load_rules.return_value = rules
        mock_load_config.return_value = MagicMock()

        # First: verify order_rules is always called
        mock_order_rules.return_value = _make_ordering_result(rules)
        select_rules(
            rules_path="rules/",
            rule_path=None,
            severity=(),
            tag=(),
            category=None,
        )
        mock_order_rules.assert_called_once_with(rules)

        # Second: cycles cause ValueError
        mock_order_rules.reset_mock()
        mock_order_rules.return_value = _make_ordering_result_with_cycles(rules)

        with pytest.raises(ValueError, match="Circular dependencies"):
            select_rules(
                rules_path="rules/",
                rule_path=None,
                severity=(),
                tag=(),
                category=None,
            )
