"""SpecDerived tests for rule ordering module."""

from __future__ import annotations

from runner.ordering import (
    OrderingResult,
    format_ordering_issues,
    get_dependency_failures,
    order_rules,
    should_skip_rule,
)


class TestRuleOrderingSpecDerived:
    """Spec-derived tests for rule ordering.

    See specs/internal/rule_ordering.spec.yaml for specification.
    """

    def test_ac1_topological_sort_dependencies_first(self):
        """AC-1: order_rules returns OrderingResult with rules topologically sorted (dependencies before dependents)."""
        rules = [
            {"id": "rule-b", "depends_on": ["rule-a"]},
            {"id": "rule-a"},
            {"id": "rule-c", "depends_on": ["rule-b"]},
        ]
        result = order_rules(rules)
        ids = [r["id"] for r in result.ordered]
        assert ids.index("rule-a") < ids.index("rule-b")
        assert ids.index("rule-b") < ids.index("rule-c")

    def test_ac2_circular_dependencies_detected(self):
        """AC-2: Circular dependencies detected and reported in cycles field."""
        rules = [
            {"id": "rule-a", "depends_on": ["rule-b"]},
            {"id": "rule-b", "depends_on": ["rule-a"]},
        ]
        result = order_rules(rules)
        assert len(result.cycles) > 0
        # The cycle should contain both rule IDs
        cycle_ids = set()
        for cycle in result.cycles:
            cycle_ids.update(cycle)
        assert "rule-a" in cycle_ids
        assert "rule-b" in cycle_ids

    def test_ac3_conflicts_with_detected(self):
        """AC-3: conflicts_with detected when both rules in active set; reported as tuples."""
        rules = [
            {"id": "rule-a", "conflicts_with": ["rule-b"]},
            {"id": "rule-b"},
        ]
        result = order_rules(rules)
        assert len(result.conflicts) == 1
        conflict = result.conflicts[0]
        assert conflict == ("rule-a", "rule-b")

    def test_ac4_supersedes_removes_from_active(self):
        """AC-4: supersedes removes superseded rules from active set."""
        rules = [
            {"id": "rule-new", "supersedes": ["rule-old"]},
            {"id": "rule-old"},
        ]
        result = order_rules(rules)
        ordered_ids = [r["id"] for r in result.ordered]
        assert "rule-old" not in ordered_ids
        assert "rule-new" in ordered_ids
        assert "rule-old" in result.skipped
        assert result.superseded["rule-old"] == "rule-new"

    def test_ac5_empty_rule_list(self):
        """AC-5: Empty rule list returns empty OrderingResult."""
        result = order_rules([])
        assert isinstance(result, OrderingResult)
        assert result.ordered == []
        assert result.cycles == []
        assert result.conflicts == []
        assert result.superseded == {}
        assert result.skipped == []

    def test_ac6_deterministic_alphabetical_tie_breaking(self):
        """AC-6: Topological sort is deterministic (alphabetical by rule ID for ties)."""
        rules = [
            {"id": "charlie"},
            {"id": "alpha"},
            {"id": "bravo"},
        ]
        result = order_rules(rules)
        ids = [r["id"] for r in result.ordered]
        assert ids == ["alpha", "bravo", "charlie"]

        # Run again to verify determinism
        result2 = order_rules(rules)
        ids2 = [r["id"] for r in result2.ordered]
        assert ids == ids2

    def test_ac7_get_dependency_failures(self):
        """AC-7: get_dependency_failures returns list of failed dependency rule IDs."""
        rules = [
            {"id": "rule-a"},
            {"id": "rule-b"},
            {"id": "rule-c", "depends_on": ["rule-a", "rule-b"]},
        ]
        failed = {"rule-a"}
        failures = get_dependency_failures("rule-c", rules, failed)
        assert failures == ["rule-a"]

        # No failures
        no_failures = get_dependency_failures("rule-c", rules, set())
        assert no_failures == []

        # Rule not found
        not_found = get_dependency_failures("nonexistent", rules, failed)
        assert not_found == []

    def test_ac8_should_skip_direct_dependency_failed(self):
        """AC-8: should_skip_rule returns (True, reason) when direct dependency failed."""
        rules = [
            {"id": "rule-a"},
            {"id": "rule-b", "depends_on": ["rule-a"]},
        ]
        failed = {"rule-a"}
        skip, reason = should_skip_rule("rule-b", rules, failed)
        assert skip is True
        assert "rule-a" in reason
        assert "dependency failed" in reason

    def test_ac9_transitive_dependency_failure(self):
        """AC-9: should_skip_rule with transitive=True detects transitively failed deps via DFS."""
        rules = [
            {"id": "rule-a"},
            {"id": "rule-b", "depends_on": ["rule-a"]},
            {"id": "rule-c", "depends_on": ["rule-b"]},
        ]
        # rule-a failed, rule-c depends on rule-b which depends on rule-a
        failed = {"rule-a"}
        skip, reason = should_skip_rule("rule-c", rules, failed, transitive=True)
        assert skip is True
        assert "transitive" in reason
        assert "rule-a" in reason

        # Without transitive, rule-c only checks direct deps (rule-b is not failed)
        skip_direct, reason_direct = should_skip_rule(
            "rule-c", rules, failed, transitive=False
        )
        assert skip_direct is False
        assert reason_direct == ""

    def test_ac10_format_ordering_issues(self):
        """AC-10: format_ordering_issues returns formatted strings: [ERROR] for cycles, [WARNING] for conflicts, [INFO] for supersedes."""
        result = OrderingResult(
            cycles=[["rule-a", "rule-b", "rule-a"]],
            conflicts=[("rule-x", "rule-y")],
            superseded={"rule-old": "rule-new"},
        )
        messages = format_ordering_issues(result)
        assert any("[ERROR]" in m and "Circular dependency" in m for m in messages)
        assert any("[WARNING]" in m and "Conflict" in m for m in messages)
        assert any("[INFO]" in m and "superseded" in m.lower() for m in messages)
