"""SpecDerived tests for framework mappings module."""

from __future__ import annotations

import yaml

from runner.mappings import (
    FrameworkIndex,
    FrameworkMapping,
    MappingEntry,
    UnimplementedEntry,
    check_coverage,
    get_applicable_mappings,
    load_all_mappings,
    load_mapping,
    rules_for_framework,
)


class TestFrameworkMappingsSpecDerived:
    """Spec-derived tests for framework mappings.

    See specs/internal/framework_mappings.spec.yaml for specification.
    """

    def test_ac1_load_mapping_returns_framework_mapping(self, tmp_path):
        """AC-1: load_mapping reads YAML and returns FrameworkMapping."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test-mapping",
                    "framework": "cis",
                    "title": "Test Mapping",
                    "published": "2024-01-15",
                    "platform": {"family": "rhel", "min_version": 9, "max_version": 9},
                    "controls": {
                        "1.1.1": {"title": "Control One", "rules": ["rule-a"]},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        assert isinstance(m, FrameworkMapping)
        assert m.id == "test-mapping"
        assert m.framework == "cis"
        assert m.title == "Test Mapping"
        assert m.published is not None
        assert m.platform is not None
        assert m.platform.family == "rhel"

    def test_ac2_controls_parsed_from_controls_key(self, tmp_path):
        """AC-2: Controls parsed from controls: key."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "controls": {
                        "1.1": {"title": "Section One", "rules": ["rule-a", "rule-b"]},
                        "1.2": {"title": "Section Two", "rules": ["rule-c"]},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        assert "1.1" in m.sections
        assert "1.2" in m.sections
        assert isinstance(m.sections["1.1"], MappingEntry)
        assert m.sections["1.1"].title == "Section One"
        assert m.sections["1.1"].metadata["rules"] == ["rule-a", "rule-b"]

    def test_ac3_unimplemented_parsed(self, tmp_path):
        """AC-3: Unimplemented sections parsed into UnimplementedEntry objects."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "controls": {},
                    "unimplemented": {
                        "2.1": {
                            "title": "Manual Check",
                            "reason": "Requires human review",
                            "type": "Manual",
                        },
                        "2.2": {"title": "N/A", "reason": "Not applicable"},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        assert "2.1" in m.unimplemented
        assert isinstance(m.unimplemented["2.1"], UnimplementedEntry)
        assert m.unimplemented["2.1"].title == "Manual Check"
        assert m.unimplemented["2.1"].reason == "Requires human review"
        assert m.unimplemented["2.1"].entry_type == "Manual"
        # Default entry_type
        assert m.unimplemented["2.2"].entry_type == "Manual"

    def test_ac4_control_ids_manifest_is_complete(self, tmp_path):
        """AC-4: control_ids manifest -> is_complete True when all accounted for."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "control_ids": ["1.1", "1.2", "2.1"],
                    "controls": {
                        "1.1": {"title": "One", "rules": ["r1"]},
                        "1.2": {"title": "Two", "rules": ["r2"]},
                    },
                    "unimplemented": {
                        "2.1": {"title": "Manual", "reason": "Manual check"},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        assert m.controls == ["1.1", "1.2", "2.1"]
        assert m.is_complete is True

    def test_ac5_no_control_ids_is_complete_true(self, tmp_path):
        """AC-5: No control_ids -> is_complete True."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "controls": {
                        "1.1": {"title": "One", "rules": ["r1"]},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        assert m.controls == []
        assert m.is_complete is True

    def test_ac6_unaccounted_controls_ordered(self, tmp_path):
        """AC-6: unaccounted_controls returns ordered list of missing IDs."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "control_ids": ["1.1", "1.2", "1.3", "2.1"],
                    "controls": {
                        "1.1": {"title": "One", "rules": ["r1"]},
                    },
                    "unimplemented": {
                        "2.1": {"title": "Manual", "reason": "Manual check"},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        assert m.is_complete is False
        unaccounted = m.unaccounted_controls
        assert unaccounted == ["1.2", "1.3"]

    def test_ac7_load_all_mappings_recursive(self, tmp_path):
        """AC-7: load_all_mappings discovers .yaml/.yml files recursively."""
        sub = tmp_path / "sub"
        sub.mkdir()

        (tmp_path / "m1.yaml").write_text(
            yaml.dump(
                {
                    "id": "m1",
                    "framework": "cis",
                    "title": "M1",
                    "controls": {},
                }
            )
        )
        (sub / "m2.yml").write_text(
            yaml.dump(
                {
                    "id": "m2",
                    "framework": "stig",
                    "title": "M2",
                    "controls": {},
                }
            )
        )

        mappings = load_all_mappings(str(tmp_path))
        assert "m1" in mappings
        assert "m2" in mappings

    def test_ac8_get_applicable_mappings_filters_by_platform(self, tmp_path):
        """AC-8: get_applicable_mappings filters by platform."""
        (tmp_path / "rhel9.yaml").write_text(
            yaml.dump(
                {
                    "id": "rhel9-cis",
                    "framework": "cis",
                    "title": "CIS RHEL 9",
                    "platform": {"family": "rhel", "min_version": 9, "max_version": 9},
                    "controls": {},
                }
            )
        )
        (tmp_path / "generic.yaml").write_text(
            yaml.dump(
                {
                    "id": "generic-nist",
                    "framework": "nist",
                    "title": "NIST Generic",
                    "controls": {},
                }
            )
        )
        (tmp_path / "debian.yaml").write_text(
            yaml.dump(
                {
                    "id": "debian-cis",
                    "framework": "cis",
                    "title": "CIS Debian",
                    "platform": {
                        "family": "debian",
                        "min_version": 11,
                        "max_version": 12,
                    },
                    "controls": {},
                }
            )
        )

        all_mappings = load_all_mappings(str(tmp_path))
        applicable = get_applicable_mappings(all_mappings, "rhel", 9)

        applicable_ids = {m.id for m in applicable}
        assert "rhel9-cis" in applicable_ids
        assert "generic-nist" in applicable_ids  # No platform constraint
        assert "debian-cis" not in applicable_ids

    def test_ac9_rules_for_framework_filters_by_rule_ids(self, tmp_path):
        """AC-9: rules_for_framework filters rules by mapping's rule_ids."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "controls": {
                        "1.1": {"title": "One", "rules": ["rule-a", "rule-b"]},
                        "1.2": {"title": "Two", "rules": ["rule-c"]},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        all_rules = [
            {"id": "rule-a", "title": "A"},
            {"id": "rule-b", "title": "B"},
            {"id": "rule-c", "title": "C"},
            {"id": "rule-d", "title": "D"},  # Not in mapping
        ]

        filtered = rules_for_framework(m, all_rules)
        ids = {r["id"] for r in filtered}
        assert ids == {"rule-a", "rule-b", "rule-c"}
        assert "rule-d" not in ids

    def test_ac10_check_coverage_returns_report(self, tmp_path):
        """AC-10: check_coverage returns CoverageReport."""
        mapping_file = tmp_path / "test.yaml"
        mapping_file.write_text(
            yaml.dump(
                {
                    "id": "test",
                    "framework": "cis",
                    "title": "Test",
                    "control_ids": ["1.1", "1.2", "1.3", "2.1"],
                    "controls": {
                        "1.1": {"title": "One", "rules": ["rule-a"]},
                        "1.2": {"title": "Two", "rules": ["rule-b", "rule-missing"]},
                    },
                    "unimplemented": {
                        "2.1": {"title": "Manual", "reason": "Manual check"},
                    },
                }
            )
        )

        m = load_mapping(str(mapping_file))
        available = {"rule-a", "rule-b"}

        report = check_coverage(m, available)
        assert report.mapping_id == "test"
        assert report.total_controls == 4
        assert report.implemented == 2
        assert report.unimplemented == 1
        assert report.unaccounted == ["1.3"]
        assert "rule-missing" in report.missing_rules
        assert report.has_manifest is True

    def test_ac11_framework_index_build_and_query_by_rule(self, tmp_path):
        """AC-11: FrameworkIndex.build constructs indexes; query_by_rule returns FrameworkReference objects."""
        (tmp_path / "m1.yaml").write_text(
            yaml.dump(
                {
                    "id": "cis-rhel9",
                    "framework": "cis",
                    "title": "CIS RHEL 9",
                    "controls": {
                        "1.1": {"title": "Control One", "rules": ["rule-a"]},
                        "1.2": {"title": "Control Two", "rules": ["rule-b"]},
                    },
                }
            )
        )
        (tmp_path / "m2.yaml").write_text(
            yaml.dump(
                {
                    "id": "stig-rhel9",
                    "framework": "stig",
                    "title": "STIG RHEL 9",
                    "controls": {
                        "V-100": {"title": "STIG One", "rules": ["rule-a"]},
                    },
                }
            )
        )

        mappings = load_all_mappings(str(tmp_path))
        index = FrameworkIndex.build(mappings)

        refs = index.query_by_rule("rule-a")
        assert len(refs) == 2
        mapping_ids = {r.mapping_id for r in refs}
        assert "cis-rhel9" in mapping_ids
        assert "stig-rhel9" in mapping_ids

        # Non-existent rule returns empty
        assert index.query_by_rule("nonexistent") == []

    def test_ac12_query_by_control_exact_and_prefix(self, tmp_path):
        """AC-12: query_by_control supports exact and prefix matching."""
        (tmp_path / "m1.yaml").write_text(
            yaml.dump(
                {
                    "id": "cis-test",
                    "framework": "cis",
                    "title": "CIS Test",
                    "controls": {
                        "5.1.1": {"title": "C1", "rules": ["rule-a"]},
                        "5.1.2": {"title": "C2", "rules": ["rule-b"]},
                        "5.2.1": {"title": "C3", "rules": ["rule-c"]},
                    },
                }
            )
        )

        mappings = load_all_mappings(str(tmp_path))
        index = FrameworkIndex.build(mappings)

        # Exact match with mapping_id prefix
        exact = index.query_by_control("cis-test:5.1.1")
        assert "rule-a" in exact
        assert "rule-b" not in exact

        # Prefix match
        prefix = index.query_by_control("5.1", prefix_match=True)
        assert "rule-a" in prefix
        assert "rule-b" in prefix
        assert "rule-c" not in prefix

        # Exact match without mapping_id
        exact_no_mid = index.query_by_control("5.2.1")
        assert "rule-c" in exact_no_mid
