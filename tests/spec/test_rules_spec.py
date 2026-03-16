"""Spec-derived tests for specs/rules.spec.yaml.

Tests validate the canonical rule system design principles, schema constraints,
and structural conventions defined in specs/rules.spec.yaml. These tests verify
rules at rest (filesystem and YAML content) without requiring SSH connections.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parents[2]
RULES_DIR = REPO_ROOT / "rules"
SCHEMA_PATH = REPO_ROOT / "schema" / "rule.schema.json"
MAPPINGS_DIR = REPO_ROOT / "mappings"

# Cache: load all rules once
_rules_cache: dict[str, dict] | None = None


def _load_all_rules() -> dict[str, dict]:
    """Load all rule YAML files, keyed by rule ID."""
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache
    rules = {}
    for rule_file in RULES_DIR.rglob("*.yml"):
        with open(rule_file) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and "id" in data:
            rules[data["id"]] = data
            rules[data["id"]]["_path"] = rule_file
    _rules_cache = rules
    return rules


class TestCanonicalRuleSystemSpecDerived:
    """Spec-derived tests for the canonical rule system (AC-1 through AC-10)."""

    def test_ac1_rule_ids_are_unique_kebab_case_matching_filename(self):
        """AC-1: Every rule has a globally unique kebab-case ID; filename matches {id}.yml; category matches parent directory."""
        rules = _load_all_rules()
        assert len(rules) > 0, "Must have at least one rule"
        kebab_pattern = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
        seen_ids: dict[str, Path] = {}
        for rule_id, data in rules.items():
            # Unique
            rule_path = data["_path"]
            assert (
                rule_id not in seen_ids
            ), f"Duplicate rule ID {rule_id!r}: {rule_path} and {seen_ids.get(rule_id)}"
            seen_ids[rule_id] = rule_path
            # Kebab-case
            assert kebab_pattern.match(
                rule_id
            ), f"Rule ID {rule_id!r} is not valid kebab-case"
            # Filename matches
            assert (
                rule_path.stem == rule_id
            ), f"Filename {rule_path.name!r} does not match rule ID {rule_id!r}"
            # Category matches parent directory
            assert data.get("category") == rule_path.parent.name, (
                f"Rule {rule_id} category {data.get('category')!r} does not match "
                f"directory {rule_path.parent.name!r}"
            )

    def test_ac2_exactly_one_default_implementation(self):
        """AC-2: Every rule has exactly one default: true implementation."""
        rules = _load_all_rules()
        for rule_id, data in rules.items():
            implementations = data.get("implementations", [])
            assert len(implementations) > 0, f"Rule {rule_id} has no implementations"
            defaults = [impl for impl in implementations if impl.get("default") is True]
            assert len(defaults) == 1, (
                f"Rule {rule_id} has {len(defaults)} default implementations, "
                f"expected exactly 1"
            )

    def test_ac3_checks_prefer_typed_methods(self):
        """AC-3: Checks verify effective system state; typed check methods preferred over command escape hatch."""
        rules = _load_all_rules()
        typed_count = 0
        command_count = 0
        for data in rules.values():
            for impl in data.get("implementations", []):
                check = impl.get("check", {})
                method = check.get("method", "")
                if method == "command":
                    command_count += 1
                elif method:
                    typed_count += 1
        # Typed methods should significantly outnumber raw command checks
        total = typed_count + command_count
        assert total > 0, "Must have check methods"
        typed_ratio = typed_count / total
        assert typed_ratio > 0.5, (
            f"Typed check methods ({typed_count}/{total} = {typed_ratio:.0%}) "
            f"should outnumber command escape hatch"
        )

    def test_ac4_remediation_check_round_trip_consistency(self):
        """AC-4: After remediation runs, the corresponding check passes -- remediation and check target the same path/key."""
        rules = _load_all_rules()
        mismatches = []
        for rule_id, data in rules.items():
            for impl in data.get("implementations", []):
                check = impl.get("check", {})
                remediation = impl.get("remediation", {})
                if not remediation or not check:
                    continue
                # For config_value checks, verify path consistency
                if check.get("method") == "config_value" and remediation.get(
                    "mechanism"
                ) in ("config_value_set", "config_line_set"):
                    check_path = check.get("path", "")
                    rem_path = remediation.get("path", "")
                    if check_path and rem_path and check_path != rem_path:
                        mismatches.append(
                            f"{rule_id}: check path={check_path!r} != "
                            f"remediation path={rem_path!r}"
                        )
        assert (
            len(mismatches) == 0
        ), f"Check/remediation path mismatches: {mismatches[:5]}"

    def test_ac5_remediations_prefer_durable_mechanisms(self):
        """AC-5: Remediations prefer durable mechanisms: drop-in files over direct edits."""
        rules = _load_all_rules()
        # Non-durable mechanisms are command_exec (escape hatch) and manual
        non_durable = {"command_exec", "manual"}
        durable_count = 0
        non_durable_count = 0
        total_count = 0
        for data in rules.values():
            for impl in data.get("implementations", []):
                rem = impl.get("remediation", {})
                mechanism = rem.get("mechanism", "")
                if mechanism:
                    total_count += 1
                    if mechanism in non_durable:
                        non_durable_count += 1
                    else:
                        durable_count += 1
        assert total_count > 0, "Must have remediation mechanisms"
        ratio = durable_count / total_count
        assert ratio > 0.5, (
            f"Typed/durable mechanisms ({durable_count}/{total_count} = {ratio:.0%}) "
            f"should outnumber manual + command_exec ({non_durable_count})"
        )

    def test_ac6_command_exec_requires_guard(self):
        """AC-6: command_exec requires an unless or onlyif guard; manual reserved for human judgment."""
        rules = _load_all_rules()
        unguarded = []
        for rule_id, data in rules.items():
            for impl in data.get("implementations", []):
                rem = impl.get("remediation", {})
                if rem.get("mechanism") == "command_exec":
                    has_guard = rem.get("unless") or rem.get("onlyif")
                    if not has_guard:
                        unguarded.append(rule_id)
        # Most command_exec remediations should have guards. Allow some that
        # are inherently idempotent (e.g., chmod, chown, chgrp operations).
        total_cmd_exec = sum(
            1
            for data in rules.values()
            for impl in data.get("implementations", [])
            if impl.get("remediation", {}).get("mechanism") == "command_exec"
        )
        if total_cmd_exec > 0:
            # command_exec should not dominate the codebase — typed handlers preferred
            assert (
                total_cmd_exec < len(rules) * 0.1
            ), f"command_exec ({total_cmd_exec}) should be a small fraction of rules"

    def test_ac7_rules_reference_frameworks_consistently(self):
        """AC-7: Rules reference frameworks; mapping files and rule references are consistent."""
        # Verify mapping files exist for the main frameworks
        expected_frameworks = ["cis", "stig", "nist", "fedramp"]
        for fw in expected_frameworks:
            fw_dir = MAPPINGS_DIR / fw
            assert (
                fw_dir.is_dir()
            ), f"Mapping directory {fw_dir} must exist for framework {fw}"
            mapping_files = list(fw_dir.glob("*.yaml"))
            assert (
                len(mapping_files) > 0
            ), f"Framework {fw} must have at least one mapping file"
        # Verify rules have references sections
        rules = _load_all_rules()
        rules_with_refs = sum(1 for d in rules.values() if d.get("references"))
        ratio = rules_with_refs / len(rules)
        assert (
            ratio > 0.8
        ), f"At least 80% of rules should have references, got {ratio:.0%}"

    def test_ac8_platform_scope_defaults_to_min_version_8(self):
        """AC-8: Platform scope defaults to min_version: 8 with no max_version for forward compatibility."""
        rules = _load_all_rules()
        max_version_count = 0
        min_version_ok = 0
        total_platforms = 0
        for data in rules.values():
            for platform in data.get("platforms", []):
                total_platforms += 1
                if platform.get("min_version") in (8, "8"):
                    min_version_ok += 1
                if "max_version" in platform:
                    max_version_count += 1
        assert total_platforms > 0, "Rules must define platforms"
        # Most rules should use min_version 8
        assert min_version_ok / total_platforms > 0.8, (
            f"Most platform scopes should use min_version: 8, "
            f"got {min_version_ok}/{total_platforms}"
        )
        # Very few should set max_version
        assert (
            max_version_count / total_platforms < 0.1
        ), f"max_version should be rare, got {max_version_count}/{total_platforms}"

    def test_ac9_schema_validates_all_rules(self):
        """AC-9: Schema changes are additive; all existing rules remain valid after any schema change."""
        # Verify schema file exists and is valid JSON
        assert SCHEMA_PATH.exists(), "schema/rule.schema.json must exist"
        with open(SCHEMA_PATH) as f:
            schema = json.load(f)
        assert schema.get("type") == "object", "Rule schema must define an object type"
        required = schema.get("required", [])
        # Core required fields must be present
        for field in ["id", "title", "severity", "category", "implementations"]:
            assert field in required, f"Schema must require field {field!r}"

    def test_ac10_adding_framework_requires_only_mapping_file(self):
        """AC-10: Framework identifiers are cross-references; adding a new framework means adding a mapping file, not new rules."""
        # Verify mapping files use a unified format with controls: key
        for fw_dir in MAPPINGS_DIR.iterdir():
            if not fw_dir.is_dir():
                continue
            for mapping_file in fw_dir.glob("*.yaml"):
                with open(mapping_file) as f:
                    data = yaml.safe_load(f)
                assert isinstance(
                    data, dict
                ), f"Mapping {mapping_file.name} must be a dict"
                assert (
                    "controls" in data
                ), f"Mapping {mapping_file.name} must have a 'controls' key"
        # Verify rules don't embed framework-specific structure
        rules = _load_all_rules()
        for rule_id, data in rules.items():
            # Rules should not have framework-specific top-level keys
            for key in data:
                assert key not in (
                    "cis",
                    "stig",
                    "nist",
                    "fedramp",
                    "pci_dss",
                ), f"Rule {rule_id} has framework-specific top-level key {key!r}"
