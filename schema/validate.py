#!/usr/bin/env python3
"""Aegis Rule Validator
====================
Validates all .yml rule files under rules/ against:
  1. The JSON Schema at schema/rule.schema.json
  2. Additional structural rules:
     - id field matches filename (without .yml)
     - category field matches parent directory name
     - Exactly one implementation has default: true
     - All non-default implementations have a 'when' field
"""

import json
import sys
from pathlib import Path

import jsonschema
import yaml

# -- Paths -------------------------------------------------------------------
SCHEMA_PATH = Path(__file__).resolve().parent / "rule.schema.json"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_schema() -> dict:
    """Load and return the JSON Schema."""
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def find_rule_files() -> list:
    """Recursively find all .yml files under the rules directory."""
    files = sorted(RULES_DIR.rglob("*.yml"))
    return files


def validate_json_schema(data: dict, schema: dict) -> list:
    """Validate data against the JSON Schema. Return list of error messages."""
    validator_cls = jsonschema.Draft202012Validator
    validator = validator_cls(schema)
    errors = []
    for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        path = (
            " -> ".join(str(p) for p in error.absolute_path)
            if error.absolute_path
            else "(root)"
        )
        errors.append(f"[schema] {path}: {error.message}")
    return errors


def validate_business_rules(data: dict, filepath: Path) -> list:
    """Validate additional business rules beyond the JSON Schema."""
    errors = []

    # -- Rule 1: id must match filename (without .yml) ----------------------
    expected_id = filepath.stem
    actual_id = data.get("id", "")
    if actual_id != expected_id:
        errors.append(
            f"[id-mismatch] id field is '{actual_id}' but filename is "
            f"'{filepath.name}' (expected id: '{expected_id}')"
        )

    # -- Rule 2: category must match parent directory name -------------------
    expected_category = filepath.parent.name
    actual_category = data.get("category", "")
    if actual_category != expected_category:
        errors.append(
            f"[category-mismatch] category is '{actual_category}' but parent "
            f"directory is '{expected_category}'"
        )

    # -- Rule 3 & 4: implementation default / when constraints ---------------
    implementations = data.get("implementations", [])
    if implementations:
        default_count = sum(
            1 for impl in implementations if impl.get("default") is True
        )
        if default_count == 0:
            errors.append(
                "[no-default] No implementation has 'default: true' "
                "(exactly one is required)"
            )
        elif default_count > 1:
            errors.append(
                f"[multi-default] {default_count} implementations have "
                f"'default: true' (exactly one is required)"
            )

        for i, impl in enumerate(implementations):
            is_default = impl.get("default") is True
            has_when = "when" in impl
            if not is_default and not has_when:
                errors.append(
                    f"[missing-when] implementations[{i}] is not the default "
                    f"but has no 'when' field"
                )

    return errors


def validate_file(filepath: Path, schema: dict) -> tuple:
    """Validate a single YAML rule file. Returns (passed, errors)."""
    errors = []

    # Load YAML
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        return False, [f"[yaml-parse] Failed to parse YAML: {exc}"]

    if not isinstance(data, dict):
        return False, [
            f"[yaml-parse] File does not contain a YAML mapping (got {type(data).__name__})"
        ]

    # JSON Schema validation
    errors.extend(validate_json_schema(data, schema))

    # Business-rule validation
    errors.extend(validate_business_rules(data, filepath))

    return len(errors) == 0, errors


def main() -> int:
    # Load schema
    print(f"Loading schema: {SCHEMA_PATH}")
    try:
        schema = load_schema()
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        print(f"FATAL: Cannot load schema: {exc}")
        return 2

    # Discover rule files
    rule_files = find_rule_files()
    if not rule_files:
        print(f"WARNING: No .yml files found under {RULES_DIR}")
        return 1

    print(f"Found {len(rule_files)} rule file(s) under {RULES_DIR}\n")
    print("=" * 78)

    passed = 0
    failed = 0
    failure_details = []

    for filepath in rule_files:
        rel = filepath.relative_to(RULES_DIR)
        ok, errors = validate_file(filepath, schema)

        if ok:
            print(f"  PASS  {rel}")
            passed += 1
        else:
            print(f"  FAIL  {rel}")
            for err in errors:
                print(f"          {err}")
            failed += 1
            failure_details.append((filepath, errors))

    # Summary
    print("=" * 78)
    print()
    print("VALIDATION SUMMARY")
    print(f"  Total files : {len(rule_files)}")
    print(f"  Passed      : {passed}")
    print(f"  Failed      : {failed}")

    if failure_details:
        print()
        print("FAILED FILES:")
        for filepath, errors in failure_details:
            rel = filepath.relative_to(RULES_DIR)
            print(f"  {rel}  ({len(errors)} error(s))")
            for err in errors:
                print(f"    - {err}")

    print()
    if failed == 0:
        print("Result: ALL RULES VALID")
    else:
        print(f"Result: {failed} RULE(S) INVALID")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
