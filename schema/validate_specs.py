#!/usr/bin/env python3
"""Validate spec YAML files against the spec JSON Schema.

Usage:
    python3 schema/validate_specs.py                     # Validate all specs
    python3 schema/validate_specs.py specs/cli/check.spec.yaml  # Specific file

"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import ValidationError, validate

SCHEMA_PATH = Path(__file__).resolve().parent / "spec.schema.json"
SPECS_DIR = Path(__file__).resolve().parent.parent / "specs"


def main() -> int:
    """Validate spec YAML files against the spec schema."""
    schema = json.loads(SCHEMA_PATH.read_text())

    if len(sys.argv) > 1:
        files = [Path(f) for f in sys.argv[1:] if Path(f).exists()]
    else:
        files = sorted(SPECS_DIR.rglob("*.spec.yaml"))

    if not files:
        print("No spec files to validate.")
        return 1

    passed = 0
    failed = 0

    for filepath in files:
        try:
            data = yaml.safe_load(filepath.read_text())
            validate(data, schema)
            print(f"  PASS  {filepath}")
            passed += 1
        except ValidationError as exc:
            print(f"  FAIL  {filepath}")
            print(f"          {exc.message}")
            if exc.path:
                print(f"          path: {'.'.join(str(p) for p in exc.path)}")
            failed += 1
        except Exception as exc:
            print(f"  FAIL  {filepath}")
            print(f"          {exc}")
            failed += 1

    print()
    print(f"Specs: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
