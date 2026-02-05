# P2-5: Validation Modularization

## Status: Not Started

## Problem

`schema/validate.py` is currently a single 188-line file that handles:
- YAML parsing
- JSON Schema validation
- Business rule validation (id↔filename, category↔directory, default impl)

As we add more validation types, this will become unwieldy:

| Feature | New Validation Needed |
|---------|----------------------|
| P2-3 Framework Mappings | Mapping file schema, rule ID existence checks |
| P2 Dependency Ordering | `depends_on`/`conflicts_with`/`supersedes` reference valid IDs, no cycles |
| Capability correctness | `when:` gates reference capabilities defined in `detect.py` |

A modular structure will keep each validator focused and testable.

## Solution

Split validation into focused modules under `schema/validators/`:

```
schema/
  validate.py              # CLI entry point — orchestrates validators
  rule.schema.json         # Rule JSON Schema (existing)
  mapping.schema.json      # Mapping JSON Schema (new, for P2-3)
  validators/
    __init__.py            # Exports all validators
    rule.py                # Per-rule validation
    mapping.py             # Per-mapping validation
    graph.py               # Cross-rule graph validation
    capabilities.py        # Capability name validation
```

### Validator Interface

Each validator module exposes a consistent interface:

```python
# schema/validators/rule.py

@dataclass
class ValidationError:
    code: str        # e.g., "id-mismatch", "schema-error"
    message: str     # Human-readable description
    path: str        # File path or JSON path
    severity: str    # "error" or "warning"

def validate_rule(filepath: Path, schema: dict) -> list[ValidationError]:
    """Validate a single rule file."""
    ...

def validate_all_rules(rules_dir: Path) -> list[ValidationError]:
    """Validate all rules in a directory."""
    ...
```

### Validator Responsibilities

#### `validators/rule.py` — Per-Rule Validation

Moved from current `validate.py`:
- YAML parse check
- JSON Schema validation against `rule.schema.json`
- Business rules:
  - `id` matches filename
  - `category` matches parent directory
  - Exactly one `default: true` implementation
  - Non-default implementations have `when` field

#### `validators/mapping.py` — Per-Mapping Validation (P2-3)

- YAML parse check
- JSON Schema validation against `mapping.schema.json`
- Business rules:
  - All `rule:` references point to existing rule IDs
  - No duplicate section/finding IDs within a mapping
  - `platform` constraints are valid (family in enum, versions are integers)

#### `validators/graph.py` — Cross-Rule Graph Validation (P2)

- `depends_on` references exist as rule IDs
- `conflicts_with` references exist as rule IDs
- `supersedes` references exist as rule IDs
- No circular dependencies in `depends_on` graph
- Warnings for orphaned rules (nothing depends on them, they depend on nothing)

#### `validators/capabilities.py` — Capability Validation

- Extract all capability names from `when:` gates across all rules
- Compare against `CAPABILITY_PROBES` keys in `runner/detect.py`
- Warning for unknown capabilities (might be typos or future probes)
- Warning for unused probes (defined but never referenced)

### CLI Interface

```bash
# Validate everything (default)
python3 schema/validate.py

# Validate specific categories
python3 schema/validate.py --rules           # Only rule files
python3 schema/validate.py --mappings        # Only mapping files
python3 schema/validate.py --graph           # Cross-rule dependencies
python3 schema/validate.py --capabilities    # Capability name check

# Validate specific file(s)
python3 schema/validate.py rules/access-control/ssh-disable-root-login.yml
python3 schema/validate.py mappings/cis/rhel9_v2.0.0.yaml

# Output formats
python3 schema/validate.py --format text     # Human-readable (default)
python3 schema/validate.py --format json     # Machine-readable
python3 schema/validate.py --format github   # GitHub Actions annotations

# Strict mode (warnings become errors)
python3 schema/validate.py --strict
```

### Output Example

```
$ python3 schema/validate.py

Loading schemas...
  rule.schema.json: OK
  mapping.schema.json: OK

Validating rules (47 files)...
  PASS  access-control/ssh-disable-root-login.yml
  PASS  access-control/ssh-max-auth-tries.yml
  FAIL  access-control/ssh-banner.yml
          [id-mismatch] id is 'ssh-banner-text' but filename is 'ssh-banner.yml'
  ...

Validating mappings (5 files)...
  PASS  cis/rhel9_v2.0.0.yaml
  WARN  stig/rhel9_v2r7.yaml
          [unknown-rule] Section V-999999 references non-existent rule 'foo-bar'
  ...

Validating cross-rule graph...
  WARN  [unused-rule] 'legacy-pam-config' is not referenced by any mapping
  PASS  No circular dependencies

Validating capabilities...
  WARN  [unknown-capability] 'when: foobar' in ssh-example.yml — not in detect.py
  WARN  [unused-probe] 'tpm2' defined in detect.py but never referenced

════════════════════════════════════════════════════════════════════════════════
VALIDATION SUMMARY
  Rules:        46 passed, 1 failed
  Mappings:      4 passed, 1 warning
  Graph:         OK (1 warning)
  Capabilities:  OK (2 warnings)

Result: 1 ERROR, 4 WARNINGS
```

## Technical Approach

### Phase 1: Extract Current Logic

Move existing validation logic to `validators/rule.py` without changing behavior:

```python
# schema/validators/rule.py
from dataclasses import dataclass
from pathlib import Path
import jsonschema
import yaml

@dataclass
class ValidationError:
    code: str
    message: str
    path: str
    severity: str = "error"

def validate_rule_schema(data: dict, schema: dict, filepath: Path) -> list[ValidationError]:
    """JSON Schema validation."""
    ...

def validate_rule_business(data: dict, filepath: Path) -> list[ValidationError]:
    """Business rule validation."""
    ...

def validate_rule(filepath: Path, schema: dict) -> list[ValidationError]:
    """Full validation of a single rule file."""
    errors = []

    # Parse YAML
    try:
        data = yaml.safe_load(filepath.read_text())
    except yaml.YAMLError as e:
        return [ValidationError("yaml-parse", str(e), str(filepath))]

    # Schema validation
    errors.extend(validate_rule_schema(data, schema, filepath))

    # Business rules
    errors.extend(validate_rule_business(data, filepath))

    return errors
```

### Phase 2: Add Mapping Validation (with P2-3)

```python
# schema/validators/mapping.py

def validate_mapping(filepath: Path, schema: dict, rule_ids: set[str]) -> list[ValidationError]:
    """Validate a mapping file."""
    errors = []

    data = yaml.safe_load(filepath.read_text())

    # Schema validation
    errors.extend(validate_mapping_schema(data, schema, filepath))

    # Check rule references
    for section_id, entry in data.get("sections", {}).items():
        rule_id = entry.get("rule")
        if rule_id and rule_id not in rule_ids:
            errors.append(ValidationError(
                "unknown-rule",
                f"Section {section_id} references non-existent rule '{rule_id}'",
                str(filepath),
                severity="warning",
            ))

    return errors
```

### Phase 3: Add Graph Validation (with P2)

```python
# schema/validators/graph.py

def validate_graph(rules: list[dict]) -> list[ValidationError]:
    """Validate cross-rule dependencies."""
    errors = []
    rule_ids = {r["id"] for r in rules}

    # Check references exist
    for rule in rules:
        for dep in rule.get("depends_on", []):
            if dep not in rule_ids:
                errors.append(ValidationError(
                    "unknown-dependency",
                    f"Rule '{rule['id']}' depends_on unknown rule '{dep}'",
                    f"rules/*/{rule['id']}.yml",
                ))

    # Check for cycles
    cycles = find_cycles(rules)
    for cycle in cycles:
        errors.append(ValidationError(
            "circular-dependency",
            f"Circular dependency: {' → '.join(cycle)}",
            "depends_on graph",
        ))

    return errors
```

### Phase 4: Add Capability Validation

```python
# schema/validators/capabilities.py

def validate_capabilities(rules: list[dict], probes: dict[str, str]) -> list[ValidationError]:
    """Validate capability names against detect.py probes."""
    errors = []

    # Extract all capability names from when: gates
    used_caps = extract_capability_names(rules)
    known_caps = set(probes.keys())

    # Unknown capabilities
    for cap, locations in used_caps.items():
        if cap not in known_caps:
            for loc in locations:
                errors.append(ValidationError(
                    "unknown-capability",
                    f"Capability '{cap}' not defined in detect.py",
                    loc,
                    severity="warning",
                ))

    # Unused probes
    unused = known_caps - set(used_caps.keys())
    for cap in unused:
        errors.append(ValidationError(
            "unused-probe",
            f"Probe '{cap}' defined but never referenced in rules",
            "runner/detect.py",
            severity="warning",
        ))

    return errors
```

### Orchestrator

```python
# schema/validate.py

from schema.validators import rule, mapping, graph, capabilities

def main():
    args = parse_args()

    all_errors = []

    if args.rules or args.all:
        rule_schema = load_schema("rule.schema.json")
        for f in find_rule_files():
            all_errors.extend(rule.validate_rule(f, rule_schema))

    if args.mappings or args.all:
        mapping_schema = load_schema("mapping.schema.json")
        rule_ids = {r["id"] for r in load_all_rules()}
        for f in find_mapping_files():
            all_errors.extend(mapping.validate_mapping(f, mapping_schema, rule_ids))

    if args.graph or args.all:
        rules = load_all_rules()
        all_errors.extend(graph.validate_graph(rules))

    if args.capabilities or args.all:
        rules = load_all_rules()
        probes = load_probes()
        all_errors.extend(capabilities.validate_capabilities(rules, probes))

    render_results(all_errors, format=args.format)
    return 1 if any(e.severity == "error" for e in all_errors) else 0
```

## Implementation Order

1. **With this PR**: Extract current logic to `validators/rule.py`, update `validate.py` to use it
2. **With P2-3**: Add `validators/mapping.py` and `mapping.schema.json`
3. **With P2**: Add `validators/graph.py`
4. **Anytime**: Add `validators/capabilities.py` (low effort, high value)

## Acceptance Criteria

- [ ] `validators/rule.py` contains all current rule validation logic
- [ ] `validate.py` is a thin orchestrator (~100 lines)
- [ ] Each validator module is independently testable
- [ ] `ValidationError` dataclass used consistently
- [ ] `--format json` produces machine-readable output
- [ ] `--format github` produces GitHub Actions annotations
- [ ] Exit code is 1 if any errors, 0 otherwise
- [ ] `--strict` makes warnings into errors
- [ ] Validation runs in <2s for 50 rules + 10 mappings

## Future Extensions

- **Pre-commit hook**: `schema/validate.py --format github` for CI
- **Watch mode**: `schema/validate.py --watch` for live validation during rule authoring
- **Fix suggestions**: Some errors could suggest fixes (e.g., "rename file to match id")
