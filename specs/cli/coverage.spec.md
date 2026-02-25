# Spec: coverage CLI Command

## Context
- **Module:** `runner/cli.py` → `coverage()`
- **Click decorators:** `@main.command()`, individual options
- **Dependencies:** `runner.mappings.load_all_mappings`, `runner.mappings.check_coverage`, `runner.engine.load_rules`

## Objective
Show coverage report for a framework mapping. Reports which framework sections have rules, which are explicitly unimplemented, and which have missing rules.

### Input Contract

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--framework / -f` | `str` | Yes | — | Framework mapping ID (e.g., cis-rhel9-v2.0.0) |
| `--rules / -r` | `str` | No | `rules/` | Path to rules directory |
| `--json` | `bool` | No | `False` | Output as JSON |

### Behavior

1. Load all framework mappings via `load_all_mappings()`.
2. If `--framework` not in mappings: print error with available frameworks, exit 1.
3. Load rules from `--rules` path via `load_rules()`.
4. If rules load fails (`ValueError` or `FileNotFoundError`): print error, exit 1.
5. Call `check_coverage(mapping, available_rules)` to generate report.
6. If `--json`: output JSON with framework metadata, coverage stats, unaccounted controls, missing rules.
7. If terminal:
   a. Print framework title.
   b. If no manifest, print warning.
   c. Print coverage stats (total, implemented, unimplemented, unaccounted).
   d. Print coverage percentages.
   e. If unaccounted controls ≤20, list them; otherwise show count with hint to use `--json`.
   f. If missing rules, list them.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Normal completion |
| 1 | Unknown framework, rule load error |

### Output Contract

**Terminal:** Framework title, optional manifest warning, coverage stats, coverage percentages, optional unaccounted/missing lists.
**--json:** JSON object with `framework` (id, title), `coverage` (total_controls, implemented, unimplemented, unaccounted, coverage_percent, accounted_percent, is_complete, has_manifest), `unaccounted_controls`, `missing_rules`.

### Side Effects

- **None.** Read-only operation.

### Acceptance Criteria

- **AC-1:** Valid framework exits 0 with coverage stats displayed.
- **AC-2:** `--json` outputs valid JSON with framework metadata and coverage.
- **AC-3:** Unknown framework exits 1 with available frameworks listed.
- **AC-4:** Invalid rules path exits 1 with error.
- **AC-5:** Missing manifest shows warning in terminal output.
- **AC-6:** Missing rules (referenced in mapping but absent) are listed.
- **AC-7:** `--json` includes `is_complete` and `has_manifest` fields.
- **AC-8:** Coverage percentages are rounded to 1 decimal place in JSON.

## Constraints

- MUST require `--framework` flag.
- MUST exit 1 for unknown framework or rule load failure.
- MUST show available frameworks on unknown framework error.
