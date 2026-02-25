# Spec: list-frameworks CLI Command

## Context
- **Module:** `runner/cli.py` → `list_frameworks()`
- **Click decorators:** `@main.command("list-frameworks")`
- **Dependencies:** `runner.mappings.load_all_mappings`

## Objective
List all available framework mappings found in the mappings/ directory.

### Input Contract

No flags or arguments.

### Behavior

1. Load all framework mappings via `load_all_mappings()`.
2. If no mappings: print "No framework mappings found", exit 0.
3. Print header with mapping count.
4. For each mapping (sorted by ID):
   a. Print mapping ID.
   b. Print title with optional platform info.
   c. Print section counts (implemented, skipped).

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Always |

### Output Contract

**Terminal:** Header with count, then per-mapping block with ID, title (+ platform), section counts. No `--json` mode.

### Side Effects

- **None.** Read-only operation.

### Acceptance Criteria

- **AC-1:** With mappings present, exits 0 and displays mapping list.
- **AC-2:** With no mappings, exits 0 and prints "No framework mappings found".
- **AC-3:** Mappings are sorted alphabetically by ID.
- **AC-4:** Platform info is included when mapping has platform constraints.
- **AC-5:** Section counts show implemented and skipped counts.

## Constraints

- MUST always exit 0.
- MUST sort mappings alphabetically.
- MUST handle empty mappings gracefully.
