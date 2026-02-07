# P2: Dependency Ordering

## Status: Complete

## Problem
Rules can declare `depends_on`, `conflicts_with`, and `supersedes` relationships. V0 ignores these — rules run in filesystem sort order. This means a rule that depends on a package being installed might run before the package installation rule.

## Solution Implemented
- `runner/ordering.py` module with `order_rules()` function
- Topological sort of rules based on `depends_on` edges
- Cycle detection with clear error messages
- Skip rules whose dependencies failed (transitive)
- `conflicts_with`: warning if both rules are in active set
- `supersedes`: skip superseded rules when superseding rule present

## Features
- Rules executed in dependency order (dependencies run first)
- Circular dependencies detected and abort with error
- Failed dependencies cause dependent rules to skip with clear message
- `conflicts_with` relationships logged as warnings
- `supersedes` relationships cause superseded rules to be skipped

## Design Decisions
- Dependency failures ARE transitive (A depends on B depends on C; C fails → skip A too)
- `conflicts_with` is a warning (not error) since P2-4 semantic conflicts handle errors
- Superseded rules are skipped silently (with INFO log)

## Implementation
- `OrderingResult` dataclass: holds ordered rules, cycles, conflicts, superseded info
- `order_rules()`: topological sort + conflict detection + supersedes handling
- `should_skip_rule()`: check if a rule should skip due to failed dependencies
- `format_ordering_issues()`: format issues for CLI display
- CLI integration: ordering applied after loading, before execution
