# P2: Dependency Ordering

## Status: Scoping

## Problem
Rules can declare `depends_on`, `conflicts_with`, and `supersedes` relationships. V0 ignores these — rules run in filesystem sort order. This means a rule that depends on a package being installed might run before the package installation rule.

## Scope
- Build a topological sort of rules based on `depends_on` edges
- Detect and report circular dependencies
- Skip rules whose dependencies failed (instead of running them and getting confusing errors)
- `conflicts_with`: warn if both rules are in the active set
- `supersedes`: if rule A supersedes rule B, skip B when A is present

## Open Questions
- Should dependency failures be transitive? (A depends on B depends on C; C fails → skip A too?)
- Should `conflicts_with` be a hard error or a warning?
