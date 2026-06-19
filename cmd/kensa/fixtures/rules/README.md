# Rule behavior fixtures

Each `<rule-id>.yaml` defines good/bad/edge cases for a file-based rule's
check. The harness (`rule_behavior_harness_test.go`) writes each case's
`content` to a temp file, points the rule's `method` + resolved `params` at
it (injecting `path`), runs the real check engine over a no-sudo local
transport, and asserts `want` (pass|fail).

Add a fixture when you add or fix a file-based rule. The coverage ratchet
(`coveredRulesFloor`) may only be raised, never lowered.

Fields: `rule` (corpus id, traceability), `method`, `params` (resolved —
no `path`; the harness injects it), `cases[]` ({name, content, want}).
