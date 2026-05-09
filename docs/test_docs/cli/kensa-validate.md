# `kensa-validate`

## Purpose

Static validator for rule YAML files and Specter spec YAML files. Used by:
- Rule authors: catch schema violations before checkin (CI gate).
- CI: ensure no broken rule slips into the corpus.
- Spec authors: confirm a new spec file passes Tier-1 structural checks.

## Current state

DONE for the V1 canonical rule schema (`docs/CANONICAL_RULE_SCHEMA_V1.md`). Validates required fields, severity enum, category presence, transactional consistency, capability gate shapes (single / all / any / not), implementation defaults, framework reference shapes (CIS versioned, NIST flat-list, STIG versioned), platform constraints.

Specter spec validation is delegated to the Specter binary via `specter check`; kensa-validate's spec mode is a thin wrapper.

## Flags

| Flag | Status |
|---|---|
| `-h, --help` | DONE |

## Verification protocol

```bash
# 1. Help text.
./bin/kensa-validate --help

# 2. Validate a single rule.
./bin/kensa-validate /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml

# 3. Validate the entire corpus.
find /home/rracine/hanalyx/kensa/rules -name '*.yml' -print0 | \
    xargs -0 -n 1 ./bin/kensa-validate

# Expected: each line either "OK <path>" or a per-error report. Exit non-zero on any failure.

# 4. Validate Specter specs.
export PATH="/home/rracine/.specter/bin:$PATH"
specter check --strict
```

## Known limits

- **Schema-only.** kensa-validate does NOT execute the rule against a host or interpret variable templates — it just confirms the YAML structure is well-formed. A rule that passes kensa-validate can still fail at runtime (e.g., its check.expected references a variable that's never defined; the comparator fails when that rule is run, not when it's validated).
- **No `--var` / `--config-dir` integration.** kensa-validate doesn't run the substitution layer, so a rule with `{{ undefined_var }}` is "valid" structurally even though running it without --var would skip-or-fail. This mirrors the Python validator's separation of concerns.
- **Rule-corpus-level checks not implemented.** A duplicate rule ID across two files would be caught at runtime by `rule.Resolve`, not by kensa-validate. Cross-file consistency is the resolver's job.
- **Specter coverage strict mode not enabled.** Per CLAUDE.md: every `@spec`/`@ac` annotation is currently a source comment, not a runner-visible test surface. Turning `specter coverage --strict` on today would demote every annotated AC. Migration to Convention A or B test naming is queued; until then, `specter check --strict` covers structural validation and `specter sync` covers the dependency graph but not test-outcome coverage.
