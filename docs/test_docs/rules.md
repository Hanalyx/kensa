# Rules — Schema, Parser, Substitution

## Purpose

The rule corpus is the *content* kensa-go executes. Rules are V1 canonical YAML files (`docs/CANONICAL_RULE_SCHEMA_V1.md`) describing what to check and how to remediate. Today's corpus lives at `/home/rracine/hanalyx/kensa/rules` (Python sister repo) — 539 rules covering RHEL 8/9/10 + Ubuntu / Debian.

## Current state

DONE for the V1 schema, parsing, validation, capability gating, framework mapping, and (Phase 3.5) variable substitution.

| Component | Location | State |
|---|---|---|
| Schema definition | `docs/CANONICAL_RULE_SCHEMA_V1.md` | Frozen V1 |
| Parser | `internal/rule/parse.go` | DONE |
| Validator | `internal/rule/validate.go` | DONE |
| Capability gate evaluator | `internal/rule/select.go` | DONE |
| Framework mapper | `internal/mappings/mappings.go` | DONE (CIS / STIG / NIST / PCI / etc.) |
| Variable substitution | `internal/varsub/` | DONE (Phase 3.5) |
| Resolution / dependency | `internal/rule/ordering.go`, `resolve.go` | DONE |
| Conflict / supersedes | `internal/rule/resolve.go` | DONE |

## Verification protocol

```bash
# 1. Validate the entire corpus.
find /home/rracine/hanalyx/kensa/rules -name '*.yml' -print0 | \
    xargs -0 -n 1 ./bin/kensa-validate

# 2. Unit tests for parser, validator, selector, resolver.
go test ./internal/rule/...

# 3. Capability gating — drives different impl selections by host caps.
# A rule with `when: { all: [authselect, pam_faillock] }` should pick the
# authselect impl on a RHEL host with both, and the default fallback elsewhere.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    -x pam_faillock_deny=3
# Capability override:
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    -x pam_faillock_deny=3 -C authselect=false

# 4. Framework filter against the loaded corpus.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -f cis_rhel9
# Expected: ~278 rules (out of 539) mapped to CIS RHEL9 controls.

# 5. Variable substitution end-to-end.
# A templated rule without --var:
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules/access-control
# Expected: stderr aggregated warning "16 rule(s) skipped — undefined variables...",
# followed by the 28 rules that don't use templates.

# 6. Resolve / order / conflicts.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules/access-control \
    --config-dir /tmp/kensa-config 2>&1 | grep -i "conflict\|warning"
# Expected: any rule conflicts surfaced as stderr warnings (e.g.,
# ssh-ciphers-fips conflicts with ssh-crypto-policy).
```

## Schema fields (summary; full schema in CANONICAL_RULE_SCHEMA_V1)

| Field | Required | Validator |
|---|---|---|
| `id` | ✓ | non-empty string, dashes-and-lowercase convention |
| `title` | ✓ | non-empty string |
| `description` | ✓ | non-empty string |
| `rationale` | ✓ | non-empty string |
| `severity` | ✓ | enum critical / high / medium / low |
| `category` | ✓ | non-empty string (free-form vocabulary) |
| `tags` | optional | list of strings |
| `transactional` | optional, default `true` | bool |
| `platforms` | ✓ | non-empty list of `{family, min_version, [max_version, derivatives]}` |
| `implementations` | ✓ | non-empty list; exactly one `default: true` |
| `references` | optional | framework map (CIS / STIG versioned, NIST / PCI flat-list) |
| `depends_on` / `conflicts_with` / `supersedes` | optional | list of rule IDs |

Each implementation:
- `when` (optional capability gate; missing means default impl).
- `check` (single check or `checks: []`).
- `remediation` (single mechanism or `steps: []`).

## Variable substitution (Phase 3.5)

Templates: `{{ name }}` (whitespace-tolerant). Vocabulary `[A-Za-z][A-Za-z0-9_]*`. Substituted at YAML-bytes layer BEFORE decode. Sources: CLI `--var KEY=VALUE` (highest priority) and `<config-dir>/defaults.yml` (fallback).

Affected rules in current corpus (sample): `pam-faillock-deny`, `pam-faillock-unlock-time`, `pam-pwquality-minlen`, `pam-pwquality-difok`, `pam-pwquality-minclass`, `ssh-client-alive-interval`, `ssh-max-auth-tries`, `login-defs-pass-max-days`, `pam-pwhistory-remember`. ~30 rules total use templates.

## Known limits

- **Schema is V1; not versioned.** A V2 schema would require either a `kensa_rule_version: 2` field or a new file extension. No mechanism exists today.
- **Cross-rule consistency is the resolver's job, not the validator's.** kensa-validate validates each rule in isolation; the resolver detects duplicate IDs / cycles / unmet `depends_on` at runtime.
- **Capability vocabulary changes are silent.** Adding a probe to `internal/detect/detect.go` doesn't break old rules referencing it; removing a probe used in `when` clauses would silently fail to match (rule selector returns no impl). No deprecation pipeline.
- **Phase 3.5 substitution is YAML-bytes textual.** A `--var` value containing `:` or `\n` may produce malformed YAML. Corpus uses bare scalars only; non-blocking but worth noting.
- **No per-host / per-group / conf.d variable tiers.** Phase 3.6.
- **No rule versioning or deprecation.** A rule's content can change between releases without a version bump. The `id` is the only stable identifier; operators relying on a specific check.expected value should pin their corpus version, not assume kensa-go's behavior.
- **Framework mapping vocabulary is corpus-driven.** kensa-go's `--framework` flag accepts whatever appears in `mappings.RefsFromReferences()` output — there is no canonical list of "supported frameworks" in code. The corpus IS the vocabulary.
