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

# 5a. Variable substitution end-to-end (Phase 3.5).
# A templated rule without --var:
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules/access-control
# Expected: stderr aggregated warning "16 rule(s) skipped — undefined variables...",
# followed by the 28 rules that don't use templates.

# 5b. Multi-tier resolution (Phase 3.6). Set up a config-dir with all four
# file-based tiers and verify the priority chain end-to-end.
mkdir -p /tmp/kensa-config/{hosts,groups,conf.d}
cat > /tmp/kensa-config/defaults.yml <<EOF
variables:
  pam_faillock_deny: 99
EOF
cat > /tmp/kensa-config/conf.d/10-base.yml <<EOF
variables:
  pam_faillock_deny: 50
EOF
cat > /tmp/kensa-config/hosts/192.168.1.211.yml <<EOF
variables:
  pam_faillock_deny: 3
EOF

# host file should win for single-host scan against 192.168.1.211.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    --config-dir /tmp/kensa-config
# Expected: 1 passed (host file's 3 wins; matches host's actual deny=3).

# CLI --var should win even over host file.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    --config-dir /tmp/kensa-config -x pam_faillock_deny=99
# Expected: 1 failed (CLI's 99 wins; host actually has 3, comparator mismatches).

# 5c. Inventory + per-host warning (Phase 3.6 → 3.7).
./bin/kensa check --inventory inventory.ini --no-strict-host-keys \
    --config-dir /tmp/kensa-config --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical 2>&1 | head -3
# Expected first line: "kensa check: --inventory + hosts/ present in --config-dir;
# per-host/per-group variable files are NOT applied in inventory mode (Phase 3.7 work)"

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

## Variable substitution (Phase 3.5 + 3.6)

Templates: `{{ name }}` (whitespace-tolerant). Vocabulary `[A-Za-z][A-Za-z0-9_]*`. Substituted at YAML-bytes layer BEFORE decode.

**Resolution priority** (highest first; matches Python kensa's 5-tier chain):

| Tier | Source | Phase | Wiring |
|---|---|---|---|
| 1 | CLI `--var KEY=VALUE` | 3.5 | All subcommands (check / remediate) |
| 2 | `<config-dir>/hosts/<hostname>.yml` | 3.6 | Single-host only; inventory mode deferred to Phase 3.7 |
| 3 | `<config-dir>/groups/<group>.yml` | 3.6 | Single-host only (no groups in single-host); inventory mode deferred |
| 4 | `<config-dir>/conf.d/*.yml` (alphabetical) | 3.6 | All modes |
| 5 | `<config-dir>/defaults.yml` | 3.5 | All modes |

Each later tier overrides earlier on key collision. conf.d files apply alphabetically (later filename wins). Group merges happen in inventory-file order (later in slice wins).

**Inventory mode limitation (Phase 3.6 → 3.7):** the corpus is loaded once before the per-host fan-out, so per-host (`hosts/<host>.yml`) and per-group (`groups/<g>.yml`) variables are NOT applied per-host in inventory mode. They apply only in single-host mode where the host name is known at flag-parse time. When operators run `kensa check --inventory ... --config-dir DIR` with a `DIR/hosts/` or `DIR/groups/` subdirectory, kensa emits a one-line stderr warning so the omission isn't silent. Phase 3.7 will rewire inventory mode to re-load the corpus per host with that host's full 5-tier resolution.

**Affected rules in current corpus (sample):** `pam-faillock-deny`, `pam-faillock-unlock-time`, `pam-pwquality-minlen`, `pam-pwquality-difok`, `pam-pwquality-minclass`, `ssh-client-alive-interval`, `ssh-max-auth-tries`, `login-defs-pass-max-days`, `pam-pwhistory-remember`. ~30 rules total use templates.

**Validation:** every tier source applies the same vocabulary check. A `hosts/web-01.yml` with `has-dash: 5` rejects with "KEY must match [A-Za-z][A-Za-z0-9_]*" before any rule loads. Malformed YAML in any tier produces a usage error naming the file path.

## Known limits

- **Schema is V1; not versioned.** A V2 schema would require either a `kensa_rule_version: 2` field or a new file extension. No mechanism exists today.
- **Cross-rule consistency is the resolver's job, not the validator's.** kensa-validate validates each rule in isolation; the resolver detects duplicate IDs / cycles / unmet `depends_on` at runtime.
- **Capability vocabulary changes are silent.** Adding a probe to `internal/detect/detect.go` doesn't break old rules referencing it; removing a probe used in `when` clauses would silently fail to match (rule selector returns no impl). No deprecation pipeline.
- **Phase 3.5 substitution is YAML-bytes textual.** A `--var` value containing `:` or `\n` may produce malformed YAML. Corpus uses bare scalars only; non-blocking but worth noting.
- **No per-host / per-group / conf.d variable tiers.** Phase 3.6.
- **No rule versioning or deprecation.** A rule's content can change between releases without a version bump. The `id` is the only stable identifier; operators relying on a specific check.expected value should pin their corpus version, not assume kensa-go's behavior.
- **Framework mapping vocabulary is corpus-driven.** kensa-go's `--framework` flag accepts whatever appears in `mappings.RefsFromReferences()` output — there is no canonical list of "supported frameworks" in code. The corpus IS the vocabulary.
