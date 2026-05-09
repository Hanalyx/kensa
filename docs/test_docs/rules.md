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

# 5a. Variable substitution end-to-end (Phase 3.5 + embedded-defaults).
# A templated rule without --var or --config-dir:
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules/access-control
# Expected: ALL ~44 rules in access-control/ run (no skip warnings) because the
# embedded built-in defaults supply the ~16 templated rules' variables. Pre-
# embedded-defaults this command produced "16 rule(s) skipped — undefined
# variables".

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

# 5c. Inventory + per-host vars active (Phase 3.7).
# Set up a 1-host inventory and a config-dir with a host file.
cat > /tmp/kensa-test-inv.ini <<EOF
[test]
192.168.1.211 ansible_user=owadmin
EOF
mkdir -p /tmp/kensa-config-inv/hosts
cat > /tmp/kensa-config-inv/hosts/192.168.1.211.yml <<EOF
variables:
  pam_faillock_deny: 3
EOF
./bin/kensa check --inventory /tmp/kensa-test-inv.ini --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    --config-dir /tmp/kensa-config-inv
# Expected: 1 passed (host file's value 3 is applied per host in inventory mode).
# Pre-Phase-3.7 this would have failed because the host file was ignored.

# 5d. Per-host renderer alignment (Phase 3.7 bug fix).
# Put a templated rule alongside an untemplated one in a corpus dir; verify
# both render with correct rule IDs even when the var is host-only.
mkdir -p /tmp/test-corpus-mixed
cp /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml /tmp/test-corpus-mixed/
cp /home/rracine/hanalyx/kensa/rules/access-control/at-access-control.yml /tmp/test-corpus-mixed/
./bin/kensa check --inventory /tmp/kensa-test-inv.ini --no-strict-host-keys --sudo \
    --rules-dir /tmp/test-corpus-mixed \
    --config-dir /tmp/kensa-config-inv 2>&1 | grep -E "pam-faillock-deny|at-access-control"
# Expected: both rules render with their proper IDs.
rm -rf /tmp/test-corpus-mixed /tmp/kensa-config-inv /tmp/kensa-test-inv.ini

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

**Resolution priority** (highest first; 6-tier chain):

| Tier | Source | Phase | Wiring |
|---|---|---|---|
| 1 | CLI `--var KEY=VALUE` | 3.5 | All subcommands (check / remediate) |
| 2 | `<config-dir>/hosts/<hostname>.yml` | 3.6 + 3.7 | Single-host (3.6) + inventory mode (3.7) |
| 3 | `<config-dir>/groups/<group>.yml` | 3.6 + 3.7 | Inventory mode (groups come from the inventory file); single-host has no groups |
| 4 | `<config-dir>/conf.d/*.yml` (alphabetical) | 3.6 | All modes |
| 5 | `<config-dir>/defaults.yml` | 3.5 | All modes |
| 6 | **Embedded built-in defaults** | embedded-defaults | All modes; ships with the binary |

Each later tier overrides earlier on key collision. conf.d files apply alphabetically (later filename wins). Group merges happen in inventory-file order (later in slice wins).

**Embedded defaults (tier 6).** kensa-go ships with a vendored copy of Python kensa's `defaults.yml` `variables:` block, embedded via `go:embed` into the binary. This is the lowest-priority floor — operators get sensible STIG-leaning values for the ~30 templated rules in the corpus without `--var` or `--config-dir`. The values are immutable per binary build; operators override via any higher-priority tier. Source vendored at `internal/varsub/embedded/defaults.yml`; locked against drift by `TestBuiltInDefaults_CoversCorpusVars`.

**`<config-dir>` auto-detect.** When `--config-dir` is empty, kensa picks the first existing path in this chain: `$KENSA_CONFIG_DIR` → `$XDG_CONFIG_HOME/kensa` → `$HOME/.config/kensa` → `/etc/kensa`. An explicit `--config-dir` always wins. Non-existent paths and non-directory paths are skipped. Tested by `TestResolveConfigDir_*`.

**Inventory-mode mechanics (Phase 3.7):** each per-host goroutine in the inventory fan-out resolves its own full 5-tier variable set using the host's address (from the inventory) and group memberships (from `[group]` sections in the inventory file). The corpus is RE-LOADED per host with that host's vars — the substituted values differ per host, but the rule-ID set after filters is identical (filter chain operates on rule metadata, not values). Output rendering uses each host's own resolved rule slice, not the global one — this avoids a misalignment bug when a rule's `{{ var }}` is defined ONLY in `hosts/<addr>.yml` (skipped in the global pre-load, loaded in the per-host pass).

Performance: per-host re-load is bounded at ~0.5ms × N rules × M hosts. For a 539-rule corpus and a 10-host fleet, that's roughly 2.7 seconds — well below the SSH ControlMaster handshake cost it adds to.

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
