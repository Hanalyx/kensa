# `kensa check`

## Purpose

Read-only compliance scan against one host or an Ansible-style inventory. Loads rules from a directory, file list, or both; filters by severity / tag / category / framework / control; renders results as text, JSON, JSONL, CSV, PDF, OSCAL, evidence, or markdown.

## Current state

DONE through Phase 3.5. The richest subcommand by flag count (~22 user-facing flags). Inventory mode fans out via the C-029 bounded goroutine pool. Variable substitution (Phase 3.5) makes the ~30 corpus rules using `{{ var }}` templates actually work.

## Flags

### Target options

| Flag | Status | Note |
|---|---|---|
| `-H, --host` | DONE | Required if `--inventory` not set |
| `-u, --user` | DONE | |
| `-k, --key` | DONE | |
| `-p, --password` | DONE (C-026) | Rejected with `--inventory` (per-host passwords differ) |
| `-P, --port` | DONE | |
| `--sudo` | DONE | |
| `--strict-host-keys` / `--no-strict-host-keys` | DONE (C-027) | Mutex; under strict, `UpdateHostKeys=no` |
| `-C, --capability` | DONE (C-028) | Repeatable, vocab-validated |
| `-i, --inventory` | DONE (C-024) | Ansible inventory.ini |
| `-l, --limit` | DONE (C-025) | Glob/group filter; supports `!` exclusion |
| `-w, --workers` | DONE (C-029) | 1-50, default 1; bounded goroutine pool |

### Rule options

| Flag | Status | Note |
|---|---|---|
| `-r, --rules-dir` | DONE | Directory walk; skip-invalid on parse error |
| `--rule` | DONE (C-037) | Single-file load (long-only). Strict loading. Additive with --rules-dir |
| `-s, --severity` | DONE (C-030) | Repeatable, choice: critical/high/medium/low |
| `-t, --tag` | DONE (C-031) | Repeatable, free-form, OR semantics |
| `-c, --category` | DONE (C-032) | Single-value, exact match (NOT repeatable like -s/-t) |
| `-f, --framework` | DONE (C-033) | e.g. `cis-rhel9` (hyphen ↔ underscore) |
| `--control` | DONE (C-035) | Repeatable `FRAMEWORK:CONTROL` (long-only — `-c` is taken) |
| `-x, --var` | DONE (Phase 3.5) | Repeatable KEY=VALUE; highest tier in 5-tier chain |
| `--config-dir` | DONE (Phase 3.5/3.6/3.7) | Loads `defaults.yml` + `conf.d/*.yml` + `hosts/<host>.yml` + `groups/<g>.yml`. Full 5-tier active in BOTH single-host and inventory modes (Phase 3.7). Long-only. |

### Output options

| Flag | Status | Note |
|---|---|---|
| `--format` | DEPRECATED | Use `-o` |
| `-o, --output` | DONE (C-019) | Repeatable; FORMAT[:PATH] |
| `-q, --quiet` | DONE | Suppresses default body |
| `-v, --verbose` | DONE (C-022) | Expands the compacted PASSED list |

Filter chain order (matters for empty-after-filter diagnostics):
**severity → tag → category → framework → control**. Each stage's empty-after-filter error includes the upstream rule count for chain disambiguation.

## Verification protocol

```bash
# 1. Help text grouped (C-038).
./bin/kensa check --help    # expect "Target options:", "Rule options:", "Output options:", "General:" sections

# 2. Negative-path validation matrix (no network).
./bin/kensa check -H foo -s bogus --rules-dir /tmp                   # exit 2
./bin/kensa check -H foo -t '' --rules-dir /tmp                       # exit 2 (empty tag dropped silently OK; bare invocation requires more)
./bin/kensa check -H foo -f cis_typo --rules-dir /home/rracine/hanalyx/kensa/rules  # exit 2 (lists available frameworks)
./bin/kensa check -H foo --control no-colon --rules-dir /home/rracine/hanalyx/kensa/rules  # exit 2
./bin/kensa check -H foo --workers 51 --rules-dir /tmp               # exit 2 (rationale: kensa as fork-bomb)
./bin/kensa check -H foo --strict-host-keys --no-strict-host-keys --rules-dir /tmp  # exit 2 (mutex)
./bin/kensa check -H foo -x bare_key --rules-dir /tmp                # exit 2 (missing '=')
./bin/kensa check --inventory hosts.ini -p secret --rules-dir /tmp   # exit 2 (--password + --inventory rejected)

# 3. Live single-host scan, full corpus.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules

# 4. Filter chain — combine severity + tag + framework.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical -s high -t pci -f cis-rhel9

# 5a. Variable substitution end-to-end (Phase 3.5).
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    -x pam_faillock_deny=3
# Expected: 1 passed, 0 failed (substitution succeeded; comparator matched).

# 5b. 5-tier resolution (Phase 3.6) for single-host mode.
# See docs/test_docs/rules.md for the full tier-priority verification.
# Quick check: with hosts/<host>.yml setting pam_faillock_deny=3,
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    --config-dir /tmp/kensa-config
# Expected: 1 passed (host file wins for single-host).

# 6. Inventory mode with bounded fan-out.
./bin/kensa check --inventory inventory.ini --no-strict-host-keys -w 4 \
    --rules-dir /home/rracine/hanalyx/kensa/rules

# 7. Output formats.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -o json -o csv:/tmp/results.csv -o evidence:/tmp/evidence.json
```

## Known limits

- **Inventory + `--password` is rejected.** Per-host passwords differ; broadcasting one is a footgun. Operators with shared credentials should set `SSHPASS` env.
- **Inventory + per-host file outputs (`-o csv:PATH`) is rejected.** The C-019 data-loss guard: a file output would be overwritten per-host. Use stdout sinks or one-host-per-file scripts.
- **Substitution is at YAML-bytes level.** A `--var` value containing `:` or `\n` may produce malformed YAML for the downstream decoder. The corpus uses bare scalar values exclusively; non-blocking. Spec AC-23 documents the trade-off.
- **Inventory mode re-parses the corpus per host.** Phase 3.7 makes per-host vars work in inventory by re-loading rules per host with that host's full 5-tier resolved variables. Performance budget: ~0.5ms × N rules × M hosts (~2.7s added for a 539-rule corpus and 10-host fleet). Above 100 hosts, future caching may be warranted; flag if real-world scans report slowdowns.
- **Conflict-resolution warnings are stderr-only.** The C-021 conflict resolver detects rules that conflict (e.g., `ssh-ciphers-fips` vs `ssh-crypto-policy`); both currently emit warnings and run anyway. A future deliverable may add `--allow-conflicts` strict mode.
- **No streaming output.** Inventory results are collected then rendered. A 100-host fleet pays the latency penalty before any output appears.
