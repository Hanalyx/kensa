# Rule authoring

_Applies to: Kensa v0.6.0 — last updated 2026-06-22._

A *rule* is a single, framework-independent statement of desired system state.
It carries its own check logic, its remediation, its framework cross-references,
and one or more capability-gated implementations. You write it once and it
applies across every supported OS version and framework. Rules are YAML, one
file per rule, under `rules/` organized by category.

Rules are *inputs to the transaction engine*. A rule declares *what* state it
wants and *which mechanism* produces it; the engine provides the *how* and the
atomicity *guarantee* (capture → apply → validate → commit-or-rollback). The
rule YAML never expresses capture, validation, or rollback; those are engine
concerns. The authoritative schema is
[`CANONICAL_RULE_SCHEMA_V1.md`](../foundation_docs/CANONICAL_RULE_SCHEMA_V1.md);
this chapter is the working subset.

## A complete rule

This is the canonical "disable SSH root login" rule. It shows every field you
reach for most of the time:

```yaml
id: ssh-disable-root-login          # unique, kebab-case, stable forever
title: Disable SSH root login        # imperative, max 100 chars
description: >                        # 2–4 sentences: what it enforces and why
  Direct root login over SSH is disabled so that administrators authenticate
  as themselves and escalate explicitly.
rationale: >                         # security justification
  Permitting root login removes individual accountability and exposes the most
  privileged account to remote password and key attacks.
severity: high                       # critical | high | medium | low
category: access-control             # must match a rules/ subdirectory
tags: [ssh, authentication, cis]     # free-form classification labels

references:                          # framework cross-references (all optional)
  cis:
    rhel9: { section: "5.2.7", level: "L1", type: "Automated" }
  stig:
    rhel9: { vuln_id: "V-257947", severity: "CAT II", cci: ["CCI-000770"] }
  nist_800_53: ["AC-6(2)", "IA-2(5)"]

platforms:                           # which OS families/versions this targets
  - family: rhel
    min_version: 8                   # inclusive; omit max_version for open-ended

implementations:                     # one or more check + remediation variants
  - when: sshd_config_d              # capability gate (optional)
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "PermitRootLogin"
      expected: "no"
      scan_pattern: "*.conf"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-kensa-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"
  - default: true                    # exactly one implementation must be default
    check:
      method: config_value
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      expected: "no"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"
```

## Metadata and classification

`id`, `title`, `description`, `rationale`, and `severity` are required. The
`id` is stable for the life of the rule. Once assigned it never changes and is
never reused. `category` must match one of the directory names under `rules/`
(`access-control`, `audit`, `filesystem`, `kernel`, `logging`, `network`,
`services`, `system`), and `tags` is a free-form list for filtering
(`kensa check -t cis`, `-c access-control`).

## `transactional`

`transactional` is optional and defaults to `true`. Leave it at the default
when every step in every implementation uses a *capturable* mechanism; the
engine can then run the rule atomically and roll it back. You **must** set
`transactional: false` when any step uses a non-capturable mechanism
(`command_exec`, `manual`, `grub_parameter_set`, `grub_parameter_remove`); the
validator rejects a `transactional: true` rule that contains one. See
[Mechanisms reference](10-mechanisms.md) for which mechanisms are capturable.

## `references`: framework mappings

`references` maps the rule to external framework identifiers and is what
`--framework` and `--control` filter on. `cis` and `stig` are objects keyed by
`{os}{version}` (they carry version-specific section / vuln-id metadata). The
remaining frameworks (`nist_800_53`, `pci_dss_4`, `iso27001_2022`, `cmmc_l2`,
`hipaa`, `srg`) are flat lists of control IDs because those identifiers are
stable across OS versions.

## `platforms`: scope

Each entry has a required `family` and `min_version`, with optional
`max_version` (inclusive) and `derivatives` (defaults `true`). A rule with no
`platforms` block runs everywhere; a rule scoped to `rhel min_version: 9`
renders `SKIP` on RHEL 8 and is never remediated there (see
[Troubleshooting](08-troubleshooting.md) on out-of-platform skips).

## `implementations`: checks and remediations

Implementations are evaluated top to bottom; the first whose `when` capability
gate the host satisfies is selected, so order the specific variants before the
`default: true` fallback. **Exactly one** implementation must be `default: true`.

`when` may be a single capability, or `all:` / `any:` / `not:` over a list:

```yaml
when: sshd_config_d                      # single capability
when: { all: [authselect, pam_faillock] }
when: { any: [crypto_policy_modules, fips_mode] }
when: { not: systemd_resolved }
```

Each implementation has a `check` and a `remediation`:

- **`check.method`** is a read-only verb: `config_value`, `sysctl_value`,
  `package_state`, `file_exists`, `service_state`, `audit_rule_exists`,
  `mount_option`, `command` (escape hatch), and others. Each method declares its
  required fields; for example `config_value` needs `path`, `key`, and
  `expected`, and takes an optional `comparator` (`==`, `!=`, `<`, `<=`, `>`,
  `>=`; use `<=`/`>=` for thresholds like `PASS_MAX_DAYS <= 365`) and
  `delimiter`. Set `delimiter: " "` for whitespace-separated files such as
  `/etc/login.defs` (`KEY value`); the default delimiter is `=`. The full method
  table is schema §3.5.3.
- **`remediation.mechanism`** names the action that produces the desired state,
  plus that mechanism's fields. See the [Mechanisms reference](10-mechanisms.md)
  for the complete catalog, where each mechanism runs, and what reversal you get.

For ordered remediations use a `steps:` list instead of a single `mechanism`;
the engine captures pre-state for every step before any runs, and rolls back all
prior successful steps in reverse order if a later step fails.

## Variables and `{{ var }}` substitution

Site-specific values are templated with `{{ var }}` and substituted before the
rule is parsed. For example, a remote-logging rule writes
`value: "@@{{ rsyslog_remote_server }}"`. Supply values with `--var
KEY=VALUE` (repeatable) or from a `defaults.yml` in `--config-dir`; `--var`
wins over `defaults.yml`. A variable value is spliced literally into the rule
YAML and may flow into shell commands run by handlers, so pass only trusted
input.

## `depends_on` and relationships

`depends_on` lists rule IDs that must be satisfied first (for example, a
firewall-backend rule `depends_on: [service-enable-firewalld]`).
`conflicts_with` marks mutually exclusive rules and `supersedes` records rule
IDs this one replaces. All three are optional ID lists.

## Validate before you commit

Every rule must pass the validator before it enters the corpus. Run it over the
whole tree:

```bash
./bin/kensa-validate --rules-dir rules
```

A clean corpus reports `0 error(s)` (the sole expected warning is a stylistic
W005 on `selinux-policy-targeted.yml`). Any `FAIL` line names the file, the rule
ID, and the violated constraint, for example `exactly one implementation must
have default:true` if you forgot the fallback, or a `transactional: true` rule
that contains a non-capturable mechanism. Fix every error before opening a PR;
CI runs the same gate.

## Next

[07-integration](07-integration.md) covers consuming scan results downstream;
[08-troubleshooting](08-troubleshooting.md) covers what to do when a scan or
remediation does not behave as a rule expects.
