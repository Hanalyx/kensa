# Rule authoring

_Applies to: Kensa v0.9.0. Last updated 2026-08-03._

A *rule* is a single, framework-independent statement of desired system state.
It carries its own check logic, its remediation, its framework cross-references,
and one or more capability-gated implementations. You write it once and it
applies across every supported OS version and framework. Rules are YAML, one
file per rule, under `rules/` organized by category.

Rules are *inputs to the transaction engine*. A rule declares *what* state it
wants and *which mechanism* produces it; the engine provides the *how* and the
atomicity *guarantee* (capture → apply → validate → commit-or-rollback). The
rule YAML never expresses capture, validation, or rollback; those are engine
concerns. The canonical rule schema is the authoritative reference; this
chapter is the working subset.

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
(`command_exec`, `manual`, `crypto_policy_subpolicy`, `grub_parameter_set`,
`grub_parameter_remove`); the validator rejects a `transactional: true` rule
that contains one. See
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
  `/etc/login.defs` (`KEY value`); the default delimiter is `=`. Each method
  declares its own required and optional fields; the canonical rule schema
  holds the full method table.
- **`set_compare`** answers "only authorized members are present". It takes
  `observed_command`, run on the host, one member per line of output, and
  `authorized`, normally a list variable. See below.
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

Resolution order, highest priority first: `--var`, then
`hosts/<hostname>.yml`, then `groups/<group>.yml` (inventory mode only, since a
single-host run belongs to no group), then `conf.d/*.yml` in alphabetical order,
then `defaults.yml`, then the values built into the binary.

### Variable types

Every variable Kensa ships a default for has a type, taken from that default.
There is no separate schema to keep in step: the type of `root_umask` is already
visible as a quoted string, and writing it down twice would only give the two
copies a chance to disagree. A variable Kensa has never heard of, such as one
your own rule introduces, is not type checked.

Values are checked when they are read, before any host is contacted.

The case this exists for is a umask. Written unquoted:

```yaml
variables:
  root_umask: 027      # wrong
```

YAML reads the leading zero as octal and hands Kensa the number **23**. Nothing
downstream can tell that apart from someone who meant 23, so the wrong mode gets
written and the rule that checks it agrees with itself. Kensa now refuses the
file and says to quote the value:

```yaml
variables:
  root_umask: '027'    # right
```

Files and the command line are checked differently, because they carry different
information. In a file the quoting is yours and it means something, so the type
is checked as written: a number where a string belongs is an error, and so is a
string where a number belongs. On the command line every value is text, so
`--var pam_faillock_deny=5` cannot be anything but a string; there Kensa checks
that the text is what it claims to be, and rejects `three`, `3.5` or `600s` for a
variable that holds a whole number.

### List variables

A variable can hold a list as well as a single value:

```yaml
variables:
  authorized_local_accounts:
    - owadmin
    - deploybot
```

On the command line, write the members separated by commas:
`--var authorized_local_accounts=owadmin,deploybot`.

Members cannot contain a comma or whitespace, and Kensa rejects the file rather
than accepting one that does. A member holding a comma would split into two
members nobody declared, and a check comparing against that set would answer a
question the operator never asked.

A list is most useful with the `set_compare` check below.

### When a variable is not declared

A rule whose variable no tier defines is **skipped**, and the run says which
variable to declare. It is not treated as empty and it is not guessed. This
matters most for a declared set: there is no honest built-in value for "the
accounts this site authorized", so the rule waits for the operator to say.

## When a check cannot reach a verdict

Some checks depend on a value only the operator can supply: a deadline, an
approved list, a site policy. Without it the check has nothing to judge, and pass,
fail and error are all wrong answers.

A command check can say so by nominating an exit code:

```yaml
check:
  method: command
  not_assessable_exit: 3
  run: |
    max="{{ flaw_remediation_max_days }}"
    if [ -z "$max" ]; then
      echo "no patch deadline is declared."
      exit 3
    fi
    ...
```

The rule is then reported as **skipped**, carrying whatever the check printed as
the reason. It is opt-in: without `not_assessable_exit` every exit code keeps its
usual meaning.

Use it for a missing declaration, not for a broken check. A command that failed
to run is an error and should stay one.

## Comparing a host against a declared set

Some controls are not a threshold or a boolean. They ask whether only the
members a site approved are present: local accounts, sudoers, open ports,
allowed firewall services. Kensa cannot know the approved list, so the operator
declares it and `set_compare` does the comparison:

```yaml
check:
  method: set_compare
  observed_command: "awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd"
  authorized: "{{ authorized_local_accounts }}"
```

Only `observed_command` runs on the host. Both sets are split and compared
inside Kensa, so a member is never re-interpreted by a shell.

What the verdicts mean:

| situation | verdict |
|---|---|
| every observed member is authorized | pass |
| a member is present that is not authorized | fail, naming the member |
| a member is authorized but absent | reported, does not fail |
| nothing observed at all | pass |
| `authorized` is empty | rule skipped, with the reason |
| the variable is not declared anywhere | rule skipped, with the name to declare |

Two of those are deliberate and worth stating plainly.

**An absent member does not fail.** An account that does not exist cannot grant
access, so it is reported for an operator whose list has drifted, not treated as
a finding.

**An empty declared set is a skip, not a pass.** Read one way it makes every
member unauthorized, read the other it makes every member acceptable. Neither is
true. What is true is that nobody has said what is allowed, and a compliance
result must not be invented from that. It is a skip rather than an error because
nothing is broken: a site that has not written its policy yet is a normal state,
not a fault, and the skip carries the name of the variable to declare.

### Matching a member by more than one name

Set `alias_separator` when one thing on the host answers to several names. A
local account is the case: a site may authorize it by user name or by numeric
UID, and both mean the same account.

```yaml
check:
  method: set_compare
  observed_command: "awk -F: '$3 >= 1000 && $3 < 65534 {print $1 \":\" $3}' /etc/passwd"
  authorized: "{{ authorized_local_accounts }}"
  alias_separator: ":"
```

Each observed line becomes one entity with several names, and it is authorized
if **any** of them was declared. Without this, a host emitting both the name and
the UID would report the UID as an unauthorized extra whenever the site had
declared only the name, which is a finding about nothing. The first name on the
line is the one reported, because it is the one an operator recognizes.

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
