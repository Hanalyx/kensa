# 09 · Command reference

_Applies to: Kensa v0.7.0 — last updated 2026-06-28._

This chapter documents every `kensa` command and flag. It is the
exhaustive counterpart to the task-focused chapters: for *how* to scan
and remediate, see [04-scan-and-remediate](04-scan-and-remediate.md);
for rollback and the transaction log, see
[05-rollback-and-history](05-rollback-and-history.md); for the mechanism
catalog a rule's remediation can name, see
[10-mechanisms](10-mechanisms.md).

Every flag below is taken verbatim from `kensa <command> --help`. Run
that yourself any time for the authoritative form on your installed
version.

## Invocation

```
kensa [global flags] <command> [flags]
```

| Command | Purpose |
|---|---|
| `detect` | Probe a host and print its capability set |
| `check` | Run read-only compliance checks (no apply) |
| `remediate` | Apply failing rules to a host |
| `rollback` | Roll back a past transaction by ID |
| `recover` | Compensate transactions interrupted before a terminal status |
| `history` | Query the transaction log |
| `plan` | Preview a rule transaction without executing |
| `mechanisms` | List registered handler mechanisms |
| `coverage` | Alias for `mechanisms` today; reports framework control coverage with `--framework` |
| `list` | Introspection commands (`kensa list frameworks`, `kensa list sessions`) |
| `info` | Rule/control lookup—multi-criteria search over the corpus |
| `diff` | Compare two stored sessions and emit per-rule drift |
| `verify` | Validate the Ed25519 signature on an evidence-envelope JSON file |
| `migrate` | Apply pending schema migrations and backfill legacy sessions |
| `version` | Print version and exit |
| `agent` | Run kensa as a stdio agent on the target host (internal; see below) |

### Global flags

These apply to `kensa` itself, before the subcommand.

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| `-V` | `--version` | | | Print version and exit |
| `-D` | `--db` | `PATH` | `.kensa/results.db` | SQLite transaction-log path |

Run `kensa <command> --help` for a subcommand's own flags.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (also `--help` / `--version`) |
| `1` | Runtime error |
| `2` | Usage error (bad flag, unknown subcommand, missing required arg) |

`verify` overloads exit `1` to mean *signature INVALID* (tampered,
wrong key, or missing key); see [verify](#verify) for the full table.

### Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `KENSA_SUDO_PASSWORD` | `detect`, `check`, `remediate`, `rollback`, `recover`, `plan` | Sudo password for non-NOPASSWD hosts, as an alternative to `--sudo-password`. Never placed in argv or recorded evidence. |
| `KENSA_NO_AGENT` | `remediate` | Set to `1` to disable agent mode and fall back to shell-best-effort for the kernel-atomic file handlers. |
| `KENSA_SIGNING_KEY` | `remediate` | Path to the Ed25519 `.priv` file for a stable signer identity; without it an ephemeral key is generated per process (see [01-install](01-install.md)). |
| `KENSA_CONFIG_DIR`, `XDG_CONFIG_HOME`, `HOME` | `verify` | Resolve the default trust directory for public keys (in that priority order). |

## Common option groups

Several commands share the same target, rule, and output option groups.
They are defined once here and referenced by each command.

### Target options

For commands that connect to a host over SSH.

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-H` | `--host` | `string` | | Target hostname (required unless noted) |
| `-u` | `--user` | `string` | current user | SSH user |
| `-k` | `--key` | `string` | | SSH private key path |
| `-p` | `--password` | `string[="<prompt>"]` | | SSH password; omit the value for a TTY prompt. The literal `<prompt>` is reserved. |
| `-P` | `--port` | `int` | `22` | SSH port |
| | `--sudo` | | | Wrap commands in sudo |
| | `--sudo-password` | `string[="<prompt>"]` | | Sudo password for non-NOPASSWD hosts; omit the value for a TTY prompt, or set `KENSA_SUDO_PASSWORD`. Requires `--sudo`. |
| | `--strict-host-keys` | | | Verify SSH host keys; reject unknown (overrides `--no-strict-host-keys`) |
| | `--no-strict-host-keys` | | default today | Trust on first use (explicit form for a future config-file override) |
| `-C` | `--capability` | `stringArray` | | Override a detected capability `KEY=VALUE`; repeatable (for example `-C apparmor=true -C selinux=false`). On duplicate keys, last value wins. |

Sudo behaviour (passwordless vs. password, the stdin mechanism, and the
fail-fast probe) is covered in [04-scan-and-remediate](04-scan-and-remediate.md).
Not every command exposes every row: `rollback` and `recover` omit
`-p/--password`, and `recover` omits `-C/--capability`. Each command's
section lists exactly what it carries.

### Rule options

For commands that load and filter the rule corpus (`check`, `remediate`).

| Short | Long | Argument | Meaning |
|---|---|---|---|
| `-r` | `--rules-dir` | `string` | Directory to scan for `*.yml` rule files |
| | `--rule` | `stringArray` | Load a single rule YAML file (strict—parse errors fail the command); long-only, repeatable, additive with `--rules-dir` and positional `*.yml` args |
| `-s` | `--severity` | `stringArray` | Filter by severity, repeatable (`-s critical -s high`); choices: `critical\|high\|medium\|low` |
| `-t` | `--tag` | `stringArray` | Filter by tag, repeatable; matches rules whose `tags:` array contains any value |
| `-c` | `--category` | `string` | Filter by category (`-c access-control`); single value, NOT repeatable (later `-c` overrides earlier) |
| `-f` | `--framework` | `cis-rhel9` | Filter to rules mapping a control under FRAMEWORK; single value. Hyphen and underscore interchangeable (`-f cis-rhel9 == -f cis_rhel9`). |
| | `--control` | `stringArray` | Filter by `FRAMEWORK:CONTROL` (`--control cis-rhel9:5.1.12`); repeatable, OR across values; framework portion accepts hyphen or underscore |
| `-x` | `--var` | `stringArray` | Override a rule variable, `KEY=VALUE`; repeatable. Wins over `--config-dir`/`defaults.yml`. **VALUE is spliced literally into rule YAML and may reach shell commands. Pass only trusted input.** |
| | `--config-dir` | `string` | Directory holding `defaults.yml` (variable defaults source). Only `defaults.yml` is read today. |

Positional `rule.yml ...` arguments are additive with `--rules-dir` and
`--rule`. Default-path resolution when no rules are specified is covered
in [06-rule-authoring](06-rule-authoring.md) and the chapter on install
(`/usr/share/kensa/rules`).

### Output options

Most commands take a subset of these.

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| | `--format` | `string` | `table` / `text` | Output format; the exact choices vary per command (see each section). Deprecated on the host commands in favour of `--output`. |
| `-o` | `--output` | `strings` | | Output destination `FORMAT[:PATH]`, repeatable (for example `-o json -o csv:results.csv`) |
| `-q` | `--quiet` | | | Suppress default output (errors still go to stderr) |
| `-v` | `--verbose` | | | (`check` only) Expand the compacted PASSED list; text format only |

`FORMAT` for `-o/--output` is one of `json`, `jsonl`, `csv`, `pdf`,
`evidence`, or `oscal`. `pdf` requires a `:PATH` destination (binary
output has no stdout form). Which formats each of `check` and
`remediate` accepts, and what each document contains, is covered in
[04-scan-and-remediate](04-scan-and-remediate.md) § Formats by command.

---

## detect

Probe a host and print its capability set. Read-only; no mutations.

```
kensa detect [flags]
```

Carries the full [target options](#target-options) group (`-H` required).

**Output options:**

| Long | Argument | Default | Meaning |
|---|---|---|---|
| `--format` | `string` | `table` | Output format: `table` or `json` (deprecated; use `--output`) |
| `-o, --output` | `strings` | | Output destination `FORMAT[:PATH]`, repeatable |
| `-q, --quiet` | | | Suppress default output |

```bash
kensa detect -H 192.168.1.211 -u owadmin --sudo
kensa detect --host web-01 --user admin --format json
```

## check

Run read-only compliance checks against one host or an inventory. See
[04-scan-and-remediate](04-scan-and-remediate.md) for the workflow.

```
kensa check [flags] [rule.yml ...]
```

Carries the full [target options](#target-options) group (`-H` required
unless `--inventory` is given) plus the inventory flags below, the full
[rule options](#rule-options) group, and the output options.

**Inventory options (additional target options):**

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-i` | `--inventory` | `string` | | Ansible-style `inventory.ini` for multi-host check |
| `-l` | `--limit` | `string` | | Limit inventory hosts to a glob/group pattern (ansible `--limit` semantics) |
| `-w` | `--workers` | `int` | `1` | Concurrent SSH connections in `--inventory` mode (1–50; 1 = sequential) |

**Output options:**

| Long | Argument | Default | Meaning |
|---|---|---|---|
| `--format` | `string` | `table` | `table`, `json`, or `jsonl` (deprecated; use `--output`) |
| `-o, --output` | `strings` | | Output destination `FORMAT[:PATH]`, repeatable |
| `-q, --quiet` | | | Suppress default output |
| `-v, --verbose` | | | Expand the compacted PASSED list (text format only) |

**Other options:**

| Long | Default | Meaning |
|---|---|---|
| `--store` | off | Persist the scan as a session + transactions record in the SQLite store (`check` is read-only by default) |

```bash
kensa check -H 192.168.1.211 -u owadmin --sudo -r /path/to/rules
kensa check --inventory hosts.ini -w 10 --sudo -r /path/to/rules
kensa check -H 192.168.1.211 -s critical -s high -r /path/to/rules
kensa check -H 192.168.1.211 -f cis-rhel9 --control cis_rhel9:5.1.12 -r /path/to/rules
kensa check -H web-01 -u admin --sudo -o jsonl rule1.yml rule2.yml
```

## remediate

Apply failing rules to a host. Each rule runs as a four-phase atomic
transaction; on validation failure the engine rolls back to the captured
pre-state. See [04-scan-and-remediate](04-scan-and-remediate.md).

```
kensa remediate [flags] [rule.yml ...]
```

Carries the full [target options](#target-options) group (`-H`
required), the full [rule options](#rule-options) group, and the output
options below.

**Output options:**

| Long | Argument | Default | Meaning |
|---|---|---|---|
| `--format` | `string` | `table` | `table` or `json` (deprecated; use `--output`) |
| `-o, --output` | `strings` | | Output destination `FORMAT[:PATH]`, repeatable |
| `--oscal` | `string` | | Write Open Security Controls Assessment Language (OSCAL) Assessment Results to this file (deprecated; use `--output oscal:PATH`) |
| `-q, --quiet` | | | Suppress default output |

Set `KENSA_NO_AGENT=1` to disable agent mode and fall back to
shell-best-effort for the kernel-atomic file handlers. Set
`KENSA_SIGNING_KEY` for a stable evidence-signer identity.

```bash
kensa remediate -H 192.168.1.211 -u owadmin --sudo -r /path/to/rules
kensa remediate -H 192.168.1.211 -s critical -t pci -r /path/to/rules
kensa remediate -H 192.168.1.211 -f cis-rhel9 --control cis_rhel9:5.1.12 -r /path/to/rules
kensa remediate -H web-01 -u admin --sudo -o json -o oscal:/tmp/results.oscal.json
```

## rollback

Roll back transactions using captured pre-state. Pick exactly one mode.
See [05-rollback-and-history](05-rollback-and-history.md).

```
kensa rollback [MODE] [flags]
```

**Mode (pick one):**

| Short | Long | Argument | Meaning |
|---|---|---|---|
| | `--list` | | List rollback-able sessions (read-only) |
| | `--info` | `SESSION_ID` | Show session detail (txns + statuses) |
| | `--start` | `SESSION_ID` | Execute rollback for every committed transaction in the session (needs `--host`) |
| `-T` | `--txn` | `TXN_UUID` | Legacy: single-transaction rollback (needs `--host`) |
| | `--detail` | | Modifier: per-step breakdown that composes with `--list` and `--info` (not `--start` or `--txn`) |

Find session UUIDs first with `kensa list sessions`.

**Target options** (required for `--start` and `--txn`): `-H, --host`
(required for those modes), `-u, --user`, `-k, --key`, `-P, --port`,
`--sudo`, `--sudo-password`, `--strict-host-keys`,
`--no-strict-host-keys`. This command does **not** carry `-p/--password`
or `-C/--capability`.

**Output options:**

| Long | Argument | Default | Meaning |
|---|---|---|---|
| `--format` | `string` | `text` | Output format: `text` or `json` |
| `-q, --quiet` | | | Suppress default output |

```bash
kensa rollback --list
kensa rollback --info 8c3a1e2b-... --detail
kensa rollback --start 8c3a1e2b-... -H 192.168.1.211 -u owadmin --sudo
kensa rollback --txn 9d4b... -H 192.168.1.211 -u owadmin --sudo   # legacy
```

## recover

Compensate transactions interrupted before they reached a terminal
status, using the durable crash-recovery journal. Each open transaction
is rolled back from its captured pre-state and recorded as recovered.
Holds an exclusive recover lock, so it never races a live kensa on the
same store. Run it after a crash, when no live kensa is operating the
host. See [05-rollback-and-history](05-rollback-and-history.md) and the
crash-recovery note in [10-mechanisms](10-mechanisms.md).

```
kensa recover [flags]
```

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-H` | `--host` | `string` | | Scope recovery to this host (also the SSH target; required) |
| `-u` | `--user` | `string` | current user | SSH user |
| `-P` | `--port` | `int` | `22` | SSH port |
| | `--key` | `string` | | SSH private key path |
| | `--sudo` | | | Wrap commands in sudo |
| | `--sudo-password` | `string` | | Sudo password for non-NOPASSWD hosts |
| | `--strict-host-keys` | | | Verify SSH host keys; reject unknown |
| `-q` | `--quiet` | | | Suppress default output |
| `-D` | `--db` | `string` | `.kensa/results.db` | SQLite transaction-log path |

## history

Query the transaction log. Without filters, lists recent transactions.
See [05-rollback-and-history](05-rollback-and-history.md).

```
kensa history [flags]
```

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| `-H` | `--host` | `string` | | Filter by host ID |
| `-R` | `--rule` | `string` | | Filter by rule ID |
| `-S` | `--since` | `string` | | Filter since a duration (for example `24h`) or RFC3339 time |
| `-n` | `--limit` | `int` | `50` | Maximum rows to return |
| | `--format` | `string` | `table` | `table`, `json`, or `jsonl` (jsonl is transaction-list only) |
| `-T` | `--txn` | `string` | | Get a single transaction by UUID |
| `-a` | `--aggregate` | `string` | | Aggregate key: `by_host`, `by_rule`, `by_framework_control` |
| | `--stats` | | | Print summary stats (sessions, transactions, by status / severity / host) and exit |
| | `--prune` | `int` | | Delete sessions and cascade older than N days (destructive; long-only) |
| | `--force` | | | Skip the confirmation prompt for `--prune` (required in non-interactive runs) |
| `-q` | `--quiet` | | | Suppress default output |

```bash
kensa history                                  # 50 most recent
kensa history -n 200 --format jsonl | jq -c .  # streamable JSON Lines
kensa history -H 192.168.1.211 -S 24h          # one host, last 24h
kensa history -a by_host -S 7d                 # 7-day posture per host
kensa history --prune 30 --force               # non-interactive prune
```

## plan

Preview a rule transaction without executing it. Returns a structured
plan with captured pre-state, apply steps, validators, rollback plan,
and warnings.

```
kensa plan [flags] rule.yml
```

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| `-H` | `--host` | `string` | | Target hostname (required) |
| `-u` | `--user` | `string` | current user | SSH user |
| `-P` | `--port` | `int` | `22` | SSH port |
| `-k` | `--key` | `string` | | SSH private key path |
| `-p` | `--password` | `string[="<prompt>"]` | | SSH password; omit value for a TTY prompt |
| | `--strict-host-keys` | | | Verify SSH host keys; reject unknown |
| | `--no-strict-host-keys` | | default today | Trust on first use |
| | `--sudo` | | | Wrap commands in sudo |
| | `--sudo-password` | `string[="<prompt>"]` | | Sudo password for non-NOPASSWD hosts; requires `--sudo` |
| | `--format` | `string` | `text` | Output format: `text`, `markdown`, `json`, `plain` |
| `-q` | `--quiet` | | | Suppress default output |

```bash
kensa plan -H 192.168.1.211 -u owadmin --sudo --format markdown rule.yml
```

## mechanisms

List every handler mechanism registered with the kensa engine, marked
capturable (participates in atomic transactions) or non-capturable
(`transactional: false` escape hatch). See [10-mechanisms](10-mechanisms.md)
for the catalog and reversal levels.

```
kensa mechanisms [flags]
```

| Short | Long | Meaning |
|---|---|---|
| `-h` | `--help` | Show help and exit |

## coverage

An alias for `mechanisms` today; printing a deprecation warning on
stderr. With `--framework`, it reports which controls in the named
framework are referenced by rules in the loaded corpus (the rule IDs per
control). The report is **numerator-only** (controls with rules, not
the framework's full control set) because kensa does not bundle an
external control catalog yet.

```
kensa coverage [flags]
kensa coverage --framework FRAMEWORK --rules-dir DIR [flags]
```

**Without `--framework`** (alias mode): only `-h, --help`.

**With `--framework`** (coverage report):

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| `-f` | `--framework` | `cis-rhel9` | | Filter rules to those mapping a control under FRAMEWORK; single value, hyphen/underscore interchangeable |
| `-r` | `--rules-dir` | `string` | | Directory of rule YAMLs to scan (required) |
| | `--format` | `string` | `text` | Output format: `text` or `json` |
| | `--full` | | | In text output, show every rule ID per control (default: truncate to first 3) |
| `-q` | `--quiet` | | | Suppress default output |

```bash
kensa coverage --framework cis_rhel9 --rules-dir /path/to/rules
kensa coverage -f nist_800_53 -r /path/to/rules --format json
kensa coverage -f cis_rhel9 -r /path/to/rules --full
```

> Migrate scripts that rely on the mechanism listing to `kensa mechanisms`
> before upgrading: `kensa coverage` changes meaning in v0.2.0.

## list

Introspection commands for the rule corpus and the transaction store.

```
kensa list <subject> [flags]
```

| Subject | Purpose |
|---|---|
| `frameworks` | Per-framework control + rule counts (requires `--rules-dir DIR`) |
| `sessions` | List recent sessions in the transaction store (with IDs for `kensa diff`) |

### list frameworks

Lists every `framework_id` in the loaded corpus with the count of
distinct controls referenced and distinct rules referencing each. Counts
are DISTINCT, not entry-counts.

```
kensa list frameworks --rules-dir DIR [flags]
```

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| `-r` | `--rules-dir` | `string` | | Directory of rule YAMLs to scan (required) |
| | `--format` | `string` | `text` | Output format: `text` or `json` |
| `-q` | `--quiet` | | | Suppress default output |

### list sessions

Lists recent sessions in the transaction store. The `session_id` column
is the UUID needed by `kensa diff`.

```
kensa list sessions [flags]
```

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| `-H` | `--host` | `string` | | Filter by hostname |
| `-n` | `--limit` | `int` | `20` | Maximum sessions to show (0 = unlimited) |
| | `--format` | `string` | `text` | Output format: `text`, `json`, or `jsonl` |
| `-q` | `--quiet` | | | Suppress default output |

## info

Multi-criteria lookup over a loaded rule corpus. Pick one mode; filters
compose with a positional `QUERY` (case-insensitive substring search over
title + description). `--rules-dir` is required.

```
kensa info [MODE] --rules-dir DIR [filters] [QUERY]
```

**Mode (pick one):**

| Short | Long | Argument | Meaning |
|---|---|---|---|
| | `--rule` | `string` | Show details for a single rule by ID (long-only; `-r` is `--rules-dir`) |
| | `--control` | `string` | Show rules mapping `FRAMEWORK:ID` (for example `cis_rhel9:5.1.12`) |
| `-L` | `--list-controls` | `string` | List every control referenced under FRAMEWORK with rule counts |
| `-r` | `--rules-dir` | `string` | Directory of rule YAMLs to scan (required) |

**Filter options** (compose with QUERY; the framework shortcuts also
narrow within `--rule`/`--control`):

| Long | Argument | Meaning |
|---|---|---|
| `--cis` | | Filter to the Center for Internet Security (CIS) family (`cis_rhel8`, `cis_rhel9`, `cis_rhel10`) |
| `--stig` | | Filter to the Security Technical Implementation Guide (STIG) family (`stig_rhel8`, `stig_rhel9`, `stig_rhel10`) |
| `--nist` | | Filter to the NIST 800-53 family (`nist_800_53`; not RHEL-versioned, so does NOT compose with `--rhel`) |
| `--rhel` | `int` | Filter by RHEL version (8, 9, or 10); composes with `--cis`/`--stig` (not `--nist`) |

`--cis`, `--stig`, and `--nist` are mutually exclusive.

**Output options:**

| Long | Argument | Default | Meaning |
|---|---|---|---|
| `--format` | `string` | `text` | `text`, `json`, or `jsonl` (jsonl is QUERY mode only) |
| `--limit` | `int` | `100` | Cap text output rows (search + list-controls modes); 0 = unlimited |
| `-q, --quiet` | | | Suppress default output |

```bash
kensa info ssh --rules-dir /path/to/rules                # substring search
kensa info ssh --cis --rhel 9 --rules-dir /path/to/rules # SSH rules in CIS RHEL9
kensa info --rule sysctl-ip-forward-disabled --rules-dir /path/to/rules
kensa info --control cis_rhel9:5.1.12 --rules-dir /path/to/rules
kensa info --list-controls cis_rhel9 --rules-dir /path/to/rules
kensa info file --rules-dir /path/to/rules --limit 0     # no truncation
```

## diff

Compare two stored sessions and emit the per-rule drift report: status
changes, rules added (in `SESSION_ID_2` only), and rules removed (in
`SESSION_ID_1` only). The `from → to` direction follows git-diff
convention, so `SESSION_ID_1` is the earlier snapshot. Comparing across
hostnames is allowed (a stderr note discloses the cross-host scope). Find
session IDs with `kensa list sessions`.

```
kensa diff SESSION_ID_1 SESSION_ID_2 [flags]
```

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| | `--format` | `string` | `text` | Output format: `text` or `json` |
| | `--show-unchanged` | | | Include rules whose status is identical between the two sessions |
| `-q` | `--quiet` | | | Suppress default output |

```bash
kensa list sessions                       # find session IDs first
kensa diff <id1> <id2>                     # compact drift report
kensa diff <id1> <id2> --show-unchanged    # include unchanged rules
kensa diff <id1> <id2> --format json       # programmatic output
```

## verify

Verify the Ed25519 signature on a kensa evidence-envelope JSON file. The
public key is looked up by the envelope's `signing_key_id` in a trust
directory (a directory of `.pub` files produced by `kensa-keygen`).

```
kensa verify <evidence-file> [flags]
```

Default trust directory, in priority order:
`$KENSA_CONFIG_DIR/keys/`, then `$XDG_CONFIG_HOME/kensa/keys/`, then
`$HOME/.config/kensa/keys/`. Override with `--trust-dir`.

| Short | Long | Argument | Default | Meaning |
|---|---|---|---|---|
| `-h` | `--help` | | | Show help and exit |
| | `--trust-dir` | `string` | matches `kensa-keygen` output dir | Directory of `.pub` files to look up `signing_key_id` |
| | `--format` | `string` | `text` | Output format: `text` or `json` |
| `-q` | `--quiet` | | | Suppress default output |

**Exit codes (verify-specific):**

| Code | Meaning |
|---|---|
| `0` | Signature is valid (envelope is authentic) |
| `1` | Signature is **INVALID** (tampered, wrong key, missing key, unknown schema version) |
| `2` | Usage error (missing file, bad flag, malformed JSON) |

Critical failure modes that exit `1` (not `2`): signature mismatch
(tampered after signing), unknown key (`signing_key_id` has no `.pub` in
the trust dir), wrong key (signature doesn't match the found `.pub`), and
unknown schema version (envelope from a future kensa).

Success warnings that still exit `0`: `signed_by_rotated_key` (authentic
but signed by a rotated-out key) and `signing_key_id_mismatch` (the
signature is real but the matched key's id disagrees with the envelope's
`signing_key_id`; investigate).

```bash
kensa verify evidence.json
kensa verify evidence.json --trust-dir /etc/kensa/keys
kensa verify evidence.json --format json | jq -r .valid
```

## migrate

Apply pending schema migrations to the SQLite store and backfill
synthetic sessions for pre-Phase-4 transactions. Idempotent: a second
run finds no work and exits `0`. Pre-Phase-4 transactions (rows whose
`session_id` is NULL) are grouped one synthetic session per `host_id`,
with subcommand `legacy-backfill` so they're distinguishable from real
sessions in later `kensa history` / `kensa diff` runs.

```
kensa migrate [flags]
```

| Short | Long | Argument | Meaning |
|---|---|---|---|
| `-h` | `--help` | | Show help and exit |
| | `--db` | `string` | Override the default store path |
| `-q` | `--quiet` | | Suppress the migration summary (errors still go to stderr) |

```bash
kensa migrate
kensa migrate --db /var/lib/kensa/results.db
kensa migrate --quiet
```

## version

Print the kensa binary version. The top-level `--version` flag is the
canonical GNU/POSIX form; this subcommand is preserved for backward
compatibility and is planned for removal in v0.2.0.

```
kensa version
```

| Short | Long | Meaning |
|---|---|---|
| `-h` | `--help` | Show help and exit |

## agent

`kensa agent` runs kensa as a stdio agent on the *target* host. It is an
internal command; `remediate` spawns it on the target over SSH (as root
via `--sudo`) to drive the kernel-IO primitives directly; you do not
invoke it by hand. Run `kensa agent --help` on the target for its
protocol flags. See [10-mechanisms](10-mechanisms.md) for which handlers
use the agent path and `KENSA_NO_AGENT=1` to opt out.

## Companion binaries

The packages install three companion binaries alongside `kensa`. They
are documented where they are used; this table is the index.

| Binary | Purpose | Documented in |
|---|---|---|
| `kensa-validate` | Validate rule YAML files against the canonical schema (`kensa-validate --rules-dir DIR`); exit codes 0 (clean), 1 (errors), 2 (usage) | [06-rule-authoring](06-rule-authoring.md) |
| `kensa-keygen` | Generate the Ed25519 keypair (`.priv`/`.pub`) used for evidence signing and `kensa verify` | [01-install](01-install.md) |
| `kensa-systemd-helper` | Privileged D-Bus subprocess for the service handlers; installed to `/usr/libexec/`, invoked by kensa, never run by hand | [01-install](01-install.md) |

## Next

That completes the operator guide. For the rule-authoring schema and
mechanism details referenced throughout, return to
[06-rule-authoring](06-rule-authoring.md) and
[10-mechanisms](10-mechanisms.md).
