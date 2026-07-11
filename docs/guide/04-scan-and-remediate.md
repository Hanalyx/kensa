# 04 · Scan and remediate

_Applies to: Kensa v0.7.6 — last updated 2026-07-10._

Two commands do the work: `kensa check` reads a host and reports
compliance without touching it, and `kensa remediate` applies the
failing rules as atomic transactions. They share the same target,
rule-selection, and output flags, so most of this chapter applies to
both; the differences are called out where they matter.

- [`check`: read-only compliance](#check-read-only-compliance)
- [`remediate`: apply failing rules](#remediate-apply-failing-rules)
- [Choosing a target](#choosing-a-target)
- [Selecting rules](#selecting-rules)
- [Privilege: sudo](#privilege-sudo)
- [Live result rows](#live-result-rows-default-text-output)
- [Outcomes: pass, fail, skipped, error](#outcomes-pass-fail-skipped-error)
- [Platform gating](#platform-gating)
- [Output formats](#output-formats)
- [Agent mode](#agent-mode)

---

## `check`: read-only compliance

```bash
kensa check -H rhel9-host.example.com -u admin --sudo -r ./rules
```

`check` evaluates each rule's check method against the host and prints a
verdict per rule. It changes nothing: no apply, no transaction, no
rollback. By default it does not even write to the SQLite store; pass
`--store` if you want the scan persisted as a session you can later
`diff` or feed to `rollback --list`.

`check` is the only scan command that accepts an **inventory** for
multi-host runs (see [Choosing a target](#choosing-a-target)).

## `remediate`: apply failing rules

```bash
kensa remediate -H rhel9-host.example.com -u admin --sudo -r ./rules
```

`remediate` runs each rule that is failing as a four-phase atomic
transaction: **Capture → Apply → Validate → Commit**. If validation
fails, the engine rolls the host back to the captured pre-state in the
same run, so a rule either lands cleanly or leaves no trace. A rule that
already passes is reported `PASS` and is not re-applied. Every committed
transaction is written to the store, which is what makes it reversible
later with [`kensa rollback`](05-rollback-and-history.md).

`remediate` is single-host: `--host` is required and there is no
`--inventory`.

---

## Choosing a target

Both commands take the same SSH connection flags.

| Flag | Meaning |
|---|---|
| `-H, --host` | Target hostname. Required (for `check`, required unless `--inventory`). |
| `-u, --user` | SSH user. Defaults to the current local user. |
| `-k, --key` | SSH private-key path. |
| `-p, --password` | SSH password. Omit the value (`-p`) for a TTY prompt. |
| `-P, --port` | SSH port (default 22). |
| `--strict-host-keys` | Verify SSH host keys; reject an unknown host. |
| `--no-strict-host-keys` | Trust on first use. This is today's default. |
| `-C, --capability KEY=VALUE` | Override a detected capability. Repeatable; on duplicate keys the last value wins (for example, `-C apparmor=true -C selinux=false`). |

Kensa drives the system `ssh` client (with ControlMaster), so your
`~/.ssh/config`, agent keys, and jump hosts all work as they normally
do.

### Inventory (`check` only)

```bash
kensa check --inventory hosts.ini --sudo -r ./rules
kensa check --inventory hosts.ini -w 10 --sudo -r ./rules
```

| Flag | Meaning |
|---|---|
| `-i, --inventory` | Ansible-style `inventory.ini` for a multi-host check. |
| `-l, --limit` | Limit inventory hosts to a glob/group pattern (ansible `--limit` semantics). |
| `-w, --workers` | Concurrent SSH connections, 1–50 (1 = sequential, the default). |

Each host scans independently; stdout carries the concatenated per-host
result documents. `remediate` and `rollback` are single-host and have no
inventory mode.

---

## Selecting rules

Rules come from three additive sources, combined into one set before any
filter is applied:

| Flag | Meaning |
|---|---|
| `-r, --rules-dir DIR` | Scan a directory for `*.yml` rule files. |
| `--rule FILE` | Load one rule YAML file, strictly: a parse error fails the command. Repeatable; additive with `--rules-dir` and positional args. |
| *positional* `rule.yml …` | Load named rule files directly. |

With the `kensa-rules` package installed, the corpus lives at
`/usr/share/kensa/rules` and is picked up automatically when you pass no
rule source at all. (Resolution order: explicit `--rules-dir` wins;
positional rule files alone skip the directory walk; otherwise the
default path is used; otherwise you get a usage error naming all three
fixes.)

### Filters

Filters narrow the loaded set. They combine with AND across *kinds*
(a rule must satisfy every filter you give) and OR *within* the
repeatable ones.

| Flag | Repeatable | Meaning |
|---|---|---|
| `-s, --severity` | yes (OR) | `critical` \| `high` \| `medium` \| `low`. |
| `-t, --tag` | yes (OR) | A rule matches if its `tags:` array contains any of these. |
| `-c, --category` | no | Single category (for example, `-c access-control`). A later `-c` overrides an earlier one. |
| `-f, --framework` | no | Keep rules mapping any control under FRAMEWORK (for example, `-f cis-rhel9`). Hyphen and underscore are interchangeable: `-f cis-rhel9` == `-f cis_rhel9`. |
| `--control` | yes (OR) | `FRAMEWORK:CONTROL` (for example, `--control cis-rhel9:5.1.12`). The framework portion accepts a hyphen or an underscore. |

```bash
# Critical + high only:
kensa check -H rhel9-host.example.com -s critical -s high -r ./rules

# One framework, one control:
kensa check -H rhel9-host.example.com -f cis-rhel9 --control cis_rhel9:5.1.12 -r ./rules
```

### Rule variables

Some rules carry `{{ var }}` placeholders (for example a faillock
threshold). You supply values two ways:

| Flag | Meaning |
|---|---|
| `-x, --var KEY=VALUE` | Override one variable. Repeatable. Wins over `--config-dir`/`defaults.yml`. |
| `--config-dir DIR` | Directory holding `defaults.yml`, the variable-defaults source. |

> **Security note.** A `--var` value is spliced literally into the rule
> YAML and may flow into shell commands the handlers run on the target.
> Pass only trusted input. This is a known trust boundary: Kensa treats
> `--var` values as operator-supplied and does not sanitize them.

---

## Privilege: sudo

Most compliance checks read root-owned files, so you almost always
use `--sudo`. Kensa supports both passwordless and password sudo.

| Flag | Meaning |
|---|---|
| `--sudo` | Wrap remote commands in sudo. |
| `--sudo-password` | A sudo password for hosts where NOPASSWD is not configured. Omit the value (`--sudo-password`) for a TTY prompt, or set `KENSA_SUDO_PASSWORD`. Requires `--sudo`. |

- **Passwordless (default).** With `--sudo` alone, Kensa runs
  `sudo -n` and never prompts. If the host's sudoers policy requires a
  password, a connect-time probe fails fast: *configure NOPASSWD or
  supply a sudo password*.
- **With a password.** Supply it via `--sudo-password`, the prompt, or
  `KENSA_SUDO_PASSWORD`. The password is fed over the SSH session's
  **stdin**, never placed in argv and never recorded in evidence
  (`CheckEvidence` / Open Security Controls Assessment Language (OSCAL)).
  A wrong password is reported as *sudo password rejected*.

`SUDO_ASKPASS` / `sudo -A` is deliberately **not** supported: it needs an
askpass helper on the target, which the agentless model does not ship.

```bash
# Passwordless sudo:
kensa check -H rhel9-host.example.com -u admin --sudo -r ./rules

# Password sudo from the environment (CI-friendly, no value in argv):
KENSA_SUDO_PASSWORD=… kensa remediate -H rhel9-host.example.com -u admin --sudo -r ./rules

# Password sudo with an interactive prompt:
kensa check -H rhel9-host.example.com -u admin --sudo --sudo-password -r ./rules
```

---

## Live result rows (default text output)

In the default text output, `check` and `remediate` stream their results
**live**: one aligned row per rule, printed **as each rule completes**,
in scan order. You watch a long scan advance instead of waiting for a
buffered report. There is no `--progress` flag and no separate progress
channel; the rows *are* the text result, on stdout.

```
───────────────────── Host: rhel9-host.example.com ──────────────────────
  Platform: RHEL 9.6
  PASS   MED   cron-logging                 Ensure cron logging is enabled
  FAIL   LOW   journald-compress            Configure journald to compress logs  config_value: key "Compress" not found in /etc/systemd/journald.conf
  PASS   MED   rsyslog-installed            Ensure rsyslog is installed
  FAIL   MED   rsyslog-file-permissions     Ensure rsyslog log file creation mode is configured  config_value: key "$FileCreateMode" not found in /etc/rsyslog.conf

  6 passed, 8 failed  (of 14)
```

- A full-width `Host:` banner, then a `Platform:` line, then one indented row
  per rule. There is no column-header row.
- Columns are `STATUS  SEVERITY  RULE-ID  DESCRIPTION`, with a trailing detail
  appended on `FAIL` / `ERROR` / `SKIP` rows.
- `STATUS` is `PASS` / `FAIL` / `ERROR` / `SKIP`. `remediate` adds `FIXED`
  (remediated this run); `PASS` there means already compliant.
- `SEVERITY` renders as `CRIT` / `HIGH` / `MED` / `LOW`.
- `STATUS` and `SEVERITY` are colored **only when stdout is a terminal**;
  redirected or piped output is plain text with no escape sequences.
- The tally lists only the non-zero outcomes and ends with `(of N)`; it adds a
  `skipped` (and `error`) count when any rule is skipped or errors.
- `-v, --verbose` (text only) expands the compacted PASSED list.
- `-q, --quiet` suppresses the default output entirely; errors still go
  to stderr.

The live rows apply to the **default human output only** (`--format
table`/`text`, or no format flag, with no `-o FILE`). Choosing a machine
format or an `-o FILE` destination turns the stream off; machine output
is always buffered and structured, never interleaved with rows.

The exit code and every `-o` output are produced from the canonical
`ScanResult` / `RemediationResult`, not reconstructed from the rendered
rows. Read the result document for the record of what happened; the rows
are the same data rendered for a human as it arrives.

---

## Outcomes: pass, fail, skipped, error

Every rule resolves to exactly one of four outcomes, the canonical
compliance verdict carried on `ScanResult.Outcomes`:

| Outcome | Meaning |
|---|---|
| `pass` | The host already satisfies the rule. |
| `fail` | The host does not satisfy the rule. On `remediate`, this is what gets applied (and becomes `FIXED` on success). |
| `skipped` | The rule does not apply to this host (see [Platform gating](#platform-gating)). It was not evaluated and, on `remediate`, never applied. |
| `error` | The check could not be completed (a command failed, the host was unreachable mid-scan, a capability could not be probed). |

These outcomes are what an embedder (OpenWatch) consumes; the legacy
`Transactions` surface, where `committed`/`rolled_back` double as
compliant/non-compliant, is kept only for backward compatibility.

---

## Platform gating

A rule may declare a `platforms:` block (an OS family plus optional
`min_version`/`max_version`). Before evaluating, Kensa reads the host's
OS from `/etc/os-release` and compares:

- If the rule **does not apply**, it renders `SKIP` with a detail such as
  `not applicable: host RHEL 8.10, rule targets rhel >=9`, instead of a
  misleading pass or fail. On `remediate`, a skipped rule's remediation
  is **never applied** (the engine is provably not invoked for it).
- A rule with **no `platforms:` block** runs everywhere.
- A host whose OS **cannot be detected** is never gated (every rule
  runs), so a detection blip cannot silently skip a scan.

Platform gating is the standalone-CLI safety net. In a fleet, OpenWatch
pre-filters by platform upstream; this in-engine gate exists for CLI
users running without it.

> The shipped corpus currently targets RHEL. Running it unmodified
> against Ubuntu skips the RHEL-only rules (they render `SKIP`), so a
> stock Ubuntu scan reports few or no in-platform rules today.

---

## Output formats

Two flag families control output. `--format` is the legacy single-format
selector; `-o`/`--output` is the current, repeatable, file-or-stdout
destination selector. Prefer `-o`.

| Flag | Meaning |
|---|---|
| `--format` | `check`: `table`, `json`, `jsonl`. `remediate`: `table`, `json`. **Deprecated**; use `--output`. |
| `-o, --output FORMAT[:PATH]` | Output destination. Repeatable. `PATH` omitted (or `-`) means stdout. |
| `-q, --quiet` | Suppress default output. |
| `--oscal FILE` | (`remediate` only) **Deprecated** alias for `-o oscal:FILE`. |

`FORMAT:PATH` lets you fan out to several artifacts in one run:

```bash
# JSON to a file:
kensa check -H rhel9-host.example.com --sudo -o json:result.json -r ./rules

# Two artifacts at once: JSONL on stdout + OSCAL to a file:
kensa check -H rhel9-host.example.com --sudo -o jsonl -o oscal:assessment.json -r ./rules

# Remediation, JSON on stdout + OSCAL to a file:
kensa remediate -H rhel9-host.example.com -u admin --sudo -o json -o oscal:/tmp/results.oscal.json -r ./rules
```

### Formats by command

| Format | `check` | `remediate` | Notes |
|---|---|---|---|
| `text`/`table` | yes | yes | Default; the live row stream. |
| `json` | yes | yes | The canonical result struct. |
| `jsonl` | yes | — | One JSON object per line (NDJSON); maps from `Outcomes`, with a first-class `skipped` count. |
| `csv` | yes | yes | Row-per-rule for spreadsheets. |
| `pdf` | yes | yes | Binary report (path required). |
| `evidence` | yes | yes | Kensa-native evidence document. |
| `oscal` | yes | yes | OSCAL 1.0.6 Assessment Results. |

### `-o evidence:` Kensa-native evidence

```bash
kensa check -H rhel9-host.example.com --sudo -o evidence:scan-evidence.json -r ./rules
```

Reproducible per-check proof behind each verdict: session and host
context plus, per rule, every command run with its stdout/stderr, exit
code, expected vs actual, and a `Truncated` flag (64 KiB per-field cap).
On `check` this document is **unsigned**; the Ed25519 signature is
exclusive to the remediation evidence-envelope path.

### `-o oscal:` OSCAL 1.0.6

```bash
kensa check -H rhel9-host.example.com --sudo -o oscal:assessment.json -r ./rules
```

A NIST OSCAL 1.0.6 Assessment Results document: one finding and one
observation per rule, framework refs as token-valid control-ids, the
verbatim command in `remarks`, raw stdout as base64 back-matter. The
output is conformance-gated against the vendored OSCAL 1.0.6 schema. The
scan-path OSCAL is **unsigned by design**; the remediation path
(`remediate -o oscal:`) anchors it in the signed evidence envelope.

> The evidence and OSCAL **schema files** are dev/CI assets and are not
> shipped in the rpm/deb until v1.0.0 (founder decision, 2026-06-13). The
> evidence and OSCAL **output** ships normally; only the schema files are
> unshipped.

---

## Agent mode

On `remediate`, Kensa runs the apply path through an on-host **agent** by
default. The agent drives kernel primitives directly (`/proc/sys` writes,
atomic file replacement, `delete_module(2)`, the systemd D-Bus helper,
audit netlink), which is what gives the file mechanisms their byte-exact
atomicity.

- `--sudo` spawns the agent as **root** (`sudo kensa agent`). The agent
  must run as root, or its direct `/proc`+`/etc` writes hit `EACCES`.
- Set `KENSA_NO_AGENT=1` to disable the agent and fall back to
  shell-best-effort. The fallback writes byte-identical files and records
  an identical pre-state, so capture and rollback are path-agnostic, but
  you lose the kernel-primitive atomicity on the agent-only mechanisms.

`check` is read-only and does not spawn the agent.

---

## Exit codes

`kensa` follows a small, stable convention (see `kensa --help`):

| Code | Meaning |
|---|---|
| `0` | Success (also `--help` / `--version`). |
| `1` | Runtime error (connect failure, host error). |
| `2` | Usage error (bad flag, unknown subcommand, missing required arg). |

A scan that completes but finds failing rules still exits `0`; the
failures are in the result, not the exit status. Read the result
document (or the rows) for the compliance verdict.

## Next

[05 · Rollback and history](05-rollback-and-history.md) covers undoing a
remediation, recovering from a crash, and querying the transaction log.
