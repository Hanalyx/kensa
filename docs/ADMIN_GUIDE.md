# Kensa Admin Guide

Complete reference for system administrators operating Kensa.

This guide assumes you have completed the [QuickStart Guide](QUICKSTART.md) and have a working installation with SSH access to target hosts. For Kensa's design principles and architecture, see the [Compliance Philosophy](COMPLIANCE_PHILOSOPHY.md).

## Commands

Kensa provides nine commands. Each is described below with its full set of options.

### detect

Probe a target host's platform and capabilities before running checks.

```bash
kensa detect -h 192.168.1.10 -u admin --sudo
```

Output shows the OS family and version (e.g., RHEL 9.3) and the state of all 22 capability probes: authselect, crypto policies, sshd_config.d support, FIPS mode, firewalld backend, GRUB variant, and more.

Use `detect` to verify connectivity and understand which implementation variants Kensa will select on a given host. Add `-v` to see probe details.

### check

Evaluate compliance rules against target hosts.

```bash
# Run all rules
kensa check -h 192.168.1.10 -u admin --sudo

# Filter to a framework
kensa check -h 192.168.1.10 -u admin --sudo -f cis-rhel9-v2.0.0

# Filter to a specific control
kensa check -h 192.168.1.10 -u admin --sudo --control cis-rhel9-v2.0.0:5.1.12

# Filter by severity and category
kensa check -h 192.168.1.10 -u admin --sudo -s high -s critical -c access-control

# Single rule file
kensa check -h 192.168.1.10 -u admin --sudo --rule rules/access-control/ssh-root-login.yml

# Export results in multiple formats
kensa check -h 192.168.1.10 -u admin --sudo \
  -o json:results.json -o csv:results.csv -o evidence:evidence.json

# Store results in local database for history tracking
kensa check -h 192.168.1.10 -u admin --sudo --store
```

**Rule filtering options:**

| Option | Description |
|--------|-------------|
| `-r, --rules PATH` | Rules directory (recursive search) |
| `--rule PATH` | Single rule file |
| `--control ID` | Framework control (e.g., `cis-rhel9-v2.0.0:5.1.12`) |
| `-s, --severity TEXT` | Filter by severity (repeatable: `-s high -s critical`) |
| `-t, --tag TEXT` | Filter by tag (repeatable) |
| `-c, --category TEXT` | Filter by category |
| `-f, --framework TEXT` | Filter to a framework mapping |
| `-V, --var KEY=VALUE` | Override a rule variable (repeatable) |

**Output options:**

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Output format: `json`, `csv`, `pdf`, `evidence`. Append `:path` to write to file. Repeatable for multiple formats. |
| `-q, --quiet` | Suppress terminal output (useful with `-o`) |
| `--store` | Persist results to local SQLite database |

### remediate

Check rules and fix failures. Remediation applies typed, idempotent mechanisms — not arbitrary scripts.

```bash
# Preview what would change (no modifications made)
kensa remediate -h 192.168.1.10 -u admin --sudo --dry-run

# Remediate with automatic rollback on failure
kensa remediate -h 192.168.1.10 -u admin --sudo --rollback-on-failure

# Remediate a single framework control
kensa remediate -h 192.168.1.10 -u admin --sudo \
  --control cis-rhel9-v2.0.0:5.1.20 --rollback-on-failure

# Skip pre-state snapshots (faster, but rollback unavailable)
kensa remediate -h 192.168.1.10 -u admin --sudo --no-snapshot
```

**Remediation-specific options:**

| Option | Description |
|--------|-------------|
| `--dry-run` | Show what would change without making modifications |
| `--rollback-on-failure` | Automatically reverse changes if remediation or post-check fails |
| `--allow-conflicts` | Proceed when multiple rules target the same file (last rule wins) |
| `--no-snapshot` | Disable pre-state capture (faster, but no rollback data) |

Remediation accepts all the same rule filtering and output options as `check`.

**Workflow recommendation:** Always run `--dry-run` first. When applying changes, use `--rollback-on-failure` so the system is never left half-remediated.

### rollback

Inspect past remediations and reverse changes from stored snapshots.

```bash
# List recent remediation sessions
kensa rollback --list

# Inspect a session's details
kensa rollback --info 3

# Inspect with per-step pre-state data
kensa rollback --info 3 --detail

# Preview what a rollback would do
kensa rollback --start 3 -h 192.168.1.10 -u admin --sudo --dry-run

# Execute rollback
kensa rollback --start 3 -h 192.168.1.10 -u admin --sudo

# Rollback a single rule from a session
kensa rollback --start 3 --rule ssh-root-login -h 192.168.1.10 -u admin --sudo
```

**Rollback options:**

| Option | Description |
|--------|-------------|
| `--list` | List recent remediation sessions |
| `--info N` | Show details for remediation session N |
| `--start N` | Execute rollback from session N's stored snapshots |
| `--detail` | Include per-step pre-state data (with `--info`) |
| `--rule TEXT` | Filter to a specific rule (with `--info` or `--start`) |
| `-n, --max N` | Max sessions to list |
| `--json` | Output as JSON |
| `--dry-run` | Preview rollback without making changes |
| `--force` | Override stale or already-rolled-back warnings |

### history

Query the local scan database. Requires previous scans run with `--store`.

```bash
# List recent scan sessions
kensa history --sessions

# Show results for a specific session
kensa history --session-id 5

# Filter by host and rule
kensa history --host web1.example.com --rule ssh-root-login

# Show database statistics
kensa history --stats

# Remove old results
kensa history --prune 90
```

| Option | Description |
|--------|-------------|
| `-h, --host TEXT` | Filter by hostname |
| `-r, --rule TEXT` | Filter by rule ID |
| `-s, --sessions` | List sessions instead of individual results |
| `-S, --session-id N` | Show results for a specific session |
| `-n, --limit N` | Max entries to show |
| `--stats` | Show database statistics |
| `--prune DAYS` | Remove results older than N days |

### diff

Compare two scan sessions to find regressions and improvements.

```bash
kensa diff 3 7

# Filter to a specific host
kensa diff 3 7 --host web1.example.com

# Include unchanged results
kensa diff 3 7 --show-unchanged

# Machine-readable output
kensa diff 3 7 --json
```

Output categories: regressions (pass to fail), resolved (fail to pass), new failures, new passes.

### info

Look up rules by ID, framework reference, or free-text search.

```bash
# Look up by rule ID
kensa info ssh-root-login

# Look up by CIS section number
kensa info 5.1.20

# Look up by STIG vulnerability ID
kensa info V-257947

# Look up by NIST 800-53 control
kensa info AC-6

# Find rules implementing a specific control
kensa info --control cis-rhel9-v2.0.0:5.1.20

# Find which frameworks reference a rule
kensa info --rule ssh-root-login

# List all controls with rule counts
kensa info --list-controls --framework cis-rhel9-v2.0.0

# Prefix matching (5.1 matches 5.1.1, 5.1.2, etc.)
kensa info 5.1 --prefix-match
```

### coverage

Show how completely a framework mapping is implemented.

```bash
kensa coverage --framework cis-rhel9-v2.0.0

# JSON output for tooling
kensa coverage --framework stig-rhel9-v2r7 --json
```

Reports the total number of controls in the framework, how many are mapped to rules, how many are explicitly marked unimplemented (with reasons), and how many are missing.

### list-frameworks

List all installed framework mappings.

```bash
kensa list-frameworks
```

## Connection Options

These options are shared across all commands that connect to hosts.

| Option | Description |
|--------|-------------|
| `-h, --host TEXT` | Target host(s), comma-separated |
| `-i, --inventory TEXT` | Inventory file (INI or YAML) |
| `-l, --limit TEXT` | Limit to a group name or hostname glob |
| `-u, --user TEXT` | SSH username |
| `-k, --key TEXT` | Path to SSH private key |
| `-p, --password TEXT` | SSH password; use `-p` without a value to prompt interactively |
| `-P, --port INTEGER` | SSH port (default: 22) |
| `--sudo` | Run commands via sudo on the target |
| `-w, --workers INTEGER` | Parallel SSH connections, 1-50 (default: 1) |
| `-C, --capability KEY=VALUE` | Override a detected capability (repeatable) |
| `-v, --verbose` | Show capability detection and implementation selection |
| `--strict-host-keys / --no-strict-host-keys` | Verify SSH host keys (default: off) |

## Inventory

Kensa accepts three formats for specifying targets.

**Command-line hosts** — one or more hosts directly:

```bash
kensa check -h 192.168.1.10,192.168.1.11 -u admin --sudo
```

**INI inventory** — Ansible-compatible format:

```ini
# hosts.ini
[webservers]
web1.example.com
web2.example.com ansible_user=admin ansible_port=2222

[databases]
db1.example.com ansible_user=dba
db2.example.com ansible_user=dba
```

```bash
kensa check -i hosts.ini --sudo -w 4
kensa check -i hosts.ini --sudo -l webservers
```

**YAML inventory:**

```yaml
# hosts.yml
all:
  - 192.168.1.10
  - 192.168.1.11

web_servers:
  - hostname: web01.example.com
    user: admin
    port: 2222
  - hostname: web02.example.com
    user: admin

db_servers:
  - hostname: db01.example.com
    user: dba
```

Per-host values in the inventory override CLI defaults. A host can appear in multiple groups.

## Configuration

Kensa's configuration lives in the `config/` directory (or `/etc/kensa/` when installed via RPM).

```
config/
├── defaults.yml          # Global variable defaults + framework overrides
├── conf.d/               # Site-specific overrides (alphabetical order)
│   └── 99-banner.yml     # Example: custom login banner
├── groups/               # Per-group variable overrides
│   └── databases.yml     # Overrides for the "databases" inventory group
└── hosts/                # Per-host variable overrides
    └── db01.example.com.yml
```

### Variable Precedence

Variables are resolved in this order (highest priority first):

1. **CLI** `--var KEY=VALUE`
2. **Per-host** `config/hosts/<hostname>.yml`
3. **Per-group** `config/groups/<group>.yml` (last group wins)
4. **Site overrides** `config/conf.d/*.yml` (alphabetical, later files override earlier)
5. **Framework defaults** `frameworks.<name>` section in `defaults.yml` (when `--framework` is used)
6. **Global defaults** `variables` section in `defaults.yml`

### Customizing Variables

Rules reference variables with `{{ variable_name }}` syntax. The defaults ship with values aligned to STIG (the most restrictive framework). Override them for your environment in `config/conf.d/`.

**Example: Custom banner text** (`config/conf.d/99-banner.yml`):

```yaml
banner_text: |
  WARNING: This system is the property of ACME Corp. Unauthorized
  access is prohibited. All activity is monitored and logged.
```

**Example: Relaxed password policy** (`config/conf.d/50-password.yml`):

```yaml
pam_pwquality_minlen: 12
login_defs_pass_max_days: 180
pam_faillock_deny: 5
pam_faillock_unlock_time: 600
```

**Example: Per-host SSH timeout** (`config/hosts/jumpbox.example.com.yml`):

```yaml
ssh_client_alive_interval: 300
ssh_client_alive_count_max: 3
```

### Default Variables

The full set of variables and their default values is documented in `config/defaults.yml`. Key variable groups:

**Password quality** (pwquality.conf): `pam_pwquality_minlen` (15), `pam_pwquality_minclass` (4), `pam_pwquality_difok` (8), `pam_pwquality_maxrepeat` (3), `pam_pwquality_dcredit` (-1), `pam_pwquality_ucredit` (-1), `pam_pwquality_lcredit` (-1), `pam_pwquality_ocredit` (-1).

**Account lockout**: `pam_faillock_deny` (3), `pam_faillock_fail_interval` (900), `pam_faillock_unlock_time` (0).

**Password aging** (login.defs): `login_defs_pass_max_days` (60), `login_defs_pass_min_days` (1), `login_defs_pass_warn_age` (7), `login_defs_umask` ("077"), `password_remember` (5).

**SSH**: `ssh_client_alive_interval` (900), `ssh_client_alive_count_max` (1), `ssh_max_auth_tries` (4), `ssh_max_sessions` (10), `ssh_login_grace_time` (60), `ssh_approved_kex`, `ssh_approved_macs`.

**Login banner**: `banner_text` — displayed before authentication via `/etc/issue` and `/etc/issue.net`.

### Framework-Specific Defaults

When you filter by framework (`-f cis-rhel9-v2.0.0`), Kensa automatically loads framework-specific variable values. This adjusts thresholds to match the framework's requirements without manual overrides.

For example, CIS allows `pam_pwquality_minlen: 14` while STIG requires `15`. Running with `-f cis-rhel9-v2.0.0` uses the CIS value; running without a framework filter uses the STIG default.

Framework defaults sit at priority level 5, below all site and host overrides but above the global defaults.

## Output Formats

### Terminal (default)

Each rule prints a status line. The summary shows totals:

```
508 rules: 312 pass, 142 fail, 48 skip, 6 error (45.2s)
```

Use `-q` to suppress terminal output when writing to files with `-o`.

### JSON (`-o json` or `-o json:path`)

Structured results with host details, platform, capabilities, per-rule results, and summary counts. Suitable for dashboards, SIEM integration, and automated processing.

Each result includes the rule ID, title, severity, pass/fail/skip/error status, detail message, the implementation variant that was selected, and the framework section (when `--framework` is used).

### CSV (`-o csv` or `-o csv:path`)

One row per host-rule combination. Columns: `host`, `platform`, `rule_id`, `framework_section`, `title`, `severity`, `passed`, `skipped`, `error`, `error_detail`, `detail`. Suitable for spreadsheet analysis and pivot tables.

### PDF (`-o pdf:path`)

Visual compliance report with a summary table and color-coded per-host results (green for PASS, red for FAIL, orange for ERROR, grey for SKIP). Requires the `reportlab` package:

```bash
pip install kensa[pdf]
```

### Evidence (`-o evidence` or `-o evidence:path`)

Full machine-verifiable evidence for every check. Each result includes the exact shell command executed, raw stdout/stderr, exit code, expected versus actual values, and framework cross-references. This is the format designed for auditors — see the [Auditor Guide](AUDITOR_GUIDE.md) for interpretation details.

## Remediation and Rollback

### How Remediation Works

Remediation is a three-phase process for each failing rule:

1. **Pre-state capture.** Kensa records the current value of every setting it will change.
2. **Apply fix.** The remediation mechanism writes the corrected configuration.
3. **Post-check.** Kensa re-runs the compliance check to verify the fix took effect.

If step 3 fails and `--rollback-on-failure` is active, Kensa reverses all changes for that rule using the captured pre-state data.

### Remediation Mechanisms

All remediations use typed, declarative mechanisms — not arbitrary shell scripts. Each mechanism is idempotent (running it twice produces the same result as running it once). Kensa selects the most durable option available: drop-in files in `.d/` directories survive package updates, while direct config edits may be overwritten.

### Risk Classification

Every remediation step is assigned a risk level based on its mechanism type and target path:

**High risk** — mechanisms that can affect boot, authentication, or mount behavior: GRUB parameters, kernel module disabling, PAM configuration, mount options. Also triggered by high-risk paths: `/etc/pam.d/`, `/etc/fstab`, `/etc/default/grub`, `/etc/selinux/config`.

**Medium risk** — mechanisms that change service or kernel behavior: config file edits, sysctl values, service masking, audit rules, SELinux booleans.

**Low risk** — narrow-scope changes: file permissions, package install/remove, cron jobs.

### Snapshot Configuration

The `rollback` section of `config/defaults.yml` controls pre-state capture:

```yaml
rollback:
  snapshot: all             # all | risk_based | none
  risk_threshold: medium    # Minimum risk level when snapshot=risk_based
  high_risk_paths: []       # Additional paths that elevate risk to high
  snapshot_active_days: 7   # Full rollback available within this window
  snapshot_archive_days: 90 # Metadata retained, pre-state data pruned
```

- **`all`** (default): Capture pre-state for every remediation step.
- **`risk_based`**: Capture only for steps at or above the risk threshold.
- **`none`**: No snapshots. Faster, but rollback is unavailable.

### Rollback Workflow

```bash
# 1. Remediate with safety net
kensa remediate -h 192.168.1.10 -u admin --sudo --rollback-on-failure

# 2. Later, if you need to reverse:
kensa rollback --list                           # Find session number
kensa rollback --info 3 --detail                # Inspect what was changed
kensa rollback --start 3 -h 192.168.1.10 -u admin --sudo --dry-run   # Preview
kensa rollback --start 3 -h 192.168.1.10 -u admin --sudo             # Execute
```

### Non-Capturable Mechanisms

Three mechanism types cannot capture pre-state: `command_exec` (arbitrary commands), `manual` (human-performed steps), and `grub_parameter_set/remove` (requires regenerating boot config). Kensa surfaces these explicitly so operators know which steps lack rollback coverage.

## History and Drift Detection

### Storing Results

Add `--store` to any `check` command to persist results in the local SQLite database (`.kensa/results.db`):

```bash
kensa check -h 192.168.1.10 -u admin --sudo --store
```

### Tracking Drift

Compare two scan sessions to find regressions and improvements:

```bash
# Run a baseline scan
kensa check -h 192.168.1.10 -u admin --sudo --store

# ... time passes, changes are made ...

# Run a follow-up scan
kensa check -h 192.168.1.10 -u admin --sudo --store

# Compare
kensa history --sessions                    # Find session IDs
kensa diff 1 2                              # See what changed
```

`diff` reports four categories: regressions (previously passing rules that now fail), resolved (previously failing rules that now pass), new failures, and new passes.

### Database Maintenance

```bash
# See database size and record counts
kensa history --stats

# Remove results older than 90 days
kensa history --prune 90
```

Remediation snapshots follow their own retention policy (configurable in `defaults.yml`): full rollback data is available for 7 days (active window), metadata is retained for 90 days (archive window), then records are pruned.

## Capability Overrides

Kensa's 22 capability probes determine which implementation variant runs for each rule. In rare cases, you may need to override a detection result:

```bash
# Force sshd_config_d capability to false
kensa check -h 192.168.1.10 -u admin --sudo -C sshd_config_d=false

# Force multiple capabilities
kensa check -h 192.168.1.10 -u admin --sudo \
  -C authselect=true -C crypto_policies=false
```

Use `-v` (verbose) to see which capabilities were detected and which implementation was selected for each rule.

## Parallel Scanning

Use `-w` to scan multiple hosts concurrently:

```bash
# Scan 8 hosts in parallel
kensa check -i production.ini --sudo -w 8
```

The worker count is capped at 50. Each worker opens an independent SSH connection. Choose a value that your SSH server and network can handle without connection throttling.

## Troubleshooting

**SSH connection failures:** Run `detect` first to verify connectivity. Check that the SSH user has access and that `--sudo` is specified when needed. Use `--strict-host-keys` if host key verification is required by your security policy.

**Unexpected SKIP results:** A rule skips when the host's platform or capabilities don't match. Run `detect` to see the capability set and compare it against the rule's `when:` gate. Use `-v` for per-rule implementation selection details.

**ERROR results:** Usually indicate SSH timeouts, command failures, or unexpected output. Check `error_detail` in JSON or evidence output for the specific error message.

**Verbose mode:** Add `-v` to any command to see capability probe results and per-rule implementation selection. This is the first tool for diagnosing unexpected behavior.
