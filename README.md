# Kensa

SSH-based compliance scanner for SysAdmin. Connects to remote hosts via SSH, evaluates compliance rules, captures machine-verifiable evidence, and maps results to multiple frameworks (CIS, STIG, NIST 800-53, PCI-DSS, FedRAMP).

**508 rules** | **7 frameworks** | **22 capability probes** | **Evidence capture**

## Installation

```bash
# From GitHub
pip install git+https://github.com/Hanalyx/kensa.git

# With PDF report support
pip install "git+https://github.com/Hanalyx/kensa.git#egg=kensa[pdf]"

# From source (development)
git clone https://github.com/Hanalyx/kensa.git
cd kensa
pip install -e ".[dev]"
```

## Quick Start

```bash
# Probe host capabilities
kensa detect --sudo --host 192.168.1.10 --user admin

# Check a single rule
kensa check --sudo --host 192.168.1.10 --user admin \
  --rule rules/access-control/ssh-disable-root-login.yml

# Check all rules
kensa check --sudo --host 192.168.1.10 --user admin --rules rules/

# Check by framework
kensa check --sudo --host 192.168.1.10 --user admin \
  --rules rules/ --framework cis-rhel9-v2.0.0

# Check by severity
kensa check --sudo --host 192.168.1.10 --user admin \
  --rules rules/ --severity high --severity critical

# Remediate failures (dry run first)
kensa remediate --sudo --host 192.168.1.10 --user admin \
  --rules rules/ --dry-run

# Export with evidence for integration
kensa check --sudo --host 192.168.1.10 --user admin \
  --rules rules/ -o evidence:results.json -q
```

## Multi-Host with Inventory

```bash
# Ansible INI inventory
kensa check --sudo -i inventory.ini --rules rules/

# Ansible YAML inventory
kensa check --sudo -i inventory.yml --rules rules/

# Limit to a group or pattern
kensa check --sudo -i inventory.yml --limit webservers --rules rules/
kensa check --sudo -i inventory.yml --limit 'web*' --rules rules/

# Parallel execution (10 hosts at once)
kensa check --sudo -i inventory.ini --rules rules/ --workers 10
```

## Configuration

Site-specific configuration lives in `config/` (maps to `/etc/kensa/` when installed via RPM):

```
config/
├── defaults.yml        # Global variable defaults and framework overrides
├── conf.d/             # Site-wide overrides (alphabetical, later wins)
│   └── 99-custom.yml
├── groups/             # Per-group variable overrides (filename = group name)
│   └── pci-scope.yml
└── hosts/              # Per-host variable overrides (filename = hostname)
    └── bastion-01.yml
```

**Variable precedence** (highest wins):

| Priority | Source | Example |
|----------|--------|---------|
| 1 | CLI `--var KEY=VALUE` | `--var ssh_max_auth_tries=2` |
| 2 | `config/hosts/<hostname>.yml` | Per-host thresholds |
| 3 | `config/groups/<group>.yml` | Per-group policy (last group wins) |
| 4 | `config/conf.d/*.yml` | Site-wide overrides |
| 5 | `frameworks.<name>` section | Framework-specific defaults |
| 6 | `config/defaults.yml` variables | Shipped defaults |

Variables use `{{ variable_name }}` syntax in rule YAML and are resolved per-host at execution time, so hosts in different groups can receive different thresholds for the same rule.

```bash
# Override a variable from the CLI
kensa check --sudo -h 192.168.1.10 -u admin -r rules/ \
  --var ssh_max_auth_tries=2

# Use a custom config directory
kensa check --sudo -h 192.168.1.10 -u admin -r rules/ \
  --config-dir /etc/kensa-staging/
```

## Framework Coverage

| Framework | Mapping ID | Controls | Status |
|-----------|------------|----------|--------|
| CIS RHEL 9 v2.0.0 | `cis-rhel9-v2.0.0` | 271 | 95%+ |
| STIG RHEL 9 V2R7 | `stig-rhel9-v2r7` | 338 | 75%+ |
| NIST 800-53 R5 | `nist-800-53-r5` | 87 | Complete |
| PCI-DSS v4.0 | `pci-dss-v4.0` | 45 | Complete |
| FedRAMP Moderate | `fedramp-moderate` | 87 | Complete |
| CIS RHEL 8 v4.0.0 | `cis-rhel8-v4.0.0` | 120 | ~80% |
| STIG RHEL 8 V2R6 | `stig-rhel8-v2r6` | 116 | ~70% |

```bash
# Show framework coverage
kensa coverage --framework cis-rhel9-v2.0.0

# Show framework info
kensa info --framework stig-rhel9-v2r7

# List all available frameworks
kensa list-frameworks
```

## Output Formats

```bash
# Terminal output (default)
kensa check -i inventory.ini --sudo -r rules/

# JSON
kensa check -i inventory.ini --sudo -r rules/ -o json:results.json

# CSV
kensa check -i inventory.ini --sudo -r rules/ -o csv:results.csv

# PDF report
kensa check -i inventory.ini --sudo -r rules/ -o pdf:report.pdf

# Evidence format (includes raw command output, groups, effective variables)
kensa check -i inventory.ini --sudo -r rules/ -o evidence:evidence.json

# Multiple outputs
kensa check -i inventory.ini --sudo -r rules/ \
  -o json:results.json -o csv:results.csv -o evidence:evidence.json
```

## Evidence Capture

Every check captures machine-verifiable evidence:

```json
{
  "rule_id": "ssh-disable-root-login",
  "passed": true,
  "evidence": {
    "method": "config_value",
    "command": "grep -E '^\\s*PermitRootLogin' /etc/ssh/sshd_config",
    "stdout": "PermitRootLogin no\n",
    "exit_code": 0,
    "expected": "no",
    "actual": "no",
    "timestamp": "2024-02-09T12:00:00Z"
  },
  "frameworks": {
    "cis_rhel9_v2": "5.1.12",
    "stig_rhel9_v2r7": "V-257983",
    "nist_800_53": "AC-6, CM-6"
  }
}
```

Evidence exports also include per-host context for audit trails:

```json
{
  "host": {
    "hostname": "web-01",
    "groups": ["web", "pci-scope"],
    "effective_variables": {
      "ssh_max_auth_tries": 3,
      "login_defs_pass_max_days": 30
    }
  }
}
```

## How It Works

1. **Resolve targets** — from `--host`, Ansible inventory, or host list
2. **Connect** — SSH with key, password, or agent auth; optional `--sudo`
3. **Detect capabilities** — 22 probes (sshd_config.d? authselect? firewalld? SELinux? ...)
4. **Detect platform** — RHEL family + version (Rocky, Alma, CentOS normalized to "rhel")
5. **Select implementations** — capability-gated rule variants; first match wins
6. **Resolve variables** — per-host, using the group/host/CLI override hierarchy
7. **Run checks** — 21 typed handlers with evidence capture
8. **Map frameworks** — extract references from rules (CIS, STIG, NIST, PCI-DSS, FedRAMP)
9. **Report** — PASS/FAIL with evidence, summaries per host and overall
10. **Remediate** (if requested) — check first, fix failures, re-check to confirm

## Rule Format

Rules are YAML files in `rules/<category>/`. Each rule declares one security control with one or more capability-gated implementations:

```yaml
id: ssh-disable-root-login
title: Disable SSH root login
severity: high
category: access-control
tags: [ssh, authentication, cis, stig]

references:
  cis:
    rhel9_v2: { section: "5.1.12", level: "L1", type: "Automated" }
  stig:
    rhel9_v2r7: { vuln_id: "V-257983", stig_id: "RHEL-09-255040", severity: "CAT II" }
  nist_800_53: ["AC-6", "CM-6"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - when: sshd_config_d              # Use drop-in if capability detected
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d/*.conf"
      key: "PermitRootLogin"
      value: "no"
    remediation:
      mechanism: config_set_dropin
      path: "/etc/ssh/sshd_config.d/99-kensa-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      restart: sshd

  - default: true                    # Fallback to main config
    check:
      method: config_value
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      value: "no"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      value: "no"
      restart: sshd
```

Full schema: `schema/rule.schema.json`

## Python API

```python
from runner.ssh import SSHSession
from runner.detect import detect_capabilities, detect_platform
from runner.engine import evaluate_rule, load_rules

with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
    # Detect host info
    caps = detect_capabilities(ssh)
    platform = detect_platform(ssh)

    # Load and evaluate rules
    rules = load_rules("rules/")
    for rule in rules:
        result = evaluate_rule(ssh, rule, caps)

        # Access results
        print(f"{result.rule_id}: {'PASS' if result.passed else 'FAIL'}")
        print(f"  Evidence: {result.evidence.actual}")
        print(f"  Frameworks: {result.framework_refs}")
```

See [KENSA Developer Guide](docs/KENSA_Developer_Guide_v1.0.0.md) for complete API documentation.

## Architecture

```
kensa/
├── kensa                  # Entry point
├── runner/
│   ├── cli.py             # CLI commands and orchestration
│   ├── ssh.py             # SSH connection management
│   ├── detect.py          # 22 capability probes
│   ├── engine.py          # Rule evaluation facade
│   ├── _config.py         # Variable loading and resolution
│   ├── _rule_selection.py # Rule selection pipeline
│   ├── _host_runner.py    # Per-host execution lifecycle
│   ├── _types.py          # Evidence, CheckResult, RuleResult
│   ├── paths.py           # Resource path resolution
│   ├── mappings.py        # Framework mapping loader
│   ├── inventory.py       # Host resolution (INI/YAML/host list)
│   ├── storage.py         # SQLite result persistence
│   ├── handlers/
│   │   ├── checks/        # 21 check handlers
│   │   ├── remediation/   # 23 remediation handlers
│   │   ├── capture/       # Pre-remediation state capture
│   │   └── rollback/      # State restoration
│   └── output/
│       ├── json_fmt.py    # JSON output
│       ├── csv_fmt.py     # CSV output
│       ├── pdf_fmt.py     # PDF reports
│       └── evidence_fmt.py # Evidence export
├── config/                # Site configuration (/etc/kensa/ in RPM)
│   ├── defaults.yml       # Variable defaults
│   ├── conf.d/            # Site-wide overrides
│   ├── groups/            # Per-group overrides
│   └── hosts/             # Per-host overrides
├── rules/                 # 508 YAML compliance rules
├── mappings/              # Framework mappings
│   ├── cis/
│   ├── stig/
│   ├── nist/
│   ├── pci-dss/
│   └── fedramp/
├── schema/                # JSON Schema + validator
└── docs/                  # Developer documentation
```

## Requirements

- Python 3.10+
- paramiko, PyYAML, click, rich
- SSH access to target hosts (key or password auth)
- `--sudo` requires passwordless sudo on targets (`NOPASSWD` in sudoers)

## Documentation

- [KENSA Developer Guide](docs/KENSA_Developer_Guide_v1.0.0.md) - Complete API reference and integration guide
- [Rule Schema](CANONICAL_RULE_SCHEMA_V0.md) - Full rule format documentation
- [CLAUDE.md](CLAUDE.md) - Project guide for contributors

## License

MIT
