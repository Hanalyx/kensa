# Aegis

SSH-based compliance test runner for RHEL systems. Connects to remote hosts via SSH, evaluates compliance rules, captures machine-verifiable evidence, and maps results to multiple frameworks (CIS, STIG, NIST 800-53, PCI-DSS, FedRAMP).

**338 rules** | **7 frameworks** | **22 capability probes** | **Evidence capture**

## Installation

```bash
# From GitHub
pip install git+https://github.com/Hanalyx/aegis.git

# With PDF report support
pip install "git+https://github.com/Hanalyx/aegis.git#egg=aegis[pdf]"

# From source (development)
git clone https://github.com/Hanalyx/aegis.git
cd aegis
pip install -e ".[dev]"
```

## Quick Start

```bash
# Probe host capabilities
aegis detect --sudo --host 192.168.1.10 --user admin

# Check a single rule
aegis check --sudo --host 192.168.1.10 --user admin \
  --rule rules/access-control/ssh-disable-root-login.yml

# Check all rules
aegis check --sudo --host 192.168.1.10 --user admin --rule rules/

# Check by framework
aegis check --sudo --host 192.168.1.10 --user admin \
  --rule rules/ --framework cis-rhel9-v2.0.0

# Check by severity
aegis check --sudo --host 192.168.1.10 --user admin \
  --rule rules/ --severity high --severity critical

# Remediate failures (dry run first)
aegis remediate --sudo --host 192.168.1.10 --user admin \
  --rule rules/ --dry-run

# Export with evidence for integration
aegis check --sudo --host 192.168.1.10 --user admin \
  --rule rules/ -o evidence:results.json -q
```

## Multi-Host with Inventory

```bash
# Ansible INI inventory
aegis check --sudo -i inventory.ini --rule rules/

# Ansible YAML inventory
aegis check --sudo -i inventory.yml --rule rules/

# Limit to a group or pattern
aegis check --sudo -i inventory.yml --limit webservers --rule rules/
aegis check --sudo -i inventory.yml --limit 'web*' --rule rules/

# Parallel execution (10 hosts at once)
aegis check --sudo -i inventory.ini --rule rules/ --workers 10
```

## Framework Coverage

| Framework | Mapping ID | Controls | Status |
|-----------|------------|----------|--------|
| CIS RHEL 9 v2.0.0 | `cis-rhel9-v2.0.0` | 271 | 95%+ |
| STIG RHEL 9 V2R7 | `stig-rhel9-v2r7` | 338 | 75%+ |
| NIST 800-53 R5 | `nist-800-53-r5` | 87 | ✓ |
| PCI-DSS v4.0 | `pci-dss-v4.0` | 45 | ✓ |
| FedRAMP Moderate | `fedramp-moderate` | 87 | ✓ |
| CIS RHEL 8 v4.0.0 | `cis-rhel8-v4.0.0` | 120 | ~80% |
| STIG RHEL 8 V2R6 | `stig-rhel8-v2r6` | 116 | ~70% |

```bash
# Show framework coverage
aegis coverage --framework cis-rhel9-v2.0.0

# Show framework info
aegis info --framework stig-rhel9-v2r7
```

## Output Formats

```bash
# Terminal output (default)
aegis check -i inventory.ini --sudo -r rules/

# JSON
aegis check -i inventory.ini --sudo -r rules/ -o json:results.json

# CSV
aegis check -i inventory.ini --sudo -r rules/ -o csv:results.csv

# PDF report
aegis check -i inventory.ini --sudo -r rules/ -o pdf:report.pdf

# Evidence format (for integration - includes raw command output)
aegis check -i inventory.ini --sudo -r rules/ -o evidence:evidence.json

# Multiple outputs
aegis check -i inventory.ini --sudo -r rules/ \
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

## How It Works

1. **Resolve targets** — from `--host`, Ansible inventory, or host list
2. **Connect** — SSH with key, password, or agent auth; optional `--sudo`
3. **Detect capabilities** — 22 probes (sshd_config.d? authselect? firewalld? SELinux? ...)
4. **Detect platform** — RHEL family + version (Rocky, Alma, CentOS normalized to "rhel")
5. **Select implementations** — capability-gated rule variants; first match wins
6. **Run checks** — 19 typed handlers with evidence capture
7. **Map frameworks** — extract references from rules (CIS, STIG, NIST, PCI-DSS, FedRAMP)
8. **Report** — PASS/FAIL with evidence, summaries per host and overall
9. **Remediate** (if requested) — check first, fix failures, re-check to confirm

## Rule Format

Rules are YAML files in `rules/<category>/`. Each rule declares one security control with one or more implementations:

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
      path: "/etc/ssh/sshd_config.d/99-aegis-root-login.conf"
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
from runner._orchestration import evaluate_rule
from runner._loading import load_rules

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

See [AEGIS Developer Guide](docs/AEGIS_Developer_Guide_v1.0.0.md) for complete API documentation.

## Architecture

```
aegis/
├── aegis                  # Entry point
├── runner/
│   ├── cli.py             # CLI commands and orchestration
│   ├── ssh.py             # SSH connection management
│   ├── detect.py          # 22 capability probes
│   ├── _orchestration.py  # Rule evaluation with evidence
│   ├── _types.py          # Evidence, CheckResult, RuleResult
│   ├── mappings.py        # Framework mapping loader
│   ├── storage.py         # SQLite result persistence
│   ├── handlers/
│   │   ├── checks/        # 19 check handlers
│   │   └── remediation/   # Remediation handlers
│   └── output/
│       ├── json_fmt.py    # JSON output
│       ├── csv_fmt.py     # CSV output
│       ├── pdf_fmt.py     # PDF reports
│       └── evidence_fmt.py # Evidence export
├── rules/                 # 338 YAML rules
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

- [AEGIS Developer Guide](docs/AEGIS_Developer_Guide_v1.0.0.md) - Complete API reference and integration guide
- [Rule Schema](CANONICAL_RULE_SCHEMA_V0.md) - Full rule format documentation
- [CLAUDE.md](CLAUDE.md) - Project guide for contributors

## License

MIT
