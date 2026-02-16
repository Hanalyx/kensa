# AEGIS Developer Guide v1.0.0

**SSH-Based Compliance Test Runner**

This guide provides comprehensive documentation for integrating AEGIS into applications like OpenWatch. AEGIS is a pure measurement engine that connects to remote hosts via SSH, evaluates compliance rules, and returns structured results with machine-verifiable evidence.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [Architecture](#3-architecture)
4. [Core Concepts](#4-core-concepts)
5. [Python API Reference](#5-python-api-reference)
6. [CLI Reference](#6-cli-reference)
7. [Evidence Model](#7-evidence-model)
8. [Framework Mappings](#8-framework-mappings)
9. [Output Formats](#9-output-formats)
10. [Extending AEGIS](#10-extending-aegis)
11. [Integration Patterns](#11-integration-patterns)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Overview

### What AEGIS Does

- Connects to remote Linux hosts via SSH
- Detects host capabilities and platform information
- Evaluates compliance rules against host configuration
- Captures raw evidence (command output) for each check
- Maps results to multiple compliance frameworks
- Optionally remediates non-compliant configurations

### What AEGIS Does NOT Do

- Long-term result storage (use OpenWatch)
- Exception/waiver management (use OpenWatch)
- User interface (use OpenWatch)
- Scan scheduling (use OpenWatch or external scheduler)
- Authentication management (expects SSH keys/credentials)

### Design Principles

1. **Pure Measurement** - AEGIS measures and reports; it doesn't interpret policy
2. **Evidence-First** - Every check captures raw proof for audit trails
3. **Framework Agnostic** - One rule maps to many frameworks; frameworks are views
4. **Capability-Gated** - Rule implementations adapt to host capabilities
5. **Stateless** - No persistent state required between runs

---

## 2. Installation

### From GitHub

```bash
# Basic installation
pip install git+https://github.com/Hanalyx/aegis.git

# With PDF report support
pip install "git+https://github.com/Hanalyx/aegis.git#egg=aegis[pdf]"

# Development installation (includes testing tools)
pip install "git+https://github.com/Hanalyx/aegis.git#egg=aegis[dev]"
```

### From Source

```bash
git clone https://github.com/Hanalyx/aegis.git
cd aegis
pip install -e ".[dev]"
```

### In requirements.txt

```
aegis @ git+https://github.com/Hanalyx/aegis.git
```

### In pyproject.toml

```toml
[project]
dependencies = [
    "aegis @ git+https://github.com/Hanalyx/aegis.git",
]
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| paramiko | >=3.0 | SSH connections |
| PyYAML | >=6.0 | Rule parsing |
| click | >=8.0 | CLI framework |
| rich | >=13.0 | Terminal output |
| reportlab | >=4.0 | PDF reports (optional) |

### System Requirements

- Python 3.10 or higher
- SSH access to target hosts
- Target hosts: RHEL 8/9, Rocky Linux, AlmaLinux, CentOS Stream

---

## 3. Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         AEGIS Package                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   cli.py    │  │  engine.py  │  │      rules/*.yml        │ │
│  │  (CLI App)  │  │  (Facade)   │  │   (Canonical Rules)     │ │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘ │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    _orchestration.py                        ││
│  │            evaluate_rule() / remediate_rule()               ││
│  └─────────────────────────┬───────────────────────────────────┘│
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         ▼                  ▼                  ▼                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  _checks.py │  │_remediation │  │     _selection.py       │ │
│  │  (Dispatch) │  │   .py       │  │  (Capability Gates)     │ │
│  └──────┬──────┘  └─────────────┘  └─────────────────────────┘ │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  handlers/checks/                           ││
│  │   _config.py  _file.py  _system.py  _service.py  etc.      ││
│  └─────────────────────────┬───────────────────────────────────┘│
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                       ssh.py                                ││
│  │                    SSHSession                               ││
│  └─────────────────────────┬───────────────────────────────────┘│
│                            │                                    │
└────────────────────────────┼────────────────────────────────────┘
                             │ SSH
                             ▼
                    ┌─────────────────┐
                    │  Target Hosts   │
                    └─────────────────┘
```

### Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `cli.py` | CLI commands, output formatting, orchestration |
| `engine.py` | Facade for programmatic access |
| `ssh.py` | SSH connection management, command execution |
| `detect.py` | Capability probes, platform detection |
| `_orchestration.py` | Rule evaluation, remediation flow |
| `_selection.py` | Capability-gated implementation selection |
| `_checks.py` | Check handler dispatch |
| `_types.py` | Data types (Evidence, CheckResult, RuleResult) |
| `_loading.py` | Rule loading and filtering |
| `handlers/checks/` | Check handler implementations |
| `handlers/remediation/` | Remediation handler implementations |
| `mappings.py` | Framework mapping loader |
| `storage.py` | Local SQLite storage (optional) |
| `output/` | Output formatters (JSON, CSV, PDF, Evidence) |

---

## 4. Core Concepts

### 4.1 Rules

Rules are YAML files defining compliance checks. Each rule has:

- **id**: Unique identifier (matches filename)
- **title**: Human-readable name
- **severity**: low, medium, high, critical
- **implementations**: One or more check/remediation pairs

```yaml
id: ssh-disable-root-login
title: Disable SSH root login
description: >
  The PermitRootLogin parameter specifies whether root can log in using SSH.
rationale: >
  Direct root login should be disabled to enforce accountability.
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
  - when: sshd_config_d
    check:
      method: config_value
      path: /etc/ssh/sshd_config.d/*.conf
      key: PermitRootLogin
      value: "no"
      case_insensitive: true
    remediation:
      mechanism: config_set_dropin
      path: /etc/ssh/sshd_config.d/99-aegis-root-login.conf
      key: PermitRootLogin
      value: "no"
      restart: sshd

  - default: true
    check:
      method: config_value
      path: /etc/ssh/sshd_config
      key: PermitRootLogin
      value: "no"
      case_insensitive: true
    remediation:
      mechanism: config_set
      path: /etc/ssh/sshd_config
      key: PermitRootLogin
      value: "no"
      restart: sshd
```

### 4.2 Capabilities

Capabilities are host features detected at runtime. Rules use capability gates (`when:`) to select appropriate implementations.

```python
# Current capabilities (22 total)
CAPABILITIES = [
    "sshd_config_d",      # SSH drop-in config support
    "authselect",         # Authselect profile management
    "authselect_sssd",    # SSSD authselect profile
    "crypto_policies",    # System-wide crypto policies
    "crypto_policy_modules",
    "fips_mode",          # FIPS mode enabled
    "firewalld_nftables", # Firewalld with nftables
    "firewalld_iptables", # Firewalld with iptables
    "systemd_resolved",   # systemd-resolved active
    "pam_faillock",       # PAM faillock configured
    "grub_bls",           # GRUB Boot Loader Spec
    "grub_legacy",        # Legacy GRUB2
    "journald_primary",   # systemd-journald active
    "rsyslog_active",     # rsyslog active
    "fapolicyd",          # File access policy daemon
    "selinux",            # SELinux enabled
    "aide",               # AIDE installed
    "tpm2",               # TPM 2.0 present
    "usbguard",           # USBGuard installed
    "dnf_automatic",      # DNF automatic updates
    "gdm",                # GNOME Display Manager
    "tmux",               # tmux available
]
```

### 4.3 Check Handlers

Check handlers verify system state. Each returns a `CheckResult` with evidence.

| Handler | Purpose | Key Parameters |
|---------|---------|----------------|
| `config_value` | Check config file key=value | path, key, value |
| `config_absent` | Verify key is not set | path, key |
| `file_permission` | Check owner/group/mode | path, owner, group, mode |
| `file_exists` | Verify file exists | path |
| `file_not_exists` | Verify file absent | path |
| `file_content_match` | Regex pattern match | path, pattern |
| `file_content_no_match` | Regex pattern absent | path, pattern |
| `sysctl_value` | Check sysctl parameter | key, value |
| `kernel_module_state` | Check module loaded/disabled | name, state |
| `mount_option` | Check mount options | mount_point, option |
| `grub_parameter` | Check GRUB cmdline | parameter, value |
| `service_state` | Check systemd service | name, enabled, active |
| `systemd_target` | Check default target | expected, not_expected |
| `package_state` | Check RPM package | name, state |
| `selinux_state` | Check SELinux mode | state |
| `selinux_boolean` | Check SELinux boolean | name, value |
| `audit_rule_exists` | Check audit rule | rule |
| `pam_module` | Check PAM configuration | service, module, type, control |
| `command` | Run arbitrary command | run, expected_exit, expected_stdout |

### 4.4 Platform Filtering

Rules specify supported platforms:

```yaml
platforms:
  - family: rhel
    min_version: 8
    max_version: 9
```

AEGIS normalizes RHEL derivatives (Rocky, Alma, CentOS, Oracle Linux) to `family: rhel`.

---

## 5. Python API Reference

### 5.1 Basic Usage

```python
from runner.ssh import SSHSession
from runner.detect import detect_capabilities, detect_platform
from runner._orchestration import evaluate_rule
from runner._loading import load_rules

# Connect to host
with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
    # Detect host info
    capabilities = detect_capabilities(ssh)
    platform = detect_platform(ssh)

    # Load rules
    rules = load_rules("rules/")

    # Evaluate each rule
    for rule in rules:
        result = evaluate_rule(ssh, rule, capabilities)
        print(f"{result.rule_id}: {'PASS' if result.passed else 'FAIL'}")
```

### 5.2 SSHSession

```python
from runner.ssh import SSHSession

# Using context manager (recommended)
with SSHSession(
    host="192.168.1.100",
    user="admin",
    port=22,                    # Optional, default 22
    key_filename="/path/to/key", # Optional
    password="secret",          # Optional (prefer keys)
    sudo=True,                  # Run commands with sudo
    connect_timeout=30,         # Connection timeout
) as ssh:
    result = ssh.run("cat /etc/os-release")
    print(result.stdout)
    print(result.exit_code)

# Manual connection management
ssh = SSHSession("192.168.1.100", user="admin")
ssh.connect()
try:
    result = ssh.run("whoami")
finally:
    ssh.close()
```

### 5.3 Capability Detection

```python
from runner.detect import detect_capabilities, detect_platform, PlatformInfo

# Detect all capabilities
caps = detect_capabilities(ssh)
# Returns: {"sshd_config_d": True, "selinux": True, "fips_mode": False, ...}

# Detect platform
platform = detect_platform(ssh)
# Returns: PlatformInfo(family="rhel", version=9)
```

### 5.4 Loading Rules

```python
from runner._loading import load_rules, rule_applies_to_platform

# Load all rules from directory
rules = load_rules("rules/")

# Load with filters
rules = load_rules(
    "rules/",
    severity=["high", "critical"],  # Filter by severity
    tags=["ssh"],                   # Filter by tags
    category="access-control",      # Filter by category
)

# Check platform applicability
if rule_applies_to_platform(rule, family="rhel", version=9):
    # Rule applies to this host
    pass
```

### 5.5 Evaluating Rules

```python
from runner._orchestration import evaluate_rule, remediate_rule
from runner._types import RuleResult

# Check only
result: RuleResult = evaluate_rule(ssh, rule, capabilities)

# Access result fields
result.rule_id          # str: Rule identifier
result.title            # str: Rule title
result.severity         # str: low/medium/high/critical
result.passed           # bool: Check passed
result.skipped          # bool: Rule was skipped
result.skip_reason      # str: Why it was skipped
result.detail           # str: Human-readable detail
result.evidence         # Evidence: Raw proof (see below)
result.framework_refs   # dict: {"cis_rhel9_v2": "5.1.12", ...}

# Check and remediate
result = remediate_rule(
    ssh,
    rule,
    capabilities,
    dry_run=False,           # Actually apply changes
    rollback_on_failure=True # Rollback if remediation fails
)

# Additional fields after remediation
result.remediated           # bool: Remediation attempted
result.remediation_detail   # str: What was done
result.rolled_back          # bool: Changes were rolled back
result.step_results         # list[StepResult]: Per-step details
```

### 5.6 Evidence Object

```python
from runner._types import Evidence
from datetime import datetime

# Evidence is automatically captured by check handlers
evidence: Evidence = result.evidence

evidence.method      # str: Handler name ("config_value")
evidence.command     # str: Shell command executed
evidence.stdout      # str: Raw stdout
evidence.stderr      # str: Raw stderr
evidence.exit_code   # int: Exit code
evidence.expected    # str: Expected value
evidence.actual      # str: Actual value found
evidence.timestamp   # datetime: When check ran (UTC)
```

### 5.7 Engine Facade

For convenience, `engine.py` provides high-level functions:

```python
from runner.engine import (
    check_single_rule,
    check_rules_from_path,
    quick_host_info,
)

with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
    # Quick host info
    caps, platform = quick_host_info(ssh)

    # Check single rule file
    result = check_single_rule(ssh, "rules/access-control/ssh-disable-root-login.yml")

    # Check multiple rules
    results = check_rules_from_path(
        ssh,
        "rules/",
        severity=["high", "critical"],
    )
```

### 5.8 Framework Mappings

```python
from runner.mappings import (
    load_mapping,
    load_all_mappings,
    get_applicable_mappings,
    rules_for_framework,
    build_rule_to_section_map,
)

# Load specific mapping
cis = load_mapping("mappings/cis/rhel9_v2.0.0.yaml")

# Load all mappings
all_mappings = load_all_mappings("mappings/")
# Returns: {"cis-rhel9-v2.0.0": FrameworkMapping, ...}

# Get mappings for a platform
applicable = get_applicable_mappings(all_mappings, family="rhel", version=9)

# Filter rules to a framework
filtered_rules = rules_for_framework(cis, all_rules)

# Get rule -> section mapping
rule_to_section = build_rule_to_section_map(cis)
# Returns: {"ssh-disable-root-login": "5.1.12", ...}
```

### 5.9 Storage (Optional)

```python
from runner.storage import ResultStore
from runner._types import Evidence

store = ResultStore()  # Uses .aegis/results.db

# Create session
session_id = store.create_session(
    hosts=["192.168.1.100", "192.168.1.101"],
    rules_path="rules/",
    options="--sudo --severity high",
)

# Record result with evidence
result_id = store.record_result(
    session_id=session_id,
    host="192.168.1.100",
    rule_id="ssh-disable-root-login",
    passed=True,
    detail="PermitRootLogin=no",
    evidence=evidence,
    framework_refs={"cis_rhel9_v2": "5.1.12"},
)

# Query evidence
stored_evidence = store.get_evidence(result_id)
stored_refs = store.get_framework_refs(result_id)

# Query by time range
from datetime import datetime, timedelta
results = store.get_results_by_timerange(
    start=datetime.now() - timedelta(days=7),
    end=datetime.now(),
    host="192.168.1.100",
    framework="cis_rhel9_v2",
)

store.close()
```

---

## 6. CLI Reference

### 6.1 Commands

```bash
# Show help
aegis --help
aegis check --help

# Detect capabilities
aegis detect --host 192.168.1.100 --user admin --sudo

# Run compliance checks
aegis check --host 192.168.1.100 --user admin --sudo --rule rules/

# Run with inventory file
aegis check -i inventory.ini --sudo -r rules/

# Remediate non-compliant rules
aegis remediate -i inventory.ini --sudo -r rules/

# Show framework coverage
aegis coverage --framework cis-rhel9-v2.0.0

# Show framework info
aegis info --framework cis-rhel9-v2.0.0
```

### 6.2 Common Options

| Option | Description |
|--------|-------------|
| `-h, --host` | Target host (single host mode) |
| `-u, --user` | SSH username |
| `-i, --inventory` | Inventory file (INI, YAML, or text) |
| `--limit` | Filter hosts by pattern |
| `--sudo` | Run commands with sudo |
| `-r, --rule` | Rule file or directory |
| `--category` | Filter by category |
| `--severity` | Filter by severity (comma-separated) |
| `--tags` | Filter by tags (comma-separated) |
| `--framework` | Filter by framework mapping |
| `-o, --output` | Output format (json, csv, pdf, evidence) |
| `-q, --quiet` | Suppress terminal output |
| `-w, --workers` | Parallel workers (default: 1) |
| `--dry-run` | Show what would be done (remediate) |

### 6.3 Output Formats

```bash
# JSON to stdout
aegis check -i inv.ini --sudo -r rules/ -o json -q

# JSON to file
aegis check -i inv.ini --sudo -r rules/ -o json:results.json

# CSV
aegis check -i inv.ini --sudo -r rules/ -o csv:results.csv

# PDF report
aegis check -i inv.ini --sudo -r rules/ -o pdf:report.pdf

# Evidence format (for OpenWatch)
aegis check -i inv.ini --sudo -r rules/ -o evidence:evidence.json

# Multiple outputs
aegis check -i inv.ini --sudo -r rules/ \
    -o json:results.json \
    -o csv:results.csv \
    -o evidence:evidence.json
```

### 6.4 Inventory File Formats

**INI**
```ini
[webservers]
web-01 host=192.168.1.10 user=admin
web-02 host=192.168.1.11 user=admin

[databases]
db-01 host=192.168.1.20 user=dba port=2222
```

**YAML**
```yaml
all:
  hosts:
    web-01:
      host: 192.168.1.10
      user: admin
    db-01:
      host: 192.168.1.20
      user: dba
```

**Plain text**
```
192.168.1.10
192.168.1.11
192.168.1.20
```

---

## 7. Evidence Model

### 7.1 Evidence Dataclass

Every check captures machine-verifiable evidence:

```python
@dataclass
class Evidence:
    method: str           # Handler name (e.g., "config_value")
    command: str | None   # Shell command executed
    stdout: str           # Raw standard output
    stderr: str           # Raw standard error
    exit_code: int        # Command exit code
    expected: str | None  # Expected value
    actual: str | None    # Actual value found
    timestamp: datetime   # UTC timestamp
```

### 7.2 Evidence Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Check Handler │────▶│   CheckResult   │────▶│   RuleResult    │
│                 │     │   + Evidence    │     │   + Evidence    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  Evidence JSON  │
                                                │    Output       │
                                                └─────────────────┘
```

### 7.3 Evidence by Handler Type

**config_value**
```json
{
  "method": "config_value",
  "command": "grep -E '^\\s*PermitRootLogin' /etc/ssh/sshd_config",
  "stdout": "PermitRootLogin no\n",
  "stderr": "",
  "exit_code": 0,
  "expected": "no",
  "actual": "no"
}
```

**sysctl_value**
```json
{
  "method": "sysctl_value",
  "command": "sysctl -n net.ipv4.ip_forward",
  "stdout": "0\n",
  "stderr": "",
  "exit_code": 0,
  "expected": "0",
  "actual": "0"
}
```

**service_state**
```json
{
  "method": "service_state",
  "command": "systemctl is-enabled/is-active sshd",
  "stdout": "is-enabled: enabled\nis-active: active",
  "stderr": "",
  "exit_code": 0,
  "expected": "enabled=enabled, active=active",
  "actual": "enabled=enabled, active=active"
}
```

**file_permission**
```json
{
  "method": "file_permission",
  "command": "stat -c '%U %G %a %n' /etc/shadow",
  "stdout": "root root 0 /etc/shadow\n",
  "stderr": "",
  "exit_code": 0,
  "expected": "owner=root, group=root, mode=0000",
  "actual": "/etc/shadow: owner=root, group=root, mode=0"
}
```

### 7.4 Using Evidence for Audit

Evidence provides:

1. **Reproducibility** - The exact command can be re-run
2. **Verification** - Raw output proves the finding
3. **Timestamps** - When the check occurred
4. **Comparison** - expected vs actual values

---

## 8. Framework Mappings

### 8.1 Available Frameworks

| Framework | ID | Controls | Coverage |
|-----------|-----|----------|----------|
| CIS RHEL 9 v2.0.0 | `cis-rhel9-v2.0.0` | 271 | 95%+ |
| CIS RHEL 8 v4.0.0 | `cis-rhel8-v4.0.0` | 120 | ~80% |
| STIG RHEL 9 V2R7 | `stig-rhel9-v2r7` | 338 | 75%+ |
| STIG RHEL 8 V2R6 | `stig-rhel8-v2r6` | 116 | ~70% |
| NIST 800-53 R5 | `nist-800-53-r5` | 87 | - |
| PCI-DSS v4.0 | `pci-dss-v4.0` | 45 | - |
| FedRAMP Moderate | `fedramp-moderate` | 87 | - |

### 8.2 Framework References in Rules

Rules embed framework references:

```yaml
references:
  cis:
    rhel9_v2: { section: "5.1.12", level: "L1", type: "Automated" }
    rhel8_v4: { section: "5.2.18", level: "L1", type: "Automated" }
  stig:
    rhel9_v2r7: { vuln_id: "V-257983", stig_id: "RHEL-09-255040", severity: "CAT II" }
  nist_800_53: ["AC-6", "CM-6", "SC-8"]
```

### 8.3 Framework References in Results

The `_orchestration.py` module extracts and flattens references:

```python
result.framework_refs = {
    "cis_rhel9_v2": "5.1.12",
    "cis_rhel8_v4": "5.2.18",
    "stig_rhel9_v2r7": "V-257983",
    "nist_800_53": "AC-6, CM-6, SC-8",
}
```

### 8.4 Filtering by Framework

```bash
# CLI: Run only rules in CIS RHEL 9
aegis check -i inv.ini --sudo -r rules/ --framework cis-rhel9-v2.0.0
```

```python
# Python: Filter rules
from runner.mappings import load_mapping, rules_for_framework

cis = load_mapping("mappings/cis/rhel9_v2.0.0.yaml")
filtered = rules_for_framework(cis, all_rules)
```

### 8.5 Mapping File Structure

**CIS/STIG style** (one rule per section):
```yaml
id: cis-rhel9-v2.0.0
framework: cis
title: "CIS RHEL 9 Benchmark v2.0.0"

sections:
  "5.1.12":
    rule: ssh-disable-root-login
    title: "Ensure SSH root login is disabled"
    level: "L1"
    type: "Automated"
```

**NIST/PCI/FedRAMP style** (multiple rules per control):
```yaml
id: nist-800-53-r5
framework: nist_800_53
title: "NIST SP 800-53 Rev. 5"

controls:
  "AC-6":
    title: "Least Privilege"
    rules:
      - sudo-use-pty
      - sudo-require-auth
      - su-require-wheel
```

---

## 9. Output Formats

### 9.1 Evidence Format (Recommended for Integration)

```json
{
  "version": "1.0.0",
  "session": {
    "id": "a1b2c3d4",
    "timestamp": "2024-02-09T12:00:00Z",
    "rules_path": "rules/",
    "command": "check"
  },
  "host": {
    "hostname": "server-01",
    "platform": {
      "family": "rhel",
      "version": 9
    },
    "capabilities": {
      "selinux": true,
      "sshd_config_d": true,
      "fips_mode": false
    }
  },
  "results": [
    {
      "rule_id": "ssh-disable-root-login",
      "title": "Disable SSH root login",
      "severity": "high",
      "passed": true,
      "skipped": false,
      "detail": "PermitRootLogin=no",
      "timestamp": "2024-02-09T12:00:01Z",
      "evidence": {
        "method": "config_value",
        "command": "grep -E '^\\s*PermitRootLogin' /etc/ssh/sshd_config",
        "stdout": "PermitRootLogin no\n",
        "stderr": "",
        "exit_code": 0,
        "expected": "no",
        "actual": "no"
      },
      "frameworks": {
        "cis_rhel9_v2": "5.1.12",
        "stig_rhel9_v2r7": "V-257983",
        "nist_800_53": "AC-6, CM-6"
      }
    }
  ],
  "summary": {
    "total": 248,
    "pass": 230,
    "fail": 15,
    "skip": 3
  }
}
```

### 9.2 JSON Format

Standard format for programmatic consumption:

```json
{
  "timestamp": "2024-02-09T12:00:00Z",
  "command": "check",
  "hosts": [
    {
      "hostname": "server-01",
      "platform": {"family": "rhel", "version": 9},
      "capabilities": {"selinux": true},
      "results": [
        {
          "rule_id": "ssh-disable-root-login",
          "title": "Disable SSH root login",
          "severity": "high",
          "passed": true,
          "detail": "PermitRootLogin=no"
        }
      ],
      "summary": {"total": 248, "pass": 230, "fail": 15, "skip": 3}
    }
  ],
  "summary": {"hosts": 1, "total": 248, "pass": 230, "fail": 15, "skip": 3}
}
```

### 9.3 CSV Format

Flat format for spreadsheets:

```csv
host,rule_id,title,severity,passed,skipped,detail
server-01,ssh-disable-root-login,Disable SSH root login,high,True,False,PermitRootLogin=no
server-01,ssh-permit-empty-passwords,Disallow empty passwords,high,True,False,PermitEmptyPasswords=no
```

### 9.4 PDF Format

Formatted report with:
- Executive summary
- Per-host results
- Color-coded pass/fail
- Framework section references

---

## 10. Extending AEGIS

### 10.1 Adding a Capability Probe

Edit `runner/detect.py`:

```python
CAPABILITY_PROBES: dict[str, str] = {
    # ... existing probes ...

    # Add new probe
    "podman": "command -v podman >/dev/null 2>&1",
    "kubernetes": "command -v kubectl >/dev/null 2>&1 && kubectl cluster-info >/dev/null 2>&1",
}
```

Use in rule:
```yaml
implementations:
  - when: podman
    check:
      method: command
      run: podman ps --format json
```

### 10.2 Adding a Check Handler

1. Create or edit handler file in `runner/handlers/checks/`:

```python
# runner/handlers/checks/_custom.py
from datetime import datetime, timezone
from runner._types import CheckResult, Evidence

def _check_custom_thing(ssh, c: dict) -> CheckResult:
    """Check some custom thing."""
    expected = c.get("expected", "value")
    check_time = datetime.now(timezone.utc)
    cmd = f"some-command {expected}"

    result = ssh.run(cmd)
    actual = result.stdout.strip()
    passed = actual == expected

    return CheckResult(
        passed=passed,
        detail=f"Got: {actual}" if passed else f"Expected {expected}, got {actual}",
        evidence=Evidence(
            method="custom_thing",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=actual,
            timestamp=check_time,
        ),
    )
```

2. Register in `runner/handlers/checks/__init__.py`:

```python
from runner.handlers.checks._custom import _check_custom_thing

CHECK_HANDLERS = {
    # ... existing handlers ...
    "custom_thing": _check_custom_thing,
}
```

3. Use in rule:

```yaml
check:
  method: custom_thing
  expected: "some-value"
```

### 10.3 Adding a Rule

1. Create YAML file in `rules/<category>/<rule-id>.yml`
2. Validate: `python -m schema.validate rules/<category>/<rule-id>.yml`
3. Test: `aegis check --host <test-host> --sudo --rule rules/<category>/<rule-id>.yml`

### 10.4 Adding a Framework Mapping

Create mapping file in `mappings/<framework>/<version>.yaml`:

```yaml
id: my-framework-v1.0
framework: my_framework
title: "My Framework v1.0"
published: 2024-01-01

controls:  # or "sections" or "requirements"
  "CTRL-001":
    title: "Control title"
    rules:
      - ssh-disable-root-login
      - ssh-permit-empty-passwords
```

---

## 11. Integration Patterns

### 11.1 Recommended Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        OpenWatch                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Scan        │  │  Results     │  │  Exception           │  │
│  │  Scheduler   │  │  Database    │  │  Management          │  │
│  └──────┬───────┘  └──────▲───────┘  └──────────────────────┘  │
│         │                 │                                     │
└─────────┼─────────────────┼─────────────────────────────────────┘
          │                 │
          ▼                 │
┌─────────────────┐         │
│     AEGIS       │─────────┘
│  (Python Lib)   │  Evidence JSON
└────────┬────────┘
         │ SSH
         ▼
┌─────────────────┐
│  Target Hosts   │
└─────────────────┘
```

### 11.2 Synchronous Scanning

```python
from runner.ssh import SSHSession
from runner.detect import detect_capabilities, detect_platform
from runner._orchestration import evaluate_rule
from runner._loading import load_rules

def scan_host(host: str, user: str, rules_path: str) -> dict:
    """Scan a single host and return results."""
    with SSHSession(host, user=user, sudo=True) as ssh:
        caps = detect_capabilities(ssh)
        platform = detect_platform(ssh)
        rules = load_rules(rules_path)

        results = []
        for rule in rules:
            result = evaluate_rule(ssh, rule, caps)
            results.append({
                "rule_id": result.rule_id,
                "passed": result.passed,
                "evidence": {
                    "method": result.evidence.method,
                    "command": result.evidence.command,
                    "stdout": result.evidence.stdout,
                    "expected": result.evidence.expected,
                    "actual": result.evidence.actual,
                    "timestamp": result.evidence.timestamp.isoformat(),
                } if result.evidence else None,
                "frameworks": result.framework_refs,
            })

        return {
            "host": host,
            "platform": {"family": platform.family, "version": platform.version},
            "capabilities": caps,
            "results": results,
        }
```

### 11.3 Async/Parallel Scanning

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def scan_hosts_parallel(hosts: list[str], user: str, rules_path: str, workers: int = 10):
    """Scan multiple hosts in parallel."""
    loop = asyncio.get_event_loop()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        tasks = [
            loop.run_in_executor(executor, scan_host, host, user, rules_path)
            for host in hosts
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    return results
```

### 11.4 Using CLI Output

```python
import subprocess
import json

def scan_with_cli(inventory: str, rules_path: str) -> dict:
    """Use CLI for scanning, parse JSON output."""
    result = subprocess.run(
        [
            "aegis", "check",
            "-i", inventory,
            "--sudo",
            "-r", rules_path,
            "-o", "evidence",
            "-q",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Scan failed: {result.stderr}")

    return json.loads(result.stdout)
```

### 11.5 Storing Results in OpenWatch

```python
def store_scan_results(scan_data: dict, openwatch_db):
    """Store AEGIS results in OpenWatch database."""

    # Create scan session
    session = openwatch_db.create_scan_session(
        timestamp=scan_data["session"]["timestamp"],
        host=scan_data["host"]["hostname"],
        platform=scan_data["host"]["platform"],
    )

    # Store each result with evidence
    for result in scan_data["results"]:
        openwatch_db.store_result(
            session_id=session.id,
            rule_id=result["rule_id"],
            passed=result["passed"],
            evidence=result.get("evidence"),  # Store raw evidence
            frameworks=result.get("frameworks"),  # Store all framework refs
        )

    return session
```

---

## 12. Troubleshooting

### 12.1 SSH Connection Issues

```python
# Enable verbose SSH debugging
import logging
logging.getLogger("paramiko").setLevel(logging.DEBUG)

# Test connection
with SSHSession(host, user=user, sudo=True) as ssh:
    result = ssh.run("whoami")
    print(f"Connected as: {result.stdout}")
```

### 12.2 Capability Detection Failures

```bash
# Run with verbose output
aegis detect --host 192.168.1.100 --user admin --sudo -v
```

```python
# Debug specific probe
caps = detect_capabilities(ssh, verbose=True)
```

### 12.3 Rule Not Matching

Check:
1. Platform matches: `rule_applies_to_platform(rule, family, version)`
2. Capability gate matches: Check `when:` clause
3. Rule loaded: Verify severity/tag/category filters

### 12.4 Evidence Not Captured

Ensure you're using updated handlers. All 19 handlers in `handlers/checks/` capture evidence as of v1.0.0.

### 12.5 Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Permission denied (publickey)` | SSH key not accepted | Add key to authorized_keys |
| `sudo: a password is required` | NOPASSWD not configured | Add NOPASSWD to sudoers |
| `No matching implementation` | No capability match | Check capabilities, add default impl |
| `Rule not found` | Path or filter issue | Check path, severity, tags |

---

## Appendix A: Rule Schema

Full schema at `schema/rule.schema.json`. Key fields:

```yaml
id: string (required, matches filename)
title: string (required)
description: string
rationale: string
severity: low|medium|high|critical (required)
category: string (required, matches directory)
tags: list[string]
references:
  cis: {version: {section, level, type}}
  stig: {version: {vuln_id, stig_id, severity}}
  nist_800_53: list[string]
platforms:
  - family: string
    min_version: int
    max_version: int
implementations:
  - when: string|{all: [...]}|{any: [...]}
    default: bool
    check:
      method: string (required)
      # method-specific fields
    remediation:
      mechanism: string
      # mechanism-specific fields
```

---

## Appendix B: Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AEGIS_RULES_PATH` | Default rules directory | `rules/` |
| `AEGIS_MAPPINGS_PATH` | Default mappings directory | `mappings/` |
| `AEGIS_DB_PATH` | SQLite database path | `.aegis/results.db` |

---

## Appendix C: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-02 | Initial release with evidence capture |

---

**Questions?** Contact the AEGIS team or open an issue at https://github.com/Hanalyx/aegis/issues
