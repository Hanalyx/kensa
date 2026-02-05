# Aegis

SSH-based compliance test runner for RHEL systems. One rule per security control, capability-gated implementations, check/remediate over SSH.

## Quick Start

```bash
pip install paramiko   # PyYAML, click, rich assumed present

# Probe host capabilities
./aegis detect --sudo --host 192.168.1.10 --user admin

# Check a single rule
./aegis check --sudo --host 192.168.1.10 --user admin \
  --rule rules/access-control/ssh-disable-root-login.yml

# Check all rules in a category
./aegis check --sudo --host 192.168.1.10 --user admin \
  --rules rules/access-control/

# Check all rules, filter by severity
./aegis check --sudo --host 192.168.1.10 --user admin \
  --rules rules/ --severity high --severity critical

# Remediate failures (dry run first)
./aegis remediate --sudo --host 192.168.1.10 --user admin \
  --rules rules/access-control/ --dry-run

# Remediate for real
./aegis remediate --sudo --host 192.168.1.10 --user admin \
  --rules rules/access-control/
```

## Multi-Host with Inventory

```bash
# Ansible INI inventory
./aegis check --sudo -i inventory.ini --user admin --rules rules/

# Ansible YAML inventory
./aegis check --sudo -i inventory.yml --rules rules/

# Limit to a group or pattern
./aegis check --sudo -i inventory.yml --limit webservers --rules rules/
./aegis check --sudo -i inventory.yml --limit 'web*' --rules rules/

# Plain text host list (one host per line)
./aegis check --sudo -i hosts.txt --user admin --key ~/.ssh/id_rsa --rules rules/
```

## How It Works

1. **Resolve targets** — from `--host`, Ansible inventory, or host list
2. **Connect** — SSH with key, password, or agent auth; optional `--sudo`
3. **Detect capabilities** — 22 probes (sshd_config.d? authselect? firewalld? SELinux? ...)
4. **Select implementations** — each rule has capability-gated variants; first matching gate wins, fallback to default
5. **Run checks** — typed handlers (config_value, file_permission, sysctl_value, command, etc.)
6. **Report** — PASS/FAIL per rule with detail, summaries per host and overall
7. **Remediate** (if requested) — check first, fix failures, re-check to confirm

## Rule Format

Rules are YAML files in `rules/<category>/`. Each rule declares one security control with one or more implementations:

```yaml
id: ssh-disable-root-login
title: Disable SSH root login
severity: high
category: access-control

implementations:
  - when: sshd_config_d              # Use drop-in if capability detected
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "PermitRootLogin"
      expected: "no"
      scan_pattern: "*.conf"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-aegis-permit-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"

  - default: true                     # Fallback to main config
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
      separator: " "
      reload: "sshd"
```

Full schema: `schema/rule.schema.json`. Detailed documentation: `CANONICAL_RULE_SCHEMA_V0.md`.

## Architecture

```
aegis              ← entry point shim
runner/
  cli.py           ← Click CLI, rich output, orchestration
  ssh.py           ← SSHSession (paramiko wrapper, sudo support)
  inventory.py     ← Target resolution (--host, Ansible INI/YAML, host lists)
  detect.py        ← 22 capability probes
  engine.py        ← Rule loading, implementation selection, check/remediate dispatch
rules/             ← 35 canonical YAML rules across 8 categories
schema/            ← JSON Schema + validator
```

## Requirements

- Python 3.10+
- paramiko
- PyYAML, click, rich (typically pre-installed)
- SSH access to target hosts (key or password auth)
- `--sudo` requires passwordless sudo on targets (`NOPASSWD` in sudoers)
