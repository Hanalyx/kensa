# CLAUDE.md — Aegis Project Guide

## What is Aegis

SSH-based compliance test runner. Takes canonical YAML rules, connects to remote RHEL hosts, detects capabilities, runs checks, reports pass/fail, and optionally remediates. The core idea: one rule per control, capability-gated implementations handle OS/config differences.

## Project Layout

```
aegis/
  aegis                  # Entry point shim
  runner/
    cli.py               # Click CLI, rich output, orchestration
    ssh.py               # SSHSession wrapper around paramiko
    inventory.py          # Ansible inventory parser + host list
    detect.py             # Capability probes (name -> shell command)
    engine.py             # Rule loading, check/remediate dispatch
  rules/                  # Canonical YAML rules (the content)
    access-control/       # SSH, PAM, authentication
    audit/                # AIDE, auditd
    filesystem/           # File permissions, mount options
    kernel/               # Sysctl, kernel modules
    logging/              # Journald, rsyslog
    network/              # Firewall, network params
    services/             # Service hardening
    system/               # Crypto policy, bootloader
  schema/
    rule.schema.json      # JSON Schema — single source of truth for rule format
    validate.py           # Schema + business rule validator
  context/                # Architecture, patterns, security reference
  prd/                    # Product requirements, prioritized task files
```

## Critical Invariants

### Rule Schema Is Canonical
- The rule format is defined in `schema/rule.schema.json` (Draft 2020-12)
- **Never invent new fields.** Check the schema first.
- Business rules enforced by `schema/validate.py`: filename matches `id`, category matches directory, exactly one `default: true` implementation
- Full documentation: `CANONICAL_RULE_SCHEMA_V0.md`

### All Remote Execution Goes Through SSHSession.run()
- No SFTP. All file operations use shell commands over SSH.
- No direct paramiko calls outside `runner/ssh.py`.
- `SSHSession.run()` handles sudo prefixing transparently when `--sudo` is set.

### Capability-Gated Implementations
- Rules have multiple implementations selected at runtime based on host capabilities.
- Non-default implementations have a `when:` gate (string, `{all: [...]}`, or `{any: [...]}`).
- Exactly one `default: true` implementation per rule is the fallback.
- First matching gate wins; if none match, default is used.
- Never hardcode OS version checks — use capabilities.

### Module Ownership
| Module | Owns | Does NOT own |
|--------|------|-------------|
| `ssh.py` | Connection lifecycle, command execution, sudo prefixing | Anything about rules or results |
| `inventory.py` | Target resolution from all sources, host filtering | SSH connections |
| `detect.py` | Capability probe definitions and execution | Rule evaluation |
| `engine.py` | Rule loading, filtering, check/remediate dispatch, result types | CLI output, SSH connections |
| `cli.py` | CLI flags, orchestration flow, rich output formatting | Rule logic, SSH internals |

## Security Rules

This project runs arbitrary shell commands on remote hosts. Shell injection is the primary risk.

### Always
- Use `shlex.quote()` on any value derived from rule YAML or user input before embedding in a shell command
- Exception: paths with glob characters (`*`, `?`, `[`) must NOT be quoted — detect via `glob` field or character inspection
- Sanitize all values before interpolating into `sed`, `grep`, or `echo` commands

### Never
- Never use f-strings to build commands with unquoted user input
- Never log SSH passwords or private key contents
- Never pass credentials as command-line arguments (visible in `ps`)
- Never write credentials to remote files

### Sudo Model
- `--sudo` flag causes all commands to run via `sudo -n sh -c '<cmd>'`
- `-n` = non-interactive (no password prompt). Assumes NOPASSWD sudo.
- The entire command is wrapped — sudo applies to probes, checks, and remediations uniformly.

## How to Add Things

### New Check Handler
1. Add function `_check_<name>(ssh, c) -> CheckResult` in `engine.py`
2. Register in `CHECK_HANDLERS` dict
3. See `context/patterns.md` for template

### New Remediation Handler
1. Add function `_remediate_<name>(ssh, r, *, dry_run) -> tuple[bool, str]` in `engine.py`
2. Register in `REMEDIATION_HANDLERS` dict
3. Call `_reload_service(ssh, r)` if the mechanism supports `reload`/`restart`
4. See `context/patterns.md` for template

### New Capability Probe
1. Add entry to `CAPABILITY_PROBES` dict in `detect.py`
2. Value is a shell command where exit 0 = capability present
3. Keep probes fast and side-effect free

### New Rule
1. Create YAML file in appropriate `rules/<category>/` directory
2. Filename must match `id` field (kebab-case)
3. Validate: `python3 schema/validate.py rules/<category>/<id>.yml`
4. Use existing check methods and remediation mechanisms — don't invent new ones without adding handlers

## Testing

Run from the `aegis/` directory:

```bash
# Quick smoke test — imports and CLI help
python3 -c "from runner.cli import main" && ./aegis --help

# Validate all rules against schema
python3 schema/validate.py rules/

# Live test against a host (requires SSH access)
./aegis detect --sudo --host <ip> --user <user>
./aegis check --sudo --host <ip> --user <user> --rule rules/access-control/ssh-disable-root-login.yml
```

## Dependencies

- Python 3.10+
- paramiko (SSH)
- PyYAML (rule parsing)
- click (CLI framework)
- rich (terminal output)
- jsonschema (rule validation only)

## Conventions

- Python type hints throughout, `from __future__ import annotations` at top of each file
- Dataclasses for data types, not dicts
- No classes where a function suffices
- Error handling: per-rule, not per-run — one rule failing doesn't stop others
- Sequential host execution (parallel is a P1 task)
