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
    engine.py             # Re-export facade (backward compat)
    _types.py            # CheckResult, PreState, StepResult, RollbackResult, RuleResult
    _loading.py          # load_rules(), rule_applies_to_platform()
    _selection.py        # evaluate_when(), select_implementation()
    _checks.py           # Check handlers + dispatch
    _remediation.py      # Remediation handlers + _reload_service
    _capture.py          # Pre-state capture handlers
    _rollback.py         # Rollback handlers + _execute_rollback
    _orchestration.py    # evaluate_rule(), remediate_rule()
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
| `detect.py` | Capability probes, platform detection (with fallback chain: os-release → redhat-release → debian_version) | Rule evaluation |
| `engine.py` | Re-export facade + convenience functions (`check_single_rule`, `check_rules_from_path`, `quick_host_info`) | Everything (delegates to `_*.py` sub-modules) |
| `_types.py` | Result dataclasses (CheckResult, PreState, StepResult, RollbackResult, RuleResult) | Any logic |
| `_loading.py` | Rule loading from YAML, severity/tag/category filters, platform filtering | Rule evaluation |
| `_selection.py` | Capability gate evaluation, implementation selection | Rule loading, checks |
| `_checks.py` | Check handlers + dispatch (run_check, CHECK_HANDLERS) | Remediation, SSH connections |
| `_remediation.py` | Remediation handlers + dispatch + _reload_service (REMEDIATION_HANDLERS) | Orchestration |
| `_capture.py` | Pre-state capture handlers (CAPTURE_HANDLERS) | Rollback logic |
| `_rollback.py` | Rollback handlers + _execute_rollback (ROLLBACK_HANDLERS) | Check logic |
| `_orchestration.py` | evaluate_rule(), remediate_rule() — top-level rule evaluation | CLI output, SSH connections |
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
1. Add function `_check_<name>(ssh, c) -> CheckResult` in `runner/_checks.py`
2. Register in `CHECK_HANDLERS` dict in `runner/_checks.py`
3. See `context/patterns.md` for template

### New Remediation Handler
1. Add function `_remediate_<name>(ssh, r, *, dry_run) -> tuple[bool, str]` in `runner/_remediation.py`
2. Register in `REMEDIATION_HANDLERS` dict in `runner/_remediation.py`
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

## Inventory Files

For repeated testing, create a local `inventory.ini` (gitignored):

```ini
# inventory.ini — Ansible INI format
[test]
192.168.1.100 ansible_user=admin
192.168.1.101 ansible_user=admin

[production]
prod-server-1 ansible_user=deploy ansible_port=2222
```

Supports Ansible INI, YAML, or plain text (one host per line). Use `--limit` to filter by group or hostname glob.

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

# Using inventory file (recommended for repeated testing)
./aegis detect --inventory inventory.ini --sudo
./aegis check --inventory inventory.ini --sudo --category access-control
./aegis check --inventory inventory.ini --sudo --limit 192.168.1.211 --rule rules/access-control/ssh-disable-root-login.yml
```

### Programmatic Usage

The engine module provides convenience functions for scripting:

```python
from runner.ssh import SSHSession
from runner.engine import check_single_rule, check_rules_from_path, quick_host_info

with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
    # Get host info in one call
    caps, platform = quick_host_info(ssh)

    # Check a single rule
    result = check_single_rule(ssh, "rules/access-control/ssh-disable-root-login.yml")

    # Check multiple rules with filtering
    results = check_rules_from_path(ssh, "rules/", severity=["high", "critical"])
```

## Dependencies

- Python 3.10+
- paramiko (SSH)
- PyYAML (rule parsing)
- click (CLI framework)
- rich (terminal output)
- jsonschema (rule validation only)
- reportlab (PDF output, optional)

## Code Quality

### Pre-commit Hooks

Pre-commit is configured to enforce code quality. Install and run:

```bash
pip install pre-commit ruff
pre-commit install           # Install hooks
pre-commit run --all-files   # Run on all files
```

Hooks include:
- **ruff**: Linting and auto-fixing (replaces flake8, isort, black)
- **ruff-format**: Code formatting
- **Trailing whitespace / EOF fixer**
- **YAML/JSON validation**
- **Rule schema validation**

### Coding Standards

- Use `from __future__ import annotations` at top of each file
- Type hints on all function signatures
- Dataclasses for structured data, not dicts
- No classes where a function suffices
- Functions should have docstrings (public APIs)
- Use ruff for formatting — don't argue about style

### Ruff Rules

The project uses these ruff rule sets (see `ruff.toml`):
- `E,F,W`: pycodestyle + pyflakes basics
- `I`: isort (import sorting)
- `B`: flake8-bugbear (common bugs)
- `C4`: flake8-comprehensions
- `SIM`: flake8-simplify
- `UP`: pyupgrade (modern Python syntax)

Run manually: `ruff check runner/ --fix && ruff format runner/`

## Conventions

- Python type hints throughout, `from __future__ import annotations` at top of each file
- Dataclasses for data types, not dicts
- No classes where a function suffices
- Error handling: per-rule, not per-run — one rule failing doesn't stop others
- Parallel host execution with `--workers N` (default: 1, max: 50)

## Output Formats

The CLI supports multiple output formats for `check` and `remediate` commands:

```bash
# JSON to stdout
./aegis check -i inventory.ini --sudo -r rules/ -o json -q

# CSV to file
./aegis check -i inventory.ini --sudo -r rules/ -o csv:results.csv

# PDF report (requires reportlab)
./aegis check -i inventory.ini --sudo -r rules/ -o pdf:report.pdf

# Multiple outputs
./aegis check -i inventory.ini --sudo -r rules/ -o json:r.json -o csv:r.csv -o pdf:report.pdf
```

Flags:
- `-o, --output FORMAT[:PATH]`: Output format (csv, json, pdf). PDF requires a filepath.
- `-q, --quiet`: Suppress terminal output (useful with -o)
