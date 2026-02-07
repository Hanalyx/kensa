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
    inventory.py         # Ansible inventory parser + host list
    detect.py            # Capability probes (name -> shell command)
    engine.py            # Re-export facade (backward compat)
    shell_util.py        # Shared shell command utilities (quoting, file ops)
    _types.py            # CheckResult, PreState, StepResult, RollbackResult, RuleResult
    _loading.py          # load_rules(), rule_applies_to_platform()
    _selection.py        # evaluate_when(), select_implementation()
    _checks.py           # Re-export: handlers from handlers/checks/
    _remediation.py      # Re-export: handlers from handlers/remediation/
    _capture.py          # Re-export: handlers from handlers/capture/
    _rollback.py         # Re-export: handlers from handlers/rollback/
    _orchestration.py    # evaluate_rule(), remediate_rule()
    handlers/            # Modular handler packages
      checks/            # Check handlers by domain
        _config.py       # config_value, config_absent
        _file.py         # file_permission, file_exists, etc.
        _system.py       # sysctl_value, kernel_module_state, etc.
        _service.py      # service_state
        _package.py      # package_state
        _security.py     # selinux_*, audit_rule_exists, pam_module
        _command.py      # command
      remediation/       # Remediation handlers by domain
        _config.py       # config_set, config_set_dropin, etc.
        _file.py         # file_permissions, file_content, file_absent
        _system.py       # sysctl_set, kernel_module_disable, etc.
        _service.py      # service_enabled/disabled/masked
        _package.py      # package_present/absent
        _security.py     # selinux_boolean_set, audit_rule_set, etc.
        _command.py      # command_exec, manual
      capture/           # Pre-state capture handlers (mirrors remediation)
      rollback/          # Rollback handlers (mirrors remediation)
  rules/                 # Canonical YAML rules (the content)
    access-control/      # SSH, PAM, authentication
    audit/               # AIDE, auditd
    filesystem/          # File permissions, mount options
    kernel/              # Sysctl, kernel modules
    logging/             # Journald, rsyslog
    network/             # Firewall, network params
    services/            # Service hardening
    system/              # Crypto policy, bootloader
  schema/
    rule.schema.json     # JSON Schema — single source of truth for rule format
    validate.py          # Schema + business rule validator
  context/               # Architecture, patterns, security reference
  prd/                   # Product requirements, prioritized task files
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
| `shell_util.py` | Shared shell utilities: quoting, file ops, grep/sed helpers, service actions | Business logic |
| `_types.py` | Result dataclasses (CheckResult, PreState, StepResult, RollbackResult, RuleResult) | Any logic |
| `_loading.py` | Rule loading from YAML, severity/tag/category filters, platform filtering | Rule evaluation |
| `_selection.py` | Capability gate evaluation, implementation selection | Rule loading, checks |
| `_checks.py` | Re-exports CHECK_HANDLERS and run_check from handlers/checks/ | Handler implementations |
| `_remediation.py` | Re-exports REMEDIATION_HANDLERS and run_remediation from handlers/remediation/ | Handler implementations |
| `_capture.py` | Re-exports CAPTURE_HANDLERS from handlers/capture/ | Handler implementations |
| `_rollback.py` | Re-exports ROLLBACK_HANDLERS and _execute_rollback from handlers/rollback/ | Handler implementations |
| `handlers/checks/` | Check handler implementations by domain | Dispatch logic |
| `handlers/remediation/` | Remediation handler implementations by domain | Dispatch logic |
| `handlers/capture/` | Pre-state capture handler implementations | Rollback logic |
| `handlers/rollback/` | Rollback handler implementations | Capture logic |
| `_orchestration.py` | evaluate_rule(), remediate_rule() — top-level rule evaluation | CLI output, SSH connections |
| `cli.py` | CLI flags, orchestration flow, rich output formatting | Rule logic, SSH internals |

## Security Rules

This project runs arbitrary shell commands on remote hosts. Shell injection is the primary risk.

### Always
- Use `shell_util.quote()` (or `shlex.quote()`) on any value derived from rule YAML or user input
- Use `shell_util.quote_path()` for file paths — automatically handles glob detection
- Use `shell_util` helpers for file operations, grep, sed patterns
- Exception: paths with glob characters (`*`, `?`, `[`) must NOT be quoted — use `shell_util.is_glob_path()` to detect

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
1. Identify the domain module (`handlers/checks/_config.py`, `_file.py`, `_system.py`, etc.)
2. Add function `_check_<name>(ssh, c) -> CheckResult` to the appropriate domain module
3. Use `shell_util` for quoting and common operations
4. Register in `CHECK_HANDLERS` dict in `handlers/checks/__init__.py`
5. See `context/patterns.md` for template

### New Remediation Handler
1. Identify the domain module (`handlers/remediation/_config.py`, `_file.py`, etc.)
2. Add function `_remediate_<name>(ssh, r, *, dry_run) -> tuple[bool, str]` to the domain module
3. Use `shell_util` for quoting and common operations
4. Call `shell_util.service_action(ssh, r)` if the mechanism supports `reload`/`restart`
5. Register in `REMEDIATION_HANDLERS` dict in `handlers/remediation/__init__.py`
6. Add corresponding capture handler in `handlers/capture/` (same domain module)
7. Add corresponding rollback handler in `handlers/rollback/` (same domain module)
8. See `context/patterns.md` for template

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
# Install pre-commit (choose one method)
pip install pre-commit        # In virtualenv
pipx install pre-commit       # System-wide via pipx

# Install git hooks (run once per clone)
pre-commit install

# Run all hooks manually
pre-commit run --all-files

# Run specific hook
pre-commit run mypy --all-files
pre-commit run ruff --all-files
```

Hooks configured in `.pre-commit-config.yaml`:
- **ruff**: Linting and auto-fixing (replaces flake8, isort, black)
- **ruff-format**: Code formatting
- **mypy**: Static type checking with type stubs for PyYAML and paramiko
- **pydocstyle**: Docstring style enforcement (Google convention)
- **Trailing whitespace / EOF fixer**
- **YAML/JSON validation**
- **Rule schema validation**: Validates rule YAML against `schema/rule.schema.json`

### Coding Standards

**File Structure:**
- Use `from __future__ import annotations` at top of each file
- Use `TYPE_CHECKING` for import-only type hints
- Group imports: stdlib, third-party, local (ruff handles this)
- Use section headers (`# ── Section ───`) for visual organization

**Type Hints:**
- Type hints on all function signatures
- Use `| None` instead of `Optional[]`
- Use `list[]`, `dict[]` instead of `List[]`, `Dict[]`

**Data Structures:**
- Dataclasses for structured data, not dicts
- No classes where a function suffices
- Named tuples for simple immutable records

**Code Style:**
- Use ruff for formatting — don't argue about style
- Extract helper functions for readability (prefix with `_` for private)
- Keep functions focused and under ~50 lines

### Documentation Standards

**Module Docstrings (Required):**
Every module must have a comprehensive docstring including:
1. Purpose and what the module provides
2. Key concepts or patterns used
3. Usage example with doctest-style code

```python
"""Capability detection probes for remote hosts.

This module detects host capabilities and platform information to enable
capability-gated rule implementations. Probes are fast, read-only shell
commands that determine what features are available on the target host.

Example:
-------
    >>> with SSHSession("192.168.1.100", user="admin") as ssh:
    ...     caps = detect_capabilities(ssh)
    ...     print(f"Has sshd_config.d: {caps['sshd_config_d']}")

"""
```

**Function Docstrings (Required for public APIs):**
Use Google-style docstrings with:
- Summary line (imperative mood)
- Detailed description if non-obvious
- Args section with types and descriptions
- Returns section with type and description
- Raises section if applicable
- Example section for complex functions

```python
def detect_platform(ssh: SSHSession) -> PlatformInfo | None:
    """Detect the remote host's OS family and version.

    Uses a fallback chain to detect platform information:
    1. /etc/os-release (preferred)
    2. /etc/redhat-release (fallback for older RHEL)

    Args:
        ssh: Active SSH session to the target host.

    Returns:
        PlatformInfo(family, version) on success, None if detection fails.

    Example:
        >>> platform = detect_platform(ssh)
        >>> if platform:
        ...     print(f"Detected: {platform.family} {platform.version}")

    """
```

**Dataclass/Class Docstrings:**
Document attributes and properties:

```python
@dataclass
class HostResult:
    """Results from a single host.

    Attributes:
        hostname: The target host's address or hostname.
        platform_family: Detected OS family (e.g., "rhel"), or None.
        error: Connection error message, or None if successful.

    Properties:
        pass_count: Number of rules that passed.
    """
```

**Comment Standards:**
- Section headers for visual organization: `# ── Section name ───`
- Explain "why" not "what" in inline comments
- Document design decisions and non-obvious behavior
- Add "how to extend" comments for extensible patterns

```python
# ── Capability probes ──────────────────────────────────────────────────
#
# Each probe maps a capability name to a shell command.
# Adding a new probe:
#   1. Add entry to this dict
#   2. Use capability name in rule `when:` gates
#   3. No code changes needed elsewhere
```

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
