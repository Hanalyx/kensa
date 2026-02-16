# CLAUDE.md — Aegis Project Guide

## What is Aegis

SSH-based compliance test runner. Takes canonical YAML rules, connects to remote RHEL hosts, detects capabilities, runs checks with evidence capture, reports pass/fail with framework mappings, and optionally remediates. The core idea: one rule per control, capability-gated implementations handle OS/config differences.

**Current stats:** 338 rules | 7 framework mappings | 22 capability probes | 20 check handlers | 23 remediation handlers

## Project Layout

```
aegis/
  aegis                  # Entry point shim
  runner/
    cli.py               # Click CLI, rich output, orchestration
    ssh.py               # SSHSession wrapper around paramiko
    inventory.py         # Inventory parser + host list (INI, YAML, plain text)
    detect.py            # 22 capability probes (name -> shell command)
    engine.py            # Re-export facade (backward compat)
    shell_util.py        # Shared shell command utilities (quoting, file ops)
    _types.py            # Evidence, CheckResult, PreState, StepResult, RollbackResult, RuleResult
    _loading.py          # load_rules(), rule_applies_to_platform()
    _selection.py        # evaluate_when(), select_implementation()
    _checks.py           # Re-export: handlers from handlers/checks/
    _remediation.py      # Re-export: handlers from handlers/remediation/
    _capture.py          # Re-export: handlers from handlers/capture/
    _rollback.py         # Re-export: handlers from handlers/rollback/
    _orchestration.py    # evaluate_rule(), remediate_rule(), _extract_framework_refs()
    _config.py           # Rule variables configuration system
    mappings.py          # Framework mapping loader (CIS, STIG, NIST, PCI-DSS, FedRAMP)
    storage.py           # SQLite result persistence with evidence
    conflicts.py         # Rule conflict detection
    ordering.py          # Dependency ordering
    handlers/            # Modular handler packages
      checks/            # 19 check handlers by domain
        _config.py       # config_value, config_absent
        _file.py         # file_permission, file_exists, file_not_exists, file_content_match, file_content_no_match
        _system.py       # sysctl_value, kernel_module_state, mount_option, grub_parameter
        _service.py      # service_state, systemd_target
        _package.py      # package_state
        _security.py     # selinux_state, selinux_boolean, audit_rule_exists, pam_module
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
    output/              # Output formatters
      __init__.py        # HostResult, RunResult, write_output()
      json_fmt.py        # JSON output formatter
      csv_fmt.py         # CSV output formatter
      pdf_fmt.py         # PDF report formatter
      evidence_fmt.py    # Evidence export formatter (for OpenWatch)
      evidence_schema.json # JSON Schema for evidence output
  rules/                 # 338 canonical YAML rules (the content)
    access-control/      # SSH, PAM, authentication
    audit/               # AIDE, auditd
    filesystem/          # File permissions, mount options
    kernel/              # Sysctl, kernel modules
    logging/             # Journald, rsyslog
    network/             # Firewall, network params
    services/            # Service hardening
    system/              # Crypto policy, bootloader
  mappings/              # Framework mapping files
    cis/                 # CIS RHEL 8/9 mappings
    stig/                # STIG RHEL 8/9 mappings
    nist/                # NIST 800-53 R5 mapping
    pci-dss/             # PCI-DSS v4.0 mapping
    fedramp/             # FedRAMP Moderate mapping
  schema/
    rule.schema.json     # JSON Schema — single source of truth for rule format
    validate.py          # Schema + business rule validator
  docs/
    AEGIS_Developer_Guide_v1.0.0.md  # Complete API reference
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

### Evidence Capture Is Mandatory
- All check handlers MUST return `CheckResult` with `Evidence` object
- Evidence contains: method, command, stdout, stderr, exit_code, expected, actual, timestamp
- Evidence flows through: CheckResult → RuleResult → output formatters

### Framework References Are Extracted at Evaluation Time
- `_orchestration.py` extracts `framework_refs` from rule's `references:` section
- Flattened to `{"cis_rhel9_v2": "5.1.12", "stig_rhel9_v2r7": "V-257983", ...}`
- Available in RuleResult regardless of `--framework` flag

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
| `detect.py` | 22 capability probes, platform detection (os-release → redhat-release → debian_version) | Rule evaluation |
| `engine.py` | Re-export facade + convenience functions (`check_single_rule`, `check_rules_from_path`, `quick_host_info`) | Everything (delegates to `_*.py` sub-modules) |
| `shell_util.py` | Shared shell utilities: quoting, file ops, grep/sed helpers, service actions | Business logic |
| `_types.py` | Result dataclasses (Evidence, CheckResult, PreState, StepResult, RollbackResult, RuleResult) | Any logic |
| `_loading.py` | Rule loading from YAML, severity/tag/category filters, platform filtering | Rule evaluation |
| `_selection.py` | Capability gate evaluation, implementation selection | Rule loading, checks |
| `_checks.py` | Re-exports CHECK_HANDLERS and run_check from handlers/checks/ | Handler implementations |
| `_remediation.py` | Re-exports REMEDIATION_HANDLERS and run_remediation from handlers/remediation/ | Handler implementations |
| `_capture.py` | Re-exports CAPTURE_HANDLERS from handlers/capture/ | Handler implementations |
| `_rollback.py` | Re-exports ROLLBACK_HANDLERS and _execute_rollback from handlers/rollback/ | Handler implementations |
| `handlers/checks/` | 19 check handler implementations by domain, evidence capture | Dispatch logic |
| `handlers/remediation/` | Remediation handler implementations by domain | Dispatch logic |
| `handlers/capture/` | Pre-state capture handler implementations | Rollback logic |
| `handlers/rollback/` | Rollback handler implementations | Capture logic |
| `_orchestration.py` | evaluate_rule(), remediate_rule(), _extract_framework_refs() | CLI output, SSH connections |
| `mappings.py` | Framework mapping loading, filtering, rule-to-section lookup | Rule definitions |
| `storage.py` | SQLite persistence, evidence storage, framework_refs storage | Business logic |
| `output/` | Output formatters (JSON, CSV, PDF, Evidence) | Result computation |
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
3. **MUST capture Evidence** — include method, command, stdout, stderr, exit_code, expected, actual, timestamp
4. Use `shell_util` for quoting and common operations
5. Register in `CHECK_HANDLERS` dict in `handlers/checks/__init__.py`
6. See existing handlers for evidence capture pattern

```python
from datetime import datetime, timezone
from runner._types import CheckResult, Evidence

def _check_example(ssh, c: dict) -> CheckResult:
    check_time = datetime.now(timezone.utc)
    cmd = f"some-command {shell_util.quote(c['param'])}"
    result = ssh.run(cmd)

    passed = result.exit_code == 0
    return CheckResult(
        passed=passed,
        detail="...",
        evidence=Evidence(
            method="example",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=c.get("expected"),
            actual=result.stdout.strip(),
            timestamp=check_time,
        ),
    )
```

### New Remediation Handler
1. Identify the domain module (`handlers/remediation/_config.py`, `_file.py`, etc.)
2. Add function `_remediate_<name>(ssh, r, *, dry_run) -> tuple[bool, str]` to the domain module
3. Use `shell_util` for quoting and common operations
4. Call `shell_util.service_action(ssh, r)` if the mechanism supports `reload`/`restart`
5. Register in `REMEDIATION_HANDLERS` dict in `handlers/remediation/__init__.py`
6. Add corresponding capture handler in `handlers/capture/` (same domain module)
7. Add corresponding rollback handler in `handlers/rollback/` (same domain module)

### New Capability Probe
1. Add entry to `CAPABILITY_PROBES` dict in `detect.py`
2. Value is a shell command where exit 0 = capability present
3. Keep probes fast and side-effect free

```python
CAPABILITY_PROBES = {
    # ... existing probes ...
    "new_capability": "command -v something >/dev/null 2>&1",
}
```

### New Rule
1. Create YAML file in appropriate `rules/<category>/` directory
2. Filename must match `id` field (kebab-case)
3. Include `references:` for framework mappings
4. Validate: `python -m schema.validate rules/<category>/<id>.yml`
5. Use existing check methods and remediation mechanisms

### New Framework Mapping
1. Create mapping file in `mappings/<framework>/<version>.yaml`
2. Use appropriate format:
   - CIS/STIG: `sections:` or `findings:` with one rule per section
   - NIST/PCI/FedRAMP: `controls:` or `requirements:` with rules list per control
3. Update `mappings.py` if new framework type needs special parsing

## Inventory Files

For repeated testing, create a local `inventory.ini` (gitignored):

```ini
# inventory.ini — INI format
[test]
192.168.1.100 user=admin
192.168.1.101 user=admin

[production]
prod-server-1 user=deploy port=2222
```

Supports INI, YAML, or plain text (one host per line). Use `--limit` to filter by group or hostname glob.

## Testing

Run from the `aegis/` directory:

```bash
# Quick smoke test — imports and CLI help
python3 -c "from runner.cli import main" && ./aegis --help

# Validate all rules against schema
python -m schema.validate rules/

# Live test against a host (requires SSH access)
./aegis detect --sudo --host <ip> --user <user>
./aegis check --sudo --host <ip> --user <user> --rule rules/access-control/ssh-disable-root-login.yml

# Using inventory file (recommended for repeated testing)
./aegis detect --inventory inventory.ini --sudo
./aegis check --inventory inventory.ini --sudo --category access-control
./aegis check --inventory inventory.ini --sudo --limit 192.168.1.211 --rule rules/

# Test evidence output
./aegis check --inventory inventory.ini --sudo --rule rules/ -o evidence:test.json -q
```

### Programmatic Usage

```python
from runner.ssh import SSHSession
from runner.detect import detect_capabilities, detect_platform
from runner._orchestration import evaluate_rule
from runner._loading import load_rules

with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
    caps = detect_capabilities(ssh)
    platform = detect_platform(ssh)
    rules = load_rules("rules/")

    for rule in rules:
        result = evaluate_rule(ssh, rule, caps)

        # Access evidence
        if result.evidence:
            print(f"Command: {result.evidence.command}")
            print(f"Actual: {result.evidence.actual}")

        # Access framework refs
        print(f"Frameworks: {result.framework_refs}")
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

**Function Docstrings (Required for public APIs):**
Use Google-style docstrings with:
- Summary line (imperative mood)
- Detailed description if non-obvious
- Args section with types and descriptions
- Returns section with type and description
- Raises section if applicable

### Ruff Rules

The project uses these ruff rule sets (see `pyproject.toml`):
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

# Evidence format (for OpenWatch integration)
./aegis check -i inventory.ini --sudo -r rules/ -o evidence:evidence.json

# Multiple outputs
./aegis check -i inventory.ini --sudo -r rules/ -o json:r.json -o csv:r.csv -o evidence:e.json
```

Flags:
- `-o, --output FORMAT[:PATH]`: Output format (csv, json, pdf, evidence). PDF requires a filepath.
- `-q, --quiet`: Suppress terminal output (useful with -o)

## Framework Mappings

Available frameworks:
- `cis-rhel9-v2.0.0` - CIS RHEL 9 Benchmark v2.0.0 (271 controls)
- `cis-rhel8-v4.0.0` - CIS RHEL 8 Benchmark v4.0.0 (120 controls)
- `stig-rhel9-v2r7` - STIG RHEL 9 V2R7 (338 controls)
- `stig-rhel8-v2r6` - STIG RHEL 8 V2R6 (116 controls)
- `nist-800-53-r5` - NIST SP 800-53 Rev. 5 (87 controls)
- `pci-dss-v4.0` - PCI-DSS v4.0 (45 requirements)
- `fedramp-moderate` - FedRAMP Moderate Baseline (87 controls)

```bash
# Run checks filtered by framework
./aegis check -i inventory.ini --sudo -r rules/ --framework cis-rhel9-v2.0.0

# Show framework coverage
./aegis coverage --framework cis-rhel9-v2.0.0

# Show framework info
./aegis info --framework stig-rhel9-v2r7
```

## Documentation

- [AEGIS Developer Guide](docs/AEGIS_Developer_Guide_v1.0.0.md) - Complete API reference for integration
- [Rule Schema](CANONICAL_RULE_SCHEMA_V0.md) - Full rule format documentation
- [README.md](README.md) - Quick start and overview
