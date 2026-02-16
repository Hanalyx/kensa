# P0: Test Runner Core (DONE)

## Status: Complete

## Summary
Built the V0 test runner: SSH-based engine that loads canonical YAML rules, connects to remote RHEL hosts, detects capabilities, selects implementations, runs checks, and reports pass/fail.

## What Was Delivered

### runner/ssh.py
- `SSHSession` class wrapping paramiko
- `connect()`, `run(cmd) -> Result(exit_code, stdout, stderr)`, `close()`
- Context manager support, 30s default timeout
- Transparent `sudo -n sh -c` wrapping via `--sudo` flag

### runner/inventory.py
- Three target sources: `--host` (comma-separated), Ansible inventory (INI + YAML), plain text host list
- Auto-detection of inventory format
- `--limit` filtering by group name or hostname glob
- `HostInfo` dataclass with per-host connection parameters
- CLI defaults as fallbacks, inventory per-host vars override (Ansible precedence)

### runner/detect.py
- 22 capability probes (name → shell command, exit 0 = present)
- `detect_capabilities(ssh) -> dict[str, bool]`

### runner/engine.py
- `load_rules()` with severity/tag/category filtering
- `evaluate_when()` supporting string, `{all: [...]}`, `{any: [...]}` gates
- `select_implementation()` — first matching gate wins, fallback to default
- 7 check handlers: config_value, file_permission, command, sysctl_value, kernel_module_state, package_state, file_exists
- 8 remediation handlers: config_set, config_set_dropin, command_exec, file_permissions, sysctl_set, package_present, kernel_module_disable, manual
- Glob path support in file_permission check and file_permissions remediation

### runner/cli.py
- Three subcommands: detect, check, remediate
- Multi-host sequential execution
- `--verbose` showing probe failures and implementation selection
- `--dry-run` on remediate
- Rich output: PASS/FAIL/FIXED/SKIP with per-host and cross-host summaries

## Validated On
- RHEL 9 host (192.168.1.211)
- 35 rules, 26 pass / 9 fail (with --sudo)
- Full check → remediate → re-check cycle confirmed working (ssh-max-auth-tries)
