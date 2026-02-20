# P1-5: Handler Modularization

## Status: Complete

## Problem

The handler modules have grown to sizes that impede maintainability:

| Module | Lines | Handlers | Concern |
|--------|-------|----------|---------|
| `_remediation.py` | 1,423 | 23 | Monolithic, hard to navigate |
| `_checks.py` | 1,135 | 18 | Monolithic, hard to navigate |
| `_capture.py` | 455 | 22 | Mirrors remediation 1:1 |
| `_rollback.py` | 442 | 22 | Mirrors remediation 1:1 |

Current architecture requires editing 3-4 files to add a single remediation mechanism. At 300 rules with 40+ mechanisms, this becomes error-prone and slows development.

### Specific Issues

1. **Monolithic files**: 1000+ LOC files are hard to navigate and review
2. **Handler triplication**: Each remediation mechanism requires parallel capture and rollback handlers
3. **Code duplication**: grep/sed patterns repeated across handlers without abstraction
4. **Inconsistent quoting**: `shlex.quote()` applied inconsistently across 67 call sites
5. **No domain separation**: Config, file, package, service, and security handlers mixed together

## Solution

Split handler modules by domain and extract shared utilities. Maintain backward compatibility through re-exports.

## Target Architecture

```
runner/
  handlers/                      # NEW: Handler subpackage
    __init__.py                  # Re-exports all handlers for backward compat

    checks/
      __init__.py                # CHECK_HANDLERS dict
      _config.py                 # config_value, config_absent
      _file.py                   # file_permission, file_exists, file_not_exists,
                                 # file_content_match, file_content_no_match
      _package.py                # package_state
      _service.py                # service_state
      _system.py                 # sysctl_value, kernel_module_state, mount_option,
                                 # grub_parameter
      _security.py               # selinux_state, selinux_boolean, audit_rule_exists,
                                 # pam_module
      _command.py                # command

    remediation/
      __init__.py                # REMEDIATION_HANDLERS dict
      _config.py                 # config_set, config_set_dropin, config_remove,
                                 # config_block
      _file.py                   # file_permissions, file_content, file_absent
      _package.py                # package_present, package_absent
      _service.py                # service_enabled, service_disabled, service_masked
      _system.py                 # sysctl_set, kernel_module_disable, mount_option_set,
                                 # grub_parameter_set, grub_parameter_remove, cron_job
      _security.py               # selinux_boolean_set, audit_rule_set,
                                 # pam_module_configure
      _command.py                # command_exec, manual

    capture/
      __init__.py                # CAPTURE_HANDLERS dict
      _generic.py                # Generic capture strategies by mechanism type

    rollback/
      __init__.py                # ROLLBACK_HANDLERS dict
      _generic.py                # Generic rollback strategies by mechanism type

  shell_util.py                  # NEW: Shared shell command utilities

  # Backward compatibility re-exports
  _checks.py                     # from runner.handlers.checks import *
  _remediation.py                # from runner.handlers.remediation import *
  _capture.py                    # from runner.handlers.capture import *
  _rollback.py                   # from runner.handlers.rollback import *
```

## Phase 1: Extract Shell Utilities

Create `runner/shell_util.py` with common patterns:

```python
"""Shell command utilities for remote execution.

Provides safe, consistent helpers for common shell operations used
across check and remediation handlers.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.ssh import SSHSession, Result


def quote(value: str) -> str:
    """Quote a value for safe shell interpolation.

    Args:
        value: String to quote.

    Returns:
        Shell-safe quoted string.
    """
    return shlex.quote(str(value))


def is_glob_path(path: str) -> bool:
    """Check if a path contains glob characters.

    Args:
        path: File path to check.

    Returns:
        True if path contains *, ?, or [ characters.
    """
    return any(ch in path for ch in "*?[")


def quote_path(path: str, allow_glob: bool = False) -> str:
    """Quote a path, optionally preserving glob characters.

    Args:
        path: File path to quote.
        allow_glob: If True and path contains glob chars, don't quote.

    Returns:
        Quoted path or unquoted glob pattern.
    """
    if allow_glob and is_glob_path(path):
        return path
    return shlex.quote(path)


def grep_config_key(
    ssh: SSHSession,
    path: str,
    key: str,
    *,
    is_dir: bool = False,
    scan_pattern: str = "*.conf",
) -> Result:
    """Search for a config key in a file or directory.

    Args:
        ssh: Active SSH session.
        path: File or directory path.
        key: Config key to search for.
        is_dir: If True, search recursively in directory.
        scan_pattern: Glob pattern for directory mode.

    Returns:
        SSH Result with matching lines in stdout.
    """
    if is_dir:
        cmd = f"grep -rh '^ *{key}' {quote(path)}/{scan_pattern} 2>/dev/null | tail -1"
    else:
        cmd = f"grep -h '^ *{key}' {quote(path)} 2>/dev/null | tail -1"
    return ssh.run(cmd)


def file_exists(ssh: SSHSession, path: str) -> bool:
    """Check if a file exists.

    Args:
        ssh: Active SSH session.
        path: File path to check.

    Returns:
        True if file exists.
    """
    return ssh.run(f"test -f {quote(path)}").ok


def dir_exists(ssh: SSHSession, path: str) -> bool:
    """Check if a directory exists.

    Args:
        ssh: Active SSH session.
        path: Directory path to check.

    Returns:
        True if directory exists.
    """
    return ssh.run(f"test -d {quote(path)}").ok


def read_file(ssh: SSHSession, path: str) -> str | None:
    """Read file contents.

    Args:
        ssh: Active SSH session.
        path: File path to read.

    Returns:
        File contents or None if file doesn't exist.
    """
    result = ssh.run(f"cat {quote(path)} 2>/dev/null")
    return result.stdout if result.ok else None


def write_file(ssh: SSHSession, path: str, content: str) -> bool:
    """Write content to a file.

    Args:
        ssh: Active SSH session.
        path: File path to write.
        content: Content to write.

    Returns:
        True if successful.
    """
    return ssh.run(f"printf %s {quote(content)} > {quote(path)}").ok


def append_file(ssh: SSHSession, path: str, line: str) -> bool:
    """Append a line to a file.

    Args:
        ssh: Active SSH session.
        path: File path.
        line: Line to append.

    Returns:
        True if successful.
    """
    return ssh.run(f"echo {quote(line)} >> {quote(path)}").ok


def sed_replace(
    ssh: SSHSession,
    path: str,
    pattern: str,
    replacement: str,
) -> bool:
    """Replace pattern in file using sed.

    Args:
        ssh: Active SSH session.
        path: File path.
        pattern: Regex pattern to match.
        replacement: Replacement string.

    Returns:
        True if successful.

    Note:
        Automatically escapes / in pattern and replacement.
    """
    escaped_pattern = pattern.replace("/", "\\/")
    escaped_replacement = replacement.replace("/", "\\/")
    cmd = f"sed -i 's/{escaped_pattern}/{escaped_replacement}/' {quote(path)}"
    return ssh.run(cmd).ok


def sed_delete(ssh: SSHSession, path: str, pattern: str) -> bool:
    """Delete lines matching pattern using sed.

    Args:
        ssh: Active SSH session.
        path: File path.
        pattern: Regex pattern to match.

    Returns:
        True if successful.
    """
    escaped_pattern = pattern.replace("/", "\\/")
    return ssh.run(f"sed -i '/{escaped_pattern}/d' {quote(path)}").ok
```

## Phase 2: Split Check Handlers

Create domain-specific check modules:

### `runner/handlers/checks/_config.py` (~150 LOC)
- `_check_config_value`
- `_check_config_absent`

### `runner/handlers/checks/_file.py` (~200 LOC)
- `_check_file_permission`
- `_check_file_exists`
- `_check_file_not_exists`
- `_check_file_content_match`
- `_check_file_content_no_match`

### `runner/handlers/checks/_system.py` (~250 LOC)
- `_check_sysctl_value`
- `_check_kernel_module_state`
- `_check_mount_option`
- `_check_grub_parameter`

### `runner/handlers/checks/_service.py` (~80 LOC)
- `_check_service_state`

### `runner/handlers/checks/_package.py` (~60 LOC)
- `_check_package_state`

### `runner/handlers/checks/_security.py` (~250 LOC)
- `_check_selinux_state`
- `_check_selinux_boolean`
- `_check_audit_rule_exists`
- `_check_pam_module`

### `runner/handlers/checks/_command.py` (~60 LOC)
- `_check_command`

### `runner/handlers/checks/__init__.py`
```python
"""Check handlers dispatch.

Re-exports all check handlers and the CHECK_HANDLERS registry.
"""

from runner.handlers.checks._config import (
    _check_config_value,
    _check_config_absent,
)
from runner.handlers.checks._file import (
    _check_file_permission,
    _check_file_exists,
    _check_file_not_exists,
    _check_file_content_match,
    _check_file_content_no_match,
)
# ... etc

CHECK_HANDLERS = {
    "config_value": _check_config_value,
    "config_absent": _check_config_absent,
    # ... all handlers
}

def run_check(ssh, check):
    """Dispatch a check to the appropriate handler."""
    # Move existing run_check logic here
```

## Phase 3: Split Remediation Handlers

Same pattern as checks, organized by domain:

- `_config.py`: config_set, config_set_dropin, config_remove, config_block
- `_file.py`: file_permissions, file_content, file_absent
- `_package.py`: package_present, package_absent
- `_service.py`: service_enabled, service_disabled, service_masked
- `_system.py`: sysctl_set, kernel_module_disable, mount_option_set, grub_*, cron_job
- `_security.py`: selinux_boolean_set, audit_rule_set, pam_module_configure
- `_command.py`: command_exec, manual

## Phase 4: Generic Capture/Rollback Framework

Replace 22 capture handlers and 22 rollback handlers with a generic framework:

```python
# runner/handlers/capture/_generic.py

"""Generic pre-state capture strategies.

Instead of one handler per mechanism, use mechanism metadata
to determine capture strategy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


@dataclass
class PreState:
    """Captured pre-remediation state."""
    mechanism: str
    data: dict  # Mechanism-specific state


# Capture strategies by mechanism type
CAPTURE_STRATEGIES = {
    # Config mechanisms: capture current file content or key value
    "config_set": _capture_config_key,
    "config_set_dropin": _capture_file_content,
    "config_remove": _capture_config_key,
    "config_block": _capture_file_content,

    # File mechanisms: capture existence and content
    "file_permissions": _capture_file_stat,
    "file_content": _capture_file_content,
    "file_absent": _capture_file_content,

    # Package mechanisms: capture installed state
    "package_present": _capture_package_state,
    "package_absent": _capture_package_state,

    # Service mechanisms: capture enabled/active state
    "service_enabled": _capture_service_state,
    "service_disabled": _capture_service_state,
    "service_masked": _capture_service_state,

    # System mechanisms: capture current values
    "sysctl_set": _capture_sysctl_value,
    "kernel_module_disable": _capture_module_state,
    # ... etc
}


def capture_pre_state(ssh: SSHSession, remediation: dict) -> PreState | None:
    """Capture pre-remediation state using appropriate strategy.

    Args:
        ssh: Active SSH session.
        remediation: Remediation definition dict.

    Returns:
        PreState object or None if capture not supported.
    """
    mechanism = remediation.get("mechanism", "")
    strategy = CAPTURE_STRATEGIES.get(mechanism)

    if strategy is None:
        return None

    data = strategy(ssh, remediation)
    return PreState(mechanism=mechanism, data=data)


def _capture_config_key(ssh: SSHSession, r: dict) -> dict:
    """Capture current value of a config key."""
    path = r["path"]
    key = r["key"]
    result = shell_util.grep_config_key(ssh, path, key)
    return {"path": path, "key": key, "existed": result.ok, "line": result.stdout.strip()}


def _capture_file_content(ssh: SSHSession, r: dict) -> dict:
    """Capture file existence and content."""
    path = r.get("path") or f"{r.get('dir')}/{r.get('file')}"
    content = shell_util.read_file(ssh, path)
    return {"path": path, "existed": content is not None, "content": content}


def _capture_file_stat(ssh: SSHSession, r: dict) -> dict:
    """Capture file permissions."""
    path = r["path"]
    result = ssh.run(f"stat -c '%U %G %a' {shell_util.quote(path)} 2>/dev/null")
    if result.ok:
        parts = result.stdout.strip().split()
        return {"path": path, "existed": True, "owner": parts[0], "group": parts[1], "mode": parts[2]}
    return {"path": path, "existed": False}


# ... similar for other capture strategies
```

```python
# runner/handlers/rollback/_generic.py

"""Generic rollback strategies.

Restores pre-remediation state captured by capture module.
"""

ROLLBACK_STRATEGIES = {
    "config_set": _rollback_config_key,
    "config_set_dropin": _rollback_file_content,
    # ... etc
}


def rollback(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Rollback to pre-remediation state.

    Args:
        ssh: Active SSH session.
        pre_state: Captured pre-state from capture_pre_state().

    Returns:
        Tuple of (success, detail).
    """
    strategy = ROLLBACK_STRATEGIES.get(pre_state.mechanism)
    if strategy is None:
        return False, f"No rollback strategy for {pre_state.mechanism}"
    return strategy(ssh, pre_state.data)


def _rollback_config_key(ssh: SSHSession, data: dict) -> tuple[bool, str]:
    """Restore a config key to its previous value."""
    path = data["path"]
    key = data["key"]

    if not data["existed"]:
        # Key didn't exist before — remove it
        shell_util.sed_delete(ssh, path, f"^ *{key}")
        return True, f"Removed {key} from {path}"
    else:
        # Restore original line
        shell_util.sed_replace(ssh, path, f"^ *{key}.*", data["line"])
        return True, f"Restored {key} in {path}"
```

## Phase 5: Backward Compatibility Layer

Maintain imports for existing code:

```python
# runner/_checks.py (reduced to re-export)
"""Backward compatibility: re-export from handlers.checks."""

from runner.handlers.checks import CHECK_HANDLERS, run_check

__all__ = ["CHECK_HANDLERS", "run_check"]
```

```python
# runner/_remediation.py (reduced to re-export)
"""Backward compatibility: re-export from handlers.remediation."""

from runner.handlers.remediation import REMEDIATION_HANDLERS, run_remediation

__all__ = ["REMEDIATION_HANDLERS", "run_remediation"]
```

## Acceptance Criteria

### Phase 1: Shell Utilities ✅
- [x] `shell_util.py` created with quote, file, and sed helpers
- [x] All handlers updated to use `shell_util` instead of inline patterns
- [x] Consistent quoting across all handlers
- [x] All existing tests pass

### Phase 2: Check Handler Split ✅
- [x] `runner/handlers/checks/` package created
- [x] 7 domain modules with handlers moved
- [x] `CHECK_HANDLERS` dict in `__init__.py`
- [x] `runner/_checks.py` reduced to re-export
- [x] All existing tests pass

### Phase 3: Remediation Handler Split ✅
- [x] `runner/handlers/remediation/` package created
- [x] 7 domain modules with handlers moved
- [x] `REMEDIATION_HANDLERS` dict in `__init__.py`
- [x] `runner/_remediation.py` reduced to re-export
- [x] `service_action` in `shell_util.py` (was `_reload_service`)
- [x] All existing tests pass

### Phase 4: Capture/Rollback Modularization ✅
- [x] `runner/handlers/capture/` package with domain modules
- [x] `runner/handlers/rollback/` package with domain modules
- [x] Handlers use shell_util for consistency
- [x] `_capture.py` and `_rollback.py` reduced to re-exports
- [x] All existing tests pass
- Note: Generic strategy pattern deferred - domain modules provide sufficient
  organization without over-abstraction

### Phase 5: Documentation ✅
- [x] CLAUDE.md updated with new module structure
- [x] Handler addition guide updated with domain module workflow
- [x] Security rules updated to reference shell_util

## Migration Strategy

1. **Phase 1 first**: Extract utilities without changing structure
2. **Phase 2-3 in parallel**: Split checks and remediation independently
3. **Phase 4 last**: Generic capture/rollback after handlers are stable
4. **Each phase is a separate commit**: Easy to bisect if issues arise

## Metrics

Track these before and after:

| Metric | Before | After Target |
|--------|--------|--------------|
| Largest single file | 1,423 LOC | <400 LOC |
| Files to edit for new mechanism | 4 | 2 |
| Handler functions total | 85 | 50 |
| Duplicate code patterns | 15+ | 0 |
| Test coverage | ? | 80%+ |

## Future Extensions

- **Handler autodiscovery**: Scan `handlers/` for `_check_*` and `_remediate_*` functions
- **Plugin system**: Load third-party handlers from `~/.kensa/handlers/`
- **Handler profiling**: Track execution time per handler type
