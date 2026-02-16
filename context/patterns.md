# Code Patterns

Concrete templates for the most common development tasks in Aegis. Copy, adapt, register.

Handlers are organized by domain across four symmetric packages under `runner/handlers/`:

```
runner/handlers/
  checks/        # Verification — 19 handlers across 7 domain modules
  remediation/   # Modification — 18+ handlers across 7 domain modules
  capture/       # Pre-state snapshot — mirrors remediation
  rollback/      # Restoration — mirrors remediation
```

Each package has domain modules: `_config.py`, `_file.py`, `_system.py`, `_service.py`, `_package.py`, `_security.py`, `_command.py`. Check handlers also have `_ssh.py`.


## Adding a Check Handler

Check handlers live in `runner/handlers/checks/<domain>.py`. Each takes an `SSHSession` and a check dict (from the rule YAML), returns a `CheckResult` with mandatory `Evidence`.

### Template

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_example(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that something has the expected value.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): What to check.
            - expected (str): Expected value.

    Returns:
        CheckResult with evidence attached.
    """
    key = c["key"]
    expected = str(c["expected"])
    check_time = datetime.now(timezone.utc)

    cmd = f"some-command {shell_util.quote(key)}"
    result = ssh.run(cmd)

    actual = result.stdout.strip()
    passed = actual == expected

    return CheckResult(
        passed=passed,
        detail=f"{key}: {actual} (expected {expected})" if not passed else f"{key}: {actual}",
        evidence=Evidence(
            method="example",
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

### Registration

Add to `CHECK_HANDLERS` dict in `runner/handlers/checks/__init__.py`:

```python
CHECK_HANDLERS = {
    # ... existing handlers ...
    "example": _check_example,
}
```

Import the function at the top of `__init__.py` from the appropriate domain module.

### Conventions

- Function name: `_check_<method_name>` where method_name matches the YAML `method:` value
- **Evidence is mandatory** — every `CheckResult` must include an `Evidence` object
- Capture `datetime.now(timezone.utc)` at the start, before running commands
- Use `shell_util.quote()` on all values from rule YAML before shell interpolation
- Use `shell_util.quote_path()` for file paths — handles glob detection automatically
- Return `CheckResult(passed=True/False, detail="...", evidence=Evidence(...))`
- Detail on failure should show actual vs expected
- Never raise exceptions for expected conditions — return a failing CheckResult
- Keep commands simple: one concept per `ssh.run()` call when possible
- Use `TYPE_CHECKING` guard for `SSHSession` import to avoid circular imports


## Adding a Remediation Handler

Remediation handlers live in `runner/handlers/remediation/<domain>.py`. They take an `SSHSession`, a remediation dict, and a `dry_run` flag. Return `(success: bool, detail: str)`.

### Template

```python
from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_example(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set something to the desired state.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): What to set.
            - value (str): Value to set.
            - reload/restart (str, optional): Service to reload after change.

    Returns:
        Tuple of (success, detail).
    """
    key = r["key"]
    value = r["value"]

    if dry_run:
        return True, f"Would set {key} to {value}"

    cmd = f"some-command {shell_util.quote(key)} {shell_util.quote(value)}"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to set {key}: {result.stderr}"

    shell_util.service_action(ssh, r)
    return True, f"Set {key} to {value}"
```

### Registration

Add to `REMEDIATION_HANDLERS` dict in `runner/handlers/remediation/__init__.py`:

```python
REMEDIATION_HANDLERS = {
    # ... existing handlers ...
    "example": _remediate_example,
}
```

### Conventions

- Function name: `_remediate_<mechanism_name>`
- `dry_run` must be keyword-only (`*, dry_run: bool = False`)
- Check `dry_run` early — return a description of what would happen
- Return `(True, detail)` on success, `(False, detail)` on failure
- Call `shell_util.service_action(ssh, r)` if the mechanism modifies service configs
- For multi-step operations, check idempotency guards (`unless`, `onlyif`) before acting
- Use `timeout=300` for slow operations (package installs)
- Use `shell_util.quote()` for all values from rule YAML


## Adding a Capture Handler

Capture handlers live in `runner/handlers/capture/<domain>.py`. Each takes an `SSHSession` and a remediation dict, returns a `PreState`. They run **read-only** SSH commands to snapshot the host's current state before a remediation step modifies it.

### Template

```python
from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_example(ssh: SSHSession, r: dict) -> PreState:
    """Capture current state before modification.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition dict.

    Returns:
        PreState with enough data to rollback.
    """
    key = r["key"]
    result = ssh.run(f"some-command --get {shell_util.quote(key)}")
    old_value = result.stdout.strip() if result.ok else None

    return PreState(
        mechanism="example",
        data={
            "key": key,
            "old_value": old_value,
            "existed": old_value is not None,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )
```

### Registration

Add to `CAPTURE_HANDLERS` dict in `runner/handlers/capture/__init__.py`:

```python
CAPTURE_HANDLERS = {
    # ... existing handlers ...
    "example": _capture_example,
}
```

### Conventions

- Function name: `_capture_<mechanism_name>` — matches the remediation mechanism
- **Read-only**: capture handlers must never modify host state
- Return `PreState(mechanism=..., data={...})` with enough info to rollback
- Store `reload`/`restart` keys from the remediation dict in `data` so rollback can call `shell_util.service_action`
- All values in `data` must be JSON-serializable (str, bool, None, list, dict)
- Set `capturable=False` for mechanisms where pre-state cannot be meaningfully captured (e.g., `command_exec`, `manual`)
- Keep commands fast — capture runs before every remediation step


## Adding a Rollback Handler

Rollback handlers live in `runner/handlers/rollback/<domain>.py`. Each takes an `SSHSession` and a `PreState`, returns `(success: bool, detail: str)`. They restore the host to the state captured before remediation.

### Template

```python
from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_example(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore to pre-remediation state.

    Args:
        ssh: Active SSH session to the target host.
        pre_state: Captured state from the corresponding capture handler.

    Returns:
        Tuple of (success, detail).
    """
    d = pre_state.data
    key = d["key"]

    if d["existed"] and d["old_value"]:
        cmd = f"some-command --set {shell_util.quote(key)} {shell_util.quote(d['old_value'])}"
        result = ssh.run(cmd)
        if not result.ok:
            return False, f"Failed to restore {key}: {result.stderr}"
    else:
        cmd = f"some-command --unset {shell_util.quote(key)}"
        ssh.run(cmd)

    if d.get("reload") or d.get("restart"):
        shell_util.service_action(
            ssh, {"reload": d.get("reload"), "restart": d.get("restart")}
        )
    return True, f"Restored {key} to previous state"
```

### Registration

Add to `ROLLBACK_HANDLERS` dict in `runner/handlers/rollback/__init__.py`:

```python
ROLLBACK_HANDLERS = {
    # ... existing handlers ...
    "example": _rollback_example,
}
```

### Conventions

- Function name: `_rollback_<mechanism_name>` — matches the capture/remediation mechanism
- Read `PreState.data` to determine what to restore
- Return `(True, detail)` on success, `(False, detail)` on failure
- Return `(False, "reason")` for mechanisms that cannot be rolled back (e.g., `command_exec`)
- Call `shell_util.service_action(ssh, {...})` after restoring config files
- Rollback handlers are called in **reverse order** by `_execute_rollback` — only successful, capturable steps are rolled back


## Adding All Four at Once

When adding a new mechanism, you need handlers in all four packages. The symmetric structure means:

1. **Check** in `handlers/checks/<domain>.py` — how to verify the state
2. **Remediation** in `handlers/remediation/<domain>.py` — how to fix it
3. **Capture** in `handlers/capture/<domain>.py` — how to snapshot before fixing
4. **Rollback** in `handlers/rollback/<domain>.py` — how to undo the fix

Register each in its package's `__init__.py`. The mechanism name ties them together.


## Adding a Capability Probe

Probes live in `runner/detect.py` as entries in the `CAPABILITY_PROBES` dict.

### Template

```python
CAPABILITY_PROBES: dict[str, str] = {
    # ... existing probes ...

    # New probe: check if chrony is the active NTP implementation
    "chrony": "systemctl is-active chronyd >/dev/null 2>&1",
}
```

### Conventions

- Value is a single shell command (or `&&`/`||` chain)
- Exit code 0 = capability present, non-zero = absent
- Suppress stderr with `2>/dev/null` to keep probe output clean
- Probes must be **fast** (< 2 seconds) and **side-effect free**
- Probes run on every host before any rules — keep the total count reasonable
- Name should match what rule `when:` gates reference


## Adding a Rule

### File Location

`rules/<category>/<id>.yml` — category must match one of: access-control, audit, filesystem, kernel, logging, network, services, system.

### Minimal Rule (Single Implementation)

```yaml
id: sysctl-net-ipv4-tcp-syncookies
title: Enable TCP SYN cookies
description: >
  TCP SYN cookies must be enabled to protect against SYN flood attacks
  when the SYN backlog queue fills up.
rationale: >
  Without SYN cookies, an attacker can exhaust server resources by
  sending a flood of SYN packets without completing the handshake.
severity: medium
category: kernel
tags: [sysctl, networking, dos-protection]

references:
  cis:
    rhel9_v2: { section: "3.3.8", level: "L1", type: "Automated" }
  nist_800_53: ["SC-5"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: sysctl_value
      key: "net.ipv4.tcp_syncookies"
      expected: "1"
    remediation:
      mechanism: sysctl_set
      key: "net.ipv4.tcp_syncookies"
      value: "1"
```

### Capability-Gated Rule (Two Implementations)

```yaml
implementations:
  - when: sshd_config_d                    # Gate: use if capability detected
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "SomeKey"
      expected: "some_value"
      scan_pattern: "*.conf"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-aegis-some-key.conf"
      key: "SomeKey"
      value: "some_value"
      reload: "sshd"

  - default: true                           # Fallback: always matches
    check:
      method: config_value
      path: "/etc/ssh/sshd_config"
      key: "SomeKey"
      expected: "some_value"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "SomeKey"
      value: "some_value"
      separator: " "
      reload: "sshd"
```

### Multi-Condition Check + Multi-Step Remediation

```yaml
implementations:
  - default: true
    check:
      checks:                               # AND semantics — all must pass
        - method: package_state
          name: "aide"
          state: "present"
        - method: file_exists
          path: "/var/lib/aide/aide.db.gz"
    remediation:
      steps:                                # Sequential execution
        - mechanism: package_present
          name: "aide"
        - mechanism: command_exec
          run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
          unless: "test -f /var/lib/aide/aide.db.gz"
```

### Validation

```bash
python3 schema/validate.py rules/<category>/<id>.yml
```

Checks JSON Schema compliance plus business rules (id/filename match, category/directory match, exactly one default implementation).


## Pattern: shell_util Usage

`runner/shell_util.py` provides safe utilities for all shell operations. Prefer these over raw string formatting.

### Quoting

```python
shell_util.quote(value)           # shlex.quote — use for all rule YAML values
shell_util.quote_path(path)       # Quote path, auto-detects globs
shell_util.is_glob_path(path)     # True if path has *, ?, or [
```

### File Operations

```python
shell_util.file_exists(ssh, path)             # bool
shell_util.dir_exists(ssh, path)              # bool
shell_util.read_file(ssh, path)               # str | None
shell_util.write_file(ssh, path, content)     # bool
shell_util.append_line(ssh, path, line)        # bool
```

### Config Operations

```python
shell_util.grep_config_key(ssh, path, key, scan_pattern="*.conf")  # Result
shell_util.config_key_exists(ssh, path, key)                        # bool
shell_util.parse_config_value(line, key)                            # str
```

### Sed Operations (auto-escapes delimiters)

```python
shell_util.sed_replace_line(ssh, path, pattern, replacement)  # bool
shell_util.sed_delete_line(ssh, path, pattern)                # bool
```

### Service Operations

```python
shell_util.reload_service(ssh, service)     # bool
shell_util.restart_service(ssh, service)    # bool
shell_util.service_action(ssh, r)           # Checks r for reload/restart keys
```

### File Stat/Permissions

```python
shell_util.get_file_stat(ssh, path, allow_glob=False)                          # Result
shell_util.set_file_owner(ssh, path, owner=None, group=None, allow_glob=False) # bool
shell_util.set_file_mode(ssh, path, mode, allow_glob=False)                    # bool
```


## Pattern: Handling Glob Paths

Some rules reference multiple files via shell globs (e.g., `/etc/ssh/ssh_host_*_key`). These paths must NOT be quoted or the glob won't expand.

### Detection

```python
# Preferred — use shell_util
quoted = shell_util.quote_path(path)  # auto-detects globs

# Manual — if you need the flag
is_glob = shell_util.is_glob_path(path)
quoted = path if is_glob else shell_util.quote(path)
```

### In Check Handlers

When stat-ing glob paths, use `%n` to get the filename and iterate results:

```python
result = ssh.run(f"stat -c '%U %G %a %n' {path} 2>/dev/null")  # unquoted glob
for line in result.stdout.strip().splitlines():
    parts = line.split()
    owner, group, mode, filepath = parts[0], parts[1], parts[2], " ".join(parts[3:])
    # ... validate each file
```


## Pattern: When Gate Evaluation

The `when:` field in implementations supports three forms:

```yaml
when: sshd_config_d                     # String: single capability
when: { all: [authselect, pam_faillock] } # All must be true
when: { any: [grub_bls, grub_legacy] }   # At least one true
```

The `evaluate_when()` function in `runner/_selection.py` handles all three. When adding a new capability, just add the probe — no changes needed to the gate evaluator.
