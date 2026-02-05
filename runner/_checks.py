"""Check handlers and dispatch."""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def run_check(ssh: SSHSession, check: dict) -> CheckResult:
    """Dispatch a single check definition to the right handler."""
    # Multi-condition check (AND semantics)
    if "checks" in check:
        details = []
        for sub in check["checks"]:
            r = _dispatch_check(ssh, sub)
            if not r.passed:
                return CheckResult(passed=False, detail=r.detail)
            details.append(r.detail)
        return CheckResult(passed=True, detail="; ".join(d for d in details if d))

    return _dispatch_check(ssh, check)


def _dispatch_check(ssh: SSHSession, check: dict) -> CheckResult:
    method = check.get("method", "")
    handler = CHECK_HANDLERS.get(method)
    if handler is None:
        return CheckResult(passed=False, detail=f"Unknown check method: {method}")
    return handler(ssh, check)


# ── Individual check handlers ──────────────────────────────────────────────


def _check_config_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check key=value in a config file or .d directory."""
    path = c["path"]
    key = c["key"]
    expected = str(c["expected"])

    # If path is a directory, scan files matching pattern
    scan_pattern = c.get("scan_pattern", "*.conf")
    result = ssh.run(f"test -d {shlex.quote(path)}")
    if result.ok:
        # Directory mode: grep across files
        cmd = (
            f"grep -rh '^ *{key}' {shlex.quote(path)}/{scan_pattern} 2>/dev/null"
            f" | tail -1"
        )
    else:
        cmd = f"grep -h '^ *{key}' {shlex.quote(path)} 2>/dev/null | tail -1"

    result = ssh.run(cmd)
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{key} not found in {path}")

    # Extract value: handle both 'key value' and 'key=value' and 'key = value'
    line = result.stdout.strip()
    # Remove the key prefix, then separators
    after_key = line[len(key):].strip() if key in line else line.split(None, 1)[-1]
    actual = after_key.lstrip("= \t").strip().strip('"').strip("'")

    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_config_absent(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a key is NOT present in a config file."""
    path = c["path"]
    key = c["key"]

    # If path is a directory, scan files matching pattern
    scan_pattern = c.get("scan_pattern", "*.conf")
    result = ssh.run(f"test -d {shlex.quote(path)}")
    if result.ok:
        # Directory mode: grep across files
        cmd = f"grep -rh '^ *{key}' {shlex.quote(path)}/{scan_pattern} 2>/dev/null"
    else:
        cmd = f"grep -h '^ *{key}' {shlex.quote(path)} 2>/dev/null"

    result = ssh.run(cmd)
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=True, detail=f"{key} not found in {path} (as required)")

    # Key was found — that's a failure
    return CheckResult(passed=False, detail=f"{key} found in {path} (should be absent)")


def _check_file_permission(ssh: SSHSession, c: dict) -> CheckResult:
    """Check file ownership and mode. Supports glob paths."""
    path = c["path"]
    is_glob = "glob" in c or any(ch in path for ch in "*?[")

    if is_glob:
        # Don't quote — let the shell expand the glob
        result = ssh.run(f"stat -c '%U %G %a %n' {path} 2>/dev/null")
    else:
        result = ssh.run(f"stat -c '%U %G %a %n' {shlex.quote(path)} 2>/dev/null")

    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{path}: not found or not accessible")

    all_failures = []
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        actual_owner, actual_group, actual_mode = parts[0], parts[1], parts[2]
        file_path = " ".join(parts[3:])
        failures = []

        if "owner" in c and actual_owner != c["owner"]:
            failures.append(f"owner={actual_owner} (expected {c['owner']})")
        if "group" in c and actual_group != c["group"]:
            failures.append(f"group={actual_group} (expected {c['group']})")
        if "mode" in c:
            expected_mode = c["mode"].lstrip("0") or "0"
            actual_mode_norm = actual_mode.lstrip("0") or "0"
            if actual_mode_norm != expected_mode:
                failures.append(f"mode={actual_mode} (expected {c['mode']})")

        if failures:
            all_failures.append(f"{file_path}: {', '.join(failures)}")

    if all_failures:
        return CheckResult(passed=False, detail="; ".join(all_failures))
    return CheckResult(passed=True, detail=f"{path}: ok")


def _check_command(ssh: SSHSession, c: dict) -> CheckResult:
    """Run arbitrary command and check exit code / stdout."""
    cmd = c["run"]
    result = ssh.run(cmd)

    expected_exit = c.get("expected_exit", 0)
    if result.exit_code != expected_exit:
        return CheckResult(
            passed=False,
            detail=f"exit {result.exit_code} (expected {expected_exit}): {result.stderr or result.stdout}",
        )

    if "expected_stdout" in c:
        if c["expected_stdout"] not in result.stdout:
            return CheckResult(
                passed=False,
                detail=f"stdout mismatch: got {result.stdout!r}",
            )

    return CheckResult(passed=True, detail=result.stdout[:200] if result.stdout else "ok")


def _check_sysctl_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check a sysctl kernel parameter value."""
    key = c["key"]
    expected = str(c["expected"])
    result = ssh.run(f"sysctl -n {shlex.quote(key)} 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail=f"sysctl {key}: not available")

    actual = result.stdout.strip()
    if actual == expected:
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_kernel_module_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if a kernel module is loaded or blacklisted."""
    name = c["name"]
    state = c.get("state", "blacklisted")

    if state == "blacklisted":
        # Module should NOT be loaded and should be blacklisted
        loaded = ssh.run(f"lsmod | grep -q '^{name} '")
        if loaded.ok:
            return CheckResult(passed=False, detail=f"{name}: still loaded")

        blacklisted = ssh.run(
            f"modprobe -n -v {shlex.quote(name)} 2>&1 | grep -q 'install /bin/true\\|install /bin/false\\|blacklist'"
        )
        if not blacklisted.ok:
            return CheckResult(passed=False, detail=f"{name}: not blacklisted")

        return CheckResult(passed=True, detail=f"{name}: blacklisted")

    elif state == "loaded":
        loaded = ssh.run(f"lsmod | grep -q '^{name} '")
        if loaded.ok:
            return CheckResult(passed=True, detail=f"{name}: loaded")
        return CheckResult(passed=False, detail=f"{name}: not loaded")

    return CheckResult(passed=False, detail=f"Unknown module state: {state}")


def _check_package_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if a package is installed or absent."""
    name = c["name"]
    state = c.get("state", "present")

    result = ssh.run(f"rpm -q {shlex.quote(name)} 2>/dev/null")

    if state == "present":
        if result.ok:
            return CheckResult(passed=True, detail=f"{name}: {result.stdout.strip()}")
        return CheckResult(passed=False, detail=f"{name}: not installed")
    elif state == "absent":
        if not result.ok:
            return CheckResult(passed=True, detail=f"{name}: not installed (as required)")
        return CheckResult(passed=False, detail=f"{name}: installed (should be absent)")

    return CheckResult(passed=False, detail=f"Unknown package state: {state}")


def _check_file_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if a file exists."""
    path = c["path"]
    result = ssh.run(f"test -f {shlex.quote(path)}")
    if result.ok:
        return CheckResult(passed=True, detail=f"{path}: exists")
    return CheckResult(passed=False, detail=f"{path}: not found")


def _check_file_not_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file does NOT exist."""
    path = c["path"]
    result = ssh.run(f"test -f {shlex.quote(path)}")
    if not result.ok:
        return CheckResult(passed=True, detail=f"{path}: not present (as required)")
    return CheckResult(passed=False, detail=f"{path}: exists (should be absent)")


def _check_file_content_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content matches a pattern."""
    path = c["path"]
    pattern = c["pattern"]

    # Check file exists first
    exists = ssh.run(f"test -f {shlex.quote(path)}")
    if not exists.ok:
        return CheckResult(passed=False, detail=f"{path}: not found")

    # Grep for pattern
    result = ssh.run(f"grep -qE {shlex.quote(pattern)} {shlex.quote(path)}")
    if result.ok:
        return CheckResult(passed=True, detail=f"{path}: contains pattern")
    return CheckResult(passed=False, detail=f"{path}: pattern not found")


def _check_file_content_no_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content does NOT match a pattern."""
    path = c["path"]
    pattern = c["pattern"]

    # Check file exists first
    exists = ssh.run(f"test -f {shlex.quote(path)}")
    if not exists.ok:
        # File doesn't exist = pattern definitely not in it
        return CheckResult(passed=True, detail=f"{path}: not found (pattern cannot exist)")

    # Grep for pattern — we want it to NOT be found
    result = ssh.run(f"grep -qE {shlex.quote(pattern)} {shlex.quote(path)}")
    if not result.ok:
        return CheckResult(passed=True, detail=f"{path}: pattern not found (as required)")
    return CheckResult(passed=False, detail=f"{path}: contains prohibited pattern")


def _check_service_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check systemd service enabled/active state."""
    name = c["name"]
    failures = []
    details = []

    # Check enabled state if specified
    if "enabled" in c:
        result = ssh.run(f"systemctl is-enabled {shlex.quote(name)} 2>/dev/null")
        actual_enabled = result.stdout.strip()
        expected_enabled = c["enabled"]

        if expected_enabled:
            if actual_enabled != "enabled":
                failures.append(f"enabled={actual_enabled} (expected enabled)")
            else:
                details.append("enabled")
        else:
            if actual_enabled == "enabled":
                failures.append(f"enabled={actual_enabled} (expected disabled)")
            else:
                details.append(f"not enabled ({actual_enabled})")

    # Check active state if specified
    if "active" in c:
        result = ssh.run(f"systemctl is-active {shlex.quote(name)} 2>/dev/null")
        actual_active = result.stdout.strip()
        expected_active = c["active"]

        if expected_active:
            if actual_active != "active":
                failures.append(f"active={actual_active} (expected active)")
            else:
                details.append("active")
        else:
            if actual_active == "active":
                failures.append(f"active={actual_active} (expected inactive)")
            else:
                details.append(f"not active ({actual_active})")

    if failures:
        return CheckResult(passed=False, detail=f"{name}: {'; '.join(failures)}")
    return CheckResult(passed=True, detail=f"{name}: {', '.join(details)}")


def _check_audit_rule_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if an audit rule exists."""
    rule = c["rule"]

    # Check if auditd is running
    result = ssh.run("auditctl -l 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail="auditctl failed - auditd may not be running")

    # Search for the rule (or key components)
    if rule in result.stdout:
        return CheckResult(passed=True, detail=f"Audit rule found")
    return CheckResult(passed=False, detail=f"Audit rule not found: {rule[:50]}...")


def _check_selinux_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux enforcement state."""
    expected = c.get("state", "Enforcing")

    result = ssh.run("getenforce 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail="getenforce failed - SELinux may not be installed")

    actual = result.stdout.strip()
    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"SELinux: {actual}")
    return CheckResult(passed=False, detail=f"SELinux: {actual} (expected {expected})")


def _check_selinux_boolean(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux boolean value."""
    name = c["name"]
    expected = c.get("value", True)
    expected_str = "on" if expected else "off"

    result = ssh.run(f"getsebool {shlex.quote(name)} 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail=f"{name}: not found or SELinux disabled")

    # Output is like "httpd_can_network_connect --> on"
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        return CheckResult(passed=False, detail=f"{name}: unexpected output format")

    actual = parts[-1]
    if actual.lower() == expected_str:
        return CheckResult(passed=True, detail=f"{name} = {actual}")
    return CheckResult(passed=False, detail=f"{name} = {actual} (expected {expected_str})")


CHECK_HANDLERS = {
    "config_value": _check_config_value,
    "config_absent": _check_config_absent,
    "file_permission": _check_file_permission,
    "command": _check_command,
    "sysctl_value": _check_sysctl_value,
    "kernel_module_state": _check_kernel_module_state,
    "package_state": _check_package_state,
    "file_exists": _check_file_exists,
    "file_not_exists": _check_file_not_exists,
    "file_content_match": _check_file_content_match,
    "file_content_no_match": _check_file_content_no_match,
    "service_state": _check_service_state,
    "selinux_state": _check_selinux_state,
    "selinux_boolean": _check_selinux_boolean,
    "audit_rule_exists": _check_audit_rule_exists,
}
