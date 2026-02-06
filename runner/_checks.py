"""Check handlers and dispatch.

This module contains all check handlers that verify compliance state on remote
hosts. Each handler implements a specific check method (e.g., config_value,
file_permission) defined in the rule schema.

Check Handler Pattern:
    All check handlers follow a consistent signature and behavior:
    - Accept an SSHSession and a check dict (from rule YAML)
    - Return a CheckResult with passed=True/False and a human-readable detail
    - Never raise exceptions for expected conditions
    - Use shlex.quote() for all values from rule YAML (except glob paths)

Example:
-------
    >>> from runner.ssh import SSHSession
    >>> from runner._checks import run_check
    >>>
    >>> check = {
    ...     "method": "config_value",
    ...     "path": "/etc/ssh/sshd_config",
    ...     "key": "PermitRootLogin",
    ...     "expected": "no"
    ... }
    >>> result = run_check(ssh, check)
    >>> if result.passed:
    ...     print(f"PASS: {result.detail}")

"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def run_check(ssh: SSHSession, check: dict) -> CheckResult:
    """Dispatch a single check definition to the appropriate handler.

    Supports both single checks and multi-condition checks (AND semantics).
    For multi-condition checks, all sub-checks must pass for the overall
    check to pass; evaluation short-circuits on first failure.

    Args:
    ----
        ssh: Active SSH session to the target host.
        check: Check definition dict from rule YAML. Must contain either:
            - "method": str - single check method name
            - "checks": list[dict] - multiple checks with AND semantics

    Returns:
    -------
        CheckResult with passed=True if all conditions met, False otherwise.
        The detail field contains human-readable status information.

    Example:
    -------
        Single check::

            check = {"method": "file_exists", "path": "/etc/aide.conf"}
            result = run_check(ssh, check)

        Multi-condition check::

            check = {
                "checks": [
                    {"method": "package_state", "name": "aide", "state": "present"},
                    {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
                ]
            }
            result = run_check(ssh, check)

    """
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
    """Check that a configuration key has an expected value.

    Searches for a key in a config file or directory of config files.
    Supports both 'key value' and 'key=value' formats with optional
    whitespace around separators.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or directory to search.
            - key (str): Configuration key name to find.
            - expected (str): Expected value for the key.
            - scan_pattern (str, optional): Glob for directory mode.
              Defaults to "*.conf".

    Returns:
    -------
        CheckResult with passed=True if key exists with expected value.
        Detail shows actual value on mismatch.

    Example:
    -------
        YAML rule definition::

            check:
              method: config_value
              path: "/etc/ssh/sshd_config"
              key: "PermitRootLogin"
              expected: "no"

        Directory scan::

            check:
              method: config_value
              path: "/etc/ssh/sshd_config.d"
              key: "MaxAuthTries"
              expected: "4"
              scan_pattern: "*.conf"

    """
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
    after_key = line[len(key) :].strip() if key in line else line.split(None, 1)[-1]
    actual = after_key.lstrip("= \t").strip().strip('"').strip("'")

    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_config_absent(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a configuration key does NOT exist in a file.

    Verifies that a specific key is absent from a config file or directory.
    Used for ensuring deprecated or insecure options are removed.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or directory to search.
            - key (str): Configuration key that should not exist.
            - scan_pattern (str, optional): Glob for directory mode.
              Defaults to "*.conf".

    Returns:
    -------
        CheckResult with passed=True if key is not found.

    Example:
    -------
        YAML rule definition::

            check:
              method: config_absent
              path: "/etc/ssh/sshd_config"
              key: "PermitEmptyPasswords"

    """
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
        return CheckResult(
            passed=True, detail=f"{key} not found in {path} (as required)"
        )

    # Key was found — that's a failure
    return CheckResult(passed=False, detail=f"{key} found in {path} (should be absent)")


def _check_file_permission(ssh: SSHSession, c: dict) -> CheckResult:
    """Check file ownership and permissions.

    Verifies owner, group, and/or mode of one or more files. Supports
    glob patterns to check multiple files matching a pattern.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or glob pattern.
            - owner (str, optional): Expected file owner.
            - group (str, optional): Expected file group.
            - mode (str, optional): Expected octal mode (e.g., "0600").
            - glob (bool, optional): Explicit glob flag (auto-detected
              if path contains *, ?, or [).

    Returns:
    -------
        CheckResult with passed=True if all specified attributes match.
        For glob paths, all matching files must pass.

    Example:
    -------
        Single file::

            check:
              method: file_permission
              path: "/etc/ssh/sshd_config"
              owner: "root"
              group: "root"
              mode: "0600"

        Glob pattern::

            check:
              method: file_permission
              path: "/etc/ssh/ssh_host_*_key"
              owner: "root"
              mode: "0600"
              glob: true

    """
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
    """Run an arbitrary command and verify its output.

    Executes a shell command and checks the exit code and optionally
    stdout content. Use for complex checks not covered by other handlers.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - run (str): Shell command to execute.
            - expected_exit (int, optional): Expected exit code.
              Defaults to 0.
            - expected_stdout (str, optional): String that must appear
              in stdout.

    Returns:
    -------
        CheckResult with passed=True if exit code matches and stdout
        contains expected string (if specified).

    Example:
    -------
        Exit code check::

            check:
              method: command
              run: "grep -q '^PASS_MAX_DAYS' /etc/login.defs"
              expected_exit: 0

        Stdout content check::

            check:
              method: command
              run: "sysctl kernel.randomize_va_space"
              expected_stdout: "= 2"

    """
    cmd = c["run"]
    result = ssh.run(cmd)

    expected_exit = c.get("expected_exit", 0)
    if result.exit_code != expected_exit:
        return CheckResult(
            passed=False,
            detail=f"exit {result.exit_code} (expected {expected_exit}): {result.stderr or result.stdout}",
        )

    if "expected_stdout" in c and c["expected_stdout"] not in result.stdout:
        return CheckResult(
            passed=False,
            detail=f"stdout mismatch: got {result.stdout!r}",
        )

    return CheckResult(
        passed=True, detail=result.stdout[:200] if result.stdout else "ok"
    )


def _check_sysctl_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check a kernel sysctl parameter value.

    Reads the current value of a sysctl parameter and compares it
    to the expected value.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): Sysctl parameter name (e.g., "net.ipv4.ip_forward").
            - expected (str): Expected value.

    Returns:
    -------
        CheckResult with passed=True if current value matches expected.

    Example:
    -------
        YAML rule definition::

            check:
              method: sysctl_value
              key: "net.ipv4.tcp_syncookies"
              expected: "1"

    """
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
    """Check kernel module load state.

    Verifies whether a kernel module is loaded or properly blacklisted.
    For blacklisted modules, checks both that it's not currently loaded
    and that modprobe is configured to prevent loading.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Kernel module name.
            - state (str, optional): Desired state - "blacklisted" or
              "loaded". Defaults to "blacklisted".

    Returns:
    -------
        CheckResult with passed=True if module is in the expected state.

    Example:
    -------
        Ensure module is blacklisted::

            check:
              method: kernel_module_state
              name: "cramfs"
              state: "blacklisted"

        Ensure module is loaded::

            check:
              method: kernel_module_state
              name: "br_netfilter"
              state: "loaded"

    """
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
    """Check RPM package installation state.

    Verifies whether a package is installed or absent using rpm -q.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Package name.
            - state (str, optional): Expected state - "present" or
              "absent". Defaults to "present".

    Returns:
    -------
        CheckResult with passed=True if package is in the expected state.

    Example:
    -------
        Ensure package is installed::

            check:
              method: package_state
              name: "aide"
              state: "present"

        Ensure package is not installed::

            check:
              method: package_state
              name: "telnet-server"
              state: "absent"

    """
    name = c["name"]
    state = c.get("state", "present")

    result = ssh.run(f"rpm -q {shlex.quote(name)} 2>/dev/null")

    if state == "present":
        if result.ok:
            return CheckResult(passed=True, detail=f"{name}: {result.stdout.strip()}")
        return CheckResult(passed=False, detail=f"{name}: not installed")
    elif state == "absent":
        if not result.ok:
            return CheckResult(
                passed=True, detail=f"{name}: not installed (as required)"
            )
        return CheckResult(passed=False, detail=f"{name}: installed (should be absent)")

    return CheckResult(passed=False, detail=f"Unknown package state: {state}")


def _check_file_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file exists.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.

    Returns:
    -------
        CheckResult with passed=True if file exists.

    Example:
    -------
        YAML rule definition::

            check:
              method: file_exists
              path: "/etc/security/pwquality.conf"

    """
    path = c["path"]
    result = ssh.run(f"test -f {shlex.quote(path)}")
    if result.ok:
        return CheckResult(passed=True, detail=f"{path}: exists")
    return CheckResult(passed=False, detail=f"{path}: not found")


def _check_file_not_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file does NOT exist.

    Used for ensuring insecure or deprecated files have been removed.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path that should not exist.

    Returns:
    -------
        CheckResult with passed=True if file does not exist.

    Example:
    -------
        YAML rule definition::

            check:
              method: file_not_exists
              path: "/etc/hosts.equiv"

    """
    path = c["path"]
    result = ssh.run(f"test -f {shlex.quote(path)}")
    if not result.ok:
        return CheckResult(passed=True, detail=f"{path}: not present (as required)")
    return CheckResult(passed=False, detail=f"{path}: exists (should be absent)")


def _check_file_content_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content matches a regex pattern.

    Uses grep -E (extended regex) to search for the pattern.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - pattern (str): Extended regex pattern to match.

    Returns:
    -------
        CheckResult with passed=True if pattern is found in file.

    Example:
    -------
        YAML rule definition::

            check:
              method: file_content_match
              path: "/etc/security/limits.conf"
              pattern: "^\\*\\s+hard\\s+core\\s+0"

    """
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
    """Check that file content does NOT match a regex pattern.

    Verifies that a prohibited pattern is absent from the file.
    If the file does not exist, the check passes (pattern cannot exist).

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - pattern (str): Extended regex pattern that should not match.

    Returns:
    -------
        CheckResult with passed=True if pattern is not found.

    Example:
    -------
        YAML rule definition::

            check:
              method: file_content_no_match
              path: "/etc/ssh/sshd_config"
              pattern: "^\\s*PermitRootLogin\\s+yes"

    """
    path = c["path"]
    pattern = c["pattern"]

    # Check file exists first
    exists = ssh.run(f"test -f {shlex.quote(path)}")
    if not exists.ok:
        # File doesn't exist = pattern definitely not in it
        return CheckResult(
            passed=True, detail=f"{path}: not found (pattern cannot exist)"
        )

    # Grep for pattern — we want it to NOT be found
    result = ssh.run(f"grep -qE {shlex.quote(pattern)} {shlex.quote(path)}")
    if not result.ok:
        return CheckResult(
            passed=True, detail=f"{path}: pattern not found (as required)"
        )
    return CheckResult(passed=False, detail=f"{path}: contains prohibited pattern")


def _check_service_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check systemd service enabled and/or active state.

    Verifies whether a systemd service is enabled (starts at boot)
    and/or active (currently running).

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Systemd service name (with or without .service).
            - enabled (bool, optional): Expected enabled state.
            - active (bool, optional): Expected active state.
            At least one of enabled/active should be specified.

    Returns:
    -------
        CheckResult with passed=True if service matches all specified states.

    Example:
    -------
        Ensure service is enabled and running::

            check:
              method: service_state
              name: "auditd"
              enabled: true
              active: true

        Ensure service is disabled::

            check:
              method: service_state
              name: "rpcbind"
              enabled: false

    """
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


def _check_mount_option(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a mount point has required mount options.

    Uses findmnt to check currently mounted options.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - mount_point (str): Mount point path (e.g., "/tmp", "/var").
            - options (list[str]): Required mount options (e.g., ["nodev", "nosuid"]).

    Returns:
    -------
        CheckResult with passed=True if all options are present.

    Example:
    -------
        YAML rule definition::

            check:
              method: mount_option
              mount_point: "/tmp"
              options:
                - nodev
                - nosuid
                - noexec

    """
    mount_point = c["mount_point"]
    required_options = c.get("options", [])

    # Get current mount options
    result = ssh.run(f"findmnt -n -o OPTIONS {shlex.quote(mount_point)} 2>/dev/null")
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{mount_point}: not mounted")

    current_options = set(result.stdout.strip().split(","))
    missing = []
    for opt in required_options:
        if opt not in current_options:
            missing.append(opt)

    if missing:
        return CheckResult(
            passed=False, detail=f"{mount_point}: missing options: {', '.join(missing)}"
        )
    return CheckResult(passed=True, detail=f"{mount_point}: has required options")


def _check_grub_parameter(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a kernel boot parameter is set in GRUB.

    Uses grubby to inspect the default kernel's boot arguments.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): Kernel parameter name.
            - expected (str, optional): Expected value. If omitted,
              only checks for parameter presence (boolean flag).

    Returns:
    -------
        CheckResult with passed=True if parameter exists with expected value.

    Example:
    -------
        Parameter with value::

            check:
              method: grub_parameter
              key: "audit"
              expected: "1"

        Boolean parameter::

            check:
              method: grub_parameter
              key: "audit_backlog_limit=8192"

    """
    key = c["key"]
    expected = c.get("expected")

    # Try grubby first (RHEL/Fedora)
    result = ssh.run("grubby --info=DEFAULT 2>/dev/null | grep -E 'args='")
    if result.ok:
        args_line = result.stdout.strip()
        # Parse the kernel args
        if f"{key}=" in args_line:
            # Extract value
            import re

            match = re.search(rf"{key}=(\S+)", args_line)
            if match:
                actual = match.group(1).strip('"')
                if expected is None or actual == expected:
                    return CheckResult(passed=True, detail=f"{key}={actual}")
                return CheckResult(
                    passed=False, detail=f"{key}={actual} (expected {expected})"
                )
        elif key in args_line:
            # Boolean parameter (no value)
            if expected is None or expected == "":
                return CheckResult(passed=True, detail=f"{key} present")
            return CheckResult(
                passed=False, detail=f"{key} present but expected value {expected}"
            )
        return CheckResult(passed=False, detail=f"{key} not found in kernel args")

    return CheckResult(passed=False, detail="grubby not available")


def _check_audit_rule_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that an audit rule is active.

    Uses auditctl -l to list current audit rules and searches for the
    specified rule or rule components.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - rule (str): Full or partial audit rule to search for.

    Returns:
    -------
        CheckResult with passed=True if rule is found in active rules.

    Example:
    -------
        YAML rule definition::

            check:
              method: audit_rule_exists
              rule: "-w /etc/passwd -p wa -k identity"

    """
    rule = c["rule"]

    # Check if auditd is running
    result = ssh.run("auditctl -l 2>/dev/null")
    if not result.ok:
        return CheckResult(
            passed=False, detail="auditctl failed - auditd may not be running"
        )

    # Search for the rule (or key components)
    if rule in result.stdout:
        return CheckResult(passed=True, detail="Audit rule found")
    return CheckResult(passed=False, detail=f"Audit rule not found: {rule[:50]}...")


def _check_selinux_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux enforcement mode.

    Uses getenforce to check the current SELinux mode.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - state (str, optional): Expected mode - "Enforcing",
              "Permissive", or "Disabled". Defaults to "Enforcing".

    Returns:
    -------
        CheckResult with passed=True if SELinux is in expected mode.

    Example:
    -------
        YAML rule definition::

            check:
              method: selinux_state
              state: "Enforcing"

    """
    expected = c.get("state", "Enforcing")

    result = ssh.run("getenforce 2>/dev/null")
    if not result.ok:
        return CheckResult(
            passed=False, detail="getenforce failed - SELinux may not be installed"
        )

    actual = result.stdout.strip()
    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"SELinux: {actual}")
    return CheckResult(passed=False, detail=f"SELinux: {actual} (expected {expected})")


def _check_selinux_boolean(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux boolean setting.

    Uses getsebool to check the current value of a SELinux boolean.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): SELinux boolean name.
            - value (bool, optional): Expected value. Defaults to True (on).

    Returns:
    -------
        CheckResult with passed=True if boolean has expected value.

    Example:
    -------
        YAML rule definition::

            check:
              method: selinux_boolean
              name: "httpd_can_network_connect"
              value: false

    """
    name = c["name"]
    expected = c.get("value", True)
    expected_str = "on" if expected else "off"

    result = ssh.run(f"getsebool {shlex.quote(name)} 2>/dev/null")
    if not result.ok:
        return CheckResult(
            passed=False, detail=f"{name}: not found or SELinux disabled"
        )

    # Output is like "httpd_can_network_connect --> on"
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        return CheckResult(passed=False, detail=f"{name}: unexpected output format")

    actual = parts[-1]
    if actual.lower() == expected_str:
        return CheckResult(passed=True, detail=f"{name} = {actual}")
    return CheckResult(
        passed=False, detail=f"{name} = {actual} (expected {expected_str})"
    )


def _check_pam_module(ssh: SSHSession, c: dict) -> CheckResult:
    """Check PAM module configuration in a service's PAM stack.

    Verifies that a PAM module is present in a service's PAM configuration
    with the expected type, control, and optional arguments.

    Args:
    ----
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - service (str): PAM service name (e.g., "system-auth", "password-auth").
            - module (str): PAM module name (e.g., "pam_faillock.so").
            - type (str, optional): PAM type to check ("auth", "account",
              "password", "session"). If omitted, any type matches.
            - control (str, optional): Expected control value ("required",
              "requisite", "sufficient", "optional", or complex []).
            - args (str, optional): Expected arguments that must be present.

    Returns:
    -------
        CheckResult with passed=True if module is configured as expected.

    Example:
    -------
        Basic module presence check::

            check:
              method: pam_module
              service: "system-auth"
              module: "pam_faillock.so"

        With type and control::

            check:
              method: pam_module
              service: "password-auth"
              module: "pam_faillock.so"
              type: "auth"
              control: "required"

        With arguments::

            check:
              method: pam_module
              service: "system-auth"
              module: "pam_pwquality.so"
              type: "password"
              args: "retry=3"

    """
    service = c["service"]
    module = c["module"]
    expected_type = c.get("type")
    expected_control = c.get("control")
    expected_args = c.get("args")

    # PAM files are typically in /etc/pam.d/
    pam_file = f"/etc/pam.d/{service}"

    # Check if file exists
    exists = ssh.run(f"test -f {shlex.quote(pam_file)}")
    if not exists.ok:
        return CheckResult(passed=False, detail=f"{pam_file}: not found")

    # Search for the module in the PAM file
    # PAM format: type  control  module  [args...]
    result = ssh.run(
        f"grep -E '\\s{shlex.quote(module)}(\\s|$)' {shlex.quote(pam_file)} 2>/dev/null"
    )
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{module} not found in {pam_file}")

    # Parse the matching lines
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        # Skip comments
        if line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        # Handle -type prefix (e.g., "-auth" instead of "auth")
        line_type = parts[0].lstrip("-")
        line_control = parts[1]
        line_module = parts[2]
        line_args = " ".join(parts[3:]) if len(parts) > 3 else ""

        # Check if this line matches our module
        if module not in line_module:
            continue

        # Check type if specified
        if expected_type and line_type != expected_type:
            continue

        # Check control if specified
        if expected_control and line_control != expected_control:
            continue

        # Check args if specified - verify expected args are present
        if expected_args and expected_args not in line_args:
            continue

        # Found a matching line
        detail = f"{line_type} {line_control} {module}"
        if line_args:
            detail += f" ({line_args[:50]}{'...' if len(line_args) > 50 else ''})"
        return CheckResult(passed=True, detail=detail)

    # No matching line found
    detail = f"{module} in {pam_file}: "
    if expected_type:
        detail += f"type={expected_type} "
    if expected_control:
        detail += f"control={expected_control} "
    if expected_args:
        detail += f"args containing '{expected_args}' "
    detail += "not found"
    return CheckResult(passed=False, detail=detail)


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
    "mount_option": _check_mount_option,
    "grub_parameter": _check_grub_parameter,
    "pam_module": _check_pam_module,
}
