"""Security-related check handlers.

Handlers for verifying security subsystem state: SELinux, audit rules,
and PAM configuration.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_selinux_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux enforcement mode.

    Uses getenforce to check the current SELinux mode.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with optional fields:
            - state (str): Expected mode. Defaults to "Enforcing".

    Returns:
        CheckResult with passed=True if SELinux is in expected mode.

    """
    expected = c.get("state", "Enforcing")
    check_time = datetime.now(timezone.utc)
    cmd = "getenforce 2>/dev/null"

    result = ssh.run(cmd)
    if not result.ok:
        return CheckResult(
            passed=False,
            detail="getenforce failed - SELinux may not be installed",
            evidence=Evidence(
                method="selinux_state",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected,
                actual=None,
                timestamp=check_time,
            ),
        )

    actual = result.stdout.strip()
    passed = actual.lower() == expected.lower()
    detail = (
        f"SELinux: {actual}" if passed else f"SELinux: {actual} (expected {expected})"
    )

    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="selinux_state",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=actual,
            timestamp=check_time,
        ),
    )


def _check_selinux_boolean(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux boolean setting.

    Uses getsebool to check the current value of a SELinux boolean.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): SELinux boolean name.
            - value (bool, optional): Expected value. Defaults to True.

    Returns:
        CheckResult with passed=True if boolean has expected value.

    """
    name = c["name"]
    expected = c.get("value", True)
    expected_str = "on" if expected else "off"
    check_time = datetime.now(timezone.utc)
    cmd = f"getsebool {shell_util.quote(name)} 2>/dev/null"

    result = ssh.run(cmd)
    if not result.ok:
        return CheckResult(
            passed=False,
            detail=f"{name}: not found or SELinux disabled",
            evidence=Evidence(
                method="selinux_boolean",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_str,
                actual=None,
                timestamp=check_time,
            ),
        )

    parts = result.stdout.strip().split()
    if len(parts) < 3:
        return CheckResult(
            passed=False,
            detail=f"{name}: unexpected output format",
            evidence=Evidence(
                method="selinux_boolean",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_str,
                actual=result.stdout.strip(),
                timestamp=check_time,
            ),
        )

    actual = parts[-1]
    passed = actual.lower() == expected_str
    detail = (
        f"{name} = {actual}"
        if passed
        else f"{name} = {actual} (expected {expected_str})"
    )

    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="selinux_boolean",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected_str,
            actual=actual,
            timestamp=check_time,
        ),
    )


def _normalize_auditctl_output(output: str) -> str:
    """Normalize auditctl -l output for reliable substring matching.

    ``auditctl -l`` displays rules in a canonical form that differs from the
    input syntax accepted by ``auditctl``.  This function reverses the
    well-known transformations so that rules written in input syntax can be
    matched via simple substring search.

    Transformations applied:
      - ``-F key=X``  → ``-k X``  (syscall rules display the long form)
      - ``auid!=-1``  → ``auid!=unset``  (numeric vs symbolic UID)
      - ``auid!=4294967295`` → ``auid!=unset``  (alternate numeric form)
      - ``-S all ``    → removed  (inserted for path-only rules)

    """
    output = re.sub(r"-F key=(\S+)", r"-k \1", output)
    output = output.replace("auid!=-1", "auid!=unset")
    output = output.replace("auid!=4294967295", "auid!=unset")
    output = output.replace("-S all ", "")
    return output


def _check_audit_rule_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that an audit rule is active.

    Uses auditctl -l to list current audit rules and searches for the
    specified rule.  The output is normalized before matching to account
    for formatting differences between auditctl input and display syntax
    (e.g. ``-k`` vs ``-F key=``, ``auid!=unset`` vs ``auid!=-1``).

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - rule (str): Full or partial audit rule to search for.

    Returns:
        CheckResult with passed=True if rule is found.

    """
    rule = c["rule"]
    check_time = datetime.now(timezone.utc)
    cmd = "auditctl -l 2>/dev/null"

    result = ssh.run(cmd)
    if not result.ok:
        return CheckResult(
            passed=False,
            detail="auditctl failed - auditd may not be running",
            evidence=Evidence(
                method="audit_rule_exists",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=f"contains '{rule[:50]}'",
                actual=None,
                timestamp=check_time,
            ),
        )

    normalized = _normalize_auditctl_output(result.stdout)
    passed = rule in normalized
    detail = "Audit rule found" if passed else f"Audit rule not found: {rule[:50]}..."

    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="audit_rule_exists",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=f"contains '{rule[:50]}'",
            actual="found" if passed else "not found",
            timestamp=check_time,
        ),
    )


def _check_pam_module(ssh: SSHSession, c: dict) -> CheckResult:
    """Check PAM module configuration in a service's PAM stack.

    Verifies that a PAM module is present in a service's PAM configuration
    with the expected type, control, and optional arguments.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - service (str): PAM service name.
            - module (str): PAM module name.
            - type (str, optional): PAM type to check.
            - control (str, optional): Expected control value.
            - args (str, optional): Expected arguments.

    Returns:
        CheckResult with passed=True if module is configured as expected.

    """
    service = c["service"]
    module = c["module"]
    expected_type = c.get("type")
    expected_control = c.get("control")
    expected_args = c.get("args")
    check_time = datetime.now(timezone.utc)

    pam_file = f"/etc/pam.d/{service}"

    if not shell_util.file_exists(ssh, pam_file):
        return CheckResult(
            passed=False,
            detail=f"{pam_file}: not found",
            evidence=Evidence(
                method="pam_module",
                command=f"test -e {pam_file}",
                stdout="",
                stderr="",
                exit_code=1,
                expected=f"{module} in {pam_file}",
                actual="file not found",
                timestamp=check_time,
            ),
        )

    cmd = f"grep -E '\\s{shell_util.quote(module)}(\\s|$)' {shell_util.quote(pam_file)} 2>/dev/null"
    result = ssh.run(cmd)

    if not result.ok or not result.stdout.strip():
        return CheckResult(
            passed=False,
            detail=f"{module} not found in {pam_file}",
            evidence=Evidence(
                method="pam_module",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=f"{module} in {pam_file}",
                actual="not found",
                timestamp=check_time,
            ),
        )

    # Build expected string for evidence
    expected_parts = [f"module={module}"]
    if expected_type:
        expected_parts.append(f"type={expected_type}")
    if expected_control:
        expected_parts.append(f"control={expected_control}")
    if expected_args:
        expected_parts.append(f"args contains '{expected_args}'")
    expected_str = ", ".join(expected_parts)

    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        line_type = parts[0].lstrip("-")
        line_control = parts[1]
        line_module = parts[2]
        line_args = " ".join(parts[3:]) if len(parts) > 3 else ""

        if module not in line_module:
            continue
        if expected_type and line_type != expected_type:
            continue
        if expected_control and line_control != expected_control:
            continue
        if expected_args and expected_args not in line_args:
            continue

        detail = f"{line_type} {line_control} {module}"
        if line_args:
            detail += f" ({line_args[:50]}{'...' if len(line_args) > 50 else ''})"

        return CheckResult(
            passed=True,
            detail=detail,
            evidence=Evidence(
                method="pam_module",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_str,
                actual=line,
                timestamp=check_time,
            ),
        )

    detail = f"{module} in {pam_file}: "
    if expected_type:
        detail += f"type={expected_type} "
    if expected_control:
        detail += f"control={expected_control} "
    if expected_args:
        detail += f"args containing '{expected_args}' "
    detail += "not found"

    return CheckResult(
        passed=False,
        detail=detail,
        evidence=Evidence(
            method="pam_module",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected_str,
            actual="no matching configuration",
            timestamp=check_time,
        ),
    )
