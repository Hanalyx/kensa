"""Service-related check handlers.

Handlers for verifying systemd service state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_service_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check systemd service enabled and/or active state.

    Verifies whether a systemd service is enabled (starts at boot)
    and/or active (currently running).

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Systemd service name.
            - enabled (bool, optional): Expected enabled state.
            - active (bool, optional): Expected active state.

    Returns:
        CheckResult with passed=True if service matches all specified states.

    """
    name = c["name"]
    failures = []
    details = []
    check_time = datetime.now(timezone.utc)
    all_stdout = []
    all_stderr = []
    expected_parts = []
    actual_parts = []

    if "enabled" in c:
        cmd = f"systemctl is-enabled {shell_util.quote(name)} 2>/dev/null"
        result = ssh.run(cmd)
        actual_enabled = result.stdout.strip()
        expected_enabled = c["enabled"]
        all_stdout.append(f"is-enabled: {actual_enabled}")
        all_stderr.append(result.stderr)
        expected_parts.append(
            f"enabled={'enabled' if expected_enabled else 'disabled'}"
        )
        actual_parts.append(f"enabled={actual_enabled}")

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

    if "active" in c:
        cmd = f"systemctl is-active {shell_util.quote(name)} 2>/dev/null"
        result = ssh.run(cmd)
        actual_active = result.stdout.strip()
        expected_active = c["active"]
        all_stdout.append(f"is-active: {actual_active}")
        all_stderr.append(result.stderr)
        expected_parts.append(f"active={'active' if expected_active else 'inactive'}")
        actual_parts.append(f"active={actual_active}")

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

    passed = not failures
    detail = (
        f"{name}: {'; '.join(failures)}"
        if failures
        else f"{name}: {', '.join(details)}"
    )

    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="service_state",
            command=f"systemctl is-enabled/is-active {name}",
            stdout="\n".join(all_stdout),
            stderr="\n".join(filter(None, all_stderr)),
            exit_code=0 if passed else 1,
            expected=", ".join(expected_parts),
            actual=", ".join(actual_parts),
            timestamp=check_time,
        ),
    )


def _check_systemd_target(ssh: SSHSession, c: dict) -> CheckResult:
    """Check the system's default systemd target.

    Verifies whether the system's default target matches (or doesn't match)
    the expected value. Commonly used to verify graphical.target vs
    multi-user.target.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with fields:
            - expected (str): Expected default target (e.g., "multi-user.target").
            - not_expected (str, optional): Target that should NOT be set.

    Returns:
        CheckResult with passed=True if the target matches expectations.

    """
    check_time = datetime.now(timezone.utc)
    cmd = "systemctl get-default 2>/dev/null"
    result = ssh.run(cmd)
    actual = result.stdout.strip()

    if "not_expected" in c:
        not_expected = c["not_expected"]
        passed = actual != not_expected
        detail = (
            f"default target is {actual}"
            if passed
            else f"default target is {actual} (should not be {not_expected})"
        )
        return CheckResult(
            passed=passed,
            detail=detail,
            evidence=Evidence(
                method="systemd_target",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=f"not {not_expected}",
                actual=actual,
                timestamp=check_time,
            ),
        )

    expected = c.get("expected", "")
    passed = actual == expected
    detail = (
        f"default target is {actual}"
        if passed
        else f"default target is {actual} (expected {expected})"
    )
    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="systemd_target",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=actual,
            timestamp=check_time,
        ),
    )
