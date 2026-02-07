"""Service-related check handlers.

Handlers for verifying systemd service state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

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

    if "enabled" in c:
        result = ssh.run(f"systemctl is-enabled {shell_util.quote(name)} 2>/dev/null")
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

    if "active" in c:
        result = ssh.run(f"systemctl is-active {shell_util.quote(name)} 2>/dev/null")
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
