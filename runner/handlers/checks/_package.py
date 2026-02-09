"""Package-related check handlers.

Handlers for verifying RPM package state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_package_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check RPM package installation state.

    Verifies whether a package is installed or absent using rpm -q.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Package name.
            - state (str, optional): Expected state - "present" or
              "absent". Defaults to "present".

    Returns:
        CheckResult with passed=True if package is in the expected state.

    """
    name = c["name"]
    state = c.get("state", "present")
    check_time = datetime.now(timezone.utc)
    cmd = f"rpm -q {shell_util.quote(name)} 2>/dev/null"

    result = ssh.run(cmd)

    if state == "present":
        if result.ok:
            actual = result.stdout.strip()
            return CheckResult(
                passed=True,
                detail=f"{name}: {actual}",
                evidence=Evidence(
                    method="package_state",
                    command=cmd,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_code=result.exit_code,
                    expected=state,
                    actual=actual,
                    timestamp=check_time,
                ),
            )
        return CheckResult(
            passed=False,
            detail=f"{name}: not installed",
            evidence=Evidence(
                method="package_state",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=state,
                actual="not installed",
                timestamp=check_time,
            ),
        )
    elif state == "absent":
        if not result.ok:
            return CheckResult(
                passed=True,
                detail=f"{name}: not installed (as required)",
                evidence=Evidence(
                    method="package_state",
                    command=cmd,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_code=result.exit_code,
                    expected=state,
                    actual="not installed",
                    timestamp=check_time,
                ),
            )
        actual = result.stdout.strip()
        return CheckResult(
            passed=False,
            detail=f"{name}: installed (should be absent)",
            evidence=Evidence(
                method="package_state",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=state,
                actual=actual,
                timestamp=check_time,
            ),
        )

    return CheckResult(passed=False, detail=f"Unknown package state: {state}")
