"""SSH-related check handlers.

Handlers for verifying SSH daemon configuration using the effective
runtime configuration rather than static file parsing.

Example:
-------
    >>> check = {"method": "sshd_effective_config", "key": "permitrootlogin", "expected": "no"}
    >>> result = run_check(ssh, check)
    >>> print(result.passed)
    True

"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_sshd_effective_config(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SSH daemon effective configuration.

    Uses `sshd -T` to verify the actual runtime configuration regardless
    of whether settings are in sshd_config, sshd_config.d/, or compiled
    defaults. This is the authoritative source for SSH configuration.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): SSH config key (case-insensitive, e.g., "permitrootlogin").
            - expected (str): Expected value for the key.
            - match_user (str, optional): User context for Match blocks.
            - match_host (str, optional): Host context for Match blocks.

    Returns:
        CheckResult with passed=True if the effective config matches expected.

    """
    key = c["key"].lower()
    expected = str(c["expected"]).lower()
    match_user = c.get("match_user")
    match_host = c.get("match_host")
    check_time = datetime.now(timezone.utc)

    # Build sshd -T command with optional match context
    cmd_parts = ["sshd", "-T"]
    if match_user or match_host:
        match_specs = []
        if match_user:
            match_specs.append(f"user={shell_util.quote(match_user)}")
        if match_host:
            match_specs.append(f"host={shell_util.quote(match_host)}")
        cmd_parts.extend(["-C", ",".join(match_specs)])

    # Run sshd -T and grep for the key
    sshd_cmd = " ".join(cmd_parts)
    cmd = f"{sshd_cmd} 2>/dev/null | grep -i '^{key} '"
    result = ssh.run(cmd)

    if not result.ok or not result.stdout.strip():
        return CheckResult(
            passed=False,
            detail=f"{key} not found in sshd effective config",
            evidence=Evidence(
                method="sshd_effective_config",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected,
                actual=None,
                timestamp=check_time,
            ),
        )

    # Parse the value from "key value" format
    line = result.stdout.strip().split("\n")[0]  # Take first match
    parts = line.split(None, 1)  # Split on whitespace, max 2 parts
    actual = parts[1].lower() if len(parts) > 1 else ""

    passed = actual == expected
    detail = f"{key}={actual}" if passed else f"{key}={actual} (expected {expected})"

    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="sshd_effective_config",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=actual,
            timestamp=check_time,
        ),
    )
