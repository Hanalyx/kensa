"""Command check handler.

Handler for arbitrary shell command verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_command(ssh: SSHSession, c: dict) -> CheckResult:
    """Run an arbitrary command and verify its output.

    Executes a shell command and checks the exit code and optionally
    stdout content. Use for complex checks not covered by other handlers.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - run (str): Shell command to execute.
            - expected_exit (int, optional): Expected exit code. Defaults to 0.
            - expected_stdout (str, optional): String that must appear in stdout.

    Returns:
        CheckResult with passed=True if exit code matches and stdout
        contains expected string (if specified).

    """
    cmd = c["run"]
    check_time = datetime.now(timezone.utc)
    result = ssh.run(cmd)

    expected_exit = c.get("expected_exit", 0)
    expected_stdout = c.get("expected_stdout")

    # Build expected string for evidence
    expected_str = f"exit={expected_exit}"
    if expected_stdout is not None:
        expected_str += f", stdout contains '{expected_stdout}'"

    if result.exit_code != expected_exit:
        return CheckResult(
            passed=False,
            detail=f"exit {result.exit_code} (expected {expected_exit}): {result.stderr or result.stdout}",
            evidence=Evidence(
                method="command",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_str,
                actual=f"exit={result.exit_code}",
                timestamp=check_time,
            ),
        )

    if expected_stdout is not None:
        # Empty string means "expect no output"; non-empty uses substring match
        stdout_ok = (
            (not result.stdout)
            if expected_stdout == ""
            else (expected_stdout in result.stdout)
        )
    else:
        stdout_ok = True
    if not stdout_ok:
        return CheckResult(
            passed=False,
            detail=f"stdout mismatch: got {result.stdout!r}",
            evidence=Evidence(
                method="command",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_str,
                actual=result.stdout[:200] if result.stdout else "",
                timestamp=check_time,
            ),
        )

    return CheckResult(
        passed=True,
        detail=result.stdout[:200] if result.stdout else "ok",
        evidence=Evidence(
            method="command",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected_str,
            actual=result.stdout[:200] if result.stdout else "ok",
            timestamp=check_time,
        ),
    )
