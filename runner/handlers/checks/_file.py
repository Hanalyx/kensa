"""File-related check handlers.

Handlers for verifying file state: existence, permissions, and content.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_file_permission(ssh: SSHSession, c: dict) -> CheckResult:
    """Check file ownership and permissions.

    Verifies owner, group, and/or mode of one or more files. Supports
    glob patterns to check multiple files matching a pattern.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or glob pattern.
            - owner (str, optional): Expected file owner.
            - group (str, optional): Expected file group.
            - mode (str, optional): Expected octal mode (e.g., "0600").
            - glob (bool, optional): Explicit glob flag.

    Returns:
        CheckResult with passed=True if all specified attributes match.

    """
    path = c["path"]
    is_glob = "glob" in c or shell_util.is_glob_path(path)
    check_time = datetime.now(timezone.utc)

    result = shell_util.get_file_stat(ssh, path, allow_glob=is_glob)
    cmd = result.command if hasattr(result, "command") else f"stat {path}"

    if not result.ok or not result.stdout.strip():
        return CheckResult(
            passed=False,
            detail=f"{path}: not found or not accessible",
            evidence=Evidence(
                method="file_permission",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=f"owner={c.get('owner', '*')}, group={c.get('group', '*')}, mode={c.get('mode', '*')}",
                actual=None,
                timestamp=check_time,
            ),
        )

    all_failures = []
    actual_parts = []
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        actual_owner, actual_group, actual_mode = parts[0], parts[1], parts[2]
        file_path = " ".join(parts[3:])
        failures = []
        actual_parts.append(
            f"{file_path}: owner={actual_owner}, group={actual_group}, mode={actual_mode}"
        )

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

    expected_str = f"owner={c.get('owner', '*')}, group={c.get('group', '*')}, mode={c.get('mode', '*')}"
    actual_str = "; ".join(actual_parts)

    if all_failures:
        return CheckResult(
            passed=False,
            detail="; ".join(all_failures),
            evidence=Evidence(
                method="file_permission",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_str,
                actual=actual_str,
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=True,
        detail=f"{path}: ok",
        evidence=Evidence(
            method="file_permission",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected_str,
            actual=actual_str,
            timestamp=check_time,
        ),
    )


def _check_file_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file exists.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.

    Returns:
        CheckResult with passed=True if file exists.

    """
    path = c["path"]
    check_time = datetime.now(timezone.utc)
    cmd = f"test -e {shell_util.quote(path)}"
    result = ssh.run(cmd)

    if result.ok:
        return CheckResult(
            passed=True,
            detail=f"{path}: exists",
            evidence=Evidence(
                method="file_exists",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected="exists",
                actual="exists",
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=False,
        detail=f"{path}: not found",
        evidence=Evidence(
            method="file_exists",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected="exists",
            actual="not found",
            timestamp=check_time,
        ),
    )


def _check_file_not_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file does NOT exist.

    Used for ensuring insecure or deprecated files have been removed.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path that should not exist.

    Returns:
        CheckResult with passed=True if file does not exist.

    """
    path = c["path"]
    check_time = datetime.now(timezone.utc)
    cmd = f"test -e {shell_util.quote(path)}"
    result = ssh.run(cmd)

    if not result.ok:
        return CheckResult(
            passed=True,
            detail=f"{path}: not present (as required)",
            evidence=Evidence(
                method="file_not_exists",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected="absent",
                actual="absent",
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=False,
        detail=f"{path}: exists (should be absent)",
        evidence=Evidence(
            method="file_not_exists",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected="absent",
            actual="exists",
            timestamp=check_time,
        ),
    )


def _check_file_content(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file's entire content matches the expected text.

    Reads the full file and compares (stripped) against expected_content.
    Useful for banner files where the exact wording must match.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - expected_content (str): Expected file content.

    Returns:
        CheckResult with passed=True if content matches exactly.

    """
    path = c["path"]
    expected = c["expected_content"]
    check_time = datetime.now(timezone.utc)

    cmd = f"cat {shell_util.quote(path)}"
    result = ssh.run(cmd)

    if not result.ok:
        return CheckResult(
            passed=False,
            detail=f"{path}: not found or not readable",
            evidence=Evidence(
                method="file_content",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected="file readable with expected content",
                actual="file not found or not readable",
                timestamp=check_time,
            ),
        )

    actual = result.stdout.strip()
    expected_stripped = expected.strip()

    if actual == expected_stripped:
        return CheckResult(
            passed=True,
            detail=f"{path}: content matches expected",
            evidence=Evidence(
                method="file_content",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected_stripped,
                actual=actual,
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=False,
        detail=f"{path}: content does not match expected",
        evidence=Evidence(
            method="file_content",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected_stripped,
            actual=actual,
            timestamp=check_time,
        ),
    )


def _check_file_content_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content matches a regex pattern.

    Uses grep -E (extended regex) to search for the pattern.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - pattern (str): Extended regex pattern to match.

    Returns:
        CheckResult with passed=True if pattern is found in file.

    """
    path = c["path"]
    pattern = c["pattern"]
    check_time = datetime.now(timezone.utc)

    # First check if file exists
    if not shell_util.file_exists(ssh, path):
        return CheckResult(
            passed=False,
            detail=f"{path}: not found",
            evidence=Evidence(
                method="file_content_match",
                command=f"test -e {path}",
                stdout="",
                stderr="",
                exit_code=1,
                expected=f"contains pattern '{pattern}'",
                actual="file not found",
                timestamp=check_time,
            ),
        )

    cmd = f"grep -qE {shell_util.quote(pattern)} {shell_util.quote(path)}"
    result = ssh.run(cmd)

    if result.ok:
        return CheckResult(
            passed=True,
            detail=f"{path}: contains pattern",
            evidence=Evidence(
                method="file_content_match",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=f"contains pattern '{pattern}'",
                actual="pattern found",
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=False,
        detail=f"{path}: pattern not found",
        evidence=Evidence(
            method="file_content_match",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=f"contains pattern '{pattern}'",
            actual="pattern not found",
            timestamp=check_time,
        ),
    )


def _check_file_content_no_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content does NOT match a regex pattern.

    Verifies that a prohibited pattern is absent from the file.
    If the file does not exist, the check passes.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - pattern (str): Extended regex pattern that should not match.

    Returns:
        CheckResult with passed=True if pattern is not found.

    """
    path = c["path"]
    pattern = c["pattern"]
    check_time = datetime.now(timezone.utc)

    if not shell_util.file_exists(ssh, path):
        return CheckResult(
            passed=True,
            detail=f"{path}: not found (pattern cannot exist)",
            evidence=Evidence(
                method="file_content_no_match",
                command=f"test -e {path}",
                stdout="",
                stderr="",
                exit_code=1,
                expected=f"does not contain pattern '{pattern}'",
                actual="file not found",
                timestamp=check_time,
            ),
        )

    cmd = f"grep -qE {shell_util.quote(pattern)} {shell_util.quote(path)}"
    result = ssh.run(cmd)

    if not result.ok:
        return CheckResult(
            passed=True,
            detail=f"{path}: pattern not found (as required)",
            evidence=Evidence(
                method="file_content_no_match",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=f"does not contain pattern '{pattern}'",
                actual="pattern not found",
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=False,
        detail=f"{path}: contains prohibited pattern",
        evidence=Evidence(
            method="file_content_no_match",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=f"does not contain pattern '{pattern}'",
            actual="pattern found",
            timestamp=check_time,
        ),
    )
