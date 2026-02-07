"""Config-related check handlers.

Handlers for verifying configuration file state: key presence,
absence, and values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_config_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a configuration key has an expected value.

    Searches for a key in a config file or directory of config files.
    Supports both 'key value' and 'key=value' formats with optional
    whitespace around separators.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or directory to search.
            - key (str): Configuration key name to find.
            - expected (str): Expected value for the key.
            - scan_pattern (str, optional): Glob for directory mode.
              Defaults to "*.conf".

    Returns:
        CheckResult with passed=True if key exists with expected value.

    """
    path = c["path"]
    key = c["key"]
    expected = str(c["expected"])
    scan_pattern = c.get("scan_pattern", "*.conf")

    result = shell_util.grep_config_key(ssh, path, key, scan_pattern=scan_pattern)

    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{key} not found in {path}")

    line = result.stdout.strip()
    actual = shell_util.parse_config_value(line, key)

    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_config_absent(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a configuration key does NOT exist in a file.

    Verifies that a specific key is absent from a config file or directory.
    Used for ensuring deprecated or insecure options are removed.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or directory to search.
            - key (str): Configuration key that should not exist.
            - scan_pattern (str, optional): Glob for directory mode.

    Returns:
        CheckResult with passed=True if key is not found.

    """
    path = c["path"]
    key = c["key"]
    scan_pattern = c.get("scan_pattern", "*.conf")

    result = shell_util.grep_config_key(ssh, path, key, scan_pattern=scan_pattern)

    if not result.ok or not result.stdout.strip():
        return CheckResult(
            passed=True, detail=f"{key} not found in {path} (as required)"
        )

    return CheckResult(passed=False, detail=f"{key} found in {path} (should be absent)")
