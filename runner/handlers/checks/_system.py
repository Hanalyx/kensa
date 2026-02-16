"""System-related check handlers.

Handlers for verifying system state: sysctl parameters, kernel modules,
mount options, and GRUB boot parameters.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult, Evidence

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_sysctl_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check a kernel sysctl parameter value.

    Reads the current value of a sysctl parameter and compares it
    to the expected value.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): Sysctl parameter name.
            - expected (str): Expected value.

    Returns:
        CheckResult with passed=True if current value matches expected.

    """
    key = c["key"]
    expected = str(c["expected"])
    check_time = datetime.now(timezone.utc)
    cmd = f"sysctl -n {shell_util.quote(key)} 2>/dev/null"
    result = ssh.run(cmd)

    if not result.ok:
        return CheckResult(
            passed=False,
            detail=f"sysctl {key}: not available",
            evidence=Evidence(
                method="sysctl_value",
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
    passed = actual == expected
    detail = f"{key}={actual}" if passed else f"{key}={actual} (expected {expected})"

    return CheckResult(
        passed=passed,
        detail=detail,
        evidence=Evidence(
            method="sysctl_value",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=actual,
            timestamp=check_time,
        ),
    )


def _check_kernel_module_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check kernel module load state.

    Verifies whether a kernel module is loaded or properly disabled/blacklisted.
    For disabled modules, checks both that it's not currently loaded
    and that modprobe is configured to prevent loading.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Kernel module name.
            - state (str, optional): Desired state - "blacklisted", "disabled",
              or "loaded". Defaults to "blacklisted". "disabled" and
              "blacklisted" are equivalent (both prevent module loading).

    Returns:
        CheckResult with passed=True if module is in the expected state.

    """
    name = c["name"]
    state = c.get("state", "blacklisted")
    check_time = datetime.now(timezone.utc)

    # "disabled" and "blacklisted" are equivalent - both prevent module loading
    if state in ("blacklisted", "disabled"):
        # Module should NOT be loaded and should be blacklisted/disabled
        lsmod_cmd = f"lsmod | grep -q '^{name} '"
        loaded = ssh.run(lsmod_cmd)
        if loaded.ok:
            return CheckResult(
                passed=False,
                detail=f"{name}: still loaded",
                evidence=Evidence(
                    method="kernel_module_state",
                    command=lsmod_cmd,
                    stdout=loaded.stdout,
                    stderr=loaded.stderr,
                    exit_code=loaded.exit_code,
                    expected=state,
                    actual="loaded",
                    timestamp=check_time,
                ),
            )

        # Check for blacklist or install /bin/false|/bin/true directives
        modprobe_cmd = f"modprobe -n -v {shell_util.quote(name)} 2>&1"
        modprobe_result = ssh.run(modprobe_cmd)
        blacklist_check = ssh.run(
            f"modprobe -n -v {shell_util.quote(name)} 2>&1 | grep -q 'install /bin/true\\|install /bin/false\\|blacklist'"
        )
        if not blacklist_check.ok:
            return CheckResult(
                passed=False,
                detail=f"{name}: not blacklisted",
                evidence=Evidence(
                    method="kernel_module_state",
                    command=modprobe_cmd,
                    stdout=modprobe_result.stdout,
                    stderr=modprobe_result.stderr,
                    exit_code=modprobe_result.exit_code,
                    expected=state,
                    actual="not blacklisted",
                    timestamp=check_time,
                ),
            )

        return CheckResult(
            passed=True,
            detail=f"{name}: blacklisted",
            evidence=Evidence(
                method="kernel_module_state",
                command=modprobe_cmd,
                stdout=modprobe_result.stdout,
                stderr=modprobe_result.stderr,
                exit_code=modprobe_result.exit_code,
                expected=state,
                actual="blacklisted",
                timestamp=check_time,
            ),
        )

    elif state == "loaded":
        lsmod_cmd = f"lsmod | grep -q '^{name} '"
        loaded = ssh.run(lsmod_cmd)
        if loaded.ok:
            return CheckResult(
                passed=True,
                detail=f"{name}: loaded",
                evidence=Evidence(
                    method="kernel_module_state",
                    command=lsmod_cmd,
                    stdout=loaded.stdout,
                    stderr=loaded.stderr,
                    exit_code=loaded.exit_code,
                    expected=state,
                    actual="loaded",
                    timestamp=check_time,
                ),
            )
        return CheckResult(
            passed=False,
            detail=f"{name}: not loaded",
            evidence=Evidence(
                method="kernel_module_state",
                command=lsmod_cmd,
                stdout=loaded.stdout,
                stderr=loaded.stderr,
                exit_code=loaded.exit_code,
                expected=state,
                actual="not loaded",
                timestamp=check_time,
            ),
        )

    return CheckResult(
        passed=False,
        detail=f"Unknown module state: {state}",
        evidence=Evidence(
            method="error",
            command=None,
            stdout="",
            stderr=f"Unknown module state: {state}",
            exit_code=-1,
            expected=state,
            actual=None,
            timestamp=check_time,
        ),
    )


def _check_mount_option(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a mount point has required mount options.

    Uses findmnt to check currently mounted options.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - mount_point (str): Mount point path.
            - options (list[str]): Required mount options.

    Returns:
        CheckResult with passed=True if all options are present.

    """
    mount_point = c["mount_point"]
    required_options = c.get("options", [])
    check_time = datetime.now(timezone.utc)
    cmd = f"findmnt -n -o OPTIONS {shell_util.quote(mount_point)} 2>/dev/null"

    result = ssh.run(cmd)
    if not result.ok or not result.stdout.strip():
        return CheckResult(
            passed=False,
            detail=f"{mount_point}: not mounted",
            evidence=Evidence(
                method="mount_option",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=",".join(required_options),
                actual=None,
                timestamp=check_time,
            ),
        )

    current_options = set(result.stdout.strip().split(","))
    missing = [opt for opt in required_options if opt not in current_options]
    actual_str = result.stdout.strip()

    if missing:
        return CheckResult(
            passed=False,
            detail=f"{mount_point}: missing options: {', '.join(missing)}",
            evidence=Evidence(
                method="mount_option",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=",".join(required_options),
                actual=actual_str,
                timestamp=check_time,
            ),
        )
    return CheckResult(
        passed=True,
        detail=f"{mount_point}: has required options",
        evidence=Evidence(
            method="mount_option",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=",".join(required_options),
            actual=actual_str,
            timestamp=check_time,
        ),
    )


def _check_grub_parameter(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a kernel boot parameter is set in GRUB.

    Uses grubby to inspect the default kernel's boot arguments.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): Kernel parameter name.
            - expected (str, optional): Expected value.

    Returns:
        CheckResult with passed=True if parameter exists with expected value.

    """
    key = c["key"]
    expected = c.get("expected")
    check_time = datetime.now(timezone.utc)
    cmd = "grubby --info=DEFAULT 2>/dev/null | grep -E 'args='"

    result = ssh.run(cmd)
    if result.ok:
        args_line = result.stdout.strip()
        if f"{key}=" in args_line:
            match = re.search(rf"{key}=(\S+)", args_line)
            if match:
                actual = match.group(1).strip('"')
                passed = expected is None or actual == expected
                detail = (
                    f"{key}={actual}"
                    if passed
                    else f"{key}={actual} (expected {expected})"
                )
                return CheckResult(
                    passed=passed,
                    detail=detail,
                    evidence=Evidence(
                        method="grub_parameter",
                        command=cmd,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        exit_code=result.exit_code,
                        expected=expected,
                        actual=actual,
                        timestamp=check_time,
                    ),
                )
        elif key in args_line:
            if expected is None or expected == "":
                return CheckResult(
                    passed=True,
                    detail=f"{key} present",
                    evidence=Evidence(
                        method="grub_parameter",
                        command=cmd,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        exit_code=result.exit_code,
                        expected=expected,
                        actual="present",
                        timestamp=check_time,
                    ),
                )
            return CheckResult(
                passed=False,
                detail=f"{key} present but expected value {expected}",
                evidence=Evidence(
                    method="grub_parameter",
                    command=cmd,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    exit_code=result.exit_code,
                    expected=expected,
                    actual="present (no value)",
                    timestamp=check_time,
                ),
            )
        return CheckResult(
            passed=False,
            detail=f"{key} not found in kernel args",
            evidence=Evidence(
                method="grub_parameter",
                command=cmd,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                expected=expected,
                actual=None,
                timestamp=check_time,
            ),
        )

    return CheckResult(
        passed=False,
        detail="grubby not available",
        evidence=Evidence(
            method="grub_parameter",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=None,
            timestamp=check_time,
        ),
    )
