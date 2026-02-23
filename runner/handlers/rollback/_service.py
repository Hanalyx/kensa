"""Service-related rollback handlers.

Handlers for rolling back systemd service changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_service_enabled(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service to pre-enabled state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    errors: list[str] = []

    if was_enabled == "masked":
        result = ssh.run(f"systemctl mask {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"mask failed: {result.stderr}")
    elif was_enabled == "disabled":
        result = ssh.run(f"systemctl disable {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"disable failed: {result.stderr}")

    if was_active in ("inactive", "failed", "unknown"):
        result = ssh.run(f"systemctl stop {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"stop failed: {result.stderr}")

    if errors:
        return False, f"Failed to restore {name}: {'; '.join(errors)}"
    return True, f"Restored {name} to {was_enabled}/{was_active}"


def _rollback_service_disabled(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore service to pre-disabled state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    errors: list[str] = []

    if was_enabled == "enabled":
        result = ssh.run(f"systemctl enable {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"enable failed: {result.stderr}")

    if was_active == "active":
        result = ssh.run(f"systemctl start {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"start failed: {result.stderr}")

    if errors:
        return False, f"Failed to restore {name}: {'; '.join(errors)}"
    return True, f"Restored {name} to {was_enabled}/{was_active}"


def _rollback_service_masked(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service from masked state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    errors: list[str] = []

    result = ssh.run(f"systemctl unmask {shell_util.quote(name)}")
    if not result.ok:
        errors.append(f"unmask failed: {result.stderr}")

    if was_enabled == "enabled":
        result = ssh.run(f"systemctl enable {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"enable failed: {result.stderr}")

    if was_active == "active":
        result = ssh.run(f"systemctl start {shell_util.quote(name)}")
        if not result.ok:
            errors.append(f"start failed: {result.stderr}")

    if errors:
        return False, f"Failed to restore {name}: {'; '.join(errors)}"
    return True, f"Restored {name} to {was_enabled}/{was_active}"
