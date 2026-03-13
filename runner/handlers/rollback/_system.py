"""System-related rollback handlers.

Handlers for rolling back system configuration changes: sysctl, kernel modules,
mount options, GRUB, and cron jobs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_sysctl_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore sysctl value and persist file."""
    d = pre_state.data
    key = d["key"]
    if d["old_value"] is not None:
        ssh.run(f"sysctl -w {shell_util.quote(key)}={shell_util.quote(d['old_value'])}")
    if d["persist_existed"] and d["old_persist"] is not None:
        shell_util.write_file(ssh, d["persist_file"], d["old_persist"])
    elif not d["persist_existed"]:
        ssh.run(f"rm -f {shell_util.quote(d['persist_file'])}")
    return True, f"Restored {key}={d['old_value']}"


def _rollback_kernel_module_disable(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore modprobe conf and reload module if it was loaded."""
    d = pre_state.data
    conf_path = d["conf_path"]
    if d["conf_existed"] and d["old_conf"] is not None:
        shell_util.write_file(ssh, conf_path, d["old_conf"])
    elif not d["conf_existed"]:
        ssh.run(f"rm -f {shell_util.quote(conf_path)}")
    if d["was_loaded"]:
        ssh.run(f"modprobe {shell_util.quote(d['name'])} 2>/dev/null")
    return True, f"Restored {d['name']} module config"


def _rollback_mount_option_set(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore fstab line to previous state."""
    d = pre_state.data
    mount_point = d["mount_point"]

    if d["old_fstab_line"] is None:
        return False, f"{mount_point}: no previous fstab line captured"

    escaped_mount = shell_util.escape_sed(mount_point)
    old_line_escaped = shell_util.escape_sed(d["old_fstab_line"])
    cmd = f"sed -i 's|.*\\s{escaped_mount}\\s.*|{old_line_escaped}|' /etc/fstab"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to restore fstab: {result.stderr}"

    ssh.run(f"mount -o remount {shell_util.quote(mount_point)}")
    return True, f"Restored {mount_point} options"


def _rollback_grub_parameter_set(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Cannot rollback GRUB parameter changes safely."""
    return False, "GRUB changes cannot be automatically rolled back"


def _rollback_grub_parameter_remove(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Cannot rollback GRUB parameter removal safely."""
    return False, "GRUB changes cannot be automatically rolled back"


def _rollback_cron_job(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore or remove cron file."""
    d = pre_state.data
    cron_file = d["cron_file"]

    if not d["existed"]:
        ssh.run(f"rm -f {shell_util.quote(cron_file)}")
        return True, f"Removed {cron_file}"

    if d["old_content"] is not None:
        if not shell_util.write_file(ssh, cron_file, d["old_content"]):
            return False, f"Failed to restore {cron_file}"
        return True, f"Restored {cron_file}"

    return True, "Cron file restored"


def _rollback_crypto_policy_subpolicy(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore previous crypto policy."""
    old_policy = pre_state.data.get("old_policy")
    if not old_policy:
        return False, "No previous crypto policy captured"
    result = ssh.run(f"update-crypto-policies --set {shell_util.quote(old_policy)}")
    if not result.ok:
        return False, f"Failed to restore crypto policy: {result.stderr}"
    return True, f"Restored crypto policy to {old_policy}"


def _rollback_dconf_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore dconf setting and lock files, then run dconf update."""
    d = pre_state.data
    setting_path = d["setting_path"]
    lock_path = d["lock_path"]

    # Restore or remove setting file
    if d["setting_existed"] and d["old_setting"] is not None:
        if not shell_util.write_file(ssh, setting_path, d["old_setting"]):
            return False, f"Failed to restore {setting_path}"
    elif not d["setting_existed"]:
        ssh.run(f"rm -f {shell_util.quote(setting_path)}")

    # Restore or remove lock file
    if d["lock_existed"] and d["old_lock"] is not None:
        if not shell_util.write_file(ssh, lock_path, d["old_lock"]):
            return False, f"Failed to restore {lock_path}"
    elif not d["lock_existed"]:
        ssh.run(f"rm -f {shell_util.quote(lock_path)}")

    ssh.run("dconf update")
    return True, f"Restored dconf settings at {setting_path}"


def _rollback_crypto_policy_set(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore previous crypto policy."""
    old_policy = pre_state.data.get("old_policy")
    if not old_policy:
        return False, "No previous crypto policy captured"
    result = ssh.run(f"update-crypto-policies --set {shell_util.quote(old_policy)}")
    if not result.ok:
        return False, f"Failed to restore crypto policy: {result.stderr}"
    return True, f"Restored crypto policy to {old_policy}"
