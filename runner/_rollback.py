"""Rollback handlers for reversing remediation steps."""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from runner._remediation import _reload_service
from runner._types import PreState, RollbackResult, StepResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_config_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore config file line to pre-remediation state."""
    d = pre_state.data
    path, key = d["path"], d["key"]
    if d["existed"] and d["old_line"]:
        # Restore the original line
        escaped = d["old_line"].replace("/", "\\/")
        cmd = f"sed -i 's/^ *{key}.*/{escaped}/' {shlex.quote(path)}"
    else:
        # Line was appended — remove it
        cmd = f"sed -i '/^ *{key}/d' {shlex.quote(path)}"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to restore {key} in {path}: {result.stderr}"
    if d.get("reload") or d.get("restart"):
        _reload_service(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})
    return True, f"Restored {key} in {path}"


def _rollback_config_set_dropin(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore or remove drop-in file."""
    d = pre_state.data
    path = d["path"]
    if not d["existed"]:
        # File didn't exist before — remove it
        result = ssh.run(f"rm -f {shlex.quote(path)}")
        if not result.ok:
            return False, f"Failed to remove {path}: {result.stderr}"
        detail = f"Removed {path}"
    else:
        # Restore old content
        result = ssh.run(
            f"printf %s {shlex.quote(d['old_content'])} > {shlex.quote(path)}"
        )
        if not result.ok:
            return False, f"Failed to restore {path}: {result.stderr}"
        detail = f"Restored {path}"
    if d.get("reload") or d.get("restart"):
        _reload_service(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})
    return True, detail


def _rollback_config_remove(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore removed config lines."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"] or d["old_lines"] is None:
        return True, f"No lines to restore in {path}"

    # Append the old lines back
    for line in d["old_lines"].splitlines():
        result = ssh.run(f"echo {shlex.quote(line)} >> {shlex.quote(path)}")
        if not result.ok:
            return False, f"Failed to restore line in {path}: {result.stderr}"

    if d.get("reload") or d.get("restart"):
        _reload_service(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})

    return True, f"Restored removed lines in {path}"


def _rollback_command_exec(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Cannot rollback arbitrary commands."""
    return False, "Cannot rollback arbitrary commands"


def _rollback_file_permissions(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore original file ownership and permissions."""
    entries = pre_state.data.get("entries", [])
    if not entries:
        return False, "No file entries to restore"
    for entry in entries:
        p = shlex.quote(entry["path"])
        ssh.run(f"chown {entry['owner']}:{entry['group']} {p}")
        ssh.run(f"chmod {entry['mode']} {p}")
    return True, f"Restored permissions on {len(entries)} file(s)"


def _rollback_sysctl_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore sysctl value and persist file."""
    d = pre_state.data
    key = d["key"]
    if d["old_value"] is not None:
        ssh.run(f"sysctl -w {shlex.quote(key)}={shlex.quote(d['old_value'])}")
    if d["persist_existed"] and d["old_persist"] is not None:
        ssh.run(
            f"printf %s {shlex.quote(d['old_persist'])} > {shlex.quote(d['persist_file'])}"
        )
    elif not d["persist_existed"]:
        ssh.run(f"rm -f {shlex.quote(d['persist_file'])}")
    return True, f"Restored {key}={d['old_value']}"


def _rollback_package_present(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Remove package if it was not installed before."""
    d = pre_state.data
    if d["was_installed"]:
        return True, f"{d['name']} was already installed, nothing to rollback"
    result = ssh.run(f"dnf remove -y {shlex.quote(d['name'])}", timeout=300)
    if not result.ok:
        return False, f"Failed to remove {d['name']}: {result.stderr}"
    return True, f"Removed {d['name']}"


def _rollback_package_absent(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Re-install package if it was installed before."""
    d = pre_state.data
    if not d["was_installed"]:
        return True, f"{d['name']} was not installed, nothing to restore"
    result = ssh.run(f"dnf install -y {shlex.quote(d['name'])}", timeout=300)
    if not result.ok:
        return False, f"Failed to reinstall {d['name']}: {result.stderr}"
    return True, f"Reinstalled {d['name']}"


def _rollback_kernel_module_disable(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore modprobe conf and reload module if it was loaded."""
    d = pre_state.data
    conf_path = d["conf_path"]
    if d["conf_existed"] and d["old_conf"] is not None:
        ssh.run(f"printf %s {shlex.quote(d['old_conf'])} > {shlex.quote(conf_path)}")
    elif not d["conf_existed"]:
        ssh.run(f"rm -f {shlex.quote(conf_path)}")
    if d["was_loaded"]:
        ssh.run(f"modprobe {shlex.quote(d['name'])} 2>/dev/null")
    return True, f"Restored {d['name']} module config"


def _rollback_manual(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Nothing to rollback for manual mechanism."""
    return False, "Nothing to rollback"


def _rollback_file_content(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore file to its previous content."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"]:
        # File didn't exist before — remove it
        result = ssh.run(f"rm -f {shlex.quote(path)}")
        if not result.ok:
            return False, f"Failed to remove {path}: {result.stderr}"
        return True, f"Removed {path}"

    # Restore old content
    if d["old_content"] is not None:
        result = ssh.run(
            f"printf %s {shlex.quote(d['old_content'])} > {shlex.quote(path)}"
        )
        if not result.ok:
            return False, f"Failed to restore {path}: {result.stderr}"

    # Restore permissions
    if d["old_owner"] or d["old_group"]:
        chown_spec = f"{d['old_owner'] or ''}:{d['old_group'] or ''}"
        ssh.run(f"chown {chown_spec} {shlex.quote(path)}")
    if d["old_mode"]:
        ssh.run(f"chmod {d['old_mode']} {shlex.quote(path)}")

    return True, f"Restored {path}"


def _rollback_file_absent(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore a removed file."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"]:
        return True, f"{path} was already absent, nothing to restore"

    # Restore old content
    if d["old_content"] is None:
        return False, f"Cannot restore {path}: content not captured"

    result = ssh.run(f"printf %s {shlex.quote(d['old_content'])} > {shlex.quote(path)}")
    if not result.ok:
        return False, f"Failed to restore {path}: {result.stderr}"

    # Restore permissions
    if d["old_owner"] or d["old_group"]:
        chown_spec = f"{d['old_owner'] or ''}:{d['old_group'] or ''}"
        ssh.run(f"chown {chown_spec} {shlex.quote(path)}")
    if d["old_mode"]:
        ssh.run(f"chmod {d['old_mode']} {shlex.quote(path)}")

    return True, f"Restored {path}"


def _rollback_config_block(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore file to state before block was added."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"]:
        # File didn't exist - remove it
        ssh.run(f"rm -f {shlex.quote(path)}")
        return True, f"Removed {path}"

    if d["old_content"] is not None:
        # Restore old content
        result = ssh.run(
            f"printf %s {shlex.quote(d['old_content'])} > {shlex.quote(path)}"
        )
        if not result.ok:
            return False, f"Failed to restore {path}: {result.stderr}"

    if d.get("reload") or d.get("restart"):
        _reload_service(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})

    return True, f"Restored {path}"


def _rollback_cron_job(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore or remove cron file."""
    d = pre_state.data
    cron_file = d["cron_file"]

    if not d["existed"]:
        # File didn't exist - remove it
        ssh.run(f"rm -f {shlex.quote(cron_file)}")
        return True, f"Removed {cron_file}"

    if d["old_content"] is not None:
        # Restore old content
        result = ssh.run(
            f"printf %s {shlex.quote(d['old_content'])} > {shlex.quote(cron_file)}"
        )
        if not result.ok:
            return False, f"Failed to restore {cron_file}: {result.stderr}"
        return True, f"Restored {cron_file}"

    return True, "Cron file restored"


def _rollback_mount_option_set(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore fstab line to previous state."""
    d = pre_state.data
    mount_point = d["mount_point"]

    if d["old_fstab_line"] is None:
        return False, f"{mount_point}: no previous fstab line captured"

    # Restore the old fstab line
    escaped_mount = mount_point.replace("/", "\\/")
    old_line_escaped = d["old_fstab_line"].replace("/", "\\/")
    cmd = f"sed -i 's|.*\\s{escaped_mount}\\s.*|{old_line_escaped}|' /etc/fstab"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to restore fstab: {result.stderr}"

    # Remount
    ssh.run(f"mount -o remount {shlex.quote(mount_point)}")
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


def _rollback_audit_rule_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Remove audit rule if it didn't exist before."""
    d = pre_state.data
    rule = d["rule"]
    persist_file = d["persist_file"]

    if d["rule_existed"]:
        return True, "Rule already existed, nothing to rollback"

    # Remove from running config
    # auditctl -d removes a rule (same syntax as -a but with -d)
    delete_rule = rule.replace("-a ", "-d ", 1).replace("-w ", "-W ", 1)
    ssh.run(f"auditctl {delete_rule} 2>/dev/null")

    # Restore persist file
    if d["persist_existed"] and d["old_persist_content"] is not None:
        ssh.run(
            f"printf %s {shlex.quote(d['old_persist_content'])} > {shlex.quote(persist_file)}"
        )
    elif not d["persist_existed"]:
        ssh.run(f"rm -f {shlex.quote(persist_file)}")

    return True, "Removed audit rule"


def _rollback_selinux_boolean_set(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore SELinux boolean to previous value."""
    d = pre_state.data
    name = d["name"]
    if d["old_value"] is None:
        return False, f"{name}: could not determine previous value"

    value_str = "on" if d["old_value"] else "off"
    cmd = f"setsebool {'-P ' if d['persistent'] else ''}{shlex.quote(name)} {value_str}"
    result = ssh.run(cmd, timeout=60)
    if not result.ok:
        return False, f"Failed to restore {name}: {result.stderr}"
    return True, f"Restored {name} = {value_str}"


def _rollback_service_enabled(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service to pre-enabled state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    # Restore enabled state
    if was_enabled in ("disabled", "masked"):
        ssh.run(f"systemctl disable {shlex.quote(name)}")
    elif was_enabled == "masked":
        ssh.run(f"systemctl mask {shlex.quote(name)}")

    # Restore active state
    if was_active in ("inactive", "failed", "unknown"):
        ssh.run(f"systemctl stop {shlex.quote(name)}")

    return True, f"Restored {name} to {was_enabled}/{was_active}"


def _rollback_service_disabled(
    ssh: SSHSession, pre_state: PreState
) -> tuple[bool, str]:
    """Restore service to pre-disabled state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    # Restore enabled state
    if was_enabled == "enabled":
        ssh.run(f"systemctl enable {shlex.quote(name)}")

    # Restore active state
    if was_active == "active":
        ssh.run(f"systemctl start {shlex.quote(name)}")

    return True, f"Restored {name} to {was_enabled}/{was_active}"


def _rollback_service_masked(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service from masked state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    # Unmask first
    ssh.run(f"systemctl unmask {shlex.quote(name)}")

    # Restore enabled state
    if was_enabled == "enabled":
        ssh.run(f"systemctl enable {shlex.quote(name)}")

    # Restore active state
    if was_active == "active":
        ssh.run(f"systemctl start {shlex.quote(name)}")

    return True, f"Restored {name} to {was_enabled}/{was_active}"


ROLLBACK_HANDLERS = {
    "config_set": _rollback_config_set,
    "config_set_dropin": _rollback_config_set_dropin,
    "config_remove": _rollback_config_remove,
    "command_exec": _rollback_command_exec,
    "file_permissions": _rollback_file_permissions,
    "file_content": _rollback_file_content,
    "file_absent": _rollback_file_absent,
    "sysctl_set": _rollback_sysctl_set,
    "package_present": _rollback_package_present,
    "package_absent": _rollback_package_absent,
    "kernel_module_disable": _rollback_kernel_module_disable,
    "manual": _rollback_manual,
    "service_enabled": _rollback_service_enabled,
    "service_disabled": _rollback_service_disabled,
    "service_masked": _rollback_service_masked,
    "selinux_boolean_set": _rollback_selinux_boolean_set,
    "audit_rule_set": _rollback_audit_rule_set,
    "mount_option_set": _rollback_mount_option_set,
    "grub_parameter_set": _rollback_grub_parameter_set,
    "grub_parameter_remove": _rollback_grub_parameter_remove,
    "config_block": _rollback_config_block,
    "cron_job": _rollback_cron_job,
}


def _execute_rollback(
    ssh: SSHSession, step_results: list[StepResult]
) -> list[RollbackResult]:
    """Roll back completed steps in reverse order."""
    results = []
    for sr in reversed(step_results):
        if not sr.success or sr.pre_state is None or not sr.pre_state.capturable:
            results.append(
                RollbackResult(sr.step_index, sr.mechanism, False, "skipped")
            )
            continue
        handler = ROLLBACK_HANDLERS.get(sr.mechanism)
        if handler is None:
            results.append(
                RollbackResult(sr.step_index, sr.mechanism, False, "no handler")
            )
            continue
        ok, detail = handler(ssh, sr.pre_state)
        results.append(RollbackResult(sr.step_index, sr.mechanism, ok, detail))
    return results
