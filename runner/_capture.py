"""Pre-state capture handlers for rollback support."""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_config_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current config line before modification."""
    path = r["path"]
    key = r["key"]
    result = ssh.run(f"grep '^ *{key}' {shlex.quote(path)} 2>/dev/null | tail -1")
    old_line = result.stdout.strip() if result.ok and result.stdout.strip() else None
    return PreState(
        mechanism="config_set",
        data={
            "path": path,
            "key": key,
            "old_line": old_line,
            "existed": old_line is not None,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_config_set_dropin(ssh: SSHSession, r: dict) -> PreState:
    """Capture drop-in file state before modification."""
    full_path = f"{r['dir']}/{r['file']}"
    exists = ssh.run(f"test -f {shlex.quote(full_path)}")
    old_content = None
    if exists.ok:
        cat = ssh.run(f"cat {shlex.quote(full_path)}")
        old_content = cat.stdout if cat.ok else None
    return PreState(
        mechanism="config_set_dropin",
        data={
            "path": full_path,
            "old_content": old_content,
            "existed": exists.ok,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_config_remove(ssh: SSHSession, r: dict) -> PreState:
    """Capture config line before removal."""
    path = r["path"]
    key = r["key"]
    result = ssh.run(f"grep '^ *{key}' {shlex.quote(path)} 2>/dev/null")
    old_lines = result.stdout.strip() if result.ok and result.stdout.strip() else None
    return PreState(
        mechanism="config_remove",
        data={
            "path": path,
            "key": key,
            "old_lines": old_lines,
            "existed": old_lines is not None,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_command_exec(ssh: SSHSession, r: dict) -> PreState:
    """Command exec cannot capture pre-state."""
    return PreState(mechanism="command_exec", data={"note": "arbitrary command"}, capturable=False)


def _capture_file_permissions(ssh: SSHSession, r: dict) -> PreState:
    """Capture current file ownership and permissions."""
    path = r["path"]
    is_glob = "glob" in r or any(ch in path for ch in "*?[")
    quoted = path if is_glob else shlex.quote(path)
    result = ssh.run(f"stat -c '%U %G %a %n' {quoted} 2>/dev/null")
    entries = []
    if result.ok and result.stdout.strip():
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                entries.append({
                    "path": " ".join(parts[3:]),
                    "owner": parts[0],
                    "group": parts[1],
                    "mode": parts[2],
                })
    return PreState(mechanism="file_permissions", data={"entries": entries})


def _capture_sysctl_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current sysctl value and persist file state."""
    key = r["key"]
    persist_file = r.get("persist_file", f"/etc/sysctl.d/99-aegis-{key.replace('.', '-')}.conf")
    result = ssh.run(f"sysctl -n {shlex.quote(key)} 2>/dev/null")
    old_value = result.stdout.strip() if result.ok else None
    persist_result = ssh.run(f"cat {shlex.quote(persist_file)} 2>/dev/null")
    return PreState(
        mechanism="sysctl_set",
        data={
            "key": key,
            "old_value": old_value,
            "persist_file": persist_file,
            "old_persist": persist_result.stdout if persist_result.ok else None,
            "persist_existed": persist_result.ok,
        },
    )


def _capture_package_present(ssh: SSHSession, r: dict) -> PreState:
    """Capture whether package is currently installed."""
    name = r["name"]
    result = ssh.run(f"rpm -q {shlex.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="package_present",
        data={"name": name, "was_installed": result.ok},
    )


def _capture_package_absent(ssh: SSHSession, r: dict) -> PreState:
    """Capture whether package is currently installed before removal."""
    name = r["name"]
    result = ssh.run(f"rpm -q {shlex.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="package_absent",
        data={
            "name": name,
            "was_installed": result.ok,
            "version": result.stdout.strip() if result.ok else None,
        },
    )


def _capture_kernel_module_disable(ssh: SSHSession, r: dict) -> PreState:
    """Capture kernel module conf and load state."""
    name = r["name"]
    conf_path = f"/etc/modprobe.d/{name}.conf"
    conf_result = ssh.run(f"cat {shlex.quote(conf_path)} 2>/dev/null")
    loaded = ssh.run(f"lsmod | grep -q '^{name} '")
    return PreState(
        mechanism="kernel_module_disable",
        data={
            "name": name,
            "conf_path": conf_path,
            "old_conf": conf_result.stdout if conf_result.ok else None,
            "conf_existed": conf_result.ok,
            "was_loaded": loaded.ok,
        },
    )


def _capture_manual(ssh: SSHSession, r: dict) -> PreState:
    """Manual mechanism cannot capture pre-state."""
    return PreState(mechanism="manual", data={}, capturable=False)


def _capture_file_content(ssh: SSHSession, r: dict) -> PreState:
    """Capture current file content before modification."""
    path = r["path"]
    exists = ssh.run(f"test -f {shlex.quote(path)}")
    old_content = None
    old_owner = None
    old_group = None
    old_mode = None

    if exists.ok:
        cat = ssh.run(f"cat {shlex.quote(path)}")
        old_content = cat.stdout if cat.ok else None
        stat = ssh.run(f"stat -c '%U %G %a' {shlex.quote(path)}")
        if stat.ok:
            parts = stat.stdout.strip().split()
            if len(parts) >= 3:
                old_owner, old_group, old_mode = parts[0], parts[1], parts[2]

    return PreState(
        mechanism="file_content",
        data={
            "path": path,
            "existed": exists.ok,
            "old_content": old_content,
            "old_owner": old_owner,
            "old_group": old_group,
            "old_mode": old_mode,
        },
    )


def _capture_file_absent(ssh: SSHSession, r: dict) -> PreState:
    """Capture file state before removal."""
    path = r["path"]
    exists = ssh.run(f"test -f {shlex.quote(path)}")
    old_content = None
    old_owner = None
    old_group = None
    old_mode = None

    if exists.ok:
        cat = ssh.run(f"cat {shlex.quote(path)}")
        old_content = cat.stdout if cat.ok else None
        stat = ssh.run(f"stat -c '%U %G %a' {shlex.quote(path)}")
        if stat.ok:
            parts = stat.stdout.strip().split()
            if len(parts) >= 3:
                old_owner, old_group, old_mode = parts[0], parts[1], parts[2]

    return PreState(
        mechanism="file_absent",
        data={
            "path": path,
            "existed": exists.ok,
            "old_content": old_content,
            "old_owner": old_owner,
            "old_group": old_group,
            "old_mode": old_mode,
        },
    )


def _capture_config_block(ssh: SSHSession, r: dict) -> PreState:
    """Capture file content before writing block."""
    path = r["path"]
    marker = r.get("marker", "# AEGIS MANAGED BLOCK")
    begin_marker = f"# BEGIN {marker}"

    exists = ssh.run(f"test -f {shlex.quote(path)}")
    old_content = None
    if exists.ok:
        cat = ssh.run(f"cat {shlex.quote(path)}")
        old_content = cat.stdout if cat.ok else None

    # Check if block already exists
    block_exists = ssh.run(f"grep -qF {shlex.quote(begin_marker)} {shlex.quote(path)} 2>/dev/null")

    return PreState(
        mechanism="config_block",
        data={
            "path": path,
            "existed": exists.ok,
            "old_content": old_content,
            "block_existed": block_exists.ok,
            "marker": marker,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_cron_job(ssh: SSHSession, r: dict) -> PreState:
    """Capture cron file state before creation."""
    name = r.get("name", "aegis-managed")
    cron_file = f"/etc/cron.d/{name}"

    exists = ssh.run(f"test -f {shlex.quote(cron_file)}")
    old_content = None
    if exists.ok:
        cat = ssh.run(f"cat {shlex.quote(cron_file)}")
        old_content = cat.stdout if cat.ok else None

    return PreState(
        mechanism="cron_job",
        data={
            "cron_file": cron_file,
            "existed": exists.ok,
            "old_content": old_content,
        },
    )


def _capture_mount_option_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current mount options before modification."""
    mount_point = r["mount_point"]

    # Get current fstab line
    fstab_result = ssh.run(f"grep -E '\\s{shlex.quote(mount_point)}\\s' /etc/fstab")
    old_fstab_line = fstab_result.stdout.strip() if fstab_result.ok else None

    # Get current mount options
    mount_result = ssh.run(f"findmnt -n -o OPTIONS {shlex.quote(mount_point)} 2>/dev/null")
    old_options = mount_result.stdout.strip() if mount_result.ok else None

    return PreState(
        mechanism="mount_option_set",
        data={
            "mount_point": mount_point,
            "old_fstab_line": old_fstab_line,
            "old_options": old_options,
        },
    )


def _capture_grub_parameter_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current GRUB kernel args before modification."""
    result = ssh.run("grubby --info=DEFAULT 2>/dev/null | grep -E 'args='")
    old_args = result.stdout.strip() if result.ok else None
    return PreState(
        mechanism="grub_parameter_set",
        data={
            "key": r["key"],
            "old_args": old_args,
        },
        capturable=False,  # GRUB changes are complex to rollback
    )


def _capture_grub_parameter_remove(ssh: SSHSession, r: dict) -> PreState:
    """Capture current GRUB kernel args before removal."""
    result = ssh.run("grubby --info=DEFAULT 2>/dev/null | grep -E 'args='")
    old_args = result.stdout.strip() if result.ok else None
    return PreState(
        mechanism="grub_parameter_remove",
        data={
            "key": r["key"],
            "old_args": old_args,
        },
        capturable=False,  # GRUB changes are complex to rollback
    )


def _capture_audit_rule_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture audit rule state before adding."""
    rule = r["rule"]
    persist_file = r.get("persist_file", "/etc/audit/rules.d/99-aegis.rules")

    # Check if rule already exists in running config
    result = ssh.run("auditctl -l 2>/dev/null")
    rule_existed = result.ok and rule in result.stdout

    # Check persist file state
    persist_result = ssh.run(f"cat {shlex.quote(persist_file)} 2>/dev/null")

    return PreState(
        mechanism="audit_rule_set",
        data={
            "rule": rule,
            "persist_file": persist_file,
            "rule_existed": rule_existed,
            "old_persist_content": persist_result.stdout if persist_result.ok else None,
            "persist_existed": persist_result.ok,
        },
    )


def _capture_selinux_boolean_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current SELinux boolean value."""
    name = r["name"]
    result = ssh.run(f"getsebool {shlex.quote(name)} 2>/dev/null")
    old_value = None
    if result.ok:
        parts = result.stdout.strip().split()
        if len(parts) >= 3:
            old_value = parts[-1].lower() == "on"
    return PreState(
        mechanism="selinux_boolean_set",
        data={
            "name": name,
            "old_value": old_value,
            "persistent": r.get("persistent", True),
        },
    )


def _capture_service_enabled(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enabled/active state before enabling."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shlex.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shlex.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_enabled",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else "unknown",
            "was_active": active.stdout.strip() if active.ok else "unknown",
        },
    )


def _capture_service_disabled(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enabled/active state before disabling."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shlex.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shlex.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_disabled",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else "unknown",
            "was_active": active.stdout.strip() if active.ok else "unknown",
        },
    )


def _capture_service_masked(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enabled/active state before masking."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shlex.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shlex.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_masked",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else "unknown",
            "was_active": active.stdout.strip() if active.ok else "unknown",
        },
    )


CAPTURE_HANDLERS = {
    "config_set": _capture_config_set,
    "config_set_dropin": _capture_config_set_dropin,
    "config_remove": _capture_config_remove,
    "command_exec": _capture_command_exec,
    "file_permissions": _capture_file_permissions,
    "file_content": _capture_file_content,
    "file_absent": _capture_file_absent,
    "sysctl_set": _capture_sysctl_set,
    "package_present": _capture_package_present,
    "package_absent": _capture_package_absent,
    "kernel_module_disable": _capture_kernel_module_disable,
    "manual": _capture_manual,
    "service_enabled": _capture_service_enabled,
    "service_disabled": _capture_service_disabled,
    "service_masked": _capture_service_masked,
    "selinux_boolean_set": _capture_selinux_boolean_set,
    "audit_rule_set": _capture_audit_rule_set,
    "mount_option_set": _capture_mount_option_set,
    "grub_parameter_set": _capture_grub_parameter_set,
    "grub_parameter_remove": _capture_grub_parameter_remove,
    "config_block": _capture_config_block,
    "cron_job": _capture_cron_job,
}


def _dispatch_capture(ssh: SSHSession, rem: dict) -> PreState | None:
    """Capture pre-state for a remediation step."""
    mechanism = rem.get("mechanism", "")
    handler = CAPTURE_HANDLERS.get(mechanism)
    if handler is None:
        return None
    return handler(ssh, rem)
