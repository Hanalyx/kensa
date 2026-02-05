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


CAPTURE_HANDLERS = {
    "config_set": _capture_config_set,
    "config_set_dropin": _capture_config_set_dropin,
    "command_exec": _capture_command_exec,
    "file_permissions": _capture_file_permissions,
    "sysctl_set": _capture_sysctl_set,
    "package_present": _capture_package_present,
    "kernel_module_disable": _capture_kernel_module_disable,
    "manual": _capture_manual,
}


def _dispatch_capture(ssh: SSHSession, rem: dict) -> PreState | None:
    """Capture pre-state for a remediation step."""
    mechanism = rem.get("mechanism", "")
    handler = CAPTURE_HANDLERS.get(mechanism)
    if handler is None:
        return None
    return handler(ssh, rem)
