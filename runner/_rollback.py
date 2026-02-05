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


def _rollback_config_set_dropin(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
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
        result = ssh.run(f"printf %s {shlex.quote(d['old_content'])} > {shlex.quote(path)}")
        if not result.ok:
            return False, f"Failed to restore {path}: {result.stderr}"
        detail = f"Restored {path}"
    if d.get("reload") or d.get("restart"):
        _reload_service(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})
    return True, detail


def _rollback_command_exec(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Cannot rollback arbitrary commands."""
    return False, "Cannot rollback arbitrary commands"


def _rollback_file_permissions(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
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
        ssh.run(f"printf %s {shlex.quote(d['old_persist'])} > {shlex.quote(d['persist_file'])}")
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


def _rollback_kernel_module_disable(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
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


ROLLBACK_HANDLERS = {
    "config_set": _rollback_config_set,
    "config_set_dropin": _rollback_config_set_dropin,
    "command_exec": _rollback_command_exec,
    "file_permissions": _rollback_file_permissions,
    "sysctl_set": _rollback_sysctl_set,
    "package_present": _rollback_package_present,
    "kernel_module_disable": _rollback_kernel_module_disable,
    "manual": _rollback_manual,
}


def _execute_rollback(
    ssh: SSHSession, step_results: list[StepResult]
) -> list[RollbackResult]:
    """Roll back completed steps in reverse order."""
    results = []
    for sr in reversed(step_results):
        if not sr.success or sr.pre_state is None or not sr.pre_state.capturable:
            results.append(RollbackResult(sr.step_index, sr.mechanism, False, "skipped"))
            continue
        handler = ROLLBACK_HANDLERS.get(sr.mechanism)
        if handler is None:
            results.append(RollbackResult(sr.step_index, sr.mechanism, False, "no handler"))
            continue
        ok, detail = handler(ssh, sr.pre_state)
        results.append(RollbackResult(sr.step_index, sr.mechanism, ok, detail))
    return results
