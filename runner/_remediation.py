"""Remediation handlers and dispatch."""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from runner._capture import _dispatch_capture
from runner._checks import run_check
from runner._types import StepResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def run_remediation(
    ssh: SSHSession,
    remediation: dict,
    *,
    dry_run: bool = False,
    check: dict | None = None,
) -> tuple[bool, str, list[StepResult]]:
    """Dispatch a remediation definition.

    Returns (success, detail, step_results).
    """
    # Multi-step remediation
    if "steps" in remediation:
        details = []
        step_results: list[StepResult] = []
        for i, step in enumerate(remediation["steps"]):
            mech = step.get("mechanism", "")
            pre_state = _dispatch_capture(ssh, step) if not dry_run else None
            ok, detail = _dispatch_remediation(ssh, step, dry_run=dry_run)
            details.append(detail)
            sr = StepResult(i, mech, ok, detail, pre_state)
            # Per-step verification (multi-step only, not dry_run)
            if ok and not dry_run and check:
                cr = run_check(ssh, check)
                sr.verified = cr.passed
                sr.verify_detail = cr.detail
            step_results.append(sr)
            if not ok:
                return False, "; ".join(details), step_results
        return True, "; ".join(details), step_results

    # Single-step
    mech = remediation.get("mechanism", "")
    pre_state = _dispatch_capture(ssh, remediation) if not dry_run else None
    ok, detail = _dispatch_remediation(ssh, remediation, dry_run=dry_run)
    sr = StepResult(0, mech, ok, detail, pre_state)
    return ok, detail, [sr]


def _dispatch_remediation(
    ssh: SSHSession, rem: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    mechanism = rem.get("mechanism", "")
    handler = REMEDIATION_HANDLERS.get(mechanism)
    if handler is None:
        return False, f"Unknown remediation mechanism: {mechanism}"
    return handler(ssh, rem, dry_run=dry_run)


# ── Individual remediation handlers ────────────────────────────────────────


def _remediate_config_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set key=value in a config file."""
    path = r["path"]
    key = r["key"]
    value = r["value"]
    sep = r.get("separator", " ")

    line = f"{key}{sep}{value}"

    if dry_run:
        return True, f"Would set '{line}' in {path}"

    # Replace existing line or append
    check = ssh.run(f"grep -q '^ *{key}' {shlex.quote(path)} 2>/dev/null")
    if check.ok:
        # Replace in place — escape sed delimiters
        escaped_line = line.replace("/", "\\/")
        cmd = f"sed -i 's/^ *{key}.*/{escaped_line}/' {shlex.quote(path)}"
    else:
        cmd = f"echo {shlex.quote(line)} >> {shlex.quote(path)}"

    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to set {key} in {path}: {result.stderr}"

    _reload_service(ssh, r)
    return True, f"Set '{line}' in {path}"


def _remediate_config_set_dropin(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Write key=value to a drop-in directory file."""
    dir_path = r["dir"]
    filename = r["file"]
    key = r["key"]
    value = r["value"]
    sep = r.get("separator", " ")

    full_path = f"{dir_path}/{filename}"
    line = f"{key}{sep}{value}"

    if dry_run:
        return True, f"Would write '{line}' to {full_path}"

    cmd = f"echo {shlex.quote(line)} > {shlex.quote(full_path)}"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to write {full_path}: {result.stderr}"

    _reload_service(ssh, r)
    return True, f"Wrote '{line}' to {full_path}"


def _remediate_config_remove(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Remove a key from a config file."""
    path = r["path"]
    key = r["key"]

    # Check if key exists
    check = ssh.run(f"grep -q '^ *{key}' {shlex.quote(path)} 2>/dev/null")
    if not check.ok:
        return True, f"{key} not found in {path} (already absent)"

    if dry_run:
        return True, f"Would remove '{key}' from {path}"

    # Remove lines matching the key
    cmd = f"sed -i '/^ *{key}/d' {shlex.quote(path)}"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to remove {key} from {path}: {result.stderr}"

    _reload_service(ssh, r)
    return True, f"Removed '{key}' from {path}"


def _remediate_command_exec(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Run a command with optional unless/onlyif guards."""
    cmd = r["run"]

    # Check unless guard (skip if it succeeds)
    if "unless" in r:
        guard = ssh.run(r["unless"])
        if guard.ok:
            return True, f"Skipped (unless guard passed): {r['unless']}"

    # Check onlyif guard (skip if it fails)
    if "onlyif" in r:
        guard = ssh.run(r["onlyif"])
        if not guard.ok:
            return True, f"Skipped (onlyif guard failed): {r['onlyif']}"

    if dry_run:
        return True, f"Would run: {cmd}"

    result = ssh.run(cmd, timeout=120)
    if not result.ok:
        return False, f"Command failed (exit {result.exit_code}): {result.stderr or result.stdout}"

    _reload_service(ssh, r)
    return True, f"Executed: {cmd}"


def _remediate_file_permissions(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set file ownership and permissions. Supports glob paths."""
    path = r["path"]
    is_glob = "glob" in r or any(ch in path for ch in "*?[")
    quoted = path if is_glob else shlex.quote(path)
    parts = []

    if "owner" in r or "group" in r:
        owner = r.get("owner", "")
        group = r.get("group", "")
        chown_spec = f"{owner}:{group}" if group else owner
        parts.append(f"chown {chown_spec} {quoted}")

    if "mode" in r:
        parts.append(f"chmod {r['mode']} {quoted}")

    if dry_run:
        return True, f"Would run: {' && '.join(parts)}"

    cmd = " && ".join(parts)
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed: {result.stderr}"
    return True, f"Set permissions on {path}"


def _remediate_sysctl_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set sysctl value and persist it."""
    key = r["key"]
    value = r["value"]
    persist_file = r.get("persist_file", f"/etc/sysctl.d/99-aegis-{key.replace('.', '-')}.conf")

    if dry_run:
        return True, f"Would set sysctl {key}={value} and persist to {persist_file}"

    # Apply immediately
    result = ssh.run(f"sysctl -w {shlex.quote(key)}={shlex.quote(str(value))}")
    if not result.ok:
        return False, f"sysctl -w failed: {result.stderr}"

    # Persist
    line = f"{key} = {value}"
    result = ssh.run(f"echo {shlex.quote(line)} > {shlex.quote(persist_file)}")
    if not result.ok:
        return False, f"Failed to persist {persist_file}: {result.stderr}"

    return True, f"Set {key}={value}, persisted to {persist_file}"


def _remediate_package_present(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Install a package via dnf."""
    name = r["name"]

    if dry_run:
        return True, f"Would install {name}"

    result = ssh.run(f"dnf install -y {shlex.quote(name)}", timeout=300)
    if not result.ok:
        return False, f"dnf install failed: {result.stderr}"
    return True, f"Installed {name}"


def _remediate_package_absent(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Remove a package via dnf."""
    name = r["name"]

    # Check if package is installed
    check = ssh.run(f"rpm -q {shlex.quote(name)} 2>/dev/null")
    if not check.ok:
        return True, f"{name}: already not installed"

    if dry_run:
        return True, f"Would remove {name}"

    result = ssh.run(f"dnf remove -y {shlex.quote(name)}", timeout=300)
    if not result.ok:
        return False, f"dnf remove failed: {result.stderr}"
    return True, f"Removed {name}"


def _remediate_kernel_module_disable(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Blacklist a kernel module."""
    name = r["name"]
    conf_path = f"/etc/modprobe.d/{name}.conf"

    if dry_run:
        return True, f"Would blacklist {name} in {conf_path}"

    content = f"blacklist {name}\ninstall {name} /bin/false\n"
    result = ssh.run(f"printf %s {shlex.quote(content)} > {shlex.quote(conf_path)}")
    if not result.ok:
        return False, f"Failed to write {conf_path}: {result.stderr}"

    # Unload if currently loaded
    ssh.run(f"modprobe -r {shlex.quote(name)} 2>/dev/null")
    return True, f"Blacklisted {name}"


def _remediate_manual(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Manual remediation — no automated action."""
    note = r.get("note", "Manual remediation required")
    return False, f"MANUAL: {note}"


def _remediate_file_content(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Write or replace file content."""
    path = r["path"]
    content = r["content"]
    owner = r.get("owner")
    group = r.get("group")
    mode = r.get("mode")

    if dry_run:
        return True, f"Would write content to {path}"

    # Write content
    result = ssh.run(f"printf %s {shlex.quote(content)} > {shlex.quote(path)}")
    if not result.ok:
        return False, f"Failed to write {path}: {result.stderr}"

    # Set permissions if specified
    if owner or group:
        chown_spec = f"{owner or ''}:{group or ''}"
        ssh.run(f"chown {chown_spec} {shlex.quote(path)}")
    if mode:
        ssh.run(f"chmod {mode} {shlex.quote(path)}")

    return True, f"Wrote content to {path}"


def _remediate_file_absent(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Ensure a file does not exist."""
    path = r["path"]

    # Check if file exists
    exists = ssh.run(f"test -e {shlex.quote(path)}")
    if not exists.ok:
        return True, f"{path}: already absent"

    if dry_run:
        return True, f"Would remove {path}"

    result = ssh.run(f"rm -f {shlex.quote(path)}")
    if not result.ok:
        return False, f"Failed to remove {path}: {result.stderr}"
    return True, f"Removed {path}"


def _remediate_service_enabled(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Enable and optionally start a systemd service."""
    name = r["name"]
    start = r.get("start", True)

    if dry_run:
        action = "enable and start" if start else "enable"
        return True, f"Would {action} {name}"

    # Enable the service
    result = ssh.run(f"systemctl enable {shlex.quote(name)}")
    if not result.ok:
        return False, f"Failed to enable {name}: {result.stderr}"

    # Start if requested
    if start:
        result = ssh.run(f"systemctl start {shlex.quote(name)}")
        if not result.ok:
            return False, f"Enabled {name} but failed to start: {result.stderr}"
        return True, f"Enabled and started {name}"

    return True, f"Enabled {name}"


def _remediate_service_disabled(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Disable and optionally stop a systemd service."""
    name = r["name"]
    stop = r.get("stop", True)

    if dry_run:
        action = "disable and stop" if stop else "disable"
        return True, f"Would {action} {name}"

    # Stop if requested (before disabling)
    if stop:
        result = ssh.run(f"systemctl stop {shlex.quote(name)}")
        if not result.ok:
            # Service might not be running, continue anyway
            pass

    # Disable the service
    result = ssh.run(f"systemctl disable {shlex.quote(name)}")
    if not result.ok:
        return False, f"Failed to disable {name}: {result.stderr}"

    if stop:
        return True, f"Stopped and disabled {name}"
    return True, f"Disabled {name}"


def _remediate_service_masked(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Mask a systemd service (prevent it from starting)."""
    name = r["name"]
    stop = r.get("stop", True)

    if dry_run:
        action = "stop and mask" if stop else "mask"
        return True, f"Would {action} {name}"

    # Stop if requested (before masking)
    if stop:
        ssh.run(f"systemctl stop {shlex.quote(name)}")

    # Mask the service
    result = ssh.run(f"systemctl mask {shlex.quote(name)}")
    if not result.ok:
        return False, f"Failed to mask {name}: {result.stderr}"

    if stop:
        return True, f"Stopped and masked {name}"
    return True, f"Masked {name}"


def _reload_service(ssh: SSHSession, r: dict) -> None:
    """Reload or restart a service if specified in the remediation."""
    if "reload" in r:
        ssh.run(f"systemctl reload {shlex.quote(r['reload'])} 2>/dev/null || systemctl restart {shlex.quote(r['reload'])} 2>/dev/null")
    elif "restart" in r:
        ssh.run(f"systemctl restart {shlex.quote(r['restart'])} 2>/dev/null")


REMEDIATION_HANDLERS = {
    "config_set": _remediate_config_set,
    "config_set_dropin": _remediate_config_set_dropin,
    "config_remove": _remediate_config_remove,
    "command_exec": _remediate_command_exec,
    "file_permissions": _remediate_file_permissions,
    "file_content": _remediate_file_content,
    "file_absent": _remediate_file_absent,
    "sysctl_set": _remediate_sysctl_set,
    "package_present": _remediate_package_present,
    "package_absent": _remediate_package_absent,
    "kernel_module_disable": _remediate_kernel_module_disable,
    "manual": _remediate_manual,
    "service_enabled": _remediate_service_enabled,
    "service_disabled": _remediate_service_disabled,
    "service_masked": _remediate_service_masked,
}
