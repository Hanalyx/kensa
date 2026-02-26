"""Security-related remediation handlers.

Handlers for security subsystems: SELinux, audit rules, and PAM.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_selinux_boolean_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set a SELinux boolean value.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): SELinux boolean name.
            - value (bool, optional): Value to set. Defaults to True.
            - persistent (bool, optional): Persist across reboots. Defaults to True.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]
    value = r.get("value", True)
    value_str = "on" if value else "off"
    persistent = r.get("persistent", True)

    if dry_run:
        flag = "-P " if persistent else ""
        return True, f"Would run: setsebool {flag}{name} {value_str}"

    cmd = f"setsebool {'-P ' if persistent else ''}{shell_util.quote(name)} {value_str}"
    result = ssh.run(cmd, timeout=60)
    if not result.ok:
        return False, f"setsebool failed: {result.stderr}"

    return True, f"Set {name} = {value_str}{' (persistent)' if persistent else ''}"


def _remediate_selinux_state_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set the SELinux enforcement state.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - state (str): Target state (enforcing, permissive, disabled).

    Returns:
        Tuple of (success, detail).

    """
    state = r["state"]

    if dry_run:
        return True, f"Would set SELinux to {state}"

    # Update /etc/selinux/config for persistence
    result = ssh.run(
        f"sed -i 's/^SELINUX=.*/SELINUX={shell_util.quote(state)}/' "
        f"{shell_util.quote('/etc/selinux/config')}"
    )
    if not result.ok:
        return False, f"Failed to set SELinux config: {result.stderr}"

    # Apply runtime change if not "disabled" (disabled requires reboot)
    if state != "disabled":
        enforce_val = "1" if state == "enforcing" else "0"
        result = ssh.run(f"setenforce {enforce_val}")
        if not result.ok:
            return False, f"setenforce failed: {result.stderr}"

    return True, f"Set SELinux to {state}"


def _remediate_audit_rule_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Add an audit rule and persist it.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - rule (str): Audit rule.
            - persist_file (str, optional): File to persist rule.

    Returns:
        Tuple of (success, detail).

    """
    rule = r["rule"]
    persist_file = r.get("persist_file", "/etc/audit/rules.d/99-kensa.rules")

    if dry_run:
        return True, f"Would add audit rule and persist to {persist_file}"

    result = ssh.run(f"auditctl {shell_util.quote(rule)}")
    if not result.ok and "already exists" not in result.stderr.lower():
        return False, f"auditctl failed: {result.stderr}"

    check = ssh.run(
        f"grep -qF {shell_util.quote(rule)} {shell_util.quote(persist_file)} 2>/dev/null"
    )
    if not check.ok and not shell_util.append_line(ssh, persist_file, rule):
        return False, "Failed to persist rule"

    return True, f"Added audit rule, persisted to {persist_file}"


def _remediate_pam_module_configure(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Configure a PAM module in a service's PAM stack.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - service (str): PAM service name.
            - module (str): PAM module name.
            - type (str): PAM type.
            - control (str): Control value.
            - args (str, optional): Module arguments.

    Returns:
        Tuple of (success, detail).

    """
    service = r["service"]
    module = r["module"]
    pam_type = r["type"]
    control = r["control"]
    args = r.get("args", "")

    pam_file = f"/etc/pam.d/{service}"
    pam_line = f"{pam_type}    {control}    {module}"
    if args:
        pam_line += f"    {args}"

    if dry_run:
        return True, f"Would configure {module} in {pam_file}: {pam_line}"

    if not shell_util.file_exists(ssh, pam_file):
        return False, f"{pam_file}: not found"

    escaped_type = shell_util.escape_grep_bre(pam_type)
    escaped_module = shell_util.escape_grep_bre(module)
    check = ssh.run(
        f"grep -E '^{escaped_type}\\s+.*{escaped_module}' {shell_util.quote(pam_file)} 2>/dev/null"
    )

    if check.ok:
        sed_type = shell_util.escape_sed(pam_type)
        sed_module = shell_util.escape_sed(module)
        sed_replacement = shell_util.escape_sed(pam_line)
        cmd = f"sed -i 's/^{sed_type}\\s\\+.*{sed_module}.*/{sed_replacement}/' {shell_util.quote(pam_file)}"
        result = ssh.run(cmd)
        if not result.ok:
            return False, f"Failed to update {pam_file}: {result.stderr}"
        return True, f"Updated {module} in {pam_file}"
    else:
        if not shell_util.append_line(ssh, pam_file, pam_line):
            return False, f"Failed to add {module} to {pam_file}"
        return True, f"Added {module} to {pam_file}"
