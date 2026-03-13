"""Security-related capture handlers.

Handlers for capturing pre-state of security subsystems: SELinux, audit, and PAM.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_selinux_boolean_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current SELinux boolean value."""
    name = r["name"]
    result = ssh.run(f"getsebool {shell_util.quote(name)} 2>/dev/null")
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


def _capture_audit_rule_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture audit rule state before adding."""
    rule = r["rule"]
    persist_file = r.get("persist_file", "/etc/audit/rules.d/99-kensa.rules")

    result = ssh.run("auditctl -l 2>/dev/null")
    rule_existed = result.ok and rule in result.stdout

    old_persist_content = shell_util.read_file(ssh, persist_file)

    return PreState(
        mechanism="audit_rule_set",
        data={
            "rule": rule,
            "persist_file": persist_file,
            "rule_existed": rule_existed,
            "old_persist_content": old_persist_content,
            "persist_existed": old_persist_content is not None,
        },
    )


def _capture_authselect_feature_enable(ssh: SSHSession, r: dict) -> PreState:
    """Capture authselect feature state before enabling."""
    feature = r["feature"]
    # Check if feature is currently active
    result = ssh.run("authselect current 2>/dev/null")
    feature_was_active = result.ok and feature in result.stdout
    return PreState(
        mechanism="authselect_feature_enable",
        data={
            "feature": feature,
            "feature_was_active": feature_was_active,
            "authselect_output": result.stdout.strip() if result.ok else None,
        },
    )


def _capture_pam_module_arg(ssh: SSHSession, r: dict) -> PreState:
    """Capture PAM file contents before arg modification."""
    files = r.get("files", [])
    file_contents = {}
    for path in files:
        content = shell_util.read_file(ssh, path)
        if content is not None:
            file_contents[path] = content
    return PreState(
        mechanism="pam_module_arg",
        data={"files": file_contents},
    )


def _capture_pam_module_configure(ssh: SSHSession, r: dict) -> PreState:
    """Capture PAM file content and authselect state before modification.

    Snapshots the target PAM service file and the current authselect
    profile so that both can be restored on rollback.
    """
    service = r["service"]
    pam_file = f"/etc/pam.d/{service}"

    old_content = shell_util.read_file(ssh, pam_file)
    existed = old_content is not None

    # Capture authselect state for systems that use it
    authselect_result = ssh.run("authselect current 2>/dev/null")
    authselect_profile = (
        authselect_result.stdout.strip() if authselect_result.ok else None
    )

    return PreState(
        mechanism="pam_module_configure",
        data={
            "service": service,
            "pam_file": pam_file,
            "existed": existed,
            "old_content": old_content,
            "authselect_profile": authselect_profile,
        },
    )
