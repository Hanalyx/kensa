"""Remediation handlers and dispatch.

This module contains all remediation handlers that modify remote host state
to achieve compliance. Each handler implements a specific remediation mechanism
(e.g., config_set, package_present) defined in the rule schema.

Remediation Handler Pattern:
    All remediation handlers follow a consistent signature and behavior:
    - Accept an SSHSession, a remediation dict, and a dry_run flag
    - Return (success: bool, detail: str)
    - Support dry_run mode to preview changes without applying them
    - Use shlex.quote() for all values from rule YAML (except glob paths)
    - Call _reload_service() for mechanisms that modify service configs

Example:
-------
    >>> from runner.ssh import SSHSession
    >>> from runner._remediation import run_remediation
    >>>
    >>> remediation = {
    ...     "mechanism": "config_set",
    ...     "path": "/etc/ssh/sshd_config",
    ...     "key": "PermitRootLogin",
    ...     "value": "no",
    ...     "reload": "sshd"
    ... }
    >>> success, detail, steps = run_remediation(ssh, remediation, dry_run=True)
    >>> print(detail)  # "Would set 'PermitRootLogin no' in /etc/ssh/sshd_config"

"""

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
    """Execute a remediation and optionally verify the result.

    Supports both single-step and multi-step remediations. For multi-step,
    executes sequentially and stops on first failure. Captures pre-state
    for each step to enable rollback.

    Args:
    ----
        ssh: Active SSH session to the target host.
        remediation: Remediation definition dict from rule YAML. Must contain:
            - "mechanism": str for single-step, or
            - "steps": list[dict] for multi-step remediation
        dry_run: If True, describe changes without applying them.
        check: Optional check definition for post-remediation verification.

    Returns:
    -------
        Tuple of (success, detail, step_results):
            - success: True if all steps completed successfully
            - detail: Human-readable summary of actions taken
            - step_results: List of StepResult for each step (for rollback)

    Example:
    -------
        Single-step remediation::

            remediation = {"mechanism": "config_set", "path": "...", "key": "...", "value": "..."}
            success, detail, steps = run_remediation(ssh, remediation)

        Multi-step remediation::

            remediation = {
                "steps": [
                    {"mechanism": "package_present", "name": "aide"},
                    {"mechanism": "command_exec", "run": "aide --init"}
                ]
            }
            success, detail, steps = run_remediation(ssh, remediation)

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
    """Set a configuration key to a value in a file.

    Replaces an existing key's value or appends the key if not found.
    Optionally reloads the associated service after modification.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): Config file path.
            - key (str): Configuration key to set.
            - value (str): Value to set.
            - separator (str, optional): Separator between key and value.
              Defaults to " " (space).
            - reload (str, optional): Service to reload after change.
            - restart (str, optional): Service to restart after change.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: config_set
              path: "/etc/ssh/sshd_config"
              key: "PermitRootLogin"
              value: "no"
              reload: "sshd"

    """
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
    """Write a configuration key to a drop-in directory file.

    Creates or overwrites a file in a .d-style configuration directory.
    Preferred for services that support drop-in configs (sshd, sysctl.d, etc.).

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - dir (str): Drop-in directory path (e.g., "/etc/ssh/sshd_config.d").
            - file (str): Filename to create (e.g., "00-aegis-permit-root.conf").
            - key (str): Configuration key.
            - value (str): Value to set.
            - separator (str, optional): Separator. Defaults to " ".
            - reload (str, optional): Service to reload.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: config_set_dropin
              dir: "/etc/ssh/sshd_config.d"
              file: "00-aegis-root-login.conf"
              key: "PermitRootLogin"
              value: "no"
              reload: "sshd"

    """
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
    """Remove a configuration key from a file.

    Deletes all lines containing the specified key from the config file.
    Idempotent: succeeds if key is already absent.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): Config file path.
            - key (str): Configuration key to remove.
            - reload (str, optional): Service to reload.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: config_remove
              path: "/etc/ssh/sshd_config"
              key: "PermitEmptyPasswords"
              reload: "sshd"

    """
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
    """Execute an arbitrary shell command.

    Supports conditional execution with unless/onlyif guards for idempotency.
    Use sparingly - prefer specific mechanisms when available.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - run (str): Shell command to execute.
            - unless (str, optional): Skip if this command succeeds (exit 0).
            - onlyif (str, optional): Skip if this command fails (non-zero).
            - reload (str, optional): Service to reload.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: command_exec
              run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
              unless: "test -f /var/lib/aide/aide.db.gz"

    """
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
        return (
            False,
            f"Command failed (exit {result.exit_code}): {result.stderr or result.stdout}",
        )

    _reload_service(ssh, r)
    return True, f"Executed: {cmd}"


def _remediate_file_permissions(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set file ownership and permissions.

    Uses chown and chmod to set the specified attributes.
    Supports glob patterns to modify multiple files.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path or glob pattern.
            - owner (str, optional): Owner to set.
            - group (str, optional): Group to set.
            - mode (str, optional): Octal mode (e.g., "0600").
            - glob (bool, optional): Explicit glob flag.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: file_permissions
              path: "/etc/ssh/ssh_host_*_key"
              owner: "root"
              group: "root"
              mode: "0600"
              glob: true

    """
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
    """Set a kernel sysctl parameter and persist it.

    Applies the value immediately with sysctl -w and persists to a
    configuration file in /etc/sysctl.d/ for reboot persistence.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Sysctl parameter name.
            - value (str): Value to set.
            - persist_file (str, optional): Custom persistence file path.
              Defaults to "/etc/sysctl.d/99-aegis-<key>.conf".
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: sysctl_set
              key: "net.ipv4.tcp_syncookies"
              value: "1"

    """
    key = r["key"]
    value = r["value"]
    persist_file = r.get(
        "persist_file", f"/etc/sysctl.d/99-aegis-{key.replace('.', '-')}.conf"
    )

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
    """Install a package using dnf.

    Uses dnf install -y with a 5-minute timeout for slow operations.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Package name to install.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: package_present
              name: "aide"

    """
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
    """Remove a package using dnf.

    Uses dnf remove -y. Idempotent: succeeds if package is already absent.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Package name to remove.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: package_absent
              name: "telnet-server"

    """
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
    """Blacklist and unload a kernel module.

    Creates a modprobe.d config to blacklist the module and prevent loading,
    then unloads the module if currently loaded.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Kernel module name.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: kernel_module_disable
              name: "cramfs"

    """
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
    """Indicate that manual remediation is required.

    Used for controls that cannot be safely automated or require
    human judgment. Always returns failure with the specified note.

    Args:
    ----
        ssh: Active SSH session to the target host (unused).
        r: Remediation definition with optional fields:
            - note (str, optional): Explanation of manual steps needed.
              Defaults to "Manual remediation required".
        dry_run: Ignored for manual remediations.

    Returns:
    -------
        Tuple of (False, "MANUAL: <note>") - always fails.

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: manual
              note: "Review application logs and configure appropriate retention"

    """
    note = r.get("note", "Manual remediation required")
    return False, f"MANUAL: {note}"


def _remediate_file_content(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Write complete content to a file.

    Creates or overwrites a file with specified content. Optionally
    sets ownership and permissions.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path to write.
            - content (str): Complete file content.
            - owner (str, optional): Owner to set.
            - group (str, optional): Group to set.
            - mode (str, optional): Octal mode.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: file_content
              path: "/etc/motd"
              content: |
                Authorized users only.
                All activity is monitored and logged.
              owner: "root"
              mode: "0644"

    """
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
    """Remove a file if it exists.

    Uses rm -f for safe removal. Idempotent: succeeds if file is already absent.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path to remove.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: file_absent
              path: "/etc/hosts.equiv"

    """
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


def _remediate_config_block(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Write a managed block of content with markers.

    Inserts or replaces a block of content delimited by begin/end markers.
    Useful for managing multi-line configuration sections.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): Config file path.
            - block (str): Content to insert between markers.
            - marker (str, optional): Marker identifier.
              Defaults to "# AEGIS MANAGED BLOCK".
            - reload (str, optional): Service to reload.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: config_block
              path: "/etc/security/limits.conf"
              marker: "AEGIS CORE LIMITS"
              block: |
                * hard core 0
                * soft core 0

    """
    path = r["path"]
    block = r["block"]
    marker = r.get("marker", "# AEGIS MANAGED BLOCK")
    begin_marker = f"# BEGIN {marker}"
    end_marker = f"# END {marker}"

    if dry_run:
        return True, f"Would write block to {path} with marker '{marker}'"

    # Check if block already exists
    check = ssh.run(
        f"grep -qF {shlex.quote(begin_marker)} {shlex.quote(path)} 2>/dev/null"
    )
    if check.ok:
        # Block exists - replace it
        # Use sed to delete between markers and insert new content
        cmd = f"sed -i '/{begin_marker.replace('/', '\\/')}/,/{end_marker.replace('/', '\\/')}/d' {shlex.quote(path)}"
        ssh.run(cmd)

    # Append the new block
    full_block = f"{begin_marker}\n{block}\n{end_marker}"
    result = ssh.run(f"printf %s {shlex.quote(full_block)} >> {shlex.quote(path)}")
    if not result.ok:
        return False, f"Failed to write block: {result.stderr}"

    _reload_service(ssh, r)
    return True, f"Wrote block to {path}"


def _remediate_cron_job(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Create a cron job in /etc/cron.d/.

    Creates a cron file with the specified schedule and command.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - schedule (str): Cron schedule (e.g., "0 5 * * *").
            - command (str): Command to execute.
            - user (str, optional): User to run as. Defaults to "root".
            - name (str, optional): Job name (filename). Defaults to "aegis-managed".
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: cron_job
              name: "aide-check"
              schedule: "0 5 * * *"
              command: "/usr/sbin/aide --check"
              user: "root"

    """
    schedule = r["schedule"]  # e.g., "0 5 * * *"
    command = r["command"]
    user = r.get("user", "root")
    name = r.get("name", "aegis-managed")

    cron_file = f"/etc/cron.d/{name}"
    cron_line = f"{schedule} {user} {command}"

    if dry_run:
        return True, f"Would create {cron_file} with: {cron_line}"

    # Write cron file
    result = ssh.run(f"echo {shlex.quote(cron_line)} > {shlex.quote(cron_file)}")
    if not result.ok:
        return False, f"Failed to create cron job: {result.stderr}"

    # Set correct permissions
    ssh.run(f"chmod 644 {shlex.quote(cron_file)}")

    return True, f"Created cron job: {cron_file}"


def _remediate_mount_option_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Add mount options to fstab and remount.

    Modifies /etc/fstab to add the specified options and remounts
    the filesystem to apply changes immediately.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - mount_point (str): Mount point path (e.g., "/tmp").
            - options (list[str]): Options to add (e.g., ["nodev", "nosuid"]).
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: mount_option_set
              mount_point: "/tmp"
              options:
                - nodev
                - nosuid
                - noexec

    """
    mount_point = r["mount_point"]
    options = r["options"]

    if dry_run:
        return (
            True,
            f"Would add options {options} to {mount_point} in fstab and remount",
        )

    # Get current fstab line
    result = ssh.run(f"grep -E '\\s{shlex.quote(mount_point)}\\s' /etc/fstab")
    if not result.ok:
        return False, f"{mount_point}: not found in /etc/fstab"

    # Parse current options and add new ones
    fstab_line = result.stdout.strip()
    parts = fstab_line.split()
    if len(parts) < 4:
        return False, f"Invalid fstab line for {mount_point}"

    current_opts = set(parts[3].split(","))
    for opt in options:
        current_opts.add(opt)
    new_opts = ",".join(sorted(current_opts))

    # Update fstab (replace options field)
    escaped_mount = mount_point.replace("/", "\\/")
    cmd = f"sed -i 's|\\(\\s{escaped_mount}\\s\\+\\S\\+\\s\\+\\)\\S\\+|\\1{new_opts}|' /etc/fstab"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to update fstab: {result.stderr}"

    # Remount
    result = ssh.run(f"mount -o remount {shlex.quote(mount_point)}")
    if not result.ok:
        return False, f"Remount failed: {result.stderr}"

    return True, f"Added options {options} to {mount_point}"


def _remediate_grub_parameter_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Add a kernel boot parameter to GRUB.

    Uses grubby to update all kernel entries. Requires reboot to take effect.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Parameter name.
            - value (str, optional): Parameter value. If omitted,
              adds as boolean flag.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: grub_parameter_set
              key: "audit"
              value: "1"

    """
    key = r["key"]
    value = r.get("value")
    arg = f"{key}={value}" if value else key

    if dry_run:
        return True, f"Would set kernel arg: {arg}"

    # Use grubby to update all kernels
    result = ssh.run(f"grubby --update-kernel=ALL --args={shlex.quote(arg)}")
    if not result.ok:
        return False, f"grubby failed: {result.stderr}"

    return True, f"Set kernel arg: {arg}"


def _remediate_grub_parameter_remove(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Remove a kernel boot parameter from GRUB.

    Uses grubby to remove the parameter from all kernel entries.
    Requires reboot to take effect.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Parameter name to remove.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: grub_parameter_remove
              key: "quiet"

    """
    key = r["key"]

    if dry_run:
        return True, f"Would remove kernel arg: {key}"

    # Use grubby to remove from all kernels
    result = ssh.run(f"grubby --update-kernel=ALL --remove-args={shlex.quote(key)}")
    if not result.ok:
        return False, f"grubby failed: {result.stderr}"

    return True, f"Removed kernel arg: {key}"


def _remediate_audit_rule_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Add an audit rule and persist it.

    Adds the rule to the running audit configuration with auditctl
    and appends it to a rules file for persistence.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - rule (str): Audit rule (e.g., "-w /etc/passwd -p wa -k identity").
            - persist_file (str, optional): File to persist rule.
              Defaults to "/etc/audit/rules.d/99-aegis.rules".
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: audit_rule_set
              rule: "-w /etc/passwd -p wa -k identity"

    """
    rule = r["rule"]
    persist_file = r.get("persist_file", "/etc/audit/rules.d/99-aegis.rules")

    if dry_run:
        return True, f"Would add audit rule and persist to {persist_file}"

    # Add rule to running config
    result = ssh.run(f"auditctl {rule}")
    if not result.ok and "already exists" not in result.stderr.lower():
        return False, f"auditctl failed: {result.stderr}"

    # Persist the rule
    # Check if rule already in file
    check = ssh.run(
        f"grep -qF {shlex.quote(rule)} {shlex.quote(persist_file)} 2>/dev/null"
    )
    if not check.ok:
        # Append the rule
        result = ssh.run(f"echo {shlex.quote(rule)} >> {shlex.quote(persist_file)}")
        if not result.ok:
            return False, f"Failed to persist rule: {result.stderr}"

    return True, f"Added audit rule, persisted to {persist_file}"


def _remediate_selinux_boolean_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set a SELinux boolean value.

    Uses setsebool to change the boolean value. By default, persists
    the change with -P flag.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): SELinux boolean name.
            - value (bool, optional): Value to set. Defaults to True.
            - persistent (bool, optional): Persist across reboots.
              Defaults to True.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: selinux_boolean_set
              name: "httpd_can_network_connect"
              value: false

    """
    name = r["name"]
    value = r.get("value", True)
    value_str = "on" if value else "off"
    persistent = r.get("persistent", True)

    if dry_run:
        flag = "-P " if persistent else ""
        return True, f"Would run: setsebool {flag}{name} {value_str}"

    # Set the boolean (with -P for persistent)
    cmd = f"setsebool {'-P ' if persistent else ''}{shlex.quote(name)} {value_str}"
    result = ssh.run(cmd, timeout=60)
    if not result.ok:
        return False, f"setsebool failed: {result.stderr}"

    return True, f"Set {name} = {value_str}{' (persistent)' if persistent else ''}"


def _remediate_service_enabled(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Enable and optionally start a systemd service.

    Uses systemctl enable to configure the service to start at boot.
    Optionally starts the service immediately.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Service name.
            - start (bool, optional): Also start the service. Defaults to True.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: service_enabled
              name: "auditd"
              start: true

    """
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
    """Disable and optionally stop a systemd service.

    Uses systemctl disable to prevent the service from starting at boot.
    Optionally stops the service immediately.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Service name.
            - stop (bool, optional): Also stop the service. Defaults to True.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: service_disabled
              name: "rpcbind"
              stop: true

    """
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
    """Mask a systemd service to prevent it from starting.

    Uses systemctl mask which links the service to /dev/null, preventing
    it from being started manually or as a dependency.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Service name.
            - stop (bool, optional): Also stop the service. Defaults to True.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: service_masked
              name: "ctrl-alt-del.target"
              stop: true

    """
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


def _remediate_pam_module_configure(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Configure a PAM module in a service's PAM stack.

    Adds or modifies a PAM module entry in the specified service file.
    For RHEL 8+, prefers authselect when available. Falls back to direct
    PAM file editing when authselect is not suitable.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - service (str): PAM service name (e.g., "system-auth", "password-auth").
            - module (str): PAM module name (e.g., "pam_faillock.so").
            - type (str): PAM type ("auth", "account", "password", "session").
            - control (str): Control value ("required", "requisite", "sufficient",
              "optional", or complex [] format).
            - args (str, optional): Module arguments.
        dry_run: If True, return description without making changes.

    Returns:
    -------
        Tuple of (success, detail).

    Example:
    -------
        YAML rule definition::

            remediation:
              mechanism: pam_module_configure
              service: "system-auth"
              module: "pam_pwquality.so"
              type: "password"
              control: "requisite"
              args: "retry=3 minlen=14 dcredit=-1"

    Note:
        PAM configuration is complex and order-dependent. This handler appends
        the module to the end of the specified type section if not already
        present. For precise ordering, consider using command_exec with
        authselect commands.

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

    # Check if file exists
    exists = ssh.run(f"test -f {shlex.quote(pam_file)}")
    if not exists.ok:
        return False, f"{pam_file}: not found"

    # Check if module is already configured with this type
    check = ssh.run(
        f"grep -E '^{pam_type}\\s+.*{shlex.quote(module)}' {shlex.quote(pam_file)} 2>/dev/null"
    )

    if check.ok:
        # Module already present - update the line
        # Use sed to replace the existing line
        escaped_line = pam_line.replace("/", "\\/")
        cmd = f"sed -i 's/^{pam_type}\\s\\+.*{module}.*/{escaped_line}/' {shlex.quote(pam_file)}"
        result = ssh.run(cmd)
        if not result.ok:
            return False, f"Failed to update {pam_file}: {result.stderr}"
        return True, f"Updated {module} in {pam_file}"
    else:
        # Module not present - append to end of file
        # In a production environment, we'd want to insert at the right position
        # based on PAM stack ordering, but that's complex
        result = ssh.run(f"echo {shlex.quote(pam_line)} >> {shlex.quote(pam_file)}")
        if not result.ok:
            return False, f"Failed to add {module} to {pam_file}: {result.stderr}"
        return True, f"Added {module} to {pam_file}"


def _reload_service(ssh: SSHSession, r: dict) -> None:
    """Reload or restart a service if specified in the remediation dict.

    Called by remediation handlers after modifying configuration files.
    Attempts reload first, falling back to restart if reload fails.

    Args:
    ----
        ssh: Active SSH session to the target host.
        r: Remediation dict. Checks for:
            - reload (str): Service to reload (tries reload, falls back to restart).
            - restart (str): Service to restart directly.

    Returns:
    -------
        None. Errors are silently ignored (service may not be running).

    """
    if "reload" in r:
        ssh.run(
            f"systemctl reload {shlex.quote(r['reload'])} 2>/dev/null || systemctl restart {shlex.quote(r['reload'])} 2>/dev/null"
        )
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
    "selinux_boolean_set": _remediate_selinux_boolean_set,
    "audit_rule_set": _remediate_audit_rule_set,
    "mount_option_set": _remediate_mount_option_set,
    "grub_parameter_set": _remediate_grub_parameter_set,
    "grub_parameter_remove": _remediate_grub_parameter_remove,
    "config_block": _remediate_config_block,
    "cron_job": _remediate_cron_job,
    "pam_module_configure": _remediate_pam_module_configure,
}
