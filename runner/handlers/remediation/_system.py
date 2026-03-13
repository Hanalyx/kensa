"""System-related remediation handlers.

Handlers for system configuration: sysctl, kernel modules, mount options,
GRUB parameters, and cron jobs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_sysctl_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set a kernel sysctl parameter and persist it.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Sysctl parameter name.
            - value (str): Value to set.
            - persist_file (str, optional): Custom persistence file.

    Returns:
        Tuple of (success, detail).

    """
    key = r["key"]
    value = r["value"]
    persist_file = r.get(
        "persist_file", f"/etc/sysctl.d/99-kensa-{key.replace('.', '-')}.conf"
    )

    if dry_run:
        return True, f"Would set sysctl {key}={value} and persist to {persist_file}"

    result = ssh.run(
        f"sysctl -w {shell_util.quote(key)}={shell_util.quote(str(value))}"
    )
    if not result.ok:
        return False, f"sysctl -w failed: {result.stderr}"

    line = f"{key} = {value}"
    if not shell_util.write_file(ssh, persist_file, line + "\n"):
        return False, f"Failed to persist {persist_file}"

    return True, f"Set {key}={value}, persisted to {persist_file}"


def _remediate_kernel_module_disable(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Blacklist and unload a kernel module.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Kernel module name.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]
    conf_path = f"/etc/modprobe.d/{name}.conf"

    if dry_run:
        return True, f"Would blacklist {name} in {conf_path}"

    content = f"blacklist {name}\ninstall {name} /bin/false\n"
    if not shell_util.write_file(ssh, conf_path, content):
        return False, f"Failed to write {conf_path}"

    ssh.run(f"modprobe -r {shell_util.quote(name)} 2>/dev/null")
    return True, f"Blacklisted {name}"


def _remediate_mount_option_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Add mount options to fstab and remount.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - mount_point (str): Mount point path.
            - options (list[str]): Options to add.

    Returns:
        Tuple of (success, detail).

    """
    mount_point = r["mount_point"]
    options = r["options"]

    if dry_run:
        return (
            True,
            f"Would add options {options} to {mount_point} in fstab and remount",
        )

    result = ssh.run(f"grep -E '\\s{shell_util.quote(mount_point)}\\s' /etc/fstab")
    if not result.ok:
        return False, f"{mount_point}: not found in /etc/fstab"

    fstab_line = result.stdout.strip()
    parts = fstab_line.split()
    if len(parts) < 4:
        return False, f"Invalid fstab line for {mount_point}"

    current_opts = set(parts[3].split(","))
    for opt in options:
        current_opts.add(opt)
    new_opts = ",".join(sorted(current_opts))

    escaped_mount = shell_util.escape_sed(mount_point)
    escaped_opts = shell_util.escape_sed(new_opts)
    cmd = f"sed -i 's|\\(\\s{escaped_mount}\\s\\+\\S\\+\\s\\+\\)\\S\\+|\\1{escaped_opts}|' /etc/fstab"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to update fstab: {result.stderr}"

    result = ssh.run(f"mount -o remount {shell_util.quote(mount_point)}")
    if not result.ok:
        return False, f"Remount failed: {result.stderr}"

    return True, f"Added options {options} to {mount_point}"


def _remediate_grub_parameter_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Add a kernel boot parameter to GRUB.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Parameter name.
            - value (str, optional): Parameter value.

    Returns:
        Tuple of (success, detail).

    """
    key = r["key"]
    value = r.get("value")
    arg = f"{key}={value}" if value else key

    if dry_run:
        return True, f"Would set kernel arg: {arg}"

    result = ssh.run(f"grubby --update-kernel=ALL --args={shell_util.quote(arg)}")
    if not result.ok:
        return False, f"grubby failed: {result.stderr}"

    return True, f"Set kernel arg: {arg}"


def _remediate_grub_parameter_remove(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Remove a kernel boot parameter from GRUB.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Parameter name to remove.

    Returns:
        Tuple of (success, detail).

    """
    key = r["key"]

    if dry_run:
        return True, f"Would remove kernel arg: {key}"

    result = ssh.run(
        f"grubby --update-kernel=ALL --remove-args={shell_util.quote(key)}"
    )
    if not result.ok:
        return False, f"grubby failed: {result.stderr}"

    return True, f"Removed kernel arg: {key}"


def _remediate_cron_job(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Create a cron job in /etc/cron.d/.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - schedule (str): Cron schedule.
            - command (str): Command to execute.
            - user (str, optional): User to run as. Defaults to "root".
            - name (str, optional): Job name. Defaults to "kensa-managed".

    Returns:
        Tuple of (success, detail).

    """
    schedule = r["schedule"]
    command = r["command"]
    user = r.get("user", "root")
    name = r.get("name", "kensa-managed")

    cron_file = f"/etc/cron.d/{name}"
    cron_line = f"{schedule} {user} {command}"

    if dry_run:
        return True, f"Would create {cron_file} with: {cron_line}"

    if not shell_util.write_file(ssh, cron_file, cron_line + "\n"):
        return False, "Failed to create cron job"

    shell_util.set_file_mode(ssh, cron_file, "644")
    return True, f"Created cron job: {cron_file}"


def _remediate_dconf_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set a dconf key in a system database drop-in file.

    Writes the setting, optionally creates a lock file, and runs
    dconf update. See specs/handlers/remediation/dconf_set.spec.yaml.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - schema (str): Dconf schema path (e.g., "org/gnome/login-screen").
            - key (str): Dconf key name.
            - value (str): Value to set.
            - file (str): Drop-in file name.
            - db (str, optional): Database name. Defaults to "local".
            - value_type (str, optional): Type prefix (e.g., "uint32").
            - lock (bool, optional): Create lock file.

    Returns:
        Tuple of (success, detail).

    """
    schema = r["schema"]
    key = r["key"]
    value = r["value"]
    file_name = r["file"]
    db = r.get("db", "local")
    value_type = r.get("value_type")
    lock = r.get("lock", False)

    composed = f"{value_type} {value}" if value_type else value
    display = f"{schema}/{key}={composed}"

    if dry_run:
        return True, f"Would set dconf {display}"

    # Write setting file
    db_dir = f"/etc/dconf/db/{db}.d"
    setting_path = f"{db_dir}/{file_name}"
    content = f"[{schema}]\n{key}={composed}\n"

    result = ssh.run(
        f"mkdir -p {shell_util.quote(db_dir)} && "
        f"cat > {shell_util.quote(setting_path)} << 'DCONF_EOF'\n{content}DCONF_EOF"
    )
    if not result.ok:
        return False, f"Failed to write dconf setting: {result.stderr}"

    # Write lock file if requested
    if lock:
        lock_dir = f"{db_dir}/locks"
        lock_path = f"{lock_dir}/{file_name}"
        lock_content = f"/{schema}/{key}\n"
        lock_result = ssh.run(
            f"mkdir -p {shell_util.quote(lock_dir)} && "
            f"cat > {shell_util.quote(lock_path)} << 'DCONF_EOF'\n{lock_content}DCONF_EOF"
        )
        if not lock_result.ok:
            return False, f"Failed to write dconf lock: {lock_result.stderr}"

    # Run dconf update
    update = ssh.run("dconf update")
    if not update.ok:
        return False, f"Failed to run dconf update: {update.stderr}"

    return True, f"Set dconf {display}"


def _remediate_crypto_policy_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set the system-wide crypto policy.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - policy (str): Crypto policy name (e.g., "DEFAULT", "FIPS").
            - subpolicy (str, optional): Subpolicy modifier (e.g., "NO-SHA1").

    Returns:
        Tuple of (success, detail).

    """
    policy = r["policy"]
    subpolicy = r.get("subpolicy")
    full_policy = f"{policy}:{subpolicy}" if subpolicy else policy

    if dry_run:
        return True, f"Would set crypto policy to {full_policy}"

    result = ssh.run(f"update-crypto-policies --set {shell_util.quote(full_policy)}")
    if not result.ok:
        return False, f"update-crypto-policies failed: {result.stderr}"

    return True, f"Set crypto policy to {full_policy}"
