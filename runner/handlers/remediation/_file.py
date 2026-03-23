"""File-related remediation handlers.

Handlers for modifying file state: permissions, content, and existence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_file_permissions(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set file ownership and permissions.

    Supports two modes:
    - Direct mode: chown/chmod on a single path or glob pattern.
    - Bulk find mode: find files in directory trees, apply changes via -exec.

    Bulk mode is activated when ``find_paths`` is present in the remediation
    dict. See specs/handlers/remediation/file_permissions.spec.yaml v2.0.0
    for AC-12 through AC-21.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition. Direct mode fields:
            - path (str): File path or glob pattern.
            - owner (str, optional): Owner to set.
            - group (str, optional): Group to set.
            - mode (str, optional): Octal or symbolic mode.
            - glob (bool, optional): Explicit glob flag.
           Bulk find mode fields:
            - find_paths (list[str]): Directories to search.
            - find_name (str, optional): -name pattern.
            - find_type (str, optional): -type filter (f/d).
            - find_args (str, optional): Extra find arguments.

    Returns:
        Tuple of (success, detail).

    """
    if "find_paths" in r:
        return _bulk_find_permissions(ssh, r, dry_run=dry_run)
    return _direct_permissions(ssh, r, dry_run=dry_run)


def _direct_permissions(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Direct path mode: chown/chmod on a single path or glob."""
    path = r["path"]
    is_glob = "glob" in r or shell_util.is_glob_path(path)
    parts = []

    # Validate owner/group/mode before interpolation
    try:
        shell_util.validate_chown_spec(r.get("owner"), r.get("group"), r.get("mode"))
    except ValueError as e:
        return False, str(e)

    if "owner" in r or "group" in r:
        owner = r.get("owner", "")
        group = r.get("group", "")
        chown_spec = f"{owner}:{group}" if group else owner
        quoted = shell_util.quote_path(path, allow_glob=is_glob)
        parts.append(f"chown {chown_spec} {quoted}")

    if "mode" in r:
        quoted = shell_util.quote_path(path, allow_glob=is_glob)
        parts.append(f"chmod {r['mode']} {quoted}")

    if dry_run:
        return True, f"Would run: {' && '.join(parts)}"

    cmd = " && ".join(parts)
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed: {result.stderr}"
    return True, f"Set permissions on {path}"


def _bulk_find_permissions(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Bulk find mode: discover files via find, apply changes via -exec."""
    find_paths = r["find_paths"]
    quoted_paths = " ".join(shell_util.quote(p) for p in find_paths)
    cmd_parts = [f"find {quoted_paths}"]

    if "find_name" in r:
        cmd_parts.append(f"-name {shell_util.quote(r['find_name'])}")
    if "find_type" in r:
        try:
            shell_util.validate_find_type(r["find_type"])
        except ValueError as e:
            return False, str(e)
        cmd_parts.append(f"-type {r['find_type']}")
    if "find_args" in r:
        cmd_parts.append(r["find_args"])

    # Validate owner/group/mode before interpolation
    try:
        shell_util.validate_chown_spec(r.get("owner"), r.get("group"), r.get("mode"))
    except ValueError as e:
        return False, str(e)

    if "owner" in r or "group" in r:
        owner = r.get("owner", "")
        group = r.get("group", "")
        chown_spec = f"{owner}:{group}" if group else owner
        cmd_parts.append(f"-exec chown {chown_spec} {{}} +")

    if "mode" in r:
        cmd_parts.append(f"-exec chmod {r['mode']} {{}} +")

    cmd = " ".join(cmd_parts)

    if dry_run:
        return True, f"Would run: {cmd}"

    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed: {result.stderr}"
    paths_str = ", ".join(find_paths)
    return True, f"Set permissions via find in {paths_str}"


def _remediate_file_content(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Write complete content to a file.

    Creates or overwrites a file with specified content.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path to write.
            - content (str): Complete file content.
            - owner (str, optional): Owner to set.
            - group (str, optional): Group to set.
            - mode (str, optional): Octal mode.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]
    content = r["content"]

    if dry_run:
        return True, f"Would write content to {path}"

    if not shell_util.write_file(ssh, path, content):
        return False, f"Failed to write {path}"

    if "owner" in r or "group" in r:
        shell_util.set_file_owner(ssh, path, r.get("owner"), r.get("group"))
    if "mode" in r:
        shell_util.set_file_mode(ssh, path, r["mode"])

    return True, f"Wrote content to {path}"


def _remediate_file_absent(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Remove a file if it exists.

    Uses rm -f for safe removal. Idempotent.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path to remove.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]

    if not shell_util.path_exists(ssh, path):
        return True, f"{path}: already absent"

    if dry_run:
        return True, f"Would remove {path}"

    result = ssh.run(f"rm -f {shell_util.quote(path)}")
    if not result.ok:
        return False, f"Failed to remove {path}: {result.stderr}"
    return True, f"Removed {path}"
