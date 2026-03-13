"""File-related capture handlers.

Handlers for capturing pre-state of files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import Result, SSHSession


def _capture_file_permissions(ssh: SSHSession, r: dict) -> PreState:
    """Capture current file ownership and permissions.

    Supports both direct path mode and bulk find mode.
    In bulk find mode, uses find + stat to enumerate matching files.
    """
    if "find_paths" in r:
        return _capture_bulk_find_permissions(ssh, r)

    path = r["path"]
    is_glob = r.get("glob") or shell_util.is_glob_path(path)
    quoted = shell_util.quote_path(path, allow_glob=is_glob)
    result = ssh.run(f"stat -c '%U %G %a %n' {quoted} 2>/dev/null")
    entries = _parse_stat_output(result)
    return PreState(mechanism="file_permissions", data={"entries": entries})


def _capture_bulk_find_permissions(ssh: SSHSession, r: dict) -> PreState:
    """Capture pre-state for bulk find mode using find + stat."""
    find_paths = r["find_paths"]
    quoted_paths = " ".join(shell_util.quote(p) for p in find_paths)
    cmd_parts = [f"find {quoted_paths}"]

    if "find_name" in r:
        cmd_parts.append(f"-name {shell_util.quote(r['find_name'])}")
    if "find_type" in r:
        cmd_parts.append(f"-type {r['find_type']}")
    if "find_args" in r:
        cmd_parts.append(r["find_args"])

    cmd_parts.append("-exec stat -c '%U %G %a %n' {} +")
    cmd = " ".join(cmd_parts) + " 2>/dev/null"
    result = ssh.run(cmd)
    entries = _parse_stat_output(result)
    return PreState(mechanism="file_permissions", data={"entries": entries})


def _parse_stat_output(result: Result) -> list[dict[str, str]]:
    """Parse stat -c '%U %G %a %n' output into entry dicts."""
    entries: list[dict[str, str]] = []
    if getattr(result, "ok", False) and getattr(result, "stdout", "").strip():
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                entries.append(
                    {
                        "path": " ".join(parts[3:]),
                        "owner": parts[0],
                        "group": parts[1],
                        "mode": parts[2],
                    }
                )
    return entries


def _capture_file_content(ssh: SSHSession, r: dict) -> PreState:
    """Capture current file content before modification."""
    path = r["path"]
    exists = shell_util.file_exists(ssh, path)
    old_content = None
    old_owner = None
    old_group = None
    old_mode = None

    if exists:
        old_content = shell_util.read_file(ssh, path)
        stat_result = shell_util.get_file_stat(ssh, path)
        if stat_result.ok and stat_result.stdout.strip():
            parts = stat_result.stdout.strip().split()
            if len(parts) >= 3:
                old_owner = parts[0]
                old_group = parts[1]
                old_mode = parts[2]

    return PreState(
        mechanism="file_content",
        data={
            "path": path,
            "existed": exists,
            "old_content": old_content,
            "old_owner": old_owner,
            "old_group": old_group,
            "old_mode": old_mode,
        },
    )


def _capture_file_absent(ssh: SSHSession, r: dict) -> PreState:
    """Capture file state before removal."""
    path = r["path"]
    exists = shell_util.file_exists(ssh, path)
    old_content = None
    old_owner = None
    old_group = None
    old_mode = None

    if exists:
        old_content = shell_util.read_file(ssh, path)
        stat_result = shell_util.get_file_stat(ssh, path)
        if stat_result.ok and stat_result.stdout.strip():
            parts = stat_result.stdout.strip().split()
            if len(parts) >= 3:
                old_owner = parts[0]
                old_group = parts[1]
                old_mode = parts[2]

    return PreState(
        mechanism="file_absent",
        data={
            "path": path,
            "existed": exists,
            "old_content": old_content,
            "old_owner": old_owner,
            "old_group": old_group,
            "old_mode": old_mode,
        },
    )
