"""Path utilities for locating Aegis resources.

This module provides functions to locate rules and schema files whether
Aegis is run from source or installed as a package.

Example:
-------
    >>> from runner.paths import get_rules_path, get_schema_path
    >>> rules_dir = get_rules_path()
    >>> print(f"Rules located at: {rules_dir}")

"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Resource location ─────────────────────────────────────────────────────────


def _find_package_data_dir() -> Path | None:
    """Find the package data directory for installed Aegis.

    Checks common installation locations for shared data.

    Returns:
        Path to data directory, or None if not found.

    """
    # Check various possible installation prefixes
    prefixes = [
        sys.prefix,  # Virtual env or system Python
        sys.base_prefix,  # Base Python (if in venv)
        "/usr/local",
        "/usr",
    ]

    for prefix in prefixes:
        data_dir = Path(prefix) / "share" / "aegis"
        if data_dir.exists():
            return data_dir

    return None


def get_rules_path(subpath: str = "") -> Path:
    """Get the path to Aegis rules directory.

    Checks locations in order:
    1. AEGIS_RULES_PATH environment variable
    2. ./rules relative to current directory (development)
    3. Installed package data location

    Args:
        subpath: Optional subdirectory or file within rules (e.g., "access-control").

    Returns:
        Path to rules directory or specific rule file.

    Raises:
        FileNotFoundError: If rules directory cannot be located.

    Example:
        >>> rules = get_rules_path()
        >>> ssh_rules = get_rules_path("access-control")
        >>> specific = get_rules_path("access-control/ssh-disable-root-login.yml")

    """
    # 1. Environment variable override
    if env_path := os.environ.get("AEGIS_RULES_PATH"):
        rules_dir = Path(env_path)
        if rules_dir.exists():
            return rules_dir / subpath if subpath else rules_dir

    # 2. Development: relative to working directory
    local_rules = Path.cwd() / "rules"
    if local_rules.exists():
        return local_rules / subpath if subpath else local_rules

    # 3. Development: relative to this file (runner/paths.py -> ../rules)
    source_rules = Path(__file__).parent.parent / "rules"
    if source_rules.exists():
        return source_rules / subpath if subpath else source_rules

    # 4. Installed package data
    if data_dir := _find_package_data_dir():
        installed_rules = data_dir / "rules"
        if installed_rules.exists():
            return installed_rules / subpath if subpath else installed_rules

    msg = (
        "Cannot locate Aegis rules directory. "
        "Set AEGIS_RULES_PATH environment variable or run from source directory."
    )
    raise FileNotFoundError(msg)


def get_schema_path(filename: str = "rule.schema.json") -> Path:
    """Get the path to Aegis schema files.

    Checks locations in order:
    1. AEGIS_SCHEMA_PATH environment variable
    2. ./schema relative to current directory (development)
    3. Installed package data location

    Args:
        filename: Schema file name (default: rule.schema.json).

    Returns:
        Path to schema file.

    Raises:
        FileNotFoundError: If schema directory cannot be located.

    """
    # 1. Environment variable override
    if env_path := os.environ.get("AEGIS_SCHEMA_PATH"):
        schema_dir = Path(env_path)
        if schema_dir.exists():
            return schema_dir / filename

    # 2. Development: relative to working directory
    local_schema = Path.cwd() / "schema"
    if local_schema.exists():
        return local_schema / filename

    # 3. Development: relative to this file
    source_schema = Path(__file__).parent.parent / "schema"
    if source_schema.exists():
        return source_schema / filename

    # 4. Installed package data
    if data_dir := _find_package_data_dir():
        installed_schema = data_dir / "schema"
        if installed_schema.exists():
            return installed_schema / filename

    msg = (
        "Cannot locate Aegis schema directory. "
        "Set AEGIS_SCHEMA_PATH environment variable or run from source directory."
    )
    raise FileNotFoundError(msg)


def get_version() -> str:
    """Get the installed Aegis version.

    Returns:
        Version string (e.g., "1.0.0") or "dev" if not installed.

    """
    try:
        from importlib.metadata import version

        return version("aegis")
    except Exception:
        return "dev"
