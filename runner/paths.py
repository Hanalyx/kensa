"""Path utilities for locating Kensa resources.

This module provides functions to locate rules and schema files whether
Kensa is run from source or installed as a package.

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
    """Find the package data directory for installed Kensa.

    Checks common installation locations for shared data.

    Returns:
        Path to data directory, or None if not found.

    """
    # Check various possible installation prefixes
    prefixes: list[str | Path] = [
        sys.prefix,  # Virtual env or system Python
        sys.base_prefix,  # Base Python (if in venv)
        Path.home() / ".local",  # pip --user
        "/usr/local",
        "/usr",
    ]

    for prefix in prefixes:
        data_dir = Path(prefix) / "share" / "kensa"
        if data_dir.exists():
            return data_dir

    # Fallback: site-packages layout (pip install with package_data)
    try:
        import kensa as _pkg

        pkg_dir = Path(_pkg.__file__).parent / "data"
        if pkg_dir.exists():
            return pkg_dir
    except (ImportError, AttributeError):
        pass

    return None


def get_rules_path(subpath: str = "") -> Path:
    """Get the path to Kensa rules directory.

    Checks locations in order:
    1. KENSA_RULES_PATH environment variable
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
    if env_path := os.environ.get("KENSA_RULES_PATH"):
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
        "Cannot locate Kensa rules directory. "
        "Set KENSA_RULES_PATH environment variable or run from source directory."
    )
    raise FileNotFoundError(msg)


def get_schema_path(filename: str = "rule.schema.json") -> Path:
    """Get the path to Kensa schema files.

    Checks locations in order:
    1. KENSA_SCHEMA_PATH environment variable
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
    if env_path := os.environ.get("KENSA_SCHEMA_PATH"):
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
        "Cannot locate Kensa schema directory. "
        "Set KENSA_SCHEMA_PATH environment variable or run from source directory."
    )
    raise FileNotFoundError(msg)


def get_config_path(subpath: str = "") -> Path:
    """Get the path to Kensa configuration directory.

    Checks locations in order:
    1. KENSA_CONFIG_PATH environment variable
    2. ./config relative to current directory (development)
    3. ./config relative to source tree (runner/../config/)
    4. /etc/kensa/ (installed)

    Args:
        subpath: Optional subdirectory or file within config (e.g., "defaults.yml").

    Returns:
        Path to config directory or specific config file.

    Raises:
        FileNotFoundError: If config directory cannot be located.

    """
    # 1. Environment variable override
    if env_path := os.environ.get("KENSA_CONFIG_PATH"):
        config_dir = Path(env_path)
        if config_dir.exists():
            return config_dir / subpath if subpath else config_dir

    # 2. Development: relative to working directory
    local_config = Path.cwd() / "config"
    if local_config.exists():
        return local_config / subpath if subpath else local_config

    # 3. Development: relative to this file (runner/paths.py -> ../config)
    source_config = Path(__file__).parent.parent / "config"
    if source_config.exists():
        return source_config / subpath if subpath else source_config

    # 4. Installed: /etc/kensa/
    etc_config = Path("/etc/kensa")
    if etc_config.exists():
        return etc_config / subpath if subpath else etc_config

    msg = (
        "Cannot locate Kensa config directory. "
        "Set KENSA_CONFIG_PATH environment variable or run from source directory."
    )
    raise FileNotFoundError(msg)


def get_mappings_path(subpath: str = "") -> Path:
    """Get the path to Kensa mappings directory.

    Checks locations in order:
    1. KENSA_MAPPINGS_PATH environment variable
    2. ./mappings relative to current directory (development)
    3. ./mappings relative to source tree (runner/../mappings/)
    4. Installed package data location

    Args:
        subpath: Optional subdirectory or file within mappings.

    Returns:
        Path to mappings directory or specific mapping file.

    Raises:
        FileNotFoundError: If mappings directory cannot be located.

    """
    # 1. Environment variable override
    if env_path := os.environ.get("KENSA_MAPPINGS_PATH"):
        mappings_dir = Path(env_path)
        if mappings_dir.exists():
            return mappings_dir / subpath if subpath else mappings_dir

    # 2. Development: relative to working directory
    local_mappings = Path.cwd() / "mappings"
    if local_mappings.exists():
        return local_mappings / subpath if subpath else local_mappings

    # 3. Development: relative to this file (runner/paths.py -> ../mappings)
    source_mappings = Path(__file__).parent.parent / "mappings"
    if source_mappings.exists():
        return source_mappings / subpath if subpath else source_mappings

    # 4. Installed package data
    if data_dir := _find_package_data_dir():
        installed_mappings = data_dir / "mappings"
        if installed_mappings.exists():
            return installed_mappings / subpath if subpath else installed_mappings

    msg = (
        "Cannot locate Kensa mappings directory. "
        "Set KENSA_MAPPINGS_PATH environment variable or run from source directory."
    )
    raise FileNotFoundError(msg)


def get_inventory_path() -> Path | None:
    """Get the path to an Kensa inventory file.

    Checks locations in order:
    1. KENSA_INVENTORY_PATH environment variable
    2. ./inventory.yml or ./inventory.ini relative to cwd
    3. /etc/kensa/inventory.yml or /etc/kensa/inventory.ini (installed)

    Returns:
        Path to inventory file, or None if not found.

    """
    # 1. Environment variable override
    if env_path := os.environ.get("KENSA_INVENTORY_PATH"):
        inv_path = Path(env_path)
        if inv_path.exists():
            return inv_path

    # 2. Development: relative to working directory
    for name in ("inventory.yml", "inventory.ini"):
        local_inv = Path.cwd() / name
        if local_inv.exists():
            return local_inv

    # 3. Installed: /etc/kensa/
    for name in ("inventory.yml", "inventory.ini"):
        etc_inv = Path("/etc/kensa") / name
        if etc_inv.exists():
            return etc_inv

    return None


def get_version() -> str:
    """Get the installed Kensa version.

    Returns:
        Version string (e.g., "1.0.0") or "dev" if not installed.

    """
    try:
        from importlib.metadata import version

        return version("kensa")
    except Exception:
        return "dev"
