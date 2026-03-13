"""Rule variable configuration loading and resolution.

This module handles loading of configurable variables for rules, allowing
different compliance frameworks (CIS, STIG, NIST) to use different threshold
values for the same control, and per-group/per-host overrides.

Configuration is loaded from the config directory (default: ./config/):
1. config/defaults.yml - Base variable definitions and framework overrides
2. config/conf.d/*.yml - Site-wide overrides (loaded alphabetically)
3. config/groups/*.yml - Per-group overrides (filename stem = group name)
4. config/hosts/*.yml  - Per-host overrides (filename stem = hostname)

Variables are resolved at per-host execution time with this priority (highest first):
1. CLI --var KEY=VALUE overrides
2. config/hosts/<hostname>.yml
3. config/groups/<group>.yml (last group wins on conflict)
4. config/conf.d/*.yml (later files override earlier)
5. frameworks.<name> section (when --framework specified)
6. variables section in config/defaults.yml

Example:
-------
    >>> from runner._config import load_config, resolve_variables
    >>>
    >>> config = load_config("config/")
    >>> rule = {"check": {"expected": "{{ pam_pwquality_minlen }}"}}
    >>> resolved = resolve_variables(rule, config, framework="stig")
    >>> print(resolved["check"]["expected"])
    '15'

"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ── Variable pattern ───────────────────────────────────────────────────────

# Matches {{ variable_name }} with optional whitespace
VARIABLE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


# ── Safe fields for substitution ───────────────────────────────────────────
#
# Security: Only substitute variables in value fields, never in paths
# or command fields that could lead to shell injection.
#

SAFE_SUBSTITUTION_FIELDS = frozenset(
    {
        "content",
        "expected",
        "expected_content",
        "value",
        "mode",
        "owner",
        "group",
    }
)


# ── Data structures ────────────────────────────────────────────────────────


@dataclass
class RuleConfig:
    """Configuration for rule variables.

    Attributes:
        variables: Default variable values.
        framework_overrides: Framework-specific variable overrides.
            Keys are framework names (e.g., "cis", "stig").
            Values are dicts mapping variable names to values.
        group_overrides: Per-group variable overrides.
            Keys are group names (filename stems from config/groups/).
            Values are dicts mapping variable names to values.
        host_overrides: Per-host variable overrides.
            Keys are hostnames (filename stems from config/hosts/).
            Values are dicts mapping variable names to values.

    """

    variables: dict[str, Any] = field(default_factory=dict)
    framework_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    group_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    host_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)


# ── Configuration loading ──────────────────────────────────────────────────


def load_config(config_path: str | None = None) -> RuleConfig:
    """Load rule configuration from config directory.

    Loads defaults.yml, conf.d/ overrides, groups/, and hosts/ from
    the specified config directory.

    Args:
        config_path: Path to config directory. If None, uses
            get_config_path() to auto-detect.

    Returns:
        RuleConfig with merged variables and framework overrides.

    """
    if config_path is None:
        from runner.paths import get_config_path

        try:
            config_dir = get_config_path()
        except FileNotFoundError:
            return RuleConfig()
    else:
        config_dir = Path(config_path)

    if not config_dir.is_dir():
        return RuleConfig()

    config = RuleConfig()

    # Load defaults.yml
    defaults_path = config_dir / "defaults.yml"
    if defaults_path.exists():
        try:
            data = yaml.safe_load(defaults_path.read_text())
            if isinstance(data, dict):
                config.variables = data.get("variables", {})
                config.framework_overrides = data.get("frameworks", {})
        except yaml.YAMLError:
            pass  # Silently ignore malformed defaults

    # Load conf.d/*.yml overrides (alphabetically)
    conf_d = config_dir / "conf.d"
    if conf_d.is_dir():
        for override_file in sorted(conf_d.glob("*.yml")):
            try:
                data = yaml.safe_load(override_file.read_text())
                if isinstance(data, dict):
                    # Merge variables
                    if "variables" in data:
                        config.variables.update(data["variables"])
                    # Merge framework overrides
                    if "frameworks" in data:
                        for fw_name, fw_vars in data["frameworks"].items():
                            if fw_name not in config.framework_overrides:
                                config.framework_overrides[fw_name] = {}
                            config.framework_overrides[fw_name].update(fw_vars)
            except yaml.YAMLError:
                pass  # Silently ignore malformed overrides

    # Load groups/*.yml → group_overrides (filename stem = group name)
    groups_dir = config_dir / "groups"
    if groups_dir.is_dir():
        for group_file in sorted(groups_dir.glob("*.yml")):
            group_name = group_file.stem
            try:
                data = yaml.safe_load(group_file.read_text())
                if isinstance(data, dict):
                    config.group_overrides[group_name] = data.get("variables", {})
            except yaml.YAMLError:
                pass

    # Load hosts/*.yml → host_overrides (filename stem = hostname)
    hosts_dir = config_dir / "hosts"
    if hosts_dir.is_dir():
        for host_file in sorted(hosts_dir.glob("*.yml")):
            host_name = host_file.stem
            try:
                data = yaml.safe_load(host_file.read_text())
                if isinstance(data, dict):
                    config.host_overrides[host_name] = data.get("variables", {})
            except yaml.YAMLError:
                pass

    return config


# ── Variable resolution ────────────────────────────────────────────────────


def _get_effective_variables(
    config: RuleConfig,
    *,
    framework: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    hostname: str | None = None,
    groups: list[str] | None = None,
) -> dict[str, Any]:
    """Build the effective variable dict with proper priority.

    Priority (highest first):
    1. CLI --var overrides
    2. Per-host overrides (config/hosts/<hostname>.yml)
    3. Per-group overrides (config/groups/<group>.yml, last group wins)
    4. conf.d overrides (already merged into config.variables)
    5. Framework-specific values
    6. Default values from config

    Args:
        config: Loaded rule configuration.
        framework: Framework name for framework-specific overrides.
        cli_overrides: CLI --var KEY=VALUE overrides.
        hostname: Target hostname for per-host overrides.
        groups: Target host's group list for per-group overrides.

    Returns:
        Dict of variable names to resolved values.

    """
    # Start with defaults (already includes conf.d merges)
    effective = dict(config.variables)

    # Apply framework overrides if specified
    if framework:
        # Extract base framework name (e.g., "cis" from "cis-rhel9")
        fw_base = framework.split("-")[0].lower()
        if fw_base in config.framework_overrides:
            effective.update(config.framework_overrides[fw_base])

    # Apply group overrides (in order — last group wins on conflict)
    for g in groups or []:
        if g in config.group_overrides:
            effective.update(config.group_overrides[g])

    # Apply host overrides
    if hostname and hostname in config.host_overrides:
        effective.update(config.host_overrides[hostname])

    # Apply CLI overrides (highest priority)
    if cli_overrides:
        effective.update(cli_overrides)

    return effective


def _substitute_string(
    value: str,
    variables: dict[str, Any],
    *,
    strict: bool = True,
) -> str:
    """Substitute {{ variable }} patterns in a string.

    Args:
        value: String potentially containing {{ variable }} patterns.
        variables: Dict of variable names to values.
        strict: If True, raise error on undefined variables.

    Returns:
        String with variables substituted.

    Raises:
        ValueError: If strict=True and a variable is undefined.

    """

    def replace_var(match: re.Match) -> str:
        var_name = match.group(1)
        if var_name in variables:
            return str(variables[var_name])
        elif strict:
            raise ValueError(f"Undefined variable: {var_name}")
        else:
            return str(match.group(0))  # Leave unchanged

    return VARIABLE_PATTERN.sub(replace_var, value)


def _substitute_in_dict(
    d: dict[str, Any],
    variables: dict[str, Any],
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Recursively substitute variables in a dict's safe fields.

    Args:
        d: Dict to process.
        variables: Variable values.
        strict: If True, raise on undefined variables.

    Returns:
        New dict with substitutions applied.

    """
    result: dict[str, Any] = {}
    for key, value in d.items():
        if isinstance(value, str):
            # Only substitute in safe fields
            if key in SAFE_SUBSTITUTION_FIELDS:
                result[key] = _substitute_string(value, variables, strict=strict)
            else:
                result[key] = value
        elif isinstance(value, dict):
            result[key] = _substitute_in_dict(value, variables, strict=strict)
        elif isinstance(value, list):
            result[key] = _substitute_in_list(value, variables, strict=strict)
        else:
            result[key] = value
    return result


def _substitute_in_list(
    lst: list[Any],
    variables: dict[str, Any],
    *,
    strict: bool = True,
) -> list[Any]:
    """Recursively substitute variables in a list.

    Args:
        lst: List to process.
        variables: Variable values.
        strict: If True, raise on undefined variables.

    Returns:
        New list with substitutions applied.

    """
    result: list[Any] = []
    for item in lst:
        if isinstance(item, dict):
            result.append(_substitute_in_dict(item, variables, strict=strict))
        elif isinstance(item, list):
            result.append(_substitute_in_list(item, variables, strict=strict))
        else:
            result.append(item)
    return result


def resolve_variables(
    rule: dict,
    config: RuleConfig,
    *,
    framework: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    hostname: str | None = None,
    groups: list[str] | None = None,
    strict: bool = True,
) -> dict:
    """Resolve {{ variable }} placeholders in a rule.

    Only substitutes in safe fields (expected, value, mode, owner, group).
    Never substitutes in path, run, command, or other execution-related fields.

    Args:
        rule: Rule dict to process.
        config: Loaded rule configuration.
        framework: Framework name for framework-specific values.
        cli_overrides: CLI --var KEY=VALUE overrides.
        hostname: Target hostname for per-host overrides.
        groups: Target host's group list for per-group overrides.
        strict: If True, raise on undefined variables.

    Returns:
        New rule dict with variables resolved.

    Raises:
        ValueError: If strict=True and a variable is undefined.

    """
    variables = _get_effective_variables(
        config,
        framework=framework,
        cli_overrides=cli_overrides,
        hostname=hostname,
        groups=groups,
    )

    # Deep copy and substitute
    return _substitute_in_dict(rule, variables, strict=strict)


def parse_var_overrides(var_flags: tuple[str, ...]) -> dict[str, str]:
    """Parse --var KEY=VALUE flags into a dict.

    Args:
        var_flags: Tuple of "KEY=VALUE" strings from CLI.

    Returns:
        Dict mapping variable names to values.

    Raises:
        ValueError: If a flag is malformed.

    """
    result = {}
    for flag in var_flags:
        if "=" not in flag:
            raise ValueError(f"Invalid --var format: {flag} (expected KEY=VALUE)")
        key, value = flag.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --var format: {flag} (empty key)")
        result[key] = value
    return result
