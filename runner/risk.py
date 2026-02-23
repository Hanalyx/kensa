"""Risk classification for remediation mechanisms.

Determines the risk level of a remediation step based on its mechanism type
and target path. Used by risk-based snapshot capture to decide which steps
need pre-state capture.
"""

from __future__ import annotations

# Risk levels ordered from lowest to highest
RISK_LEVELS = ("na", "low", "medium", "high")

# Base risk by mechanism type
MECHANISM_RISK: dict[str, str] = {
    # High risk — can brick boot, break mounts, lock out users
    "grub_parameter_set": "high",
    "grub_parameter_remove": "high",
    "mount_option_set": "high",
    "pam_module_configure": "high",
    "kernel_module_disable": "high",
    # Medium risk — can break services or change security posture
    "config_set": "medium",
    "config_set_dropin": "medium",
    "config_block": "medium",
    "config_remove": "medium",
    "sysctl_set": "medium",
    "service_masked": "medium",
    "service_disabled": "medium",
    "audit_rule_set": "medium",
    "selinux_boolean_set": "medium",
    "file_content": "medium",
    # Low risk — narrow blast radius, easily reversed
    "file_permissions": "low",
    "package_present": "low",
    "package_absent": "low",
    "service_enabled": "low",
    "cron_job": "low",
    "file_absent": "low",
    # Not capturable
    "command_exec": "na",
    "manual": "na",
}

# Paths that escalate risk regardless of mechanism
HIGH_RISK_PATHS: list[str] = [
    "/etc/pam.d/",
    "/etc/fstab",
    "/etc/crypttab",
    "/etc/default/grub",
    "/etc/selinux/config",
]

# Paths that set a minimum of medium risk
MEDIUM_RISK_PATHS: list[str] = [
    "/etc/ssh/sshd_config",
    "/etc/security/",
]


def _risk_ord(level: str) -> int:
    """Return numeric ordering for a risk level."""
    try:
        return RISK_LEVELS.index(level)
    except ValueError:
        return 0


def _path_risk(path: str, extra_high_risk: list[str] | None = None) -> str | None:
    """Determine risk escalation from a file path.

    Returns the escalated risk level or None if no escalation applies.
    """
    if not path:
        return None

    all_high = HIGH_RISK_PATHS + (extra_high_risk or [])
    for pattern in all_high:
        if pattern.endswith("/"):
            if path.startswith(pattern):
                return "high"
        elif path == pattern:
            return "high"

    for pattern in MEDIUM_RISK_PATHS:
        if pattern.endswith("/"):
            if path.startswith(pattern):
                return "medium"
        elif path == pattern:
            return "medium"

    return None


def classify_step_risk(
    mechanism: str,
    remediation: dict,
    *,
    extra_high_risk: list[str] | None = None,
) -> str:
    """Classify the risk of a remediation step.

    Risk is determined by the mechanism type and target path. The effective
    risk is max(mechanism_risk, path_risk).

    Args:
        mechanism: Remediation mechanism name.
        remediation: Remediation step dict (may contain 'path', 'file', etc.).
        extra_high_risk: Additional paths that escalate to high risk.

    Returns:
        Risk level: 'high', 'medium', 'low', or 'na'.

    """
    base = MECHANISM_RISK.get(mechanism, "medium")

    # Extract path from remediation dict
    path = remediation.get("path", "") or remediation.get("file", "") or ""

    path_level = _path_risk(path, extra_high_risk)
    if path_level is None:
        return base

    # Return the higher risk
    if _risk_ord(path_level) > _risk_ord(base):
        return path_level
    return base


def should_capture(
    mechanism: str,
    remediation: dict,
    *,
    snapshot_mode: str = "all",
    risk_threshold: str = "medium",
    extra_high_risk: list[str] | None = None,
) -> bool:
    """Determine whether pre-state capture should occur for a step.

    Args:
        mechanism: Remediation mechanism name.
        remediation: Remediation step dict.
        snapshot_mode: 'all', 'risk_based', or 'none'.
        risk_threshold: Minimum risk level to capture ('high', 'medium', 'low').
        extra_high_risk: Additional paths that escalate to high risk.

    Returns:
        True if pre-state should be captured.

    """
    if snapshot_mode == "none":
        return False
    if snapshot_mode == "all":
        return True

    # risk_based mode
    risk = classify_step_risk(mechanism, remediation, extra_high_risk=extra_high_risk)
    if risk == "na":
        return False
    return _risk_ord(risk) >= _risk_ord(risk_threshold)
