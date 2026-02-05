"""Rule engine — re-export facade.

All public (and test-visible) symbols are defined in sub-modules and
re-exported here so that ``from runner.engine import X`` continues to work
unchanged for cli.py and the test suite.
"""

from __future__ import annotations

# ── Data types ─────────────────────────────────────────────────────────────
from runner._types import (  # noqa: F401
    CheckResult,
    PreState,
    RollbackResult,
    RuleResult,
    StepResult,
)

# ── Rule loading & platform filtering ──────────────────────────────────────
from runner._loading import (  # noqa: F401
    load_rules,
    rule_applies_to_platform,
)

# ── Implementation selection ───────────────────────────────────────────────
from runner._selection import (  # noqa: F401
    evaluate_when,
    select_implementation,
)

# ── Check dispatch ─────────────────────────────────────────────────────────
from runner._checks import (  # noqa: F401
    run_check,
)

# ── Remediation dispatch ──────────────────────────────────────────────────
from runner._remediation import (  # noqa: F401
    run_remediation,
)

# ── Pre-state capture (used by tests) ─────────────────────────────────────
from runner._capture import (  # noqa: F401
    _capture_command_exec,
    _capture_config_remove,
    _capture_config_set,
    _capture_config_set_dropin,
    _capture_file_absent,
    _capture_file_content,
    _capture_file_permissions,
    _capture_kernel_module_disable,
    _capture_manual,
    _capture_package_absent,
    _capture_package_present,
    _capture_service_disabled,
    _capture_service_enabled,
    _capture_audit_rule_set,
    _capture_config_block,
    _capture_cron_job,
    _capture_grub_parameter_remove,
    _capture_grub_parameter_set,
    _capture_mount_option_set,
    _capture_selinux_boolean_set,
    _capture_service_masked,
    _capture_sysctl_set,
)

# ── Rollback (used by tests) ──────────────────────────────────────────────
from runner._rollback import (  # noqa: F401
    _execute_rollback,
    _rollback_command_exec,
    _rollback_config_remove,
    _rollback_config_set,
    _rollback_config_set_dropin,
    _rollback_file_absent,
    _rollback_file_content,
    _rollback_file_permissions,
    _rollback_kernel_module_disable,
    _rollback_manual,
    _rollback_package_absent,
    _rollback_package_present,
    _rollback_service_disabled,
    _rollback_service_enabled,
    _rollback_audit_rule_set,
    _rollback_config_block,
    _rollback_cron_job,
    _rollback_grub_parameter_remove,
    _rollback_grub_parameter_set,
    _rollback_mount_option_set,
    _rollback_selinux_boolean_set,
    _rollback_service_masked,
    _rollback_sysctl_set,
)

# ── Top-level orchestration ───────────────────────────────────────────────
from runner._orchestration import (  # noqa: F401
    evaluate_rule,
    remediate_rule,
)
