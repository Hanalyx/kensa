"""Result data types for the rule engine."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired

# ── Rule schema type ─────────────────────────────────────────────────────────


class Rule(TypedDict):
    """Structural contract for a loaded YAML rule dictionary.

    Zero runtime cost — used only for type-checking with mypy.
    """

    id: str
    title: str
    severity: str
    category: str
    tags: NotRequired[list[str]]
    platforms: NotRequired[list[dict]]
    implementations: list[dict]
    references: NotRequired[dict]
    depends_on: NotRequired[list[str]]


# ── Result data types ─────────────────────────────────────────────────────────


@dataclass
class Evidence:
    """Raw evidence captured during a check.

    Provides machine-verifiable proof of configuration state for audit
    and compliance purposes. All fields are populated by check handlers.

    Attributes:
        method: Handler name that performed the check (e.g., "config_value").
        command: Actual shell command executed on the target host.
        stdout: Raw standard output from the command.
        stderr: Raw standard error from the command.
        exit_code: Command exit code.
        expected: Expected value for comparison (if applicable).
        actual: Actual value found on the system.
        timestamp: UTC timestamp when the check was executed.

    """

    method: str
    command: str | None
    stdout: str
    stderr: str
    exit_code: int
    expected: str | None
    actual: str | None
    timestamp: datetime


@dataclass
class CheckResult:
    """Outcome of a single check."""

    passed: bool
    detail: str = ""
    evidence: Evidence | None = None


@dataclass
class PreState:
    """Captured state before a remediation step."""

    mechanism: str
    data: dict  # mechanism-specific, all values are str/bool/None/list
    capturable: bool = True  # False for command_exec and manual


@dataclass
class StepResult:
    """Outcome of a single remediation step."""

    step_index: int
    mechanism: str
    success: bool
    detail: str
    pre_state: PreState | None = None
    verified: bool | None = None  # None = not attempted
    verify_detail: str = ""


@dataclass
class RollbackResult:
    """Outcome of rolling back one step."""

    step_index: int
    mechanism: str
    success: bool
    detail: str


@dataclass
class RuleResult:
    """Outcome of evaluating one rule on one host.

    Attributes:
        rule_id: Unique identifier for the rule.
        title: Human-readable rule title.
        severity: Rule severity (low, medium, high, critical).
        passed: Whether the check passed.
        skipped: Whether the rule was skipped.
        skip_reason: Reason for skipping (if skipped).
        detail: Human-readable check result detail.
        evidence: Raw evidence from the check (for audit).
        framework_refs: All framework references (e.g., {"cis_rhel9_v2": "5.1.12"}).
        remediated: Whether remediation was attempted.
        remediation_detail: Remediation outcome message.
        step_results: Individual remediation step outcomes.
        rolled_back: Whether rollback was performed.
        rollback_results: Individual rollback step outcomes.
        framework_section: Primary framework section (legacy, use framework_refs).

    """

    rule_id: str
    title: str
    severity: str
    passed: bool
    skipped: bool = False
    skip_reason: str = ""
    detail: str = ""
    error: bool = False
    error_detail: str = ""
    evidence: Evidence | None = None
    framework_refs: dict[str, str] = field(default_factory=dict)
    remediated: bool = False
    remediation_detail: str = ""
    step_results: list[StepResult] = field(default_factory=list)
    rolled_back: bool = False
    rollback_results: list[RollbackResult] = field(default_factory=list)
    framework_section: str | None = None
