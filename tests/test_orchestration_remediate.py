"""Spec-derived tests for remediate_rule orchestration pipeline.

See specs/orchestration/remediate_rule.spec.md for full specification.

Tests mock at the seam boundaries (evaluate_rule, select_implementation,
run_remediation, run_check, _execute_rollback) to isolate orchestration
logic from handler implementations.
"""

from __future__ import annotations

from unittest.mock import patch

from runner._orchestration import remediate_rule
from runner._types import CheckResult, Evidence, RollbackResult, RuleResult, StepResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Patch targets — these are the names as imported inside _orchestration.py
_PATCH_EVALUATE = "runner._orchestration.evaluate_rule"
_PATCH_SELECT = "runner._orchestration.select_implementation"
_PATCH_REMEDIATE = "runner._orchestration.run_remediation"
_PATCH_CHECK = "runner._orchestration.run_check"
_PATCH_ROLLBACK = "runner._orchestration._execute_rollback"


def _make_rule(
    rule_id: str = "test-rule",
    title: str = "Test Rule",
    severity: str = "medium",
) -> dict:
    """Build a minimal rule dict for orchestration tests."""
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "category": "test",
        "implementations": [
            {
                "default": True,
                "check": {
                    "method": "command",
                    "run": "echo ok",
                    "expected_stdout": "ok",
                },
                "remediation": {
                    "mechanism": "command_exec",
                    "run": "echo fix",
                },
            }
        ],
    }


def _failing_result(rule_id: str = "test-rule") -> RuleResult:
    """Return a RuleResult representing an initial failing check."""
    return RuleResult(
        rule_id=rule_id,
        title="Test Rule",
        severity="medium",
        passed=False,
        detail="check failed",
    )


def _passing_result(rule_id: str = "test-rule") -> RuleResult:
    """Return a RuleResult representing a passing check."""
    return RuleResult(
        rule_id=rule_id,
        title="Test Rule",
        severity="medium",
        passed=True,
        detail="check passed",
    )


def _skipped_result(rule_id: str = "test-rule") -> RuleResult:
    """Return a RuleResult representing a skipped rule."""
    return RuleResult(
        rule_id=rule_id,
        title="Test Rule",
        severity="medium",
        passed=False,
        skipped=True,
        skip_reason="No matching implementation",
    )


def _step_results_ok() -> list[StepResult]:
    """Successful single-step remediation results."""
    return [
        StepResult(step_index=0, mechanism="command_exec", success=True, detail="done")
    ]


def _step_results_fail() -> list[StepResult]:
    """Failed single-step remediation results."""
    return [
        StepResult(
            step_index=0, mechanism="command_exec", success=False, detail="failed"
        )
    ]


def _rollback_results() -> list[RollbackResult]:
    """Rollback results for a single step."""
    return [
        RollbackResult(
            step_index=0, mechanism="command_exec", success=True, detail="rolled back"
        )
    ]


def _impl_with_check_and_remediation() -> dict:
    """Implementation dict with both check and remediation."""
    return {
        "default": True,
        "check": {"method": "command", "run": "echo ok", "expected_stdout": "ok"},
        "remediation": {"mechanism": "command_exec", "run": "echo fix"},
    }


def _impl_no_remediation() -> dict:
    """Implementation dict with check but no remediation."""
    return {
        "default": True,
        "check": {"method": "command", "run": "echo ok", "expected_stdout": "ok"},
    }


def _impl_no_check() -> dict:
    """Implementation dict with remediation but no check."""
    return {
        "default": True,
        "remediation": {"mechanism": "command_exec", "run": "echo fix"},
    }


# ---------------------------------------------------------------------------
# Spec-derived tests
# ---------------------------------------------------------------------------


class TestRemediateRuleSpecDerived:
    """Spec-derived tests for remediate_rule orchestration pipeline.

    See specs/orchestration/remediate_rule.spec.md for acceptance criteria.
    """

    # ── AC-1: Rule already passes ────────────────────────────────────────

    def test_already_passing_skips_remediation(self, mock_ssh):
        """AC-1: Rule already passes -> early return, remediated=False."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with patch(_PATCH_EVALUATE, return_value=_passing_result()):
            result = remediate_rule(ssh, rule, {})

        assert result.passed is True
        assert result.remediated is False
        assert result.step_results == []
        assert result.rolled_back is False

    def test_already_passing_does_not_call_select_implementation(self, mock_ssh):
        """AC-1: When rule passes, select_implementation is NOT called a second time."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_passing_result()),
            patch(_PATCH_SELECT) as mock_select,
        ):
            remediate_rule(ssh, rule, {})

        mock_select.assert_not_called()

    # ── AC-2: Rule is skipped ────────────────────────────────────────────

    def test_skipped_rule_returns_early(self, mock_ssh):
        """AC-2: Rule skipped -> early return, remediated=False."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with patch(_PATCH_EVALUATE, return_value=_skipped_result()):
            result = remediate_rule(ssh, rule, {})

        assert result.skipped is True
        assert result.remediated is False
        assert result.step_results == []

    # ── AC-3: No matching implementation ─────────────────────────────────

    def test_no_implementation_sets_detail(self, mock_ssh):
        """AC-3: No matching implementation -> remediation_detail set, remediated=False."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=None),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is False
        assert result.remediation_detail == "No matching implementation"
        assert result.passed is False

    # ── AC-4: No remediation defined ─────────────────────────────────────

    def test_no_remediation_block_sets_detail(self, mock_ssh):
        """AC-4: Implementation exists but no remediation -> remediation_detail set."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_no_remediation()),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is False
        assert result.remediation_detail == "No remediation defined"
        assert result.passed is False

    # ── AC-5: Remediation succeeds, re-check passes ─────────────────────

    def test_remediation_success_recheck_passes(self, mock_ssh):
        """AC-5: Remediation succeeds, re-check passes -> passed=True, evidence updated."""
        ssh = mock_ssh({})
        rule = _make_rule()
        recheck_evidence = Evidence(
            method="command",
            command="echo ok",
            stdout="ok",
            stderr="",
            exit_code=0,
            expected="ok",
            actual="ok",
            timestamp=None,
        )
        recheck_result = CheckResult(
            passed=True, detail="re-check passed", evidence=recheck_evidence
        )
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK, return_value=recheck_result),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is True
        assert result.passed is True
        assert result.detail == "re-check passed"
        assert result.evidence is recheck_evidence
        assert result.rolled_back is False
        assert len(result.step_results) == 1

    # ── AC-6: Dry-run ────────────────────────────────────────────────────

    def test_dry_run_skips_recheck(self, mock_ssh):
        """AC-6: Dry-run -> remediated=True, no re-check, passed remains False."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "would fix", _step_results_ok()),
            ),
            patch(_PATCH_CHECK) as mock_check,
        ):
            result = remediate_rule(ssh, rule, {}, dry_run=True)

        assert result.remediated is True
        assert result.passed is False  # not updated because no re-check
        assert result.remediation_detail == "would fix"
        mock_check.assert_not_called()

    def test_dry_run_passes_dry_run_to_run_remediation(self, mock_ssh):
        """AC-6: dry_run flag is forwarded to run_remediation."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "would fix", _step_results_ok()),
            ) as mock_rem,
        ):
            remediate_rule(ssh, rule, {}, dry_run=True)

        _, kwargs = mock_rem.call_args
        assert kwargs.get("dry_run") is True

    # ── AC-7: Remediation fails ──────────────────────────────────────────

    def test_remediation_fails_no_rollback(self, mock_ssh):
        """AC-7: Remediation fails -> remediated=True, passed=False, no rollback."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(False, "step failed", _step_results_fail()),
            ),
            patch(_PATCH_ROLLBACK) as mock_rollback,
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is True
        assert result.passed is False
        assert result.remediation_detail == "step failed"
        assert len(result.step_results) == 1
        assert result.rolled_back is False
        mock_rollback.assert_not_called()

    # ── AC-8: Remediation fails + rollback_on_failure ────────────────────

    def test_remediation_fails_with_rollback(self, mock_ssh):
        """AC-8: Remediation fails + rollback_on_failure -> rolled_back=True."""
        ssh = mock_ssh({})
        rule = _make_rule()
        rb_results = _rollback_results()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(False, "step failed", _step_results_fail()),
            ),
            patch(_PATCH_ROLLBACK, return_value=rb_results),
        ):
            result = remediate_rule(ssh, rule, {}, rollback_on_failure=True)

        assert result.remediated is True
        assert result.rolled_back is True
        assert result.rollback_results == rb_results

    # ── AC-9: Re-check fails ────────────────────────────────────────────

    def test_recheck_fails_no_rollback(self, mock_ssh):
        """AC-9: Re-check fails -> passed=False, remediated=True, no rollback."""
        ssh = mock_ssh({})
        rule = _make_rule()
        recheck_result = CheckResult(passed=False, detail="still failing")
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK, return_value=recheck_result),
            patch(_PATCH_ROLLBACK) as mock_rollback,
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is True
        assert result.passed is False
        assert result.detail == "still failing"
        assert result.rolled_back is False
        mock_rollback.assert_not_called()

    # ── AC-10: Re-check fails + rollback_on_failure ──────────────────────

    def test_recheck_fails_with_rollback(self, mock_ssh):
        """AC-10: Re-check fails + rollback_on_failure -> rolled_back=True."""
        ssh = mock_ssh({})
        rule = _make_rule()
        rb_results = _rollback_results()
        recheck_result = CheckResult(passed=False, detail="still failing")
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK, return_value=recheck_result),
            patch(_PATCH_ROLLBACK, return_value=rb_results),
        ):
            result = remediate_rule(ssh, rule, {}, rollback_on_failure=True)

        assert result.remediated is True
        assert result.rolled_back is True
        assert result.rollback_results == rb_results
        assert result.passed is False

    # ── AC-11: run_remediation throws exception ──────────────────────────

    def test_run_remediation_exception_caught(self, mock_ssh):
        """AC-11: run_remediation exception -> remediation_detail has 'Error:' prefix."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(_PATCH_REMEDIATE, side_effect=RuntimeError("ssh timeout")),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is False
        assert result.remediation_detail.startswith("Error:")
        assert "ssh timeout" in result.remediation_detail
        assert result.step_results == []

    # ── AC-12: run_check throws exception during re-check ────────────────

    def test_recheck_exception_caught(self, mock_ssh):
        """AC-12: run_check exception during re-check -> detail has 'Re-check error:' prefix."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK, side_effect=RuntimeError("connection lost")),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is True
        assert result.detail.startswith("Re-check error:")
        assert "connection lost" in result.detail

    def test_recheck_exception_with_rollback(self, mock_ssh):
        """AC-12: Re-check exception + rollback_on_failure -> rollback triggered."""
        ssh = mock_ssh({})
        rule = _make_rule()
        rb_results = _rollback_results()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK, side_effect=RuntimeError("connection lost")),
            patch(_PATCH_ROLLBACK, return_value=rb_results),
        ):
            result = remediate_rule(ssh, rule, {}, rollback_on_failure=True)

        assert result.rolled_back is True
        assert result.rollback_results == rb_results
        # passed remains False (initial check value, not updated because exception)
        assert result.passed is False

    # ── AC-13: Dry-run + remediation fails + rollback_on_failure ─────────

    def test_dry_run_no_rollback_on_failure(self, mock_ssh):
        """AC-13: Remediation fails + rollback_on_failure + dry_run -> no rollback."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(False, "would fail", _step_results_fail()),
            ),
            patch(_PATCH_ROLLBACK) as mock_rollback,
        ):
            result = remediate_rule(
                ssh, rule, {}, dry_run=True, rollback_on_failure=True
            )

        assert result.remediated is True
        assert result.rolled_back is False
        mock_rollback.assert_not_called()

    # ── AC-14: No check block -> re-check skipped ───────────────────────

    def test_no_check_block_skips_recheck(self, mock_ssh):
        """AC-14: No check in implementation -> re-check phase is skipped."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_no_check()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK) as mock_check,
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediated is True
        # run_check should not be called for re-check when no check block
        mock_check.assert_not_called()
        # passed stays False because no re-check updated it
        assert result.passed is False

    # ── AC-15: select_implementation called with same args ───────────────

    def test_select_implementation_called_with_correct_args(self, mock_ssh):
        """AC-15: select_implementation is called with the same rule and capabilities."""
        ssh = mock_ssh({})
        rule = _make_rule()
        caps = {"sshd_config_d": True}
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(
                _PATCH_SELECT, return_value=_impl_with_check_and_remediation()
            ) as mock_select,
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(
                _PATCH_CHECK,
                return_value=CheckResult(passed=True, detail="ok"),
            ),
        ):
            remediate_rule(ssh, rule, caps)

        mock_select.assert_called_once_with(rule, caps)

    # ── Additional edge cases ────────────────────────────────────────────

    def test_snapshot_forwarded_to_run_remediation(self, mock_ssh):
        """snapshot parameter is forwarded to run_remediation."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ) as mock_rem,
            patch(
                _PATCH_CHECK,
                return_value=CheckResult(passed=True, detail="ok"),
            ),
        ):
            remediate_rule(ssh, rule, {}, snapshot=False)

        _, kwargs = mock_rem.call_args
        assert kwargs.get("snapshot") is False

    def test_step_results_populated_on_success(self, mock_ssh):
        """step_results from run_remediation are attached to the final RuleResult."""
        ssh = mock_ssh({})
        rule = _make_rule()
        steps = _step_results_ok()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", steps),
            ),
            patch(
                _PATCH_CHECK,
                return_value=CheckResult(passed=True, detail="ok"),
            ),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.step_results is steps
        assert len(result.step_results) == 1
        assert result.step_results[0].mechanism == "command_exec"

    def test_remediation_detail_from_run_remediation(self, mock_ssh):
        """remediation_detail is set from run_remediation's detail string."""
        ssh = mock_ssh({})
        rule = _make_rule()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "Set net.ipv4.ip_forward=0", _step_results_ok()),
            ),
            patch(
                _PATCH_CHECK,
                return_value=CheckResult(passed=True, detail="ok"),
            ),
        ):
            result = remediate_rule(ssh, rule, {})

        assert result.remediation_detail == "Set net.ipv4.ip_forward=0"

    def test_rollback_not_called_when_flag_false(self, mock_ssh):
        """rollback_on_failure=False (default) -> _execute_rollback never called."""
        ssh = mock_ssh({})
        rule = _make_rule()
        recheck_result = CheckResult(passed=False, detail="still failing")
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=_impl_with_check_and_remediation()),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ),
            patch(_PATCH_CHECK, return_value=recheck_result),
            patch(_PATCH_ROLLBACK) as mock_rollback,
        ):
            result = remediate_rule(ssh, rule, {}, rollback_on_failure=False)

        assert result.passed is False
        assert result.rolled_back is False
        mock_rollback.assert_not_called()

    def test_check_forwarded_to_run_remediation(self, mock_ssh):
        """check block from implementation is forwarded to run_remediation."""
        ssh = mock_ssh({})
        rule = _make_rule()
        impl = _impl_with_check_and_remediation()
        with (
            patch(_PATCH_EVALUATE, return_value=_failing_result()),
            patch(_PATCH_SELECT, return_value=impl),
            patch(
                _PATCH_REMEDIATE,
                return_value=(True, "remediated", _step_results_ok()),
            ) as mock_rem,
            patch(
                _PATCH_CHECK,
                return_value=CheckResult(passed=True, detail="ok"),
            ),
        ):
            remediate_rule(ssh, rule, {})

        _, kwargs = mock_rem.call_args
        assert kwargs.get("check") == impl["check"]
