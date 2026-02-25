"""Spec-derived tests for rollback orchestration.

Tests for:
- _execute_rollback (runner/handlers/rollback/__init__.py)
- rollback_from_stored (runner/_orchestration.py)

Spec: specs/orchestration/rollback.spec.md
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from runner._orchestration import rollback_from_stored
from runner._types import PreState, RollbackResult, StepResult
from runner.handlers.rollback import _execute_rollback
from runner.storage import RemediationStepRecord

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_step(
    *,
    step_index: int = 0,
    mechanism: str = "config_set",
    success: bool = True,
    detail: str = "ok",
    pre_state: PreState | None = None,
) -> StepResult:
    """Build a StepResult with sensible defaults."""
    return StepResult(
        step_index=step_index,
        mechanism=mechanism,
        success=success,
        detail=detail,
        pre_state=pre_state,
    )


def _make_pre_state(
    mechanism: str = "config_set",
    data: dict | None = None,
    capturable: bool = True,
) -> PreState:
    """Build a PreState with sensible defaults."""
    if data is None:
        data = {
            "path": "/etc/test.conf",
            "key": "K",
            "old_line": "K V",
            "existed": True,
        }
    return PreState(mechanism=mechanism, data=data, capturable=capturable)


def _make_db_record(
    *,
    record_id: int = 1,
    remediation_id: int = 1,
    step_index: int = 0,
    mechanism: str = "config_set",
    success: bool = True,
    detail: str = "ok",
    pre_state_data: dict | None = None,
    pre_state_capturable: bool = True,
) -> RemediationStepRecord:
    """Build a RemediationStepRecord with sensible defaults."""
    return RemediationStepRecord(
        id=record_id,
        remediation_id=remediation_id,
        step_index=step_index,
        mechanism=mechanism,
        success=success,
        detail=detail,
        pre_state_data=pre_state_data,
        pre_state_capturable=pre_state_capturable,
    )


# ── _execute_rollback tests ─────────────────────────────────────────────────


class TestExecuteRollbackSpecDerived:
    """Spec-derived tests for _execute_rollback.

    Spec: specs/orchestration/rollback.spec.md, Part A.
    """

    @pytest.fixture()
    def ssh(self):
        """Provide a mock SSH session."""
        return MagicMock()

    def test_ac1_reverse_order(self, ssh):
        """AC-1: Steps are rolled back in reverse order."""
        call_order = []

        def handler_0(ssh, pre_state):
            call_order.append(0)
            return True, "rolled back step 0"

        def handler_1(ssh, pre_state):
            call_order.append(1)
            return True, "rolled back step 1"

        def handler_2(ssh, pre_state):
            call_order.append(2)
            return True, "rolled back step 2"

        steps = [
            _make_step(
                step_index=0,
                mechanism="mech_0",
                pre_state=_make_pre_state(mechanism="mech_0"),
            ),
            _make_step(
                step_index=1,
                mechanism="mech_1",
                pre_state=_make_pre_state(mechanism="mech_1"),
            ),
            _make_step(
                step_index=2,
                mechanism="mech_2",
                pre_state=_make_pre_state(mechanism="mech_2"),
            ),
        ]

        mock_registry = {
            "mech_0": handler_0,
            "mech_1": handler_1,
            "mech_2": handler_2,
        }

        with patch("runner.handlers.rollback.ROLLBACK_HANDLERS", mock_registry):
            results = _execute_rollback(ssh, steps)

        # Handlers called in reverse order: 2, 1, 0
        assert call_order == [2, 1, 0]

        # Results in reverse order
        assert [r.step_index for r in results] == [2, 1, 0]
        assert all(r.success is True for r in results)

    def test_ac2_failed_steps_skipped(self, ssh):
        """AC-2: Failed remediation steps are skipped."""
        handler = MagicMock(return_value=(True, "ok"))

        step = _make_step(
            step_index=0,
            mechanism="config_set",
            success=False,
            pre_state=_make_pre_state(),
        )

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"config_set": handler}
        ):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].detail == "skipped"
        handler.assert_not_called()

    def test_ac3_no_pre_state_skipped(self, ssh):
        """AC-3: Steps with no pre_state are skipped."""
        handler = MagicMock(return_value=(True, "ok"))

        step = _make_step(step_index=0, mechanism="config_set", pre_state=None)

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"config_set": handler}
        ):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].detail == "skipped"
        handler.assert_not_called()

    def test_ac4_non_capturable_skipped(self, ssh):
        """AC-4: Steps with non-capturable pre_state are skipped."""
        handler = MagicMock(return_value=(True, "ok"))

        step = _make_step(
            step_index=0,
            mechanism="command_exec",
            pre_state=_make_pre_state(
                mechanism="command_exec", data={}, capturable=False
            ),
        )

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"command_exec": handler}
        ):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].detail == "skipped"
        handler.assert_not_called()

    def test_ac5_missing_handler(self, ssh):
        """AC-5: Unknown mechanism produces 'no handler' result."""
        step = _make_step(
            step_index=0,
            mechanism="unknown_mech",
            pre_state=_make_pre_state(mechanism="unknown_mech"),
        )

        with patch("runner.handlers.rollback.ROLLBACK_HANDLERS", {}):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].detail == "no handler"
        assert results[0].mechanism == "unknown_mech"

    def test_ac6_handler_exception_caught(self, ssh):
        """AC-6: Handler exception is caught and recorded."""

        def bad_handler(ssh, pre_state):
            raise ValueError("something broke")

        step = _make_step(
            step_index=0,
            mechanism="config_set",
            pre_state=_make_pre_state(),
        )

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"config_set": bad_handler}
        ):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is False
        assert "Exception" in results[0].detail
        assert "something broke" in results[0].detail

    def test_ac7_handler_success(self, ssh):
        """AC-7: Handler returning (True, detail) produces success result."""
        handler = MagicMock(return_value=(True, "Restored config"))

        step = _make_step(
            step_index=0,
            mechanism="config_set",
            pre_state=_make_pre_state(),
        )

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"config_set": handler}
        ):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].detail == "Restored config"
        assert results[0].step_index == 0
        assert results[0].mechanism == "config_set"

    def test_ac8_handler_failure(self, ssh):
        """AC-8: Handler returning (False, detail) produces failure result."""
        handler = MagicMock(return_value=(False, "Could not restore"))

        step = _make_step(
            step_index=0,
            mechanism="config_set",
            pre_state=_make_pre_state(),
        )

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"config_set": handler}
        ):
            results = _execute_rollback(ssh, [step])

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].detail == "Could not restore"

    def test_ac9_empty_input(self, ssh):
        """AC-9: Empty step_results list returns empty results."""
        results = _execute_rollback(ssh, [])

        assert results == []

    def test_ac15_all_steps_attempted_despite_exception(self, ssh):
        """AC-15: All steps are attempted even if one handler throws."""
        call_order = []

        def handler_a(ssh, pre_state):
            call_order.append("a")
            raise RuntimeError("boom")

        def handler_b(ssh, pre_state):
            call_order.append("b")
            return True, "ok"

        def handler_c(ssh, pre_state):
            call_order.append("c")
            return True, "ok"

        steps = [
            _make_step(
                step_index=0,
                mechanism="mech_a",
                pre_state=_make_pre_state(mechanism="mech_a"),
            ),
            _make_step(
                step_index=1,
                mechanism="mech_b",
                pre_state=_make_pre_state(mechanism="mech_b"),
            ),
            _make_step(
                step_index=2,
                mechanism="mech_c",
                pre_state=_make_pre_state(mechanism="mech_c"),
            ),
        ]

        mock_registry = {
            "mech_a": handler_a,
            "mech_b": handler_b,
            "mech_c": handler_c,
        }

        with patch("runner.handlers.rollback.ROLLBACK_HANDLERS", mock_registry):
            results = _execute_rollback(ssh, steps)

        # All three handlers called (reverse: c, b, a)
        assert call_order == ["c", "b", "a"]
        assert len(results) == 3

        # Step 2 (first in results): success
        assert results[0].step_index == 2
        assert results[0].success is True

        # Step 1 (second): success
        assert results[1].step_index == 1
        assert results[1].success is True

        # Step 0 (third): exception caught
        assert results[2].step_index == 0
        assert results[2].success is False
        assert "Exception" in results[2].detail

    def test_result_count_equals_input_count(self, ssh):
        """Constraint: One RollbackResult per input step."""
        handler = MagicMock(return_value=(True, "ok"))

        steps = [
            # Successful capturable step
            _make_step(
                step_index=0,
                mechanism="config_set",
                pre_state=_make_pre_state(),
            ),
            # Failed step (skipped)
            _make_step(step_index=1, mechanism="config_set", success=False),
            # No pre_state (skipped)
            _make_step(step_index=2, mechanism="config_set", pre_state=None),
            # Non-capturable (skipped)
            _make_step(
                step_index=3,
                mechanism="manual",
                pre_state=_make_pre_state(
                    mechanism="manual", data={}, capturable=False
                ),
            ),
        ]

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS",
            {"config_set": handler, "manual": handler},
        ):
            results = _execute_rollback(ssh, steps)

        assert len(results) == 4

    def test_handler_receives_pre_state(self, ssh):
        """Handler is called with (ssh, pre_state) arguments."""
        handler = MagicMock(return_value=(True, "ok"))
        ps = _make_pre_state(
            data={"path": "/etc/foo", "key": "A", "old_line": "A B", "existed": True}
        )

        step = _make_step(
            step_index=0,
            mechanism="config_set",
            pre_state=ps,
        )

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS", {"config_set": handler}
        ):
            _execute_rollback(ssh, [step])

        handler.assert_called_once_with(ssh, ps)

    def test_mixed_skip_conditions(self, ssh):
        """Multiple skip conditions in one run produce correct results."""
        handler = MagicMock(return_value=(True, "restored"))

        steps = [
            # Step 0: capturable success -> should execute
            _make_step(
                step_index=0,
                mechanism="config_set",
                pre_state=_make_pre_state(),
            ),
            # Step 1: failed -> skipped
            _make_step(
                step_index=1,
                mechanism="config_set",
                success=False,
                pre_state=_make_pre_state(),
            ),
            # Step 2: no pre_state -> skipped
            _make_step(step_index=2, mechanism="config_set", pre_state=None),
            # Step 3: non-capturable -> skipped
            _make_step(
                step_index=3,
                mechanism="command_exec",
                pre_state=_make_pre_state(
                    mechanism="command_exec", data={}, capturable=False
                ),
            ),
            # Step 4: capturable success -> should execute
            _make_step(
                step_index=4,
                mechanism="config_set",
                pre_state=_make_pre_state(),
            ),
        ]

        with patch(
            "runner.handlers.rollback.ROLLBACK_HANDLERS",
            {"config_set": handler, "command_exec": handler},
        ):
            results = _execute_rollback(ssh, steps)

        assert len(results) == 5
        # Reverse order: 4, 3, 2, 1, 0
        assert [r.step_index for r in results] == [4, 3, 2, 1, 0]

        # Step 4: success
        assert results[0].success is True
        assert results[0].detail == "restored"

        # Step 3: skipped (non-capturable)
        assert results[1].success is False
        assert results[1].detail == "skipped"

        # Step 2: skipped (no pre_state)
        assert results[2].success is False
        assert results[2].detail == "skipped"

        # Step 1: skipped (failed)
        assert results[3].success is False
        assert results[3].detail == "skipped"

        # Step 0: success
        assert results[4].success is True
        assert results[4].detail == "restored"

        # Handler called exactly twice (steps 4 and 0)
        assert handler.call_count == 2


# ── rollback_from_stored tests ──────────────────────────────────────────────


class TestRollbackFromStoredSpecDerived:
    """Spec-derived tests for rollback_from_stored.

    Spec: specs/orchestration/rollback.spec.md, Part B.
    """

    @pytest.fixture()
    def ssh(self):
        """Provide a mock SSH session."""
        return MagicMock()

    def test_ac10_capturable_reconstruction(self, ssh):
        """AC-10: Capturable record with data reconstructs PreState correctly."""
        pre_data = {
            "path": "/etc/test.conf",
            "key": "Foo",
            "old_line": "Foo bar",
            "existed": True,
        }

        record = _make_db_record(
            step_index=0,
            mechanism="config_set",
            success=True,
            pre_state_data=pre_data,
            pre_state_capturable=True,
        )

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = [RollbackResult(0, "config_set", True, "ok")]
            rollback_from_stored(ssh, [record])

            # Inspect the StepResult passed to _execute_rollback
            args = mock_exec.call_args
            step_results = args[0][1]
            assert len(step_results) == 1

            sr = step_results[0]
            assert sr.pre_state is not None
            assert sr.pre_state.mechanism == "config_set"
            assert sr.pre_state.data == pre_data
            assert sr.pre_state.capturable is True

    def test_ac11_non_capturable_reconstruction(self, ssh):
        """AC-11: Non-capturable record reconstructs PreState with empty data and capturable=False."""
        record = _make_db_record(
            step_index=0,
            mechanism="command_exec",
            success=True,
            pre_state_data=None,
            pre_state_capturable=False,
        )

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = []
            rollback_from_stored(ssh, [record])

            step_results = mock_exec.call_args[0][1]
            sr = step_results[0]
            assert sr.pre_state is not None
            assert sr.pre_state.mechanism == "command_exec"
            assert sr.pre_state.data == {}
            assert sr.pre_state.capturable is False

    def test_ac11_non_capturable_ignores_data(self, ssh):
        """AC-11: Non-capturable record with data still uses empty dict."""
        record = _make_db_record(
            step_index=0,
            mechanism="command_exec",
            success=True,
            pre_state_data={"some": "data"},
            pre_state_capturable=False,
        )

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = []
            rollback_from_stored(ssh, [record])

            step_results = mock_exec.call_args[0][1]
            sr = step_results[0]
            assert sr.pre_state is not None
            assert sr.pre_state.data == {}
            assert sr.pre_state.capturable is False

    def test_ac12_no_data_capturable_sets_none(self, ssh):
        """AC-12: Capturable record with no data reconstructs pre_state=None."""
        record = _make_db_record(
            step_index=0,
            mechanism="config_set",
            success=True,
            pre_state_data=None,
            pre_state_capturable=True,
        )

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = []
            rollback_from_stored(ssh, [record])

            step_results = mock_exec.call_args[0][1]
            sr = step_results[0]
            assert sr.pre_state is None

    def test_ac13_detail_fallback(self, ssh):
        """AC-13: None detail in DB record becomes empty string."""
        record = _make_db_record(
            step_index=0,
            mechanism="config_set",
            success=True,
            detail=None,
            pre_state_data={"path": "/etc/test.conf"},
            pre_state_capturable=True,
        )

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = []
            rollback_from_stored(ssh, [record])

            step_results = mock_exec.call_args[0][1]
            sr = step_results[0]
            assert sr.detail == ""

    def test_ac14_delegation(self, ssh):
        """AC-14: rollback_from_stored delegates to _execute_rollback and returns its result."""
        expected_results = [
            RollbackResult(0, "config_set", True, "Restored"),
            RollbackResult(1, "sysctl_set", False, "skipped"),
        ]

        record0 = _make_db_record(
            step_index=0,
            mechanism="config_set",
            success=True,
            pre_state_data={"path": "/etc/test.conf"},
            pre_state_capturable=True,
        )
        record1 = _make_db_record(
            record_id=2,
            step_index=1,
            mechanism="sysctl_set",
            success=False,
            pre_state_data=None,
            pre_state_capturable=True,
        )

        with patch(
            "runner._orchestration._execute_rollback",
            return_value=expected_results,
        ) as mock_exec:
            actual = rollback_from_stored(ssh, [record0, record1])

        assert actual is expected_results
        mock_exec.assert_called_once()
        # SSH session passed through
        assert mock_exec.call_args[0][0] is ssh

    def test_empty_steps(self, ssh):
        """Empty steps list delegates empty list and returns empty results."""
        with patch(
            "runner._orchestration._execute_rollback",
            return_value=[],
        ) as mock_exec:
            results = rollback_from_stored(ssh, [])

        assert results == []
        mock_exec.assert_called_once_with(ssh, [])

    def test_step_result_fields_populated(self, ssh):
        """All StepResult fields are populated correctly from DB records."""
        record = _make_db_record(
            step_index=3,
            mechanism="sysctl_set",
            success=True,
            detail="Set net.ipv4.ip_forward=0",
            pre_state_data={"key": "net.ipv4.ip_forward", "old_value": "1"},
            pre_state_capturable=True,
        )

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = []
            rollback_from_stored(ssh, [record])

            step_results = mock_exec.call_args[0][1]
            sr = step_results[0]
            assert sr.step_index == 3
            assert sr.mechanism == "sysctl_set"
            assert sr.success is True
            assert sr.detail == "Set net.ipv4.ip_forward=0"

    def test_multiple_records_all_reconstructed(self, ssh):
        """Multiple DB records are all reconstructed and passed through."""
        records = [
            _make_db_record(
                record_id=1,
                step_index=0,
                mechanism="config_set",
                success=True,
                pre_state_data={"path": "/etc/a"},
                pre_state_capturable=True,
            ),
            _make_db_record(
                record_id=2,
                step_index=1,
                mechanism="command_exec",
                success=True,
                pre_state_data=None,
                pre_state_capturable=False,
            ),
            _make_db_record(
                record_id=3,
                step_index=2,
                mechanism="sysctl_set",
                success=False,
                detail="failed to set",
                pre_state_data=None,
                pre_state_capturable=True,
            ),
        ]

        with patch("runner._orchestration._execute_rollback") as mock_exec:
            mock_exec.return_value = []
            rollback_from_stored(ssh, records)

            step_results = mock_exec.call_args[0][1]
            assert len(step_results) == 3

            # Record 0: capturable with data
            assert step_results[0].pre_state is not None
            assert step_results[0].pre_state.capturable is True
            assert step_results[0].pre_state.data == {"path": "/etc/a"}

            # Record 1: non-capturable
            assert step_results[1].pre_state is not None
            assert step_results[1].pre_state.capturable is False
            assert step_results[1].pre_state.data == {}

            # Record 2: capturable but no data
            assert step_results[2].pre_state is None
            assert step_results[2].success is False
