"""SpecDerived tests for command rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._command import _rollback_command_exec, _rollback_manual


class TestRollbackCommandSpecDerived:
    """Spec-derived tests for command rollback handlers.

    See specs/handlers/rollback/command.spec.yaml for specification.
    """

    def test_ac1_command_exec_always_returns_false(self, mock_ssh):
        """AC-1: _rollback_command_exec always returns (False, "Cannot rollback arbitrary commands")."""
        ssh = mock_ssh({})
        pre_state = PreState(mechanism="command_exec", data={}, capturable=False)
        ok, detail = _rollback_command_exec(ssh, pre_state)
        assert ok is False
        assert detail == "Cannot rollback arbitrary commands"

    def test_ac2_manual_always_returns_false(self, mock_ssh):
        """AC-2: _rollback_manual always returns (False, "Nothing to rollback")."""
        ssh = mock_ssh({})
        pre_state = PreState(mechanism="manual", data={}, capturable=False)
        ok, detail = _rollback_manual(ssh, pre_state)
        assert ok is False
        assert detail == "Nothing to rollback"

    def test_ac3_no_remote_commands(self, mock_ssh):
        """AC-3: Neither handler executes any remote commands (ssh and pre_state are unused)."""
        ssh = mock_ssh({})
        pre_state_cmd = PreState(mechanism="command_exec", data={}, capturable=False)
        pre_state_man = PreState(mechanism="manual", data={}, capturable=False)
        _rollback_command_exec(ssh, pre_state_cmd)
        _rollback_manual(ssh, pre_state_man)
        assert ssh.commands_run == []

    def test_ac4_registered_in_rollback_handlers(self):
        """AC-4: Both handlers are registered in ROLLBACK_HANDLERS for dispatch consistency."""
        from runner.handlers.rollback import ROLLBACK_HANDLERS

        assert "command_exec" in ROLLBACK_HANDLERS
        assert "manual" in ROLLBACK_HANDLERS
