"""SpecDerived tests for command capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._command import _capture_command_exec, _capture_manual


class TestCaptureCommandSpecDerived:
    """Spec-derived tests for command capture handlers.

    See specs/handlers/capture/command.spec.yaml for specification.
    """

    def test_ac1_command_exec_returns_prestate(self, mock_ssh):
        """AC-1: _capture_command_exec returns PreState with mechanism="command_exec", capturable=False, and data containing a note about arbitrary command."""
        ssh = mock_ssh({})
        result = _capture_command_exec(ssh, {"run": "echo hello"})
        assert isinstance(result, PreState)
        assert result.mechanism == "command_exec"
        assert result.capturable is False
        assert "note" in result.data
        assert "arbitrary command" in result.data["note"]

    def test_ac2_manual_returns_prestate(self, mock_ssh):
        """AC-2: _capture_manual returns PreState with mechanism="manual", capturable=False, and empty data dict."""
        ssh = mock_ssh({})
        result = _capture_manual(ssh, {"note": "do something"})
        assert isinstance(result, PreState)
        assert result.mechanism == "manual"
        assert result.capturable is False
        assert result.data == {}

    def test_ac3_no_remote_commands(self, mock_ssh):
        """AC-3: Neither handler executes any remote commands (ssh parameter is unused)."""
        ssh = mock_ssh({})
        _capture_command_exec(ssh, {"run": "echo hello"})
        _capture_manual(ssh, {"note": "manual step"})
        assert ssh.commands_run == []

    def test_ac4_registered_in_capture_handlers(self):
        """AC-4: Both handlers are registered in CAPTURE_HANDLERS for dispatch consistency."""
        from runner.handlers.capture import CAPTURE_HANDLERS

        assert "command_exec" in CAPTURE_HANDLERS
        assert "manual" in CAPTURE_HANDLERS
