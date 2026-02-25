"""SpecDerived tests for service capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._service import (
    _capture_service_disabled,
    _capture_service_enabled,
    _capture_service_masked,
)
from runner.ssh import Result


class TestCaptureServiceSpecDerived:
    """Spec-derived tests for service capture handlers.

    See specs/handlers/capture/service.spec.yaml for specification.
    """

    def test_ac1_service_enabled_captures_state(self, mock_ssh):
        """AC-1: _capture_service_enabled captures was_enabled and was_active; data has name, was_enabled, was_active."""
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="enabled\n", stderr=""
                ),
                "systemctl is-active": Result(
                    exit_code=0, stdout="active\n", stderr=""
                ),
            }
        )
        result = _capture_service_enabled(ssh, {"name": "sshd"})
        assert isinstance(result, PreState)
        assert result.mechanism == "service_enabled"
        assert result.data["name"] == "sshd"
        assert result.data["was_enabled"] == "enabled"
        assert result.data["was_active"] == "active"

    def test_ac2_service_disabled_captures_state(self, mock_ssh):
        """AC-2: _capture_service_disabled captures same fields."""
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="enabled\n", stderr=""
                ),
                "systemctl is-active": Result(
                    exit_code=0, stdout="active\n", stderr=""
                ),
            }
        )
        result = _capture_service_disabled(ssh, {"name": "cups"})
        assert isinstance(result, PreState)
        assert result.mechanism == "service_disabled"
        assert result.data["name"] == "cups"
        assert result.data["was_enabled"] == "enabled"
        assert result.data["was_active"] == "active"

    def test_ac3_service_masked_captures_state(self, mock_ssh):
        """AC-3: _capture_service_masked captures same fields."""
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="disabled\n", stderr=""
                ),
                "systemctl is-active": Result(
                    exit_code=3, stdout="inactive\n", stderr=""
                ),
            }
        )
        result = _capture_service_masked(ssh, {"name": "rpcbind"})
        assert isinstance(result, PreState)
        assert result.mechanism == "service_masked"
        assert result.data["name"] == "rpcbind"
        assert result.data["was_enabled"] == "disabled"
        # is-active exit code 3 means inactive — not ok
        assert result.data["was_active"] == "unknown"

    def test_ac4_enabled_fails_returns_unknown(self, mock_ssh):
        """AC-4: When systemctl is-enabled fails, was_enabled is "unknown"."""
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(exit_code=1, stdout="", stderr=""),
                "systemctl is-active": Result(
                    exit_code=0, stdout="active\n", stderr=""
                ),
            }
        )
        result = _capture_service_enabled(ssh, {"name": "sshd"})
        assert result.data["was_enabled"] == "unknown"

    def test_ac5_active_fails_returns_unknown(self, mock_ssh):
        """AC-5: When systemctl is-active fails, was_active is "unknown"."""
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="enabled\n", stderr=""
                ),
                "systemctl is-active": Result(
                    exit_code=3, stdout="inactive\n", stderr=""
                ),
            }
        )
        result = _capture_service_enabled(ssh, {"name": "sshd"})
        assert result.data["was_active"] == "unknown"

    def test_ac6_all_service_capturable(self, mock_ssh):
        """AC-6: All service capture handlers return PreState with capturable=True."""
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(exit_code=1, stdout="", stderr=""),
                "systemctl is-active": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        assert _capture_service_enabled(ssh, {"name": "x"}).capturable is True
        assert _capture_service_disabled(ssh, {"name": "x"}).capturable is True
        assert _capture_service_masked(ssh, {"name": "x"}).capturable is True

    def test_ac7_uses_shell_quote(self, mock_ssh):
        """AC-7: All handlers use shell_util.quote for safe service name interpolation."""
        # Use a name with shell-special characters to verify quoting
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(exit_code=1, stdout="", stderr=""),
                "systemctl is-active": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        _capture_service_enabled(ssh, {"name": "my service"})
        for cmd in ssh.commands_run:
            assert "'my service'" in cmd
