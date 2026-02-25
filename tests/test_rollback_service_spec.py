"""SpecDerived tests for service rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._service import (
    _rollback_service_disabled,
    _rollback_service_enabled,
    _rollback_service_masked,
)
from runner.ssh import Result


class TestRollbackServiceSpecDerived:
    """Spec-derived tests for service rollback handlers.

    See specs/handlers/rollback/service.spec.yaml for specification.
    """

    def test_ac1_service_enabled_was_masked(self, mock_ssh):
        """AC-1: _rollback_service_enabled when was_enabled="masked": runs systemctl mask; returns (True, "Restored {name} to masked/{was_active}")."""
        ssh = mock_ssh({"systemctl": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="service_enabled",
            data={"name": "rpcbind", "was_enabled": "masked", "was_active": "inactive"},
        )
        ok, detail = _rollback_service_enabled(ssh, pre_state)
        assert ok is True
        assert detail == "Restored rpcbind to masked/inactive"
        assert any("systemctl mask" in cmd for cmd in ssh.commands_run)

    def test_ac2_service_enabled_was_disabled(self, mock_ssh):
        """AC-2: When was_enabled="disabled": runs systemctl disable; returns success."""
        ssh = mock_ssh({"systemctl": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="service_enabled",
            data={"name": "sshd", "was_enabled": "disabled", "was_active": "active"},
        )
        ok, detail = _rollback_service_enabled(ssh, pre_state)
        assert ok is True
        assert any("systemctl disable" in cmd for cmd in ssh.commands_run)

    def test_ac3_service_enabled_was_inactive(self, mock_ssh):
        """AC-3: When was_active is "inactive"/"failed"/"unknown": runs systemctl stop."""
        ssh = mock_ssh({"systemctl": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="service_enabled",
            data={"name": "sshd", "was_enabled": "enabled", "was_active": "inactive"},
        )
        ok, detail = _rollback_service_enabled(ssh, pre_state)
        assert ok is True
        assert any("systemctl stop" in cmd for cmd in ssh.commands_run)

    def test_ac4_service_disabled_was_enabled_and_active(self, mock_ssh):
        """AC-4: _rollback_service_disabled when was_enabled="enabled": runs enable; when was_active="active": runs start."""
        ssh = mock_ssh({"systemctl": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="service_disabled",
            data={
                "name": "firewalld",
                "was_enabled": "enabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_disabled(ssh, pre_state)
        assert ok is True
        assert any("systemctl enable" in cmd for cmd in ssh.commands_run)
        assert any("systemctl start" in cmd for cmd in ssh.commands_run)

    def test_ac5_service_masked_unmasks_then_enables_starts(self, mock_ssh):
        """AC-5: _rollback_service_masked: always unmasks first; then conditionally enables/starts."""
        ssh = mock_ssh({"systemctl": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="service_masked",
            data={
                "name": "firewalld",
                "was_enabled": "enabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_masked(ssh, pre_state)
        assert ok is True
        assert ssh.commands_run[0].startswith("systemctl unmask")
        assert any("systemctl enable" in cmd for cmd in ssh.commands_run)
        assert any("systemctl start" in cmd for cmd in ssh.commands_run)

    def test_ac6_service_enabled_errors_collected(self, mock_ssh):
        """AC-6: All handlers collect errors; if any fail, return (False, "Failed to restore {name}: {errors}")."""
        ssh = mock_ssh(
            {
                "systemctl mask": Result(exit_code=1, stdout="", stderr="mask failed"),
                "systemctl stop": Result(exit_code=1, stdout="", stderr="stop failed"),
            }
        )
        pre_state = PreState(
            mechanism="service_enabled",
            data={"name": "rpcbind", "was_enabled": "masked", "was_active": "inactive"},
        )
        ok, detail = _rollback_service_enabled(ssh, pre_state)
        assert ok is False
        assert "Failed to restore rpcbind" in detail

    def test_ac7_service_disabled_all_succeed(self, mock_ssh):
        """AC-7: All return (True, "Restored {name} to {was_enabled}/{was_active}") when all succeed."""
        ssh = mock_ssh({"systemctl": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="service_disabled",
            data={
                "name": "firewalld",
                "was_enabled": "enabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_disabled(ssh, pre_state)
        assert ok is True
        assert detail == "Restored firewalld to enabled/active"
