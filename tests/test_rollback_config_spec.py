"""SpecDerived tests for config rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._config import (
    _rollback_config_block,
    _rollback_config_remove,
    _rollback_config_set,
    _rollback_config_set_dropin,
)
from runner.ssh import Result


class TestRollbackConfigSpecDerived:
    """Spec-derived tests for config rollback handlers.

    See specs/handlers/rollback/config.spec.yaml for specification.
    """

    def test_ac1_config_set_key_existed(self, mock_ssh):
        """AC-1: _rollback_config_set when key existed: uses sed to replace; returns (True, "Restored {key} in {path}")."""
        ssh = mock_ssh({"sed": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_set",
            data={
                "path": "/etc/ssh/sshd_config",
                "key": "PermitRootLogin",
                "existed": True,
                "old_line": "PermitRootLogin yes",
            },
        )
        ok, detail = _rollback_config_set(ssh, pre_state)
        assert ok is True
        assert detail == "Restored PermitRootLogin in /etc/ssh/sshd_config"
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_ac2_config_set_key_did_not_exist(self, mock_ssh):
        """AC-2: _rollback_config_set when key did not exist: sed to delete; returns (True, "Restored {key} in {path}")."""
        ssh = mock_ssh({"sed": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_set",
            data={
                "path": "/etc/ssh/sshd_config",
                "key": "PermitRootLogin",
                "existed": False,
                "old_line": None,
            },
        )
        ok, detail = _rollback_config_set(ssh, pre_state)
        assert ok is True
        assert detail == "Restored PermitRootLogin in /etc/ssh/sshd_config"
        assert any("sed" in cmd and "/d" in cmd for cmd in ssh.commands_run)

    def test_ac3_config_set_sed_fails(self, mock_ssh):
        """AC-3: _rollback_config_set when sed fails: returns (False, "Failed to restore ...")."""
        ssh = mock_ssh(
            {"sed": Result(exit_code=1, stdout="", stderr="permission denied")}
        )
        pre_state = PreState(
            mechanism="config_set",
            data={
                "path": "/etc/ssh/sshd_config",
                "key": "PermitRootLogin",
                "existed": True,
                "old_line": "PermitRootLogin yes",
            },
        )
        ok, detail = _rollback_config_set(ssh, pre_state)
        assert ok is False
        assert "Failed to restore" in detail

    def test_ac4_config_set_dropin_file_did_not_exist(self, mock_ssh):
        """AC-4: _rollback_config_set_dropin when file did not exist before: rm -f; returns (True, "Removed {path}")."""
        ssh = mock_ssh({"rm -f": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_set_dropin",
            data={
                "path": "/etc/ssh/sshd_config.d/00-kensa.conf",
                "existed": False,
                "old_content": None,
            },
        )
        ok, detail = _rollback_config_set_dropin(ssh, pre_state)
        assert ok is True
        assert detail == "Removed /etc/ssh/sshd_config.d/00-kensa.conf"

    def test_ac5_config_set_dropin_file_existed(self, mock_ssh):
        """AC-5: _rollback_config_set_dropin when file existed: writes old_content back; returns (True, "Restored {path}")."""
        ssh = mock_ssh({"printf": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_set_dropin",
            data={
                "path": "/etc/ssh/sshd_config.d/00-kensa.conf",
                "existed": True,
                "old_content": "PermitRootLogin yes\n",
            },
        )
        ok, detail = _rollback_config_set_dropin(ssh, pre_state)
        assert ok is True
        assert detail == "Restored /etc/ssh/sshd_config.d/00-kensa.conf"

    def test_ac6_config_remove_lines_existed(self, mock_ssh):
        """AC-6: _rollback_config_remove when lines existed: appends each line back; returns (True, "Restored removed lines in {path}")."""
        ssh = mock_ssh({"echo": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_remove",
            data={
                "path": "/etc/sysctl.conf",
                "existed": True,
                "old_lines": "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1",
            },
        )
        ok, detail = _rollback_config_remove(ssh, pre_state)
        assert ok is True
        assert detail == "Restored removed lines in /etc/sysctl.conf"

    def test_ac7_config_remove_no_lines_existed(self, mock_ssh):
        """AC-7: _rollback_config_remove when no lines existed: returns (True, "No lines to restore in {path}")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="config_remove",
            data={
                "path": "/etc/sysctl.conf",
                "existed": False,
                "old_lines": None,
            },
        )
        ok, detail = _rollback_config_remove(ssh, pre_state)
        assert ok is True
        assert detail == "No lines to restore in /etc/sysctl.conf"

    def test_ac8_config_block_file_did_not_exist(self, mock_ssh):
        """AC-8: _rollback_config_block when file did not exist: removes; returns (True, "Removed {path}")."""
        ssh = mock_ssh({"rm -f": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_block",
            data={
                "path": "/etc/crypto-policies/back-ends/test.config",
                "existed": False,
                "old_content": None,
            },
        )
        ok, detail = _rollback_config_block(ssh, pre_state)
        assert ok is True
        assert detail == "Removed /etc/crypto-policies/back-ends/test.config"

    def test_ac9_config_block_file_existed(self, mock_ssh):
        """AC-9: _rollback_config_block when file existed: writes old_content back; returns (True, "Restored {path}")."""
        ssh = mock_ssh({"printf": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="config_block",
            data={
                "path": "/etc/crypto-policies/back-ends/test.config",
                "existed": True,
                "old_content": "original content\n",
            },
        )
        ok, detail = _rollback_config_block(ssh, pre_state)
        assert ok is True
        assert detail == "Restored /etc/crypto-policies/back-ends/test.config"

    def test_ac10_service_action_triggered(self, mock_ssh):
        """AC-10: All handlers trigger service_action when captured data contains reload or restart keys."""
        ssh = mock_ssh(
            {
                "sed": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="config_set",
            data={
                "path": "/etc/ssh/sshd_config",
                "key": "PermitRootLogin",
                "existed": True,
                "old_line": "PermitRootLogin yes",
                "reload": "sshd",
            },
        )
        ok, detail = _rollback_config_set(ssh, pre_state)
        assert ok is True
        assert any("systemctl" in cmd for cmd in ssh.commands_run)
