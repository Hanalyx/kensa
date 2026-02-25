"""SpecDerived tests for file rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._file import (
    _rollback_file_absent,
    _rollback_file_content,
    _rollback_file_permissions,
)
from runner.ssh import Result


class TestRollbackFileSpecDerived:
    """Spec-derived tests for file rollback handlers.

    See specs/handlers/rollback/file.spec.yaml for specification.
    """

    def test_ac1_file_permissions_restores_entries(self, mock_ssh):
        """AC-1: _rollback_file_permissions iterates entries, runs chown and chmod; returns (True, "Restored permissions on N file(s)")."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="file_permissions",
            data={
                "entries": [
                    {
                        "path": "/etc/passwd",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                    },
                    {
                        "path": "/etc/shadow",
                        "owner": "root",
                        "group": "shadow",
                        "mode": "0640",
                    },
                ]
            },
        )
        ok, detail = _rollback_file_permissions(ssh, pre_state)
        assert ok is True
        assert detail == "Restored permissions on 2 file(s)"
        chown_cmds = [c for c in ssh.commands_run if "chown" in c]
        chmod_cmds = [c for c in ssh.commands_run if "chmod" in c]
        assert len(chown_cmds) == 2
        assert len(chmod_cmds) == 2

    def test_ac2_file_permissions_empty_entries(self, mock_ssh):
        """AC-2: Empty entries list returns (False, "No file entries to restore")."""
        ssh = mock_ssh({})
        pre_state = PreState(mechanism="file_permissions", data={"entries": []})
        ok, detail = _rollback_file_permissions(ssh, pre_state)
        assert ok is False
        assert detail == "No file entries to restore"

    def test_ac3_file_permissions_chown_fails(self, mock_ssh):
        """AC-3: When chown/chmod fails: returns (False, detail listing failures)."""
        ssh = mock_ssh(
            {
                "chown": Result(
                    exit_code=1, stdout="", stderr="operation not permitted"
                ),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="file_permissions",
            data={
                "entries": [
                    {
                        "path": "/etc/passwd",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                    },
                ]
            },
        )
        ok, detail = _rollback_file_permissions(ssh, pre_state)
        assert ok is False
        assert "Failed to restore permissions" in detail

    def test_ac4_file_content_did_not_exist(self, mock_ssh):
        """AC-4: _rollback_file_content when file didn't exist before: rm -f; returns (True, "Removed {path}")."""
        ssh = mock_ssh({"rm -f": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="file_content",
            data={
                "path": "/etc/issue.net",
                "existed": False,
                "old_content": None,
                "old_owner": None,
                "old_group": None,
                "old_mode": None,
            },
        )
        ok, detail = _rollback_file_content(ssh, pre_state)
        assert ok is True
        assert detail == "Removed /etc/issue.net"

    def test_ac5_file_content_existed(self, mock_ssh):
        """AC-5: _rollback_file_content when file existed: writes content, restores owner/group/mode; returns (True, "Restored {path}")."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="file_content",
            data={
                "path": "/etc/issue.net",
                "existed": True,
                "old_content": "Old banner\n",
                "old_owner": "root",
                "old_group": "root",
                "old_mode": "0644",
            },
        )
        ok, detail = _rollback_file_content(ssh, pre_state)
        assert ok is True
        assert detail == "Restored /etc/issue.net"

    def test_ac6_file_absent_already_absent(self, mock_ssh):
        """AC-6: _rollback_file_absent when already absent: returns (True, "{path} was already absent, nothing to restore")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="file_absent",
            data={
                "path": "/etc/hosts.equiv",
                "existed": False,
                "old_content": None,
                "old_owner": None,
                "old_group": None,
                "old_mode": None,
            },
        )
        ok, detail = _rollback_file_absent(ssh, pre_state)
        assert ok is True
        assert detail == "/etc/hosts.equiv was already absent, nothing to restore"

    def test_ac7_file_absent_content_not_captured(self, mock_ssh):
        """AC-7: _rollback_file_absent when existed but content not captured: returns (False, "Cannot restore {path}: content not captured")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="file_absent",
            data={
                "path": "/etc/hosts.equiv",
                "existed": True,
                "old_content": None,
                "old_owner": "root",
                "old_group": "root",
                "old_mode": "0644",
            },
        )
        ok, detail = _rollback_file_absent(ssh, pre_state)
        assert ok is False
        assert detail == "Cannot restore /etc/hosts.equiv: content not captured"

    def test_ac8_file_absent_content_captured(self, mock_ssh):
        """AC-8: _rollback_file_absent when existed and content captured: writes content, restores metadata; returns (True, "Restored {path}")."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="file_absent",
            data={
                "path": "/etc/hosts.equiv",
                "existed": True,
                "old_content": "some content\n",
                "old_owner": "root",
                "old_group": "root",
                "old_mode": "0644",
            },
        )
        ok, detail = _rollback_file_absent(ssh, pre_state)
        assert ok is True
        assert detail == "Restored /etc/hosts.equiv"
