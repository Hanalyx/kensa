"""SpecDerived tests for security rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._security import (
    _rollback_audit_rule_set,
    _rollback_pam_module_configure,
    _rollback_selinux_boolean_set,
)
from runner.ssh import Result


class TestRollbackSecuritySpecDerived:
    """Spec-derived tests for security rollback handlers.

    See specs/handlers/rollback/security.spec.yaml for specification.
    """

    def test_ac1_selinux_boolean_old_value_present(self, mock_ssh):
        """AC-1: _rollback_selinux_boolean_set when old_value not None: runs setsebool; returns (True, "Restored {name} = {value}")."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="selinux_boolean_set",
            data={
                "name": "httpd_can_network_connect",
                "old_value": True,
                "persistent": True,
            },
        )
        ok, detail = _rollback_selinux_boolean_set(ssh, pre_state)
        assert ok is True
        assert detail == "Restored httpd_can_network_connect = on"
        assert any("setsebool" in cmd for cmd in ssh.commands_run)

    def test_ac2_selinux_boolean_old_value_none(self, mock_ssh):
        """AC-2: When old_value is None: returns (False, "{name}: could not determine previous value")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="selinux_boolean_set",
            data={
                "name": "httpd_can_network_connect",
                "old_value": None,
                "persistent": True,
            },
        )
        ok, detail = _rollback_selinux_boolean_set(ssh, pre_state)
        assert ok is False
        assert detail == "httpd_can_network_connect: could not determine previous value"

    def test_ac3_selinux_boolean_timeout(self, mock_ssh):
        """AC-3: Uses 60-second timeout for setsebool -P."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="selinux_boolean_set",
            data={
                "name": "httpd_can_network_connect",
                "old_value": False,
                "persistent": True,
            },
        )
        _rollback_selinux_boolean_set(ssh, pre_state)
        assert any("setsebool" in cmd and "-P" in cmd for cmd in ssh.commands_run)

    def test_ac4_audit_rule_already_existed(self, mock_ssh):
        """AC-4: _rollback_audit_rule_set when rule already existed: returns (True, "Rule already existed, nothing to rollback")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="audit_rule_set",
            data={
                "rule": "-a always,exit -F arch=b64 -S open",
                "persist_file": "/etc/audit/rules.d/kensa.rules",
                "rule_existed": True,
                "persist_existed": True,
                "old_persist_content": None,
            },
        )
        ok, detail = _rollback_audit_rule_set(ssh, pre_state)
        assert ok is True
        assert detail == "Rule already existed, nothing to rollback"

    def test_ac5_audit_rule_newly_added(self, mock_ssh):
        """AC-5: When rule was newly added: removes from running config (converts -a to -d, -w to -W); restores persist file."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="audit_rule_set",
            data={
                "rule": "-a always,exit -F arch=b64 -S open",
                "persist_file": "/etc/audit/rules.d/kensa.rules",
                "rule_existed": False,
                "persist_existed": False,
                "old_persist_content": None,
            },
        )
        ok, detail = _rollback_audit_rule_set(ssh, pre_state)
        assert ok is True
        assert detail == "Removed audit rule"
        auditctl_cmds = [c for c in ssh.commands_run if "auditctl" in c]
        assert len(auditctl_cmds) == 1
        assert "-d" in auditctl_cmds[0]

    def test_ac5_audit_rule_watch_conversion(self, mock_ssh):
        """AC-5: Watch rules convert -w to -W for deletion."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="audit_rule_set",
            data={
                "rule": "-w /etc/passwd -p wa -k identity",
                "persist_file": "/etc/audit/rules.d/kensa.rules",
                "rule_existed": False,
                "persist_existed": True,
                "old_persist_content": "# old rules\n",
            },
        )
        ok, detail = _rollback_audit_rule_set(ssh, pre_state)
        assert ok is True
        auditctl_cmds = [c for c in ssh.commands_run if "auditctl" in c]
        assert any("-W" in c for c in auditctl_cmds)

    def test_ac6_pam_file_did_not_exist(self, mock_ssh):
        """AC-6: _rollback_pam_module_configure when file didn't exist: removes PAM file; returns (True, "Removed {pam_file}")."""
        ssh = mock_ssh({"rm -f": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="pam_module_configure",
            data={
                "pam_file": "/etc/pam.d/system-auth",
                "service": "system-auth",
                "existed": False,
                "old_content": None,
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, pre_state)
        assert ok is True
        assert detail == "Removed /etc/pam.d/system-auth"

    def test_ac7_pam_file_existed_content_none(self, mock_ssh):
        """AC-7: When file existed but content is None: returns (False, "Cannot restore {pam_file}: content not captured")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="pam_module_configure",
            data={
                "pam_file": "/etc/pam.d/system-auth",
                "service": "system-auth",
                "existed": True,
                "old_content": None,
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, pre_state)
        assert ok is False
        assert detail == "Cannot restore /etc/pam.d/system-auth: content not captured"

    def test_ac8_pam_file_existed_content_captured(self, mock_ssh):
        """AC-8: When file existed and content captured: writes back; returns (True, "Restored {service} PAM config")."""
        ssh = mock_ssh({"printf": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="pam_module_configure",
            data={
                "pam_file": "/etc/pam.d/system-auth",
                "service": "system-auth",
                "existed": True,
                "old_content": "auth required pam_unix.so\n",
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, pre_state)
        assert ok is True
        assert detail == "Restored system-auth PAM config"
