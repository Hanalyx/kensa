"""SpecDerived tests for security capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._security import (
    _capture_audit_rule_set,
    _capture_pam_module_configure,
    _capture_selinux_boolean_set,
)
from runner.ssh import Result


class TestCaptureSecuritySpecDerived:
    """Spec-derived tests for security capture handlers.

    See specs/handlers/capture/security.spec.yaml for specification.
    """

    def test_ac1_selinux_boolean_captures_value(self, mock_ssh):
        """AC-1: _capture_selinux_boolean_set captures old_value as bool (True for 'on', False for 'off', None if fails); data has name, old_value, persistent."""
        ssh_on = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0, stdout="httpd_can_network_connect --> on\n", stderr=""
                ),
            }
        )
        result = _capture_selinux_boolean_set(
            ssh_on, {"name": "httpd_can_network_connect"}
        )
        assert isinstance(result, PreState)
        assert result.mechanism == "selinux_boolean_set"
        assert result.data["name"] == "httpd_can_network_connect"
        assert result.data["old_value"] is True
        assert result.data["persistent"] is True

        ssh_off = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0, stdout="httpd_can_network_connect --> off\n", stderr=""
                ),
            }
        )
        result2 = _capture_selinux_boolean_set(
            ssh_off, {"name": "httpd_can_network_connect"}
        )
        assert result2.data["old_value"] is False

        ssh_fail = mock_ssh(
            {
                "getsebool": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        result3 = _capture_selinux_boolean_set(ssh_fail, {"name": "bad_bool"})
        assert result3.data["old_value"] is None

    def test_ac2_selinux_parses_getsebool_output(self, mock_ssh):
        """AC-2: Parses getsebool output by splitting on whitespace and checking if last element is 'on'."""
        ssh = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0, stdout="ftp_home_dir --> on\n", stderr=""
                ),
            }
        )
        result = _capture_selinux_boolean_set(ssh, {"name": "ftp_home_dir"})
        # The parser splits on whitespace and checks parts[-1] == "on"
        assert result.data["old_value"] is True

        ssh2 = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0, stdout="ftp_home_dir --> off\n", stderr=""
                ),
            }
        )
        result2 = _capture_selinux_boolean_set(ssh2, {"name": "ftp_home_dir"})
        assert result2.data["old_value"] is False

    def test_ac3_audit_rule_captures_state(self, mock_ssh):
        """AC-3: _capture_audit_rule_set captures rule_existed, persist_file, old_persist_content, persist_existed."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/passwd -p wa -k identity\n",
                    stderr="",
                ),
                "cat": Result(
                    exit_code=0, stdout="-w /etc/passwd -p wa -k identity\n", stderr=""
                ),
            }
        )
        r = {
            "rule": "-w /etc/passwd -p wa -k identity",
            "persist_file": "/etc/audit/rules.d/99-kensa.rules",
        }
        result = _capture_audit_rule_set(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "audit_rule_set"
        assert result.data["rule_existed"] is True
        assert result.data["persist_file"] == "/etc/audit/rules.d/99-kensa.rules"
        assert (
            result.data["old_persist_content"] == "-w /etc/passwd -p wa -k identity\n"
        )
        assert result.data["persist_existed"] is True

    def test_ac4_audit_checks_running_rules(self, mock_ssh):
        """AC-4: Checks running rules via auditctl -l and string match."""
        ssh_present = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/shadow -p wa -k shadow\n",
                    stderr="",
                ),
                "cat": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"rule": "-w /etc/shadow -p wa -k shadow"}
        result = _capture_audit_rule_set(ssh_present, r)
        assert result.data["rule_existed"] is True

        ssh_absent = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/passwd -p wa -k identity\n",
                    stderr="",
                ),
                "cat": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r2 = {"rule": "-w /etc/shadow -p wa -k shadow"}
        result2 = _capture_audit_rule_set(ssh_absent, r2)
        assert result2.data["rule_existed"] is False

    def test_ac5_pam_captures_content(self, mock_ssh):
        """AC-5: _capture_pam_module_configure captures PAM file content, existed flag, authselect_profile."""
        ssh = mock_ssh(
            {
                "cat": Result(
                    exit_code=0,
                    stdout="auth required pam_faillock.so\n",
                    stderr="",
                ),
                "authselect current": Result(
                    exit_code=0,
                    stdout="sssd with-faillock\n",
                    stderr="",
                ),
            }
        )
        r = {"service": "system-auth"}
        result = _capture_pam_module_configure(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "pam_module_configure"
        assert result.data["service"] == "system-auth"
        assert result.data["pam_file"] == "/etc/pam.d/system-auth"
        assert result.data["existed"] is True
        assert result.data["old_content"] == "auth required pam_faillock.so\n"
        assert result.data["authselect_profile"] == "sssd with-faillock"

    def test_ac6_pam_file_missing(self, mock_ssh):
        """AC-6: When PAM file does not exist: existed=False and old_content=None."""
        ssh = mock_ssh(
            {
                "cat": Result(exit_code=1, stdout="", stderr="No such file"),
                "authselect current": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"service": "nonexistent"}
        result = _capture_pam_module_configure(ssh, r)
        assert result.data["existed"] is False
        assert result.data["old_content"] is None
        assert result.data["authselect_profile"] is None

    def test_ac7_all_security_capturable(self, mock_ssh):
        """AC-7: All security capture handlers return PreState with capturable=True."""
        ssh = mock_ssh(
            {
                "getsebool": Result(exit_code=1, stdout="", stderr=""),
                "auditctl -l": Result(exit_code=1, stdout="", stderr=""),
                "cat": Result(exit_code=1, stdout="", stderr=""),
                "authselect current": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        assert _capture_selinux_boolean_set(ssh, {"name": "x"}).capturable is True
        assert _capture_audit_rule_set(ssh, {"rule": "x"}).capturable is True
        assert _capture_pam_module_configure(ssh, {"service": "x"}).capturable is True
