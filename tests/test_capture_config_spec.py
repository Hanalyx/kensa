"""SpecDerived tests for config capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._config import (
    _capture_config_block,
    _capture_config_remove,
    _capture_config_set,
    _capture_config_set_dropin,
)
from runner.ssh import Result


class TestCaptureConfigSpecDerived:
    """Spec-derived tests for config capture handlers.

    See specs/handlers/capture/config.spec.yaml for specification.
    """

    def test_ac1_config_set_captures_current_line(self, mock_ssh):
        """AC-1: _capture_config_set captures the current config line; data contains path, key, old_line (str or None), existed (bool), and optional reload/restart."""
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="PermitRootLogin no\n", stderr=""),
            }
        )
        r = {
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "reload": "sshd",
        }
        result = _capture_config_set(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "config_set"
        assert result.data["path"] == "/etc/ssh/sshd_config"
        assert result.data["key"] == "PermitRootLogin"
        assert result.data["old_line"] == "PermitRootLogin no"
        assert result.data["existed"] is True
        assert result.data["reload"] == "sshd"

    def test_ac2_config_set_key_missing(self, mock_ssh):
        """AC-2: _capture_config_set when key does not exist: old_line is None and existed is False."""
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"path": "/etc/ssh/sshd_config", "key": "NonExistent"}
        result = _capture_config_set(ssh, r)
        assert result.data["old_line"] is None
        assert result.data["existed"] is False

    def test_ac3_config_set_dropin_captures_content(self, mock_ssh):
        """AC-3: _capture_config_set_dropin captures drop-in file content; data contains path (full), old_content (str or None), existed (bool), and optional reload/restart."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="PermitRootLogin no\n", stderr=""),
            }
        )
        r = {
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "reload": "sshd",
        }
        result = _capture_config_set_dropin(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "config_set_dropin"
        assert result.data["path"] == "/etc/ssh/sshd_config.d/00-kensa.conf"
        assert result.data["old_content"] == "PermitRootLogin no\n"
        assert result.data["existed"] is True
        assert result.data["reload"] == "sshd"

    def test_ac4_config_set_dropin_file_missing(self, mock_ssh):
        """AC-4: _capture_config_set_dropin when file does not exist: old_content is None and existed is False."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"dir": "/etc/ssh/sshd_config.d", "file": "00-kensa.conf"}
        result = _capture_config_set_dropin(ssh, r)
        assert result.data["old_content"] is None
        assert result.data["existed"] is False

    def test_ac5_config_remove_captures_lines(self, mock_ssh):
        """AC-5: _capture_config_remove captures all lines matching the key pattern; data contains path, key, old_lines (str or None), existed (bool), and optional reload/restart."""
        ssh = mock_ssh(
            {
                "grep '^ *PermitRootLogin'": Result(
                    exit_code=0, stdout="PermitRootLogin yes\n", stderr=""
                ),
            }
        )
        r = {
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "restart": "sshd",
        }
        result = _capture_config_remove(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "config_remove"
        assert result.data["path"] == "/etc/ssh/sshd_config"
        assert result.data["key"] == "PermitRootLogin"
        assert result.data["old_lines"] == "PermitRootLogin yes"
        assert result.data["existed"] is True
        assert result.data["restart"] == "sshd"

    def test_ac6_config_block_captures_file(self, mock_ssh):
        """AC-6: _capture_config_block captures entire file content before block insertion; data contains path, existed, old_content, block_existed, marker, and optional reload/restart."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="existing content\n", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        r = {
            "path": "/etc/issue",
            "marker": "# KENSA MANAGED BLOCK",
            "reload": "sshd",
        }
        result = _capture_config_block(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "config_block"
        assert result.data["path"] == "/etc/issue"
        assert result.data["existed"] is True
        assert result.data["old_content"] == "existing content\n"
        assert result.data["block_existed"] is True
        assert result.data["marker"] == "# KENSA MANAGED BLOCK"
        assert result.data["reload"] == "sshd"

    def test_ac7_all_config_capturable(self, mock_ssh):
        """AC-7: All config capture handlers return PreState with capturable=True."""
        ssh_set = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        ssh_dropin = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        ssh_remove = mock_ssh(
            {
                "grep '^ *Key'": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        ssh_block = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
            }
        )

        r_set = {"path": "/etc/f.conf", "key": "Key"}
        r_dropin = {"dir": "/etc/d", "file": "f.conf"}
        r_remove = {"path": "/etc/f.conf", "key": "Key"}
        r_block = {"path": "/etc/f.conf"}

        assert _capture_config_set(ssh_set, r_set).capturable is True
        assert _capture_config_set_dropin(ssh_dropin, r_dropin).capturable is True
        assert _capture_config_remove(ssh_remove, r_remove).capturable is True
        assert _capture_config_block(ssh_block, r_block).capturable is True

    def test_ac8_reload_restart_preserved(self, mock_ssh):
        """AC-8: All handlers preserve reload/restart keys from remediation dict into captured PreState data."""
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=1, stdout="", stderr=""),
                "test -f": Result(exit_code=1, stdout="", stderr=""),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
            }
        )

        r_with_reload = {"path": "/etc/f.conf", "key": "K", "reload": "myservice"}
        result_set = _capture_config_set(ssh, r_with_reload)
        assert result_set.data["reload"] == "myservice"

        r_with_restart = {"dir": "/etc/d", "file": "f.conf", "restart": "myservice"}
        result_dropin = _capture_config_set_dropin(ssh, r_with_restart)
        assert result_dropin.data["restart"] == "myservice"

        # Without reload/restart, they should be None
        r_no_service = {"path": "/etc/f.conf", "key": "K"}
        result_no = _capture_config_set(ssh, r_no_service)
        assert result_no.data["reload"] is None
        assert result_no.data["restart"] is None
