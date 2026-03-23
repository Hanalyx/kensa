"""SpecDerived tests for file capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._file import (
    _capture_file_absent,
    _capture_file_content,
    _capture_file_permissions,
)
from runner.ssh import Result


class TestCaptureFileSpecDerived:
    """Spec-derived tests for file capture handlers.

    See specs/handlers/capture/file.spec.yaml for specification.
    """

    def test_ac1_file_permissions_captures_entries(self, mock_ssh):
        """AC-1: _capture_file_permissions captures owner, group, and mode for each file; data.entries is a list of {path, owner, group, mode} dicts."""
        ssh = mock_ssh(
            {
                "stat -c": Result(
                    exit_code=0,
                    stdout="root root 644 /etc/passwd\n",
                    stderr="",
                ),
            }
        )
        r = {"path": "/etc/passwd"}
        result = _capture_file_permissions(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "file_permissions"
        assert len(result.data["entries"]) == 1
        entry = result.data["entries"][0]
        assert entry["path"] == "/etc/passwd"
        assert entry["owner"] == "root"
        assert entry["group"] == "root"
        assert entry["mode"] == "644"

    def test_ac2_file_permissions_glob(self, mock_ssh):
        """AC-2: _capture_file_permissions with glob path uses allow_glob=True for stat command, producing multiple entries."""
        ssh = mock_ssh(
            {
                "stat -c": Result(
                    exit_code=0,
                    stdout="root root 644 /etc/ssh/sshd_config\nroot root 600 /etc/ssh/ssh_host_rsa_key\n",
                    stderr="",
                ),
            }
        )
        r = {"path": "/etc/ssh/*", "glob": True}
        result = _capture_file_permissions(ssh, r)
        assert len(result.data["entries"]) == 2
        assert result.data["entries"][0]["path"] == "/etc/ssh/sshd_config"
        assert result.data["entries"][1]["path"] == "/etc/ssh/ssh_host_rsa_key"

    def test_ac3_file_permissions_nonexistent(self, mock_ssh):
        """AC-3: _capture_file_permissions for non-existent file produces empty entries list."""
        ssh = mock_ssh(
            {
                "stat -c": Result(exit_code=1, stdout="", stderr="No such file"),
            }
        )
        r = {"path": "/nonexistent"}
        result = _capture_file_permissions(ssh, r)
        assert result.data["entries"] == []

    def test_ac4_file_content_captures_content(self, mock_ssh):
        """AC-4: _capture_file_content captures full file content, owner, group, mode; data has path, existed, old_content, old_owner, old_group, old_mode."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="file contents here\n", stderr=""),
                "stat -c": Result(exit_code=0, stdout="root wheel 640\n", stderr=""),
            }
        )
        r = {"path": "/etc/issue"}
        result = _capture_file_content(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "file_content"
        assert result.data["path"] == "/etc/issue"
        assert result.data["existed"] is True
        assert result.data["old_content"] == "file contents here\n"
        assert result.data["old_owner"] == "root"
        assert result.data["old_group"] == "wheel"
        assert result.data["old_mode"] == "640"

    def test_ac5_file_content_nonexistent(self, mock_ssh):
        """AC-5: _capture_file_content for non-existent file: existed=False, old_content=None, old_owner/old_group/old_mode all None."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"path": "/nonexistent"}
        result = _capture_file_content(ssh, r)
        assert result.data["existed"] is False
        assert result.data["old_content"] is None
        assert result.data["old_owner"] is None
        assert result.data["old_group"] is None
        assert result.data["old_mode"] is None

    def test_ac6_file_absent_captures_same_fields(self, mock_ssh):
        """AC-6: _capture_file_absent captures same fields as file_content."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="old data\n", stderr=""),
                "stat -c": Result(
                    exit_code=0, stdout="nobody nogroup 755\n", stderr=""
                ),
            }
        )
        r = {"path": "/etc/tempfile"}
        result = _capture_file_absent(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "file_absent"
        assert result.data["path"] == "/etc/tempfile"
        assert result.data["existed"] is True
        assert result.data["old_content"] == "old data\n"
        assert result.data["old_owner"] == "nobody"
        assert result.data["old_group"] == "nogroup"
        assert result.data["old_mode"] == "755"

    def test_ac7_file_absent_nonexistent(self, mock_ssh):
        """AC-7: _capture_file_absent for non-existent file: existed=False and all old_* fields are None."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"path": "/nonexistent"}
        result = _capture_file_absent(ssh, r)
        assert result.data["existed"] is False
        assert result.data["old_content"] is None
        assert result.data["old_owner"] is None
        assert result.data["old_group"] is None
        assert result.data["old_mode"] is None

    def test_ac8_all_file_capturable(self, mock_ssh):
        """AC-8: All file capture handlers return PreState with capturable=True."""
        ssh = mock_ssh(
            {
                "stat -c": Result(exit_code=1, stdout="", stderr=""),
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"path": "/any"}
        assert _capture_file_permissions(ssh, r).capturable is True
        assert _capture_file_content(ssh, r).capturable is True
        assert _capture_file_absent(ssh, r).capturable is True

    def test_ac9_bulk_find_type_validation_rejects_invalid(self, mock_ssh):
        """AC-9: In bulk find mode, invalid find_type values are rejected."""
        from runner.handlers.capture._file import _capture_bulk_find_permissions

        ssh = mock_ssh({})
        r = {
            "find_paths": ["/etc"],
            "find_type": "f; rm -rf /",
            "find_name": "*.conf",
        }
        # Should raise ValueError or skip the type filter — not pass to shell
        import pytest

        with pytest.raises(ValueError):
            _capture_bulk_find_permissions(ssh, r)
        # Verify no commands were run with the malicious input
        assert len(ssh.commands_run) == 0

    def test_ac9_bulk_find_type_accepts_valid(self, mock_ssh):
        """AC-9: In bulk find mode, valid find_type values are accepted."""
        from runner.handlers.capture._file import _capture_bulk_find_permissions

        for valid_type in ["f", "d", "l"]:
            ssh = mock_ssh({"find": Result(exit_code=0, stdout="", stderr="")})
            r = {
                "find_paths": ["/etc"],
                "find_type": valid_type,
            }
            result = _capture_bulk_find_permissions(ssh, r)
            assert result.mechanism == "file_permissions"
