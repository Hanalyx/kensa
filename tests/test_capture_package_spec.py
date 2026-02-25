"""SpecDerived tests for package capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._package import (
    _capture_package_absent,
    _capture_package_present,
)
from runner.ssh import Result


class TestCapturePackageSpecDerived:
    """Spec-derived tests for package capture handlers.

    See specs/handlers/capture/package.spec.yaml for specification.
    """

    def test_ac1_package_present_installed(self, mock_ssh):
        """AC-1: _capture_package_present: was_installed=True when rpm -q succeeds, False when fails; data has name, was_installed."""
        ssh_installed = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=0,
                    stdout="openssh-server-8.7p1-34.el9.x86_64\n",
                    stderr="",
                ),
            }
        )
        result = _capture_package_present(ssh_installed, {"name": "openssh-server"})
        assert isinstance(result, PreState)
        assert result.mechanism == "package_present"
        assert result.data["name"] == "openssh-server"
        assert result.data["was_installed"] is True

        ssh_not_installed = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=1, stdout="package not installed\n", stderr=""
                ),
            }
        )
        result2 = _capture_package_present(ssh_not_installed, {"name": "absent-pkg"})
        assert result2.data["name"] == "absent-pkg"
        assert result2.data["was_installed"] is False

    def test_ac2_package_absent_installed(self, mock_ssh):
        """AC-2: _capture_package_absent: has was_installed and version when installed; data has name, was_installed, version."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=0, stdout="telnet-0.17-85.el9.x86_64\n", stderr=""
                ),
            }
        )
        result = _capture_package_absent(ssh, {"name": "telnet"})
        assert isinstance(result, PreState)
        assert result.mechanism == "package_absent"
        assert result.data["name"] == "telnet"
        assert result.data["was_installed"] is True
        assert result.data["version"] == "telnet-0.17-85.el9.x86_64"

    def test_ac3_package_absent_not_installed(self, mock_ssh):
        """AC-3: _capture_package_absent when not installed: was_installed=False and version=None."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        result = _capture_package_absent(ssh, {"name": "not-installed"})
        assert result.data["was_installed"] is False
        assert result.data["version"] is None

    def test_ac4_uses_shell_quote(self, mock_ssh):
        """AC-4: Both handlers use shell_util.quote for safe package name interpolation."""
        # Use a name with shell-special characters to verify quoting
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        _capture_package_present(ssh, {"name": "my package"})
        assert len(ssh.commands_run) == 1
        assert "'my package'" in ssh.commands_run[0]

        ssh2 = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        _capture_package_absent(ssh2, {"name": "other pkg"})
        assert "'other pkg'" in ssh2.commands_run[0]

    def test_ac5_both_capturable(self, mock_ssh):
        """AC-5: Both handlers return PreState with capturable=True."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        assert _capture_package_present(ssh, {"name": "pkg"}).capturable is True
        ssh2 = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        assert _capture_package_absent(ssh2, {"name": "pkg"}).capturable is True
