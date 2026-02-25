"""SpecDerived tests for package rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._package import (
    _rollback_package_absent,
    _rollback_package_present,
)
from runner.ssh import Result


class TestRollbackPackageSpecDerived:
    """Spec-derived tests for package rollback handlers.

    See specs/handlers/rollback/package.spec.yaml for specification.
    """

    def test_ac1_package_present_was_installed(self, mock_ssh):
        """AC-1: _rollback_package_present when was_installed=True: returns (True, "{name} was already installed, nothing to rollback")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="package_present",
            data={"name": "aide", "was_installed": True},
        )
        ok, detail = _rollback_package_present(ssh, pre_state)
        assert ok is True
        assert detail == "aide was already installed, nothing to rollback"

    def test_ac2_package_present_not_installed_before(self, mock_ssh):
        """AC-2: _rollback_package_present when not installed before: runs dnf remove -y with 300s timeout; returns (True, "Removed {name}")."""
        ssh = mock_ssh({"dnf remove": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="package_present",
            data={"name": "aide", "was_installed": False},
        )
        ok, detail = _rollback_package_present(ssh, pre_state)
        assert ok is True
        assert detail == "Removed aide"
        assert any("dnf remove -y" in cmd for cmd in ssh.commands_run)

    def test_ac3_package_present_dnf_remove_fails(self, mock_ssh):
        """AC-3: When dnf remove fails: returns (False, "Failed to remove {name}: {stderr}")."""
        ssh = mock_ssh(
            {
                "dnf remove": Result(exit_code=1, stdout="", stderr="dependency error"),
            }
        )
        pre_state = PreState(
            mechanism="package_present",
            data={"name": "aide", "was_installed": False},
        )
        ok, detail = _rollback_package_present(ssh, pre_state)
        assert ok is False
        assert "Failed to remove aide" in detail
        assert "dependency error" in detail

    def test_ac4_package_absent_not_installed_before(self, mock_ssh):
        """AC-4: _rollback_package_absent when not installed before: returns (True, "{name} was not installed, nothing to restore")."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="package_absent",
            data={"name": "telnet", "was_installed": False},
        )
        ok, detail = _rollback_package_absent(ssh, pre_state)
        assert ok is True
        assert detail == "telnet was not installed, nothing to restore"

    def test_ac5_package_absent_was_installed(self, mock_ssh):
        """AC-5: _rollback_package_absent when was installed: runs dnf install -y with 300s timeout; returns (True, "Reinstalled {name}")."""
        ssh = mock_ssh({"dnf install": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="package_absent",
            data={"name": "telnet", "was_installed": True},
        )
        ok, detail = _rollback_package_absent(ssh, pre_state)
        assert ok is True
        assert detail == "Reinstalled telnet"
        assert any("dnf install -y" in cmd for cmd in ssh.commands_run)

    def test_ac6_package_absent_dnf_install_fails(self, mock_ssh):
        """AC-6: When dnf install fails: returns (False, "Failed to reinstall {name}: {stderr}")."""
        ssh = mock_ssh(
            {
                "dnf install": Result(
                    exit_code=1, stdout="", stderr="no package available"
                ),
            }
        )
        pre_state = PreState(
            mechanism="package_absent",
            data={"name": "telnet", "was_installed": True},
        )
        ok, detail = _rollback_package_absent(ssh, pre_state)
        assert ok is False
        assert "Failed to reinstall telnet" in detail
        assert "no package available" in detail
