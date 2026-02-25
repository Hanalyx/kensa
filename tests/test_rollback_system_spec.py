"""SpecDerived tests for system rollback handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.rollback._system import (
    _rollback_cron_job,
    _rollback_grub_parameter_remove,
    _rollback_grub_parameter_set,
    _rollback_kernel_module_disable,
    _rollback_mount_option_set,
    _rollback_sysctl_set,
)
from runner.ssh import Result


class TestRollbackSystemSpecDerived:
    """Spec-derived tests for system rollback handlers.

    See specs/handlers/rollback/system.spec.yaml for specification.
    """

    def test_ac1_sysctl_set_restores_runtime_and_persist(self, mock_ssh):
        """AC-1: _rollback_sysctl_set restores runtime value via sysctl -w; restores/removes persist file."""
        ssh = mock_ssh(
            {
                "sysctl": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="sysctl_set",
            data={
                "key": "net.ipv4.ip_forward",
                "old_value": "1",
                "persist_file": "/etc/sysctl.d/99-kensa.conf",
                "persist_existed": True,
                "old_persist": "net.ipv4.ip_forward = 1\n",
            },
        )
        ok, detail = _rollback_sysctl_set(ssh, pre_state)
        assert ok is True
        assert detail == "Restored net.ipv4.ip_forward=1"
        assert any("sysctl -w" in cmd for cmd in ssh.commands_run)

    def test_ac2_sysctl_set_persist_did_not_exist(self, mock_ssh):
        """AC-2: When persist file didn't exist: removes via rm -f."""
        ssh = mock_ssh(
            {
                "sysctl": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="sysctl_set",
            data={
                "key": "net.ipv4.ip_forward",
                "old_value": "0",
                "persist_file": "/etc/sysctl.d/99-kensa.conf",
                "persist_existed": False,
                "old_persist": None,
            },
        )
        ok, detail = _rollback_sysctl_set(ssh, pre_state)
        assert ok is True
        assert any("rm -f" in cmd for cmd in ssh.commands_run)

    def test_ac3_kernel_module_disable_restores_conf_and_reloads(self, mock_ssh):
        """AC-3: _rollback_kernel_module_disable restores conf, reloads module via modprobe when was_loaded."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="kernel_module_disable",
            data={
                "name": "usb-storage",
                "conf_path": "/etc/modprobe.d/usb-storage.conf",
                "conf_existed": True,
                "old_conf": "# no blacklist\n",
                "was_loaded": True,
            },
        )
        ok, detail = _rollback_kernel_module_disable(ssh, pre_state)
        assert ok is True
        assert detail == "Restored usb-storage module config"
        assert any("modprobe" in cmd for cmd in ssh.commands_run)

    def test_ac4_mount_option_set_restores_fstab_and_remounts(self, mock_ssh):
        """AC-4: _rollback_mount_option_set restores fstab line and runs mount -o remount; returns (False, ...) when no fstab line."""
        # Success case: fstab line exists
        ssh = mock_ssh(
            {
                "sed": Result(exit_code=0, stdout="", stderr=""),
                "mount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        pre_state = PreState(
            mechanism="mount_option_set",
            data={
                "mount_point": "/tmp",
                "old_fstab_line": "tmpfs /tmp tmpfs defaults,noexec 0 0",
            },
        )
        ok, detail = _rollback_mount_option_set(ssh, pre_state)
        assert ok is True
        assert detail == "Restored /tmp options"
        assert any("mount -o remount" in cmd for cmd in ssh.commands_run)

    def test_ac4_mount_option_set_no_fstab_line(self, mock_ssh):
        """AC-4: returns (False, ...) when no fstab line captured."""
        ssh = mock_ssh({})
        pre_state = PreState(
            mechanism="mount_option_set",
            data={
                "mount_point": "/tmp",
                "old_fstab_line": None,
            },
        )
        ok, detail = _rollback_mount_option_set(ssh, pre_state)
        assert ok is False
        assert "no previous fstab line captured" in detail

    def test_ac5_grub_parameter_set_cannot_rollback(self, mock_ssh):
        """AC-5: _rollback_grub_parameter_set always returns (False, "GRUB changes cannot be automatically rolled back")."""
        ssh = mock_ssh({})
        pre_state = PreState(mechanism="grub_parameter_set", data={})
        ok, detail = _rollback_grub_parameter_set(ssh, pre_state)
        assert ok is False
        assert detail == "GRUB changes cannot be automatically rolled back"

    def test_ac6_grub_parameter_remove_cannot_rollback(self, mock_ssh):
        """AC-6: _rollback_grub_parameter_remove always returns (False, "GRUB changes cannot be automatically rolled back")."""
        ssh = mock_ssh({})
        pre_state = PreState(mechanism="grub_parameter_remove", data={})
        ok, detail = _rollback_grub_parameter_remove(ssh, pre_state)
        assert ok is False
        assert detail == "GRUB changes cannot be automatically rolled back"

    def test_ac7_cron_job_did_not_exist(self, mock_ssh):
        """AC-7: _rollback_cron_job when didn't exist: rm -f; returns (True, "Removed {cron_file}")."""
        ssh = mock_ssh({"rm -f": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="cron_job",
            data={
                "cron_file": "/etc/cron.d/aide-check",
                "existed": False,
                "old_content": None,
            },
        )
        ok, detail = _rollback_cron_job(ssh, pre_state)
        assert ok is True
        assert detail == "Removed /etc/cron.d/aide-check"

    def test_ac8_cron_job_existed_content_captured(self, mock_ssh):
        """AC-8: _rollback_cron_job when existed and content captured: writes back; returns (True, "Restored {cron_file}")."""
        ssh = mock_ssh({"printf": Result(exit_code=0, stdout="", stderr="")})
        pre_state = PreState(
            mechanism="cron_job",
            data={
                "cron_file": "/etc/cron.d/aide-check",
                "existed": True,
                "old_content": "0 5 * * * root /usr/sbin/aide --check\n",
            },
        )
        ok, detail = _rollback_cron_job(ssh, pre_state)
        assert ok is True
        assert detail == "Restored /etc/cron.d/aide-check"
