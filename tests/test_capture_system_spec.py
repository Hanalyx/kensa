"""SpecDerived tests for system capture handlers."""

from __future__ import annotations

from runner._types import PreState
from runner.handlers.capture._system import (
    _capture_cron_job,
    _capture_grub_parameter_remove,
    _capture_grub_parameter_set,
    _capture_kernel_module_disable,
    _capture_mount_option_set,
    _capture_sysctl_set,
)
from runner.ssh import Result


class TestCaptureSystemSpecDerived:
    """Spec-derived tests for system capture handlers.

    See specs/handlers/capture/system.spec.yaml for specification.
    """

    def test_ac1_sysctl_captures_value(self, mock_ssh):
        """AC-1: _capture_sysctl_set captures old_value, persist_file, old_persist, persist_existed."""
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=0, stdout="1\n", stderr=""),
                "cat": Result(
                    exit_code=0, stdout="net.ipv4.ip_forward = 1\n", stderr=""
                ),
            }
        )
        r = {"key": "net.ipv4.ip_forward"}
        result = _capture_sysctl_set(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "sysctl_set"
        assert result.data["key"] == "net.ipv4.ip_forward"
        assert result.data["old_value"] == "1"
        assert (
            result.data["persist_file"]
            == "/etc/sysctl.d/99-kensa-net-ipv4-ip_forward.conf"
        )
        assert result.data["old_persist"] == "net.ipv4.ip_forward = 1\n"
        assert result.data["persist_existed"] is True

    def test_ac2_sysctl_default_persist_file(self, mock_ssh):
        """AC-2: Default persist_file is /etc/sysctl.d/99-kensa-{key_dashed}.conf."""
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=1, stdout="", stderr=""),
                "cat": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"key": "kernel.randomize_va_space"}
        result = _capture_sysctl_set(ssh, r)
        assert (
            result.data["persist_file"]
            == "/etc/sysctl.d/99-kensa-kernel-randomize_va_space.conf"
        )

    def test_ac3_kernel_module_disable(self, mock_ssh):
        """AC-3: _capture_kernel_module_disable captures conf_path, old_conf, conf_existed, was_loaded."""
        ssh = mock_ssh(
            {
                "cat": Result(
                    exit_code=0, stdout="install cramfs /bin/true\n", stderr=""
                ),
                "lsmod": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        r = {"name": "cramfs"}
        result = _capture_kernel_module_disable(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "kernel_module_disable"
        assert result.data["name"] == "cramfs"
        assert result.data["conf_path"] == "/etc/modprobe.d/cramfs.conf"
        assert result.data["old_conf"] == "install cramfs /bin/true\n"
        assert result.data["conf_existed"] is True
        assert result.data["was_loaded"] is False

    def test_ac4_mount_option_captures_fstab(self, mock_ssh):
        """AC-4: _capture_mount_option_set captures old_fstab_line and old_options."""
        ssh = mock_ssh(
            {
                "grep -E": Result(
                    exit_code=0,
                    stdout="tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0\n",
                    stderr="",
                ),
                "findmnt": Result(
                    exit_code=0,
                    stdout="rw,nosuid,nodev,noexec\n",
                    stderr="",
                ),
            }
        )
        r = {"mount_point": "/tmp"}
        result = _capture_mount_option_set(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "mount_option_set"
        assert result.data["mount_point"] == "/tmp"
        assert (
            result.data["old_fstab_line"]
            == "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0"
        )
        assert result.data["old_options"] == "rw,nosuid,nodev,noexec"

    def test_ac5_grub_parameter_set_not_capturable(self, mock_ssh):
        """AC-5: _capture_grub_parameter_set returns capturable=False; data has key and old_args."""
        ssh = mock_ssh(
            {
                "grubby --info=DEFAULT": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto audit=1"\n',
                    stderr="",
                ),
            }
        )
        r = {"key": "audit"}
        result = _capture_grub_parameter_set(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "grub_parameter_set"
        assert result.capturable is False
        assert result.data["key"] == "audit"
        assert result.data["old_args"] == 'args="ro crashkernel=auto audit=1"'

    def test_ac6_grub_parameter_remove_not_capturable(self, mock_ssh):
        """AC-6: _capture_grub_parameter_remove returns capturable=False."""
        ssh = mock_ssh(
            {
                "grubby --info=DEFAULT": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto"\n',
                    stderr="",
                ),
            }
        )
        r = {"key": "crashkernel"}
        result = _capture_grub_parameter_remove(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "grub_parameter_remove"
        assert result.capturable is False

    def test_ac7_cron_job_captures_file(self, mock_ssh):
        """AC-7: _capture_cron_job captures cron_file, existed, old_content."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(
                    exit_code=0, stdout="0 5 * * * /usr/bin/aide --check\n", stderr=""
                ),
            }
        )
        r = {"name": "aide-check"}
        result = _capture_cron_job(ssh, r)
        assert isinstance(result, PreState)
        assert result.mechanism == "cron_job"
        assert result.data["cron_file"] == "/etc/cron.d/aide-check"
        assert result.data["existed"] is True
        assert result.data["old_content"] == "0 5 * * * /usr/bin/aide --check\n"

    def test_ac8_capturable_except_grub(self, mock_ssh):
        """AC-8: All except GRUB return capturable=True."""
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=1, stdout="", stderr=""),
                "cat": Result(exit_code=1, stdout="", stderr=""),
                "lsmod": Result(exit_code=1, stdout="", stderr=""),
                "grep -E": Result(exit_code=1, stdout="", stderr=""),
                "findmnt": Result(exit_code=1, stdout="", stderr=""),
                "grubby --info=DEFAULT": Result(exit_code=1, stdout="", stderr=""),
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        assert _capture_sysctl_set(ssh, {"key": "k"}).capturable is True
        assert _capture_kernel_module_disable(ssh, {"name": "n"}).capturable is True
        assert _capture_mount_option_set(ssh, {"mount_point": "/m"}).capturable is True
        assert _capture_grub_parameter_set(ssh, {"key": "k"}).capturable is False
        assert _capture_grub_parameter_remove(ssh, {"key": "k"}).capturable is False
        assert _capture_cron_job(ssh, {"name": "j"}).capturable is True
