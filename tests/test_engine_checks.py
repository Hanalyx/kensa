"""Tests for check handlers in runner/engine.py."""

from __future__ import annotations

from runner.engine import run_check
from runner.ssh import Result


class TestConfigValue:
    def test_key_found_correct_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="PermitRootLogin no", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_key_found_wrong_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="PermitRootLogin yes", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected no" in r.detail

    def test_key_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail

    def test_directory_mode_with_scan_pattern(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=0, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="PermitRootLogin no", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config.d",
            "key": "PermitRootLogin",
            "expected": "no",
            "scan_pattern": "*.conf",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_equals_separator(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="deny = 3", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/security/faillock.conf",
            "key": "deny",
            "expected": "3",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_case_insensitive_comparison(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="PermitRootLogin No", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is True


class TestFilePermission:
    def test_correct_permissions(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 0 /etc/shadow", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0000",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_wrong_owner(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="nobody root 600 /etc/shadow", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0600",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "owner=nobody" in r.detail

    def test_wrong_mode(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 644 /etc/shadow", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0000",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "mode=644" in r.detail

    def test_file_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat": Result(exit_code=1, stdout="", stderr="No such file"),
            }
        )
        check = {"method": "file_permission", "path": "/nonexistent", "owner": "root"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail

    def test_glob_path_multiple_files(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0,
                    stdout="root ssh_keys 640 /etc/ssh/ssh_host_ecdsa_key\nroot ssh_keys 640 /etc/ssh/ssh_host_ed25519_key",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/ssh/ssh_host_*_key",
            "owner": "root",
            "group": "ssh_keys",
            "mode": "0640",
            "glob": "ssh_host_*_key",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_glob_path_partial_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0,
                    stdout="root ssh_keys 640 /etc/ssh/ssh_host_ecdsa_key\nroot root 644 /etc/ssh/ssh_host_rsa_key",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/ssh/ssh_host_*_key",
            "owner": "root",
            "group": "ssh_keys",
            "mode": "0640",
            "glob": "ssh_host_*_key",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "ssh_host_rsa_key" in r.detail


class TestCommand:
    def test_exit_code_matches(self, mock_ssh):
        ssh = mock_ssh(
            {
                "authselect current": Result(
                    exit_code=0, stdout="Profile ID: sssd", stderr=""
                ),
            }
        )
        check = {"method": "command", "run": "authselect current", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_exit_code_mismatch(self, mock_ssh):
        ssh = mock_ssh(
            {
                "authselect current": Result(
                    exit_code=1, stdout="", stderr="No configuration"
                ),
            }
        )
        check = {"method": "command", "run": "authselect current", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "exit 1" in r.detail

    def test_expected_stdout(self, mock_ssh):
        ssh = mock_ssh(
            {
                "cat /etc/hostname": Result(
                    exit_code=0, stdout="webserver-01", stderr=""
                ),
            }
        )
        check = {
            "method": "command",
            "run": "cat /etc/hostname",
            "expected_exit": 0,
            "expected_stdout": "webserver",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_expected_stdout_mismatch(self, mock_ssh):
        ssh = mock_ssh(
            {
                "cat /etc/hostname": Result(
                    exit_code=0, stdout="dbserver-01", stderr=""
                ),
            }
        )
        check = {
            "method": "command",
            "run": "cat /etc/hostname",
            "expected_exit": 0,
            "expected_stdout": "webserver",
        }
        r = run_check(ssh, check)
        assert r.passed is False

    def test_expected_empty_stdout_pass(self, mock_ssh):
        """expected_stdout='' must pass when command produces no output."""
        ssh = mock_ssh({"find /bad": Result(exit_code=0, stdout="", stderr="")})
        check = {
            "method": "command",
            "run": "find /bad",
            "expected_exit": 0,
            "expected_stdout": "",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_expected_empty_stdout_fail(self, mock_ssh):
        """expected_stdout='' must fail when command produces output."""
        ssh = mock_ssh(
            {"find /bad": Result(exit_code=0, stdout="/bad/file.txt", stderr="")}
        )
        check = {
            "method": "command",
            "run": "find /bad",
            "expected_exit": 0,
            "expected_stdout": "",
        }
        r = run_check(ssh, check)
        assert r.passed is False

    def test_nonzero_expected_exit(self, mock_ssh):
        """Some checks expect failure (e.g., 'this should NOT be found')."""
        ssh = mock_ssh(
            {
                "grep bad": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "command", "run": "grep bad /etc/conf", "expected_exit": 1}
        r = run_check(ssh, check)
        assert r.passed is True


class TestSysctlValue:
    def test_matching_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=0, stdout="0", stderr=""),
            }
        )
        check = {
            "method": "sysctl_value",
            "key": "net.ipv4.ip_forward",
            "expected": "0",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_mismatching_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=0, stdout="1", stderr=""),
            }
        )
        check = {
            "method": "sysctl_value",
            "key": "net.ipv4.ip_forward",
            "expected": "0",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected 0" in r.detail

    def test_sysctl_not_available(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sysctl": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        check = {"method": "sysctl_value", "key": "nonexistent.param", "expected": "0"}
        r = run_check(ssh, check)
        assert r.passed is False


class TestKernelModuleState:
    def test_blacklisted_and_not_loaded(self, mock_ssh):
        ssh = mock_ssh(
            {
                "lsmod": Result(exit_code=1, stdout="", stderr=""),
                "modprobe": Result(exit_code=0, stdout="install /bin/true", stderr=""),
            }
        )
        check = {
            "method": "kernel_module_state",
            "name": "cramfs",
            "state": "blacklisted",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_still_loaded(self, mock_ssh):
        ssh = mock_ssh(
            {
                "lsmod": Result(exit_code=0, stdout="cramfs 16384 0", stderr=""),
            }
        )
        check = {
            "method": "kernel_module_state",
            "name": "cramfs",
            "state": "blacklisted",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "still loaded" in r.detail

    def test_not_blacklisted(self, mock_ssh):
        ssh = mock_ssh(
            {
                "lsmod": Result(exit_code=1, stdout="", stderr=""),
                "modprobe": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "kernel_module_state",
            "name": "cramfs",
            "state": "blacklisted",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not blacklisted" in r.detail


class TestPackageState:
    def test_present_and_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=0, stdout="aide-0.16-14.el9.x86_64", stderr=""
                ),
            }
        )
        check = {"method": "package_state", "name": "aide", "state": "present"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_present_but_not_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=1, stdout="package aide is not installed", stderr=""
                ),
            }
        )
        check = {"method": "package_state", "name": "aide", "state": "present"}
        r = run_check(ssh, check)
        assert r.passed is False

    def test_absent_and_not_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "package_state", "name": "badpkg", "state": "absent"}
        r = run_check(ssh, check)
        assert r.passed is True


class TestFileExists:
    def test_exists(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_missing(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.passed is False


class TestFileContent:
    def test_content_matches(self, mock_ssh):
        banner = "Authorized uses only. All activity may be monitored and reported."
        ssh = mock_ssh(
            {
                "cat": Result(exit_code=0, stdout=banner, stderr=""),
            }
        )
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_content_mismatch(self, mock_ssh):
        ssh = mock_ssh(
            {
                "cat": Result(
                    exit_code=0,
                    stdout="Old banner text from previous admin.",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": "New organization consent warning.",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "does not match" in r.detail

    def test_file_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "cat": Result(exit_code=1, stdout="", stderr="No such file"),
            }
        )
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": "Banner text",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail or "not readable" in r.detail

    def test_trailing_newline_ignored(self, mock_ssh):
        """Trailing newlines should not cause a mismatch."""
        ssh = mock_ssh(
            {
                "cat": Result(exit_code=0, stdout="Banner text\n", stderr=""),
            }
        )
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": "Banner text\n",
        }
        r = run_check(ssh, check)
        assert r.passed is True


class TestMultiConditionCheck:
    def test_all_pass(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="aide-0.16", stderr=""),
                "test -e": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {
            "checks": [
                {"method": "package_state", "name": "aide", "state": "present"},
                {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"},
            ]
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_first_fails_short_circuits(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "checks": [
                {"method": "package_state", "name": "aide", "state": "present"},
                {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"},
            ]
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not installed" in r.detail


class TestServiceState:
    def test_enabled_and_running(self, mock_ssh):
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="enabled", stderr=""),
                "is-active": Result(exit_code=0, stdout="active", stderr=""),
            }
        )
        check = {
            "method": "service_state",
            "name": "sshd",
            "enabled": True,
            "active": True,
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_enabled_but_not_running(self, mock_ssh):
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="enabled", stderr=""),
                "is-active": Result(exit_code=3, stdout="inactive", stderr=""),
            }
        )
        check = {
            "method": "service_state",
            "name": "sshd",
            "enabled": True,
            "active": True,
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "active=inactive" in r.detail

    def test_disabled_as_expected(self, mock_ssh):
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="disabled", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_static_counts_as_enabled(self, mock_ssh):
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="static", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "systemd-journald", "enabled": True}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_masked_counts_as_disabled(self, mock_ssh):
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="masked", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_enabled_when_should_be_disabled(self, mock_ssh):
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="enabled", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected disabled" in r.detail


class TestSystemdTarget:
    def test_expected_target_matches(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="multi-user.target", stderr=""
                ),
            }
        )
        check = {
            "method": "systemd_target",
            "expected": "multi-user.target",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_expected_target_mismatch(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="graphical.target", stderr=""
                ),
            }
        )
        check = {
            "method": "systemd_target",
            "expected": "multi-user.target",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "graphical.target" in r.detail

    def test_not_expected_target(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="multi-user.target", stderr=""
                ),
            }
        )
        check = {
            "method": "systemd_target",
            "not_expected": "graphical.target",
        }
        r = run_check(ssh, check)
        assert r.passed is True


class TestConfigAbsent:
    def test_key_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "config_absent",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitEmptyPasswords",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_key_present_when_should_be_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(
                    exit_code=0, stdout="PermitEmptyPasswords yes", stderr=""
                ),
            }
        )
        check = {
            "method": "config_absent",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitEmptyPasswords",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "should be absent" in r.detail


class TestFileNotExists:
    def test_file_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "file_not_exists", "path": "/etc/cron.deny"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_file_present_when_should_be_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {"method": "file_not_exists", "path": "/etc/cron.deny"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "should be absent" in r.detail


class TestFileContentMatch:
    def test_pattern_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -qE": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_match",
            "path": "/etc/login.defs",
            "pattern": "^ENCRYPT_METHOD\\s+SHA512",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_pattern_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -qE": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_match",
            "path": "/etc/login.defs",
            "pattern": "^ENCRYPT_METHOD\\s+SHA512",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "pattern not found" in r.detail

    def test_file_missing(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_match",
            "path": "/nonexistent",
            "pattern": "anything",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail


class TestFileContentNoMatch:
    def test_prohibited_pattern_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -qE": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_no_match",
            "path": "/etc/issue",
            "pattern": "\\\\[vrmns]",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_prohibited_pattern_present(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -qE": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_no_match",
            "path": "/etc/issue",
            "pattern": "\\\\[vrmns]",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "prohibited pattern" in r.detail

    def test_missing_file_passes(self, mock_ssh):
        """If the file doesn't exist, the pattern can't be present."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_no_match",
            "path": "/nonexistent",
            "pattern": "anything",
        }
        r = run_check(ssh, check)
        assert r.passed is True


class TestMountOption:
    def test_required_options_present(self, mock_ssh):
        ssh = mock_ssh(
            {
                "findmnt": Result(
                    exit_code=0, stdout="rw,nosuid,nodev,noexec,relatime", stderr=""
                ),
            }
        )
        check = {
            "method": "mount_option",
            "mount_point": "/tmp",
            "options": ["nosuid", "nodev", "noexec"],
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_missing_option(self, mock_ssh):
        ssh = mock_ssh(
            {
                "findmnt": Result(exit_code=0, stdout="rw,nosuid,relatime", stderr=""),
            }
        )
        check = {
            "method": "mount_option",
            "mount_point": "/tmp",
            "options": ["nosuid", "nodev", "noexec"],
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "nodev" in r.detail
        assert "noexec" in r.detail

    def test_not_mounted(self, mock_ssh):
        ssh = mock_ssh(
            {
                "findmnt": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "mount_option",
            "mount_point": "/tmp",
            "options": ["nosuid"],
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not mounted" in r.detail


class TestGrubParameter:
    def test_parameter_with_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto audit=1"',
                    stderr="",
                ),
            }
        )
        check = {
            "method": "grub_parameter",
            "key": "audit",
            "expected": "1",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_parameter_wrong_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto audit=0"',
                    stderr="",
                ),
            }
        )
        check = {
            "method": "grub_parameter",
            "key": "audit",
            "expected": "1",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected 1" in r.detail

    def test_parameter_missing(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto"',
                    stderr="",
                ),
            }
        )
        check = {
            "method": "grub_parameter",
            "key": "audit",
            "expected": "1",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail

    def test_grubby_not_available(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=1, stdout="", stderr="not found"),
            }
        )
        check = {"method": "grub_parameter", "key": "audit", "expected": "1"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "grubby" in r.detail.lower()


class TestSelinuxState:
    def test_enforcing(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=0, stdout="Enforcing", stderr=""),
            }
        )
        check = {"method": "selinux_state", "state": "Enforcing"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_permissive_when_enforcing_expected(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=0, stdout="Permissive", stderr=""),
            }
        )
        check = {"method": "selinux_state", "state": "Enforcing"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "Permissive" in r.detail

    def test_getenforce_fails(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=1, stdout="", stderr="not found"),
            }
        )
        check = {"method": "selinux_state"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not be installed" in r.detail


class TestSelinuxBoolean:
    def test_boolean_on(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0,
                    stdout="httpd_can_network_connect --> on",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "selinux_boolean",
            "name": "httpd_can_network_connect",
            "value": True,
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_boolean_off_when_on_expected(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0,
                    stdout="httpd_can_network_connect --> off",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "selinux_boolean",
            "name": "httpd_can_network_connect",
            "value": True,
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected on" in r.detail

    def test_boolean_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getsebool": Result(exit_code=1, stdout="", stderr="not found"),
            }
        )
        check = {
            "method": "selinux_boolean",
            "name": "nonexistent_bool",
            "value": True,
        }
        r = run_check(ssh, check)
        assert r.passed is False


class TestAuditRuleExists:
    def test_rule_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "audit_rule_exists",
            "rule": "-w /etc/passwd -p wa -k identity",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_rule_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/shadow -p wa -k identity",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "audit_rule_exists",
            "rule": "-w /etc/passwd -p wa -k identity",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail

    def test_auditd_not_running(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl -l": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        check = {
            "method": "audit_rule_exists",
            "rule": "-w /etc/passwd -p wa",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "auditctl" in r.detail

    def test_normalize_key_format(self, mock_ssh):
        """auditctl -l outputs -F key=X for syscall rules; rule uses -k X."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout=(
                        "-a always,exit -F arch=b64 -S open -F exit=-EACCES"
                        " -F auid>=1000 -F auid!=-1 -F key=access"
                    ),
                    stderr="",
                ),
            }
        )
        check = {"method": "audit_rule_exists", "rule": "-k access"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_normalize_auid_unset(self, mock_ssh):
        """auditctl -l shows auid!=-1; rule uses auid!=unset."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout=(
                        "-a always,exit -F path=/usr/bin/chage"
                        " -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage"
                    ),
                    stderr="",
                ),
            }
        )
        check = {
            "method": "audit_rule_exists",
            "rule": "-F auid!=unset -k privileged-chage",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_normalize_s_all_removed(self, mock_ssh):
        """auditctl -l inserts -S all for path-only rules."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout=(
                        "-a always,exit -S all -F path=/usr/bin/su"
                        " -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-su"
                    ),
                    stderr="",
                ),
            }
        )
        check = {
            "method": "audit_rule_exists",
            "rule": (
                "-a always,exit -F path=/usr/bin/su"
                " -F perm=x -F auid>=1000 -F auid!=unset -k privileged-su"
            ),
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_normalize_combined(self, mock_ssh):
        """All normalizations applied together."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout=(
                        "-a always,exit -S all -F path=/usr/sbin/usermod"
                        " -F perm=x -F auid>=1000 -F auid!=4294967295"
                        " -F key=privileged-usermod"
                    ),
                    stderr="",
                ),
            }
        )
        check = {
            "method": "audit_rule_exists",
            "rule": (
                "-a always,exit -F path=/usr/sbin/usermod"
                " -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod"
            ),
        }
        r = run_check(ssh, check)
        assert r.passed is True


class TestSshdEffectiveConfig:
    def test_key_matches(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin no", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_key_wrong_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin yes", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected no" in r.detail

    def test_key_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail


class TestPamModule:
    def test_module_found_with_correct_type(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep": Result(
                    exit_code=0,
                    stdout="auth        required      pam_faillock.so preauth",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "pam_module",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_module_not_found(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "pam_module",
            "service": "system-auth",
            "module": "pam_faillock.so",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail

    def test_pam_file_missing(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "pam_module",
            "service": "nonexistent",
            "module": "pam_faillock.so",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail


class TestConfigValueComparator:
    def test_greater_than_or_equal_pass(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="minlen = 15", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/security/pwquality.conf",
            "key": "minlen",
            "expected": "14",
            "comparator": ">=",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_greater_than_or_equal_fail(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="minlen = 8", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/security/pwquality.conf",
            "key": "minlen",
            "expected": "14",
            "comparator": ">=",
        }
        r = run_check(ssh, check)
        assert r.passed is False


class TestUnknownMethod:
    def test_unknown_check_method(self, mock_ssh):
        ssh = mock_ssh({})
        check = {"method": "nonexistent_method"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "Unknown check method" in r.detail
