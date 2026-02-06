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
                "test -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_missing(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.passed is False


class TestMultiConditionCheck:
    def test_all_pass(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="aide-0.16", stderr=""),
                "test -f": Result(exit_code=0, stdout="", stderr=""),
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


class TestUnknownMethod:
    def test_unknown_check_method(self, mock_ssh):
        ssh = mock_ssh({})
        check = {"method": "nonexistent_method"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "Unknown check method" in r.detail
