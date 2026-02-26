"""Tests for check handlers in runner/engine.py."""

from __future__ import annotations

from datetime import datetime, timezone

from runner.engine import run_check
from runner.ssh import Result


class TestConfigValue:
    def test_key_found_correct_value(self, mock_ssh):
        """AC-1: Key present with correct value → PASS."""
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
        """AC-2: Key present with wrong value → FAIL with 'expected' detail."""
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
        """AC-3: Key not found (grep exit 1) → FAIL with 'not found' detail."""
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
        """AC-4: Directory mode with scan_pattern → recursive grep."""
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
        """AC-5: Equals separator (key = value) parsed correctly."""
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
        """AC-6: Case-insensitive comparison (No matches no) → PASS."""
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
        """AC-1, AC-10: All attributes match (including mode 0000 -> 0 normalization) -> PASS."""
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
        """AC-2: Wrong owner -> FAIL with 'owner={actual}' in detail."""
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
        """AC-3: Wrong mode -> FAIL with 'mode={actual}' in detail."""
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
        """AC-4, AC-8: File not found -> FAIL, evidence.actual is None."""
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
        """AC-5: Glob path, all files pass -> PASS."""
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
        """AC-6: Glob path, some files fail -> FAIL with failing file in detail."""
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


class TestFilePermissionSpecDerived:
    """Spec-derived gap tests for file_permission handler.

    See specs/handlers/checks/file_permission.spec.md for full specification.
    """

    def test_evidence_fields_populated_on_pass(self, mock_ssh):
        """AC-7: Evidence fields fully populated on successful check."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 644 /etc/passwd", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/passwd",
            "owner": "root",
            "group": "root",
            "mode": "0644",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.method == "file_permission"
        assert r.evidence.command is not None
        assert "stat" in r.evidence.command
        assert r.evidence.stdout == "root root 644 /etc/passwd"
        assert r.evidence.exit_code == 0
        assert r.evidence.expected == "owner=root, group=root, mode=0644"
        assert r.evidence.actual is not None
        assert "owner=root" in r.evidence.actual
        assert r.evidence.timestamp is not None

    def test_evidence_actual_none_when_not_found(self, mock_ssh):
        """AC-8: Evidence actual is None when file not found."""
        ssh = mock_ssh(
            {
                "stat": Result(exit_code=1, stdout="", stderr="No such file"),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/nonexistent",
            "owner": "root",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.actual is None
        assert r.evidence.stderr == "No such file"

    def test_mode_normalization_leading_zero_strip(self, mock_ssh):
        """AC-9: Mode '0600' expected matches '600' actual (leading zero stripped)."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 600 /etc/shadow", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/shadow",
            "mode": "0600",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_mode_normalization_reverse(self, mock_ssh):
        """AC-9: Mode '600' expected matches '0600' actual (stat reports with leading zero)."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 0600 /etc/shadow", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/shadow",
            "mode": "600",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_mode_all_zeros_normalization(self, mock_ssh):
        """AC-10: Mode '0000' expected matches '0' actual (all-zero edge case)."""
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
            "mode": "0000",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_partial_check_owner_only(self, mock_ssh):
        """AC-11: Only owner specified -> only owner is validated."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root wheel 755 /usr/bin/test", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/usr/bin/test",
            "owner": "root",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "group=*" in r.evidence.expected
        assert "mode=*" in r.evidence.expected

    def test_partial_check_mode_only(self, mock_ssh):
        """AC-12: Only mode specified -> only mode is validated."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="nobody nogroup 600 /etc/secret", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/secret",
            "mode": "0600",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "owner=*" in r.evidence.expected
        assert "group=*" in r.evidence.expected

    def test_wrong_group(self, mock_ssh):
        """AC-13: Wrong group -> FAIL with 'group={actual}' in detail."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root nobody 600 /etc/shadow", stderr=""
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
        assert "group=nobody" in r.detail

    def test_empty_stdout_exit_zero(self, mock_ssh):
        """AC-14: Empty stdout with exit code 0 -> FAIL as not found."""
        ssh = mock_ssh(
            {
                "stat": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/shadow",
            "owner": "root",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found" in r.detail

    def test_glob_key_presence_triggers_glob_mode(self, mock_ssh):
        """AC-15: 'glob' key presence forces glob mode even without glob chars in path."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 644 /etc/passwd", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/passwd",
            "owner": "root",
            "glob": True,
        }
        r = run_check(ssh, check)
        assert r.passed is True
        # Verify that stat was called — the mock matched on "stat" substring
        assert any("stat" in cmd for cmd in ssh.commands_run)

    def test_glob_auto_detect_from_path(self, mock_ssh):
        """AC-16: Glob chars in path auto-triggers glob mode without 'glob' key."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0,
                    stdout="root root 644 /etc/cron.d/job1\nroot root 644 /etc/cron.d/job2",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/cron.d/*",
            "owner": "root",
            "mode": "0644",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_expected_string_wildcard_for_unchecked(self, mock_ssh):
        """AC-17: Expected string uses '*' for attributes not in check definition."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="root root 644 /etc/passwd", stderr=""
                ),
            }
        )
        check = {
            "method": "file_permission",
            "path": "/etc/passwd",
            "owner": "root",
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.expected == "owner=root, group=*, mode=*"

    def test_evidence_on_fail_mismatch(self, mock_ssh):
        """AC-7: Evidence fields populated on fail (attribute mismatch)."""
        ssh = mock_ssh(
            {
                "stat": Result(
                    exit_code=0, stdout="nobody root 644 /etc/shadow", stderr=""
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
        assert r.evidence is not None
        assert r.evidence.method == "file_permission"
        assert r.evidence.exit_code == 0
        assert r.evidence.actual is not None
        assert "owner=nobody" in r.evidence.actual
        assert r.evidence.expected == "owner=root, group=root, mode=0600"


class TestCommand:
    def test_exit_code_matches(self, mock_ssh):
        """AC-1: Matching exit code (default 0), no expected_stdout -> PASS."""
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
        """AC-2: Mismatching exit code -> FAIL with exit codes in detail."""
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
        """AC-3: Non-empty expected_stdout substring found -> PASS."""
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
        """AC-4: Non-empty expected_stdout NOT found -> FAIL with 'stdout mismatch'."""
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
        """AC-5: expected_stdout='' with empty stdout -> PASS."""
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
        """AC-6: expected_stdout='' with non-empty stdout -> FAIL."""
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
        """AC-7: Non-zero expected_exit matching actual -> PASS."""
        ssh = mock_ssh(
            {
                "grep bad": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "command", "run": "grep bad /etc/conf", "expected_exit": 1}
        r = run_check(ssh, check)
        assert r.passed is True


class TestCommandSpecDerived:
    """Gap tests derived from command.spec.md acceptance criteria."""

    def test_exit_mismatch_detail_prefers_stderr(self, mock_ssh):
        """AC-8: Exit code mismatch detail shows stderr when non-empty."""
        ssh = mock_ssh(
            {
                "check-cmd": Result(
                    exit_code=2, stdout="some output", stderr="fatal error"
                ),
            }
        )
        check = {"method": "command", "run": "check-cmd", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "fatal error" in r.detail
        assert "exit 2" in r.detail

    def test_exit_mismatch_detail_falls_back_to_stdout(self, mock_ssh):
        """AC-8: Exit code mismatch detail shows stdout when stderr is empty."""
        ssh = mock_ssh(
            {
                "check-cmd": Result(exit_code=3, stdout="unexpected output", stderr=""),
            }
        )
        check = {"method": "command", "run": "check-cmd", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "unexpected output" in r.detail
        assert "exit 3" in r.detail

    def test_evidence_method_is_command_on_pass(self, mock_ssh):
        """AC-9: Evidence method is 'command' on pass path."""
        ssh = mock_ssh({"echo hello": Result(exit_code=0, stdout="hello", stderr="")})
        check = {"method": "command", "run": "echo hello"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.method == "command"

    def test_evidence_method_is_command_on_exit_fail(self, mock_ssh):
        """AC-9: Evidence method is 'command' on exit-code failure."""
        ssh = mock_ssh({"fail-cmd": Result(exit_code=1, stdout="", stderr="err")})
        check = {"method": "command", "run": "fail-cmd", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.method == "command"

    def test_evidence_method_is_command_on_stdout_fail(self, mock_ssh):
        """AC-9: Evidence method is 'command' on stdout-mismatch failure."""
        ssh = mock_ssh({"some-cmd": Result(exit_code=0, stdout="wrong", stderr="")})
        check = {
            "method": "command",
            "run": "some-cmd",
            "expected_stdout": "right",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.method == "command"

    def test_evidence_command_matches_run_value(self, mock_ssh):
        """AC-10: Evidence command is the run value from check definition."""
        ssh = mock_ssh({"ls -la /tmp": Result(exit_code=0, stdout="files", stderr="")})
        check = {"method": "command", "run": "ls -la /tmp"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.command == "ls -la /tmp"

    def test_evidence_expected_exit_only(self, mock_ssh):
        """AC-11: Evidence expected includes exit=N when no expected_stdout."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="ok", stderr="")})
        check = {"method": "command", "run": "cmd", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.expected == "exit=0"

    def test_evidence_expected_with_stdout(self, mock_ssh):
        """AC-11: Evidence expected includes stdout constraint when set."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="hello world", stderr="")})
        check = {
            "method": "command",
            "run": "cmd",
            "expected_exit": 0,
            "expected_stdout": "hello",
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert "exit=0" in r.evidence.expected
        assert "stdout contains 'hello'" in r.evidence.expected

    def test_evidence_actual_on_pass_with_stdout(self, mock_ssh):
        """AC-12: Evidence actual on pass is stdout[:200] when stdout truthy."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="result data", stderr="")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.actual == "result data"

    def test_evidence_actual_on_pass_empty_stdout(self, mock_ssh):
        """AC-12, AC-16: Evidence actual and detail are 'ok' when stdout empty."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.actual == "ok"
        assert r.detail == "ok"

    def test_evidence_actual_on_exit_failure(self, mock_ssh):
        """AC-13: Evidence actual on exit-code failure is 'exit=N'."""
        ssh = mock_ssh({"cmd": Result(exit_code=127, stdout="", stderr="not found")})
        check = {"method": "command", "run": "cmd", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.actual == "exit=127"

    def test_evidence_actual_on_stdout_mismatch_with_output(self, mock_ssh):
        """AC-14: Evidence actual on stdout mismatch is stdout[:200] when truthy."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="wrong data", stderr="")})
        check = {
            "method": "command",
            "run": "cmd",
            "expected_stdout": "right data",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.actual == "wrong data"

    def test_evidence_actual_on_stdout_mismatch_empty(self, mock_ssh):
        """AC-14: Evidence actual on stdout mismatch is '' when stdout falsy."""
        # expected_stdout="something" but stdout is empty -> mismatch
        # Wait: if stdout is empty, then "something" in "" is False -> mismatch.
        # But evidence.actual = stdout[:200] if stdout else "" -- stdout is "", falsy.
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="", stderr="")})
        check = {
            "method": "command",
            "run": "cmd",
            "expected_stdout": "something",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.actual == ""

    def test_pass_detail_truncates_long_stdout(self, mock_ssh):
        """AC-15: Pass detail truncates stdout to 200 characters."""
        long_output = "x" * 300
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout=long_output, stderr="")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert len(r.detail) == 200
        assert r.detail == "x" * 200
        # Evidence actual also truncated
        assert r.evidence is not None
        assert len(r.evidence.actual) == 200

    def test_evidence_stdout_not_truncated(self, mock_ssh):
        """AC-15 constraint: evidence.stdout preserves full raw output."""
        long_output = "x" * 300
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout=long_output, stderr="")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert len(r.evidence.stdout) == 300

    def test_evidence_timestamp_is_utc(self, mock_ssh):
        """AC-17: Evidence timestamp is a UTC datetime."""
        before = datetime.now(timezone.utc)
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="ok", stderr="")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        after = datetime.now(timezone.utc)
        assert r.evidence is not None
        assert isinstance(r.evidence.timestamp, datetime)
        assert r.evidence.timestamp.tzinfo is not None
        assert before <= r.evidence.timestamp <= after

    def test_expected_exit_defaults_to_zero(self, mock_ssh):
        """AC-18: expected_exit defaults to 0 when omitted."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="output", stderr="")})
        # No expected_exit in check dict
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "exit=0" in r.evidence.expected

    def test_expected_exit_defaults_to_zero_mismatch(self, mock_ssh):
        """AC-18: Omitted expected_exit defaults to 0; exit 1 is a mismatch."""
        ssh = mock_ssh({"cmd": Result(exit_code=1, stdout="", stderr="err")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected 0" in r.detail

    def test_evidence_preserves_stderr(self, mock_ssh):
        """AC-9/AC-10: Evidence stderr field captures raw stderr."""
        ssh = mock_ssh(
            {"cmd": Result(exit_code=0, stdout="ok", stderr="warning: something")}
        )
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.stderr == "warning: something"

    def test_stdout_mismatch_detail_contains_repr(self, mock_ssh):
        """AC-4 detail: stdout mismatch detail includes repr of stdout."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="actual output", stderr="")})
        check = {
            "method": "command",
            "run": "cmd",
            "expected_stdout": "expected",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "stdout mismatch" in r.detail
        assert "actual output" in r.detail

    def test_evidence_exit_code_on_pass(self, mock_ssh):
        """AC-9: Evidence exit_code reflects actual exit code on pass."""
        ssh = mock_ssh({"cmd": Result(exit_code=0, stdout="data", stderr="")})
        check = {"method": "command", "run": "cmd"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.exit_code == 0

    def test_evidence_exit_code_on_failure(self, mock_ssh):
        """AC-9: Evidence exit_code reflects actual exit code on failure."""
        ssh = mock_ssh({"cmd": Result(exit_code=42, stdout="", stderr="bad")})
        check = {"method": "command", "run": "cmd", "expected_exit": 0}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.exit_code == 42


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
        """AC-1: Enabled and active both True with matching state -> PASS."""
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
        """AC-2: Enabled True but actual active=inactive -> FAIL."""
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
        """AC-3: Enabled False with actual 'disabled' -> PASS."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="disabled", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_static_counts_as_enabled(self, mock_ssh):
        """AC-4: Static service counts as enabled -> PASS."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="static", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "systemd-journald", "enabled": True}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_masked_counts_as_disabled(self, mock_ssh):
        """AC-5: Masked service counts as disabled -> PASS."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="masked", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_enabled_when_should_be_disabled(self, mock_ssh):
        """AC-6: Enabled=False but actual 'enabled' -> FAIL with 'expected disabled'."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="enabled", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected disabled" in r.detail


class TestServiceStateSpecDerived:
    """Spec-derived gap tests for service_state handler.

    See specs/handlers/checks/service_state.spec.md for full specification.
    """

    def test_indirect_counts_as_enabled(self, mock_ssh):
        """AC-7: Indirect service counts as enabled -> PASS."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="indirect", stderr=""),
            }
        )
        check = {
            "method": "service_state",
            "name": "systemd-tmpfiles-clean.timer",
            "enabled": True,
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert "indirect" in r.detail

    def test_not_found_counts_as_disabled(self, mock_ssh):
        """AC-8: Not-found service counts as disabled -> PASS."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="not-found", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "enabled": False}
        r = run_check(ssh, check)
        assert r.passed is True
        assert "not-found" in r.detail

    def test_masked_fails_when_expected_enabled(self, mock_ssh):
        """AC-9: Enabled=True with actual 'masked' -> FAIL."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="masked", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "sshd", "enabled": True}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected enabled" in r.detail

    def test_active_true_but_inactive(self, mock_ssh):
        """AC-10: Active=True with actual 'inactive' -> FAIL."""
        ssh = mock_ssh(
            {
                "is-active": Result(exit_code=3, stdout="inactive", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "sshd", "active": True}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected active" in r.detail

    def test_active_false_but_active(self, mock_ssh):
        """AC-11: Active=False with actual 'active' -> FAIL."""
        ssh = mock_ssh(
            {
                "is-active": Result(exit_code=0, stdout="active", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "active": False}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "expected inactive" in r.detail

    def test_active_false_and_inactive(self, mock_ssh):
        """AC-12: Active=False with actual 'inactive' -> PASS."""
        ssh = mock_ssh(
            {
                "is-active": Result(exit_code=3, stdout="inactive", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "autofs", "active": False}
        r = run_check(ssh, check)
        assert r.passed is True
        assert "not active" in r.detail

    def test_active_only_no_enabled_key(self, mock_ssh):
        """AC-13: Only active specified -> only is-active runs."""
        ssh = mock_ssh(
            {
                "is-active": Result(exit_code=0, stdout="active", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "sshd", "active": True}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "is-active: active" in r.evidence.stdout
        # Should NOT contain is-enabled output since enabled was not checked
        assert "is-enabled" not in r.evidence.stdout

    def test_enabled_only_no_active_key(self, mock_ssh):
        """AC-14: Only enabled specified -> only is-enabled runs."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=0, stdout="enabled", stderr=""),
            }
        )
        check = {"method": "service_state", "name": "sshd", "enabled": True}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "is-enabled: enabled" in r.evidence.stdout
        # Should NOT contain is-active output since active was not checked
        assert "is-active" not in r.evidence.stdout

    def test_evidence_fields_on_pass(self, mock_ssh):
        """AC-15: Evidence populated correctly on pass."""
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
        assert r.evidence is not None
        assert r.evidence.method == "service_state"
        assert r.evidence.command == "systemctl is-enabled/is-active sshd"
        assert r.evidence.exit_code == 0
        assert "is-enabled: enabled" in r.evidence.stdout
        assert "is-active: active" in r.evidence.stdout
        assert "enabled=enabled" in r.evidence.expected
        assert "active=active" in r.evidence.expected
        assert "enabled=enabled" in r.evidence.actual
        assert "active=active" in r.evidence.actual
        assert r.evidence.timestamp is not None

    def test_evidence_fields_on_fail(self, mock_ssh):
        """AC-16: Evidence populated correctly on fail."""
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
        assert r.evidence is not None
        assert r.evidence.method == "service_state"
        assert r.evidence.exit_code == 1
        assert "is-active: inactive" in r.evidence.stdout
        assert "active=active" in r.evidence.expected
        assert "active=inactive" in r.evidence.actual

    def test_neither_enabled_nor_active_vacuous_pass(self, mock_ssh):
        """AC-17: Neither enabled nor active specified -> vacuous PASS."""
        ssh = mock_ssh({})
        check = {"method": "service_state", "name": "sshd"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.method == "service_state"
        assert r.evidence.exit_code == 0

    def test_both_dimensions_fail(self, mock_ssh):
        """AC-18: Both enabled and active fail -> detail has both failures."""
        ssh = mock_ssh(
            {
                "is-enabled": Result(exit_code=1, stdout="disabled", stderr=""),
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
        assert "expected enabled" in r.detail
        assert "expected active" in r.detail
        # Both failures joined by "; "
        assert "; " in r.detail


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
    """Tests for sshd_effective_config check handler.

    See specs/handlers/checks/sshd_effective_config.spec.md for full specification.
    """

    def test_key_matches(self, mock_ssh):
        """AC-1: Key present with matching value -> passed=True."""
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
        """AC-2: Key present with wrong value -> passed=False, detail contains 'expected'."""
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
        """AC-3: Key not found (command exit code != 0) -> passed=False, 'not found'."""
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


class TestSshdEffectiveConfigSpecDerived:
    """Spec-derived gap tests for sshd_effective_config handler.

    See specs/handlers/checks/sshd_effective_config.spec.md for full specification.
    """

    def test_not_found_empty_stdout_exit_zero(self, mock_ssh):
        """AC-4: Exit code 0 but stdout empty -> FAIL with 'not found', actual is None."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="", stderr=""),
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
        assert r.evidence is not None
        assert r.evidence.actual is None

    def test_evidence_fields_on_match(self, mock_ssh):
        """AC-5: Evidence fields fully populated on successful match."""
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
        assert r.evidence is not None
        assert r.evidence.method == "sshd_effective_config"
        assert r.evidence.command is not None
        assert "sshd -T" in r.evidence.command
        assert r.evidence.expected == "no"
        assert r.evidence.actual == "no"
        assert r.evidence.exit_code == 0
        assert r.evidence.stdout == "permitrootlogin no"
        assert r.evidence.timestamp is not None

    def test_evidence_fields_on_not_found(self, mock_ssh):
        """AC-6: Evidence populated on not-found path with actual=None."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=1, stdout="", stderr="some error"),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.evidence is not None
        assert r.evidence.method == "sshd_effective_config"
        assert r.evidence.actual is None
        assert r.evidence.expected == "no"
        assert r.evidence.stderr == "some error"

    def test_match_user_only(self, mock_ssh):
        """AC-7: match_user only -> command includes '-C user=...' without host."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin no", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
            "match_user": "testuser",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "-C" in r.evidence.command
        assert "user=" in r.evidence.command
        assert "host=" not in r.evidence.command

    def test_match_host_only(self, mock_ssh):
        """AC-8: match_host only -> command includes '-C host=...' without user."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin no", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
            "match_host": "10.0.0.1",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "-C" in r.evidence.command
        assert "host=" in r.evidence.command
        assert "user=" not in r.evidence.command

    def test_match_user_and_host(self, mock_ssh):
        """AC-9: Both match_user and match_host -> '-C user=...,host=...'."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin no", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
            "match_user": "testuser",
            "match_host": "10.0.0.1",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert "-C" in r.evidence.command
        assert "user=" in r.evidence.command
        assert "host=" in r.evidence.command

    def test_no_match_context_plain_command(self, mock_ssh):
        """AC-10: No match_user/match_host -> plain 'sshd -T' (no -C flag)."""
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
        assert r.evidence is not None
        assert "-C" not in r.evidence.command

    def test_case_insensitive_key_and_expected(self, mock_ssh):
        """AC-11: Key and expected are lowercased internally."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin no", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "No",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.expected == "no"
        assert r.evidence.actual == "no"

    def test_multiline_output_uses_first_line(self, mock_ssh):
        """AC-12: Multi-line output -> only first line used for value extraction."""
        ssh = mock_ssh(
            {
                "sshd": Result(
                    exit_code=0,
                    stdout="permitrootlogin no\npermitRootLogin yes",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "no",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.actual == "no"

    def test_key_only_line_empty_value(self, mock_ssh):
        """AC-13: Line with key but no value part -> actual is empty string."""
        ssh = mock_ssh(
            {
                "sshd": Result(exit_code=0, stdout="permitrootlogin", stderr=""),
            }
        )
        check = {
            "method": "sshd_effective_config",
            "key": "PermitRootLogin",
            "expected": "",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.actual == ""


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
        """AC-7: Numeric >= comparator when actual >= expected → PASS."""
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
        """AC-8: Numeric >= comparator when actual < expected → FAIL."""
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


class TestConfigValueSpecDerived:
    """Spec-derived gap tests for config_value handler.

    See specs/handlers/checks/config_value.spec.md for full specification.
    """

    def test_evidence_fields_populated(self, mock_ssh):
        """AC-9: Evidence fields populated on successful check."""
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
        assert r.evidence is not None
        assert r.evidence.method == "config_value"
        assert r.evidence.command is not None
        assert r.evidence.expected == "no"
        assert r.evidence.actual == "no"
        assert r.evidence.exit_code == 0
        assert r.evidence.stdout == "PermitRootLogin no"

    def test_invalid_comparator_rejected(self, mock_ssh):
        """AC-10: Invalid comparator → FAIL with descriptive error."""
        ssh = mock_ssh({})
        check = {
            "method": "config_value",
            "path": "/etc/security/pwquality.conf",
            "key": "minlen",
            "expected": "14",
            "comparator": "!=",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "Invalid comparator" in r.detail
        assert "!=" in r.detail

    def test_less_than_comparators(self, mock_ssh):
        """AC-11: Numeric < and <= comparators behave correctly."""
        ssh_lt = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="maxretries = 3", stderr=""),
            }
        )
        check_lt = {
            "method": "config_value",
            "path": "/etc/security/faillock.conf",
            "key": "maxretries",
            "expected": "5",
            "comparator": "<",
        }
        r = run_check(ssh_lt, check_lt)
        assert r.passed is True

        ssh_le = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="maxretries = 5", stderr=""),
            }
        )
        check_le = {
            "method": "config_value",
            "path": "/etc/security/faillock.conf",
            "key": "maxretries",
            "expected": "5",
            "comparator": "<=",
        }
        r = run_check(ssh_le, check_le)
        assert r.passed is True

        ssh_gt = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="maxretries = 2", stderr=""),
            }
        )
        check_gt = {
            "method": "config_value",
            "path": "/etc/security/faillock.conf",
            "key": "maxretries",
            "expected": "5",
            "comparator": ">",
        }
        r = run_check(ssh_gt, check_gt)
        assert r.passed is False

    def test_numeric_comparator_non_numeric_fallback(self, mock_ssh):
        """AC-12: Numeric comparator with non-numeric value → string fallback."""
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="LogLevel VERBOSE", stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "LogLevel",
            "expected": "VERBOSE",
            "comparator": ">=",
        }
        r = run_check(ssh, check)
        # Non-numeric values fall back to case-insensitive string equality
        assert r.passed is True

        ssh_fail = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="LogLevel INFO", stderr=""),
            }
        )
        check_fail = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "LogLevel",
            "expected": "VERBOSE",
            "comparator": ">=",
        }
        r = run_check(ssh_fail, check_fail)
        assert r.passed is False

    def test_quoted_value_extraction(self, mock_ssh):
        """AC-13: Quoted value extraction strips quotes."""
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout='Banner="/etc/issue"', stderr=""),
            }
        )
        check = {
            "method": "config_value",
            "path": "/etc/ssh/sshd_config",
            "key": "Banner",
            "expected": "/etc/issue",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.evidence is not None
        assert r.evidence.actual == "/etc/issue"

    def test_empty_stdout_exit_zero_not_found(self, mock_ssh):
        """AC-14: Empty stdout with exit code 0 → FAIL as not found."""
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep": Result(exit_code=0, stdout="", stderr=""),
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


class TestFileExistsSpecDerived:
    """Spec-derived gap tests for file_exists handler.

    See specs/handlers/checks/file_exists.spec.yaml for full specification.
    """

    def test_ac1_file_exists_returns_pass(self, mock_ssh):
        """AC-1: File exists returns pass."""
        ssh = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_ac2_file_not_found_returns_fail(self, mock_ssh):
        """AC-2: File missing returns fail."""
        ssh = mock_ssh({"test -e": Result(exit_code=1, stdout="", stderr="")})
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.passed is False

    def test_ac3_evidence_method(self, mock_ssh):
        """AC-3: Evidence method is file_exists."""
        ssh = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "file_exists"

    def test_ac4_evidence_command(self, mock_ssh):
        """AC-4: Evidence command contains test -e."""
        ssh = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert "test -e" in r.evidence.command

    def test_ac5_detail_format_pass(self, mock_ssh):
        """AC-5: Detail on pass is '{path}: exists'."""
        path = "/var/lib/aide/aide.db.gz"
        ssh = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "file_exists", "path": path}
        r = run_check(ssh, check)
        assert r.detail == f"{path}: exists"

    def test_ac6_evidence_timestamp(self, mock_ssh):
        """AC-6: Evidence timestamp is a UTC datetime."""
        ssh = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "file_exists", "path": "/var/lib/aide/aide.db.gz"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert isinstance(r.evidence.timestamp, datetime)
        assert r.evidence.timestamp.tzinfo == timezone.utc


class TestFileNotExistsSpecDerived:
    """Spec-derived gap tests for file_not_exists handler.

    See specs/handlers/checks/file_not_exists.spec.yaml for full specification.
    """

    def test_ac1_file_absent_returns_pass(self, mock_ssh):
        """AC-1: File absent returns pass."""
        ssh = mock_ssh({"test -e": Result(exit_code=1, stdout="", stderr="")})
        check = {"method": "file_not_exists", "path": "/etc/cron.deny"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_ac2_file_present_returns_fail(self, mock_ssh):
        """AC-2: File exists returns fail."""
        ssh = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        check = {"method": "file_not_exists", "path": "/etc/cron.deny"}
        r = run_check(ssh, check)
        assert r.passed is False

    def test_ac3_evidence_method(self, mock_ssh):
        """AC-3: Evidence method is file_not_exists."""
        ssh = mock_ssh({"test -e": Result(exit_code=1, stdout="", stderr="")})
        check = {"method": "file_not_exists", "path": "/etc/cron.deny"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "file_not_exists"

    def test_ac4_detail_format(self, mock_ssh):
        """AC-4: Detail contains expected strings on pass and fail."""
        path = "/etc/cron.deny"
        ssh_pass = mock_ssh({"test -e": Result(exit_code=1, stdout="", stderr="")})
        r = run_check(ssh_pass, {"method": "file_not_exists", "path": path})
        assert "not present (as required)" in r.detail

        ssh_fail = mock_ssh({"test -e": Result(exit_code=0, stdout="", stderr="")})
        r = run_check(ssh_fail, {"method": "file_not_exists", "path": path})
        assert "should be absent" in r.detail

    def test_ac5_evidence_expected(self, mock_ssh):
        """AC-5: Evidence expected is 'absent'."""
        ssh = mock_ssh({"test -e": Result(exit_code=1, stdout="", stderr="")})
        check = {"method": "file_not_exists", "path": "/etc/cron.deny"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.expected == "absent"


class TestFileContentSpecDerived:
    """Spec-derived gap tests for file_content handler.

    See specs/handlers/checks/file_content.spec.yaml for full specification.
    """

    def test_ac1_content_matches(self, mock_ssh):
        """AC-1: Exact content match returns pass."""
        banner = "Authorized uses only."
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout=banner, stderr="")})
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_ac2_content_mismatch(self, mock_ssh):
        """AC-2: Different content returns fail."""
        ssh = mock_ssh(
            {"cat": Result(exit_code=0, stdout="Old banner text.", stderr="")}
        )
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": "New consent warning.",
        }
        r = run_check(ssh, check)
        assert r.passed is False

    def test_ac3_file_not_readable(self, mock_ssh):
        """AC-3: Non-zero exit code returns fail with 'not found or not readable'."""
        ssh = mock_ssh({"cat": Result(exit_code=1, stdout="", stderr="No such file")})
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": "Banner text",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "not found or not readable" in r.detail

    def test_ac4_evidence_method(self, mock_ssh):
        """AC-4: Evidence method is file_content."""
        banner = "Authorized uses only."
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout=banner, stderr="")})
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "file_content"

    def test_ac5_content_stripped(self, mock_ssh):
        """AC-5: Trailing/leading whitespace stripped before comparison."""
        ssh = mock_ssh(
            {"cat": Result(exit_code=0, stdout="  Banner text  \n", stderr="")}
        )
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": "  Banner text  \n",
        }
        r = run_check(ssh, check)
        assert r.passed is True

    def test_ac6_detail_pass_format(self, mock_ssh):
        """AC-6: Detail on pass is '{path}: content matches expected'."""
        path = "/etc/issue"
        banner = "Authorized uses only."
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout=banner, stderr="")})
        check = {
            "method": "file_content",
            "path": path,
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.detail == f"{path}: content matches expected"

    def test_ac7_detail_fail_format(self, mock_ssh):
        """AC-7: Detail on fail is '{path}: content does not match expected'."""
        path = "/etc/issue"
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout="wrong content", stderr="")})
        check = {
            "method": "file_content",
            "path": path,
            "expected_content": "expected content",
        }
        r = run_check(ssh, check)
        assert r.detail == f"{path}: content does not match expected"

    def test_ac8_evidence_expected(self, mock_ssh):
        """AC-8: Evidence expected is the expected content (stripped)."""
        banner = "  Authorized uses only.  "
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout=banner.strip(), stderr="")})
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.expected == banner.strip()

    def test_ac9_evidence_command(self, mock_ssh):
        """AC-9: Evidence command contains 'cat'."""
        banner = "Authorized uses only."
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout=banner, stderr="")})
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert "cat" in r.evidence.command

    def test_ac10_evidence_timestamp(self, mock_ssh):
        """AC-10: Evidence timestamp is a UTC datetime."""
        banner = "Authorized uses only."
        ssh = mock_ssh({"cat": Result(exit_code=0, stdout=banner, stderr="")})
        check = {
            "method": "file_content",
            "path": "/etc/issue",
            "expected_content": banner,
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert isinstance(r.evidence.timestamp, datetime)
        assert r.evidence.timestamp.tzinfo == timezone.utc


class TestFileContentMatchSpecDerived:
    """Spec-derived gap tests for file_content_match handler.

    See specs/handlers/checks/file_content_match.spec.yaml for full specification.
    """

    def test_ac1_pattern_found(self, mock_ssh):
        """AC-1: Grep succeeds returns pass."""
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

    def test_ac2_pattern_not_found(self, mock_ssh):
        """AC-2: Grep fails returns fail."""
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

    def test_ac3_file_not_found(self, mock_ssh):
        """AC-3: File missing returns fail with 'not found' in detail."""
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

    def test_ac4_evidence_method(self, mock_ssh):
        """AC-4: Evidence method is file_content_match."""
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
        assert r.evidence is not None
        assert r.evidence.method == "file_content_match"

    def test_ac5_evidence_expected_includes_pattern(self, mock_ssh):
        """AC-5: Evidence expected includes the pattern."""
        pattern = "^ENCRYPT_METHOD\\s+SHA512"
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -qE": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        check = {
            "method": "file_content_match",
            "path": "/etc/login.defs",
            "pattern": pattern,
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert pattern in r.evidence.expected

    def test_ac6_evidence_actual_found(self, mock_ssh):
        """AC-6: Evidence actual is 'pattern found' on pass."""
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
        assert r.evidence is not None
        assert r.evidence.actual == "pattern found"

    def test_ac7_evidence_actual_not_found(self, mock_ssh):
        """AC-7: Evidence actual is 'pattern not found' on fail."""
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
        assert r.evidence is not None
        assert r.evidence.actual == "pattern not found"

    def test_ac8_uses_grep_qe(self, mock_ssh):
        """AC-8: Evidence command contains 'grep -qE' when file exists."""
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
        assert r.evidence is not None
        assert "grep -qE" in r.evidence.command


class TestFileContentNoMatchSpecDerived:
    """Spec-derived gap tests for file_content_no_match handler.

    See specs/handlers/checks/file_content_no_match.spec.yaml for full specification.
    """

    def test_ac1_file_absent_passes(self, mock_ssh):
        """AC-1: File missing returns pass."""
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

    def test_ac2_pattern_not_found_passes(self, mock_ssh):
        """AC-2: Pattern absent returns pass."""
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

    def test_ac3_pattern_found_fails(self, mock_ssh):
        """AC-3: Pattern present returns fail."""
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

    def test_ac4_evidence_method(self, mock_ssh):
        """AC-4: Evidence method is file_content_no_match."""
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
        assert r.evidence is not None
        assert r.evidence.method == "file_content_no_match"

    def test_ac5_file_missing_detail(self, mock_ssh):
        """AC-5: Detail on file missing contains expected string."""
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
        assert "not found (pattern cannot exist)" in r.detail

    def test_ac6_detail_format_fail(self, mock_ssh):
        """AC-6: Detail on fail contains 'contains prohibited pattern'."""
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
        assert "contains prohibited pattern" in r.detail


class TestConfigAbsentSpecDerived:
    """Spec-derived gap tests for config_absent handler.

    See specs/handlers/checks/config_absent.spec.yaml for full specification.
    """

    def test_ac1_key_absent_passes(self, mock_ssh):
        """AC-1: Key not found returns pass."""
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

    def test_ac2_key_found_fails(self, mock_ssh):
        """AC-2: Key found returns fail."""
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

    def test_ac3_evidence_method(self, mock_ssh):
        """AC-3: Evidence method is config_absent."""
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
        assert r.evidence is not None
        assert r.evidence.method == "config_absent"

    def test_ac4_detail_format_pass(self, mock_ssh):
        """AC-4: Detail on pass contains 'not found in' and '(as required)'."""
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
        assert "not found in" in r.detail
        assert "(as required)" in r.detail

    def test_ac5_detail_format_fail(self, mock_ssh):
        """AC-5: Detail on fail contains 'should be absent'."""
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
        assert "should be absent" in r.detail

    def test_ac6_evidence_expected_null(self, mock_ssh):
        """AC-6: Evidence expected is None on pass path."""
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
        assert r.evidence is not None
        assert r.evidence.expected is None


class TestAuditRuleExistsSpecDerived:
    """Spec-derived tests for audit_rule_exists handler.

    See specs/handlers/checks/audit_rule_exists.spec.yaml for full specification.
    """

    def test_rule_found_returns_pass(self, mock_ssh):
        """AC-1: Rule pattern found in normalized auditctl output returns passed=True."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/passwd -p wa -k identity",
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
        assert r.detail == "Audit rule found"

    def test_rule_not_found_returns_fail(self, mock_ssh):
        """AC-2: Rule pattern not found returns passed=False with truncated detail."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-w /etc/shadow -p wa -k identity",
                    stderr="",
                ),
            }
        )
        rule = "-w /etc/passwd -p wa -k identity"
        check = {"method": "audit_rule_exists", "rule": rule}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "Audit rule not found" in r.detail
        assert rule[:50] in r.detail

    def test_auditctl_failure_returns_fail(self, mock_ssh):
        """AC-3: auditctl command failing returns passed=False."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        check = {"method": "audit_rule_exists", "rule": "-w /etc/passwd"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "auditctl failed - auditd may not be running"

    def test_normalize_key_format(self, mock_ssh):
        """AC-4: Normalization converts '-F key=X' to '-k X' before matching."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-a always,exit -F arch=b64 -S open -F key=access",
                    stderr="",
                ),
            }
        )
        check = {"method": "audit_rule_exists", "rule": "-k access"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_normalize_auid_unset(self, mock_ssh):
        """AC-5: Normalization converts 'auid!=-1' and 'auid!=4294967295' to 'auid!=unset'."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-a always,exit -F auid>=1000 -F auid!=4294967295 -F key=priv",
                    stderr="",
                ),
            }
        )
        check = {"method": "audit_rule_exists", "rule": "auid!=unset -k priv"}
        r = run_check(ssh, check)
        assert r.passed is True

    def test_evidence_method_always_audit_rule_exists(self, mock_ssh):
        """AC-6: Evidence method is always 'audit_rule_exists'."""
        ssh = mock_ssh(
            {
                "auditctl -l": Result(exit_code=1, stdout="", stderr="err"),
            }
        )
        check = {"method": "audit_rule_exists", "rule": "-w /etc/passwd"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "audit_rule_exists"

    def test_evidence_expected_truncated_pattern(self, mock_ssh):
        """AC-7: Evidence expected contains rule pattern truncated to 50 chars."""
        long_rule = "a" * 100
        ssh = mock_ssh(
            {
                "auditctl -l": Result(exit_code=0, stdout="no match", stderr=""),
            }
        )
        check = {"method": "audit_rule_exists", "rule": long_rule}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.expected == f"contains '{long_rule[:50]}'"

    def test_evidence_actual_values(self, mock_ssh):
        """AC-8: Evidence actual is 'found'/'not found'/None depending on path."""
        # Pass path: actual = 'found'
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0, stdout="-w /etc/passwd -p wa", stderr=""
                ),
            }
        )
        check = {"method": "audit_rule_exists", "rule": "-w /etc/passwd -p wa"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.actual == "found"

        # Fail path: actual = 'not found'
        ssh2 = mock_ssh(
            {
                "auditctl -l": Result(exit_code=0, stdout="other rule", stderr=""),
            }
        )
        r2 = run_check(ssh2, check)
        assert r2.evidence is not None
        assert r2.evidence.actual == "not found"

        # Command failure path: actual = None
        ssh3 = mock_ssh(
            {
                "auditctl -l": Result(exit_code=1, stdout="", stderr="err"),
            }
        )
        r3 = run_check(ssh3, check)
        assert r3.evidence is not None
        assert r3.evidence.actual is None


class TestGrubParameterSpecDerived:
    """Spec-derived tests for grub_parameter handler.

    See specs/handlers/checks/grub_parameter.spec.yaml for full specification.
    """

    def test_value_match_returns_pass(self, mock_ssh):
        """AC-1: Parameter found with value matching expected returns passed=True."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto audit=1"',
                    stderr="",
                ),
            }
        )
        check = {"method": "grub_parameter", "key": "audit", "expected": "1"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "audit=1"

    def test_value_mismatch_returns_fail(self, mock_ssh):
        """AC-2: Parameter found with value not matching returns passed=False."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro audit=0"',
                    stderr="",
                ),
            }
        )
        check = {"method": "grub_parameter", "key": "audit", "expected": "1"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "audit=0" in r.detail
        assert "expected 1" in r.detail

    def test_parameter_not_found(self, mock_ssh):
        """AC-3: Parameter not found in kernel args returns passed=False."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro crashkernel=auto"',
                    stderr="",
                ),
            }
        )
        check = {"method": "grub_parameter", "key": "audit", "expected": "1"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "audit not found in kernel args"

    def test_grubby_not_available(self, mock_ssh):
        """AC-4: Grubby command failing returns passed=False."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=1, stdout="", stderr="not found"),
            }
        )
        check = {"method": "grub_parameter", "key": "audit", "expected": "1"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "grubby not available"

    def test_presence_only_check_pass(self, mock_ssh):
        """AC-5: Presence-only check (expected is None) with parameter present returns passed=True."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro quiet splash"',
                    stderr="",
                ),
            }
        )
        check = {"method": "grub_parameter", "key": "quiet"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "quiet present"

    def test_presence_without_value_but_value_expected(self, mock_ssh):
        """AC-6: Parameter present without value but expected has a value returns passed=False."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=0,
                    stdout='args="ro quiet splash"',
                    stderr="",
                ),
            }
        )
        check = {"method": "grub_parameter", "key": "quiet", "expected": "1"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "quiet present but expected value 1"

    def test_evidence_method_always_grub_parameter(self, mock_ssh):
        """AC-7: Evidence method is always 'grub_parameter'."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=1, stdout="", stderr="err"),
            }
        )
        check = {"method": "grub_parameter", "key": "audit"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "grub_parameter"


class TestKernelModuleStateSpecDerived:
    """Spec-derived tests for kernel_module_state handler.

    See specs/handlers/checks/kernel_module_state.spec.yaml for full specification.
    """

    def test_blacklisted_not_loaded_with_directive(self, mock_ssh):
        """AC-1: Module not loaded and blacklist directive present returns passed=True."""
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
        assert r.detail == "cramfs: blacklisted"

    def test_still_loaded_returns_fail(self, mock_ssh):
        """AC-2: Module still loaded when state is blacklisted returns passed=False."""
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
        assert r.detail == "cramfs: still loaded"

    def test_not_loaded_no_directive_returns_fail(self, mock_ssh):
        """AC-3: Module not loaded but no blacklist directive returns passed=False."""
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
        assert r.detail == "cramfs: not blacklisted"

    def test_loaded_when_expected_loaded(self, mock_ssh):
        """AC-4: Module loaded when state='loaded' returns passed=True."""
        ssh = mock_ssh(
            {
                "lsmod": Result(exit_code=0, stdout="ip_tables 16384 0", stderr=""),
            }
        )
        check = {
            "method": "kernel_module_state",
            "name": "ip_tables",
            "state": "loaded",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "ip_tables: loaded"

    def test_not_loaded_when_expected_loaded(self, mock_ssh):
        """AC-5: Module not loaded when state='loaded' returns passed=False."""
        ssh = mock_ssh(
            {
                "lsmod": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "kernel_module_state",
            "name": "ip_tables",
            "state": "loaded",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "ip_tables: not loaded"

    def test_unknown_state_returns_fail(self, mock_ssh):
        """AC-6: Unknown state value returns passed=False with error detail."""
        ssh = mock_ssh({})
        check = {
            "method": "kernel_module_state",
            "name": "cramfs",
            "state": "invalid_state",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "Unknown module state: invalid_state"
        assert r.evidence is not None
        assert r.evidence.method == "error"

    def test_evidence_method_valid_vs_error(self, mock_ssh):
        """AC-7: Evidence method is 'kernel_module_state' for valid, 'error' for unknown."""
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
        assert r.evidence is not None
        assert r.evidence.method == "kernel_module_state"

    def test_disabled_treated_same_as_blacklisted(self, mock_ssh):
        """AC-8: 'disabled' and 'blacklisted' states are treated identically."""
        ssh = mock_ssh(
            {
                "lsmod": Result(exit_code=1, stdout="", stderr=""),
                "modprobe": Result(exit_code=0, stdout="install /bin/false", stderr=""),
            }
        )
        check = {
            "method": "kernel_module_state",
            "name": "cramfs",
            "state": "disabled",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "cramfs: blacklisted"


class TestMountOptionSpecDerived:
    """Spec-derived tests for mount_option handler.

    See specs/handlers/checks/mount_option.spec.yaml for full specification.
    """

    def test_all_options_present_returns_pass(self, mock_ssh):
        """AC-1: All required options present returns passed=True."""
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
        assert r.detail == "/tmp: has required options"

    def test_missing_options_returns_fail(self, mock_ssh):
        """AC-2: One or more options missing returns passed=False."""
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

    def test_not_mounted_returns_fail(self, mock_ssh):
        """AC-3: Mount point not mounted returns passed=False."""
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
        assert r.detail == "/tmp: not mounted"

    def test_evidence_method_always_mount_option(self, mock_ssh):
        """AC-4: Evidence method is always 'mount_option'."""
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
        assert r.evidence is not None
        assert r.evidence.method == "mount_option"

    def test_evidence_expected_comma_joined(self, mock_ssh):
        """AC-5: Evidence expected is the comma-joined list of required options."""
        ssh = mock_ssh(
            {
                "findmnt": Result(
                    exit_code=0, stdout="rw,nosuid,nodev,noexec", stderr=""
                ),
            }
        )
        check = {
            "method": "mount_option",
            "mount_point": "/tmp",
            "options": ["nosuid", "nodev", "noexec"],
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.expected == "nosuid,nodev,noexec"

    def test_fail_detail_lists_specific_missing_options(self, mock_ssh):
        """AC-6: Detail on failure lists the specific missing options comma-separated."""
        ssh = mock_ssh(
            {
                "findmnt": Result(exit_code=0, stdout="rw,relatime", stderr=""),
            }
        )
        check = {
            "method": "mount_option",
            "mount_point": "/var",
            "options": ["nosuid", "nodev"],
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "nosuid" in r.detail
        assert "nodev" in r.detail

    def test_evidence_timestamp_is_utc(self, mock_ssh):
        """AC-7: Evidence timestamp is a UTC datetime captured before the command executes."""
        before = datetime.now(timezone.utc)
        ssh = mock_ssh(
            {
                "findmnt": Result(exit_code=0, stdout="rw,nosuid,nodev", stderr=""),
            }
        )
        check = {
            "method": "mount_option",
            "mount_point": "/tmp",
            "options": ["nosuid"],
        }
        r = run_check(ssh, check)
        after = datetime.now(timezone.utc)
        assert r.evidence is not None
        assert isinstance(r.evidence.timestamp, datetime)
        assert r.evidence.timestamp.tzinfo is not None
        assert before <= r.evidence.timestamp <= after

    def test_evidence_actual_none_when_not_mounted(self, mock_ssh):
        """AC-8: Evidence actual is None when not mounted, full options string on success."""
        # Not mounted: actual = None
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
        assert r.evidence is not None
        assert r.evidence.actual is None

        # Mounted: actual = stripped stdout
        ssh2 = mock_ssh(
            {
                "findmnt": Result(
                    exit_code=0, stdout="rw,nosuid,nodev,relatime", stderr=""
                ),
            }
        )
        r2 = run_check(ssh2, check)
        assert r2.evidence is not None
        assert r2.evidence.actual == "rw,nosuid,nodev,relatime"


class TestPackageStateSpecDerived:
    """Spec-derived tests for package_state handler.

    See specs/handlers/checks/package_state.spec.yaml for full specification.
    """

    def test_present_installed_returns_pass_with_version(self, mock_ssh):
        """AC-1: Package installed when state='present' returns passed=True with version."""
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
        assert r.detail == "aide: aide-0.16-14.el9.x86_64"

    def test_present_not_installed_returns_fail(self, mock_ssh):
        """AC-2: Package not installed when state='present' returns passed=False."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "package_state", "name": "aide", "state": "present"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "aide: not installed"

    def test_absent_not_installed_returns_pass(self, mock_ssh):
        """AC-3: Package not installed when state='absent' returns passed=True."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {"method": "package_state", "name": "telnet", "state": "absent"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "telnet: not installed (as required)"

    def test_absent_but_installed_returns_fail(self, mock_ssh):
        """AC-4: Package installed when state='absent' returns passed=False."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=0, stdout="telnet-0.17-85.el9.x86_64", stderr=""
                ),
            }
        )
        check = {"method": "package_state", "name": "telnet", "state": "absent"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "telnet: installed (should be absent)"

    def test_unknown_state_returns_fail(self, mock_ssh):
        """AC-5: Unknown state value returns passed=False with error evidence."""
        ssh = mock_ssh({})
        check = {"method": "package_state", "name": "aide", "state": "invalid"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "Unknown package state: invalid"
        assert r.evidence is not None
        assert r.evidence.method == "error"

    def test_evidence_method_valid_vs_error(self, mock_ssh):
        """AC-6: Evidence method is 'package_state' for valid, 'error' for unknown."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(
                    exit_code=0, stdout="aide-0.16-14.el9.x86_64", stderr=""
                ),
            }
        )
        check = {"method": "package_state", "name": "aide", "state": "present"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "package_state"


class TestPamModuleSpecDerived:
    """Spec-derived tests for pam_module handler.

    See specs/handlers/checks/pam_module.spec.yaml for full specification.
    """

    def test_module_found_matching_all_criteria(self, mock_ssh):
        """AC-1: Module found matching all specified criteria returns passed=True."""
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
        assert "auth" in r.detail
        assert "required" in r.detail
        assert "pam_faillock.so" in r.detail

    def test_module_not_found_in_pam_file(self, mock_ssh):
        """AC-2: Module not found in PAM file returns passed=False."""
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
        assert r.detail == "pam_faillock.so not found in /etc/pam.d/system-auth"

    def test_pam_file_does_not_exist(self, mock_ssh):
        """AC-3: PAM file does not exist returns passed=False."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
                "test -e": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        check = {
            "method": "pam_module",
            "service": "nonexistent",
            "module": "pam_faillock.so",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "/etc/pam.d/nonexistent: not found"

    def test_type_mismatch_skips_line(self, mock_ssh):
        """AC-4: Module found but type mismatch skips the line, returns passed=False."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep": Result(
                    exit_code=0,
                    stdout="password    required      pam_pwquality.so",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "pam_module",
            "service": "system-auth",
            "module": "pam_pwquality.so",
            "type": "auth",
        }
        r = run_check(ssh, check)
        assert r.passed is False

    def test_control_mismatch_skips_line(self, mock_ssh):
        """AC-5: Module found but control mismatch skips the line, returns passed=False."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep": Result(
                    exit_code=0,
                    stdout="auth        sufficient    pam_faillock.so",
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
        assert r.passed is False

    def test_args_mismatch_skips_line(self, mock_ssh):
        """AC-6: Module found but args substring not present skips the line."""
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
            "args": "authfail",
        }
        r = run_check(ssh, check)
        assert r.passed is False

    def test_evidence_method_always_pam_module(self, mock_ssh):
        """AC-7: Evidence method is always 'pam_module'."""
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
        assert r.evidence is not None
        assert r.evidence.method == "pam_module"

    def test_criteria_mismatch_detail_includes_unmatched(self, mock_ssh):
        """AC-8: Criteria mismatch detail includes the specific criteria not found."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep": Result(
                    exit_code=0,
                    stdout="password    sufficient    pam_unix.so sha512",
                    stderr="",
                ),
            }
        )
        check = {
            "method": "pam_module",
            "service": "system-auth",
            "module": "pam_unix.so",
            "type": "auth",
            "control": "required",
            "args": "nullok",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert "type=auth" in r.detail
        assert "control=required" in r.detail
        assert "nullok" in r.detail


class TestSelinuxBooleanSpecDerived:
    """Spec-derived tests for selinux_boolean handler.

    See specs/handlers/checks/selinux_boolean.spec.yaml for full specification.
    """

    def test_value_matches_returns_pass(self, mock_ssh):
        """AC-1: Boolean value matching expected returns passed=True."""
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
        assert r.detail == "httpd_can_network_connect = on"

    def test_value_mismatch_returns_fail(self, mock_ssh):
        """AC-2: Boolean value not matching expected returns passed=False."""
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
        assert r.detail == "httpd_can_network_connect = off (expected on)"

    def test_not_found_returns_fail(self, mock_ssh):
        """AC-3: Boolean not found or SELinux disabled returns passed=False."""
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
        assert r.detail == "nonexistent_bool: not found or SELinux disabled"

    def test_unexpected_output_format(self, mock_ssh):
        """AC-4: Unexpected output format (fewer than 3 tokens) returns passed=False."""
        ssh = mock_ssh(
            {
                "getsebool": Result(exit_code=0, stdout="garbled", stderr=""),
            }
        )
        check = {
            "method": "selinux_boolean",
            "name": "test_bool",
            "value": True,
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "test_bool: unexpected output format"

    def test_evidence_method_always_selinux_boolean(self, mock_ssh):
        """AC-5: Evidence method is always 'selinux_boolean'."""
        ssh = mock_ssh(
            {
                "getsebool": Result(exit_code=1, stdout="", stderr="err"),
            }
        )
        check = {
            "method": "selinux_boolean",
            "name": "test_bool",
            "value": True,
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "selinux_boolean"

    def test_evidence_expected_on_off_string(self, mock_ssh):
        """AC-6: Evidence expected is 'on' when value=True, 'off' when value=False."""
        ssh_on = mock_ssh(
            {
                "getsebool": Result(exit_code=0, stdout="test --> on", stderr=""),
            }
        )
        check_on = {
            "method": "selinux_boolean",
            "name": "test",
            "value": True,
        }
        r = run_check(ssh_on, check_on)
        assert r.evidence is not None
        assert r.evidence.expected == "on"

        ssh_off = mock_ssh(
            {
                "getsebool": Result(exit_code=0, stdout="test --> off", stderr=""),
            }
        )
        check_off = {
            "method": "selinux_boolean",
            "name": "test",
            "value": False,
        }
        r2 = run_check(ssh_off, check_off)
        assert r2.evidence is not None
        assert r2.evidence.expected == "off"


class TestSelinuxStateSpecDerived:
    """Spec-derived tests for selinux_state handler.

    See specs/handlers/checks/selinux_state.spec.yaml for full specification.
    """

    def test_mode_matches_returns_pass(self, mock_ssh):
        """AC-1: SELinux mode matching expected (case-insensitive) returns passed=True."""
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=0, stdout="Enforcing", stderr=""),
            }
        )
        check = {"method": "selinux_state", "state": "Enforcing"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "SELinux: Enforcing"

    def test_mode_mismatch_returns_fail(self, mock_ssh):
        """AC-2: SELinux mode not matching expected returns passed=False."""
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=0, stdout="Permissive", stderr=""),
            }
        )
        check = {"method": "selinux_state", "state": "Enforcing"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "SELinux: Permissive (expected Enforcing)"

    def test_getenforce_fails_returns_fail(self, mock_ssh):
        """AC-3: getenforce command failing returns passed=False."""
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=1, stdout="", stderr="not found"),
            }
        )
        check = {"method": "selinux_state"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "getenforce failed - SELinux may not be installed"

    def test_evidence_method_always_selinux_state(self, mock_ssh):
        """AC-4: Evidence method is always 'selinux_state'."""
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=1, stdout="", stderr="err"),
            }
        )
        check = {"method": "selinux_state"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "selinux_state"

    def test_case_insensitive_comparison(self, mock_ssh):
        """AC-5: Comparison uses case-insensitive matching."""
        ssh = mock_ssh(
            {
                "getenforce": Result(exit_code=0, stdout="enforcing", stderr=""),
            }
        )
        check = {"method": "selinux_state", "state": "Enforcing"}
        r = run_check(ssh, check)
        assert r.passed is True


class TestSysctlValueSpecDerived:
    """Spec-derived tests for sysctl_value handler.

    See specs/handlers/checks/sysctl_value.spec.yaml for full specification.
    """

    def test_value_matches_returns_pass(self, mock_ssh):
        """AC-1: Sysctl value matching expected returns passed=True."""
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
        assert r.detail == "net.ipv4.ip_forward=0"

    def test_value_mismatch_returns_fail(self, mock_ssh):
        """AC-2: Sysctl value not matching expected returns passed=False."""
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
        assert r.detail == "net.ipv4.ip_forward=1 (expected 0)"

    def test_sysctl_not_available_returns_fail(self, mock_ssh):
        """AC-3: Sysctl command failing returns passed=False."""
        ssh = mock_ssh(
            {
                "sysctl": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        check = {
            "method": "sysctl_value",
            "key": "nonexistent.param",
            "expected": "0",
        }
        r = run_check(ssh, check)
        assert r.passed is False
        assert r.detail == "sysctl nonexistent.param: not available"

    def test_evidence_method_always_sysctl_value(self, mock_ssh):
        """AC-4: Evidence method is always 'sysctl_value'."""
        ssh = mock_ssh(
            {
                "sysctl": Result(exit_code=1, stdout="", stderr="err"),
            }
        )
        check = {
            "method": "sysctl_value",
            "key": "net.ipv4.ip_forward",
            "expected": "0",
        }
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "sysctl_value"

    def test_detail_format_pass_and_mismatch(self, mock_ssh):
        """AC-5: Detail format on pass is 'key=actual'; on mismatch includes expected."""
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=0, stdout="1", stderr=""),
            }
        )
        check = {
            "method": "sysctl_value",
            "key": "net.ipv4.ip_forward",
            "expected": "1",
        }
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "net.ipv4.ip_forward=1"

    def test_evidence_timestamp_is_utc(self, mock_ssh):
        """AC-6: Evidence timestamp is a UTC datetime captured before the command executes."""
        before = datetime.now(timezone.utc)
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
        after = datetime.now(timezone.utc)
        assert r.evidence is not None
        assert isinstance(r.evidence.timestamp, datetime)
        assert r.evidence.timestamp.tzinfo is not None
        assert before <= r.evidence.timestamp <= after


class TestSystemdTargetSpecDerived:
    """Spec-derived tests for systemd_target handler.

    See specs/handlers/checks/systemd_target.spec.yaml for full specification.
    """

    def test_expected_target_matches(self, mock_ssh):
        """AC-1: Default target matching expected returns passed=True."""
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="multi-user.target", stderr=""
                ),
            }
        )
        check = {"method": "systemd_target", "expected": "multi-user.target"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "default target is multi-user.target"

    def test_expected_target_mismatch(self, mock_ssh):
        """AC-2: Default target not matching expected returns passed=False."""
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="graphical.target", stderr=""
                ),
            }
        )
        check = {"method": "systemd_target", "expected": "multi-user.target"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert (
            r.detail
            == "default target is graphical.target (expected multi-user.target)"
        )

    def test_not_expected_passes_when_different(self, mock_ssh):
        """AC-3: Default target not matching not_expected returns passed=True."""
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="multi-user.target", stderr=""
                ),
            }
        )
        check = {"method": "systemd_target", "not_expected": "graphical.target"}
        r = run_check(ssh, check)
        assert r.passed is True
        assert r.detail == "default target is multi-user.target"

    def test_not_expected_fails_when_matching(self, mock_ssh):
        """AC-4: Default target matching not_expected returns passed=False."""
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="graphical.target", stderr=""
                ),
            }
        )
        check = {"method": "systemd_target", "not_expected": "graphical.target"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert (
            r.detail
            == "default target is graphical.target (should not be graphical.target)"
        )

    def test_evidence_method_always_systemd_target(self, mock_ssh):
        """AC-5: Evidence method is always 'systemd_target'."""
        ssh = mock_ssh(
            {
                "systemctl get-default": Result(
                    exit_code=0, stdout="multi-user.target", stderr=""
                ),
            }
        )
        check = {"method": "systemd_target", "expected": "multi-user.target"}
        r = run_check(ssh, check)
        assert r.evidence is not None
        assert r.evidence.method == "systemd_target"


class TestUnknownMethod:
    def test_unknown_check_method(self, mock_ssh):
        ssh = mock_ssh({})
        check = {"method": "nonexistent_method"}
        r = run_check(ssh, check)
        assert r.passed is False
        assert "Unknown check method" in r.detail
