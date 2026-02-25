"""SpecDerived tests for shell_util module."""

from __future__ import annotations

import shlex

from runner.shell_util import (
    escape_grep_bre,
    escape_sed,
    file_exists,
    get_file_stat,
    grep_config_key,
    is_glob_path,
    parse_config_value,
    quote,
    sed_replace_line,
    service_action,
)
from runner.ssh import Result


class TestShellUtilSpecDerived:
    """Spec-derived tests for shell_util.

    See specs/internal/shell_util.spec.yaml for specification.
    """

    def test_ac1_quote_returns_shlex_quote(self):
        """AC-1: quote(value) returns shlex.quote(str(value))."""
        assert quote("hello world") == shlex.quote("hello world")
        assert quote("it's") == shlex.quote("it's")
        assert quote("/etc/passwd") == shlex.quote("/etc/passwd")
        # Numeric values are converted to str
        assert quote(42) == shlex.quote("42")

    def test_ac2_is_glob_path_detects_globs(self):
        """AC-2: is_glob_path(path) returns True if path contains *, ?, or [ characters."""
        assert is_glob_path("/etc/ssh/*.conf") is True
        assert is_glob_path("/etc/cron.d/[a-z]*") is True
        assert is_glob_path("/tmp/file?.txt") is True
        assert is_glob_path("/etc/ssh/sshd_config") is False
        assert is_glob_path("") is False

    def test_ac3_escape_sed_escapes_metacharacters(self):
        """AC-3: escape_sed(value) escapes all sed BRE metacharacters (\\ / . ^ $ * [ ] &)."""
        assert escape_sed("net.ipv4.ip_forward") == r"net\.ipv4\.ip_forward"
        assert escape_sed("/etc/ssh/sshd_config") == r"\/etc\/ssh\/sshd_config"
        # All metacharacters escaped
        result = escape_sed(r"\/.^$*[]&")
        for ch in r"\/.^$*[]&":
            assert f"\\{ch}" in result

    def test_ac4_escape_grep_bre_escapes_metacharacters(self):
        """AC-4: escape_grep_bre(value) escapes grep BRE metacharacters (\\ . ^ $ * [ ])."""
        assert escape_grep_bre("net.ipv4.ip_forward") == r"net\.ipv4\.ip_forward"
        assert escape_grep_bre("^start$") == r"\^start\$"
        assert escape_grep_bre("file[0]") == r"file\[0\]"
        # & and / are NOT escaped by grep_bre (only by sed)
        assert escape_grep_bre("a/b&c") == "a/b&c"

    def test_ac5_file_exists_returns_bool(self, mock_ssh):
        """AC-5: file_exists(ssh, path) returns True when test -f succeeds on quoted path."""
        ssh_ok = mock_ssh({"test -f": Result(exit_code=0, stdout="", stderr="")})
        assert file_exists(ssh_ok, "/etc/passwd") is True

        ssh_fail = mock_ssh({"test -f": Result(exit_code=1, stdout="", stderr="")})
        assert file_exists(ssh_fail, "/nonexistent") is False

        # Verify the command uses test -f with path
        assert ssh_ok.commands_run[0] == f"test -f {quote('/etc/passwd')}"

    def test_ac6_grep_config_key_searches_with_autodetect(self, mock_ssh):
        """AC-6: grep_config_key(ssh, path, key) searches for lines starting with key; auto-detects directory mode."""
        # File mode: test -d fails, then grep -h runs
        ssh = mock_ssh(
            {
                "test -d": Result(exit_code=1, stdout="", stderr=""),
                "grep -h": Result(
                    exit_code=0, stdout="PermitRootLogin no\n", stderr=""
                ),
            }
        )
        result = grep_config_key(ssh, "/etc/ssh/sshd_config", "PermitRootLogin")
        assert result.ok
        assert "PermitRootLogin no" in result.stdout
        # Should have run test -d for auto-detection, then grep -h for file mode
        assert any("grep -h" in cmd for cmd in ssh.commands_run)

        # Directory mode: test -d succeeds, then grep -rh runs
        ssh_dir = mock_ssh(
            {
                "test -d": Result(exit_code=0, stdout="", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="MaxSessions 10\n", stderr=""),
            }
        )
        result_dir = grep_config_key(ssh_dir, "/etc/ssh/sshd_config.d", "MaxSessions")
        assert result_dir.ok
        assert any("grep -rh" in cmd for cmd in ssh_dir.commands_run)

    def test_ac7_parse_config_value_extracts_value(self):
        """AC-7: parse_config_value(line, key) extracts value from 'key value' or 'key=value' lines."""
        assert parse_config_value("PermitRootLogin no", "PermitRootLogin") == "no"
        assert parse_config_value("MaxAuthTries=4", "MaxAuthTries") == "4"
        assert parse_config_value('Banner="/etc/issue"', "Banner") == "/etc/issue"
        # Leading whitespace in value is stripped
        assert parse_config_value("Key   value_here", "Key") == "value_here"

    def test_ac8_sed_replace_line_runs_sed(self, mock_ssh):
        """AC-8: sed_replace_line(ssh, path, pattern, replacement) replaces matching lines using sed -i."""
        ssh = mock_ssh({"sed -i": Result(exit_code=0, stdout="", stderr="")})
        result = sed_replace_line(
            ssh, "/etc/ssh/sshd_config", "^PermitRootLogin.*", "PermitRootLogin no"
        )
        assert result is True
        assert len(ssh.commands_run) == 1
        cmd = ssh.commands_run[0]
        assert "sed -i" in cmd
        assert "/etc/ssh/sshd_config" in cmd

    def test_ac9_get_file_stat_supports_glob(self, mock_ssh):
        """AC-9: get_file_stat(ssh, path) returns stat output; supports glob when allow_glob=True."""
        ssh = mock_ssh(
            {
                "stat -c": Result(
                    exit_code=0, stdout="root root 644 /etc/passwd\n", stderr=""
                )
            }
        )
        result = get_file_stat(ssh, "/etc/passwd")
        assert result.ok
        assert "root root 644" in result.stdout
        # Path should be present in the stat command
        assert "/etc/passwd" in ssh.commands_run[0]

        # With glob: path should NOT be quoted
        ssh_glob = mock_ssh(
            {
                "stat -c": Result(
                    exit_code=0, stdout="root root 644 /etc/cron.d/test\n", stderr=""
                )
            }
        )
        result_glob = get_file_stat(ssh_glob, "/etc/cron.d/*", allow_glob=True)
        assert result_glob.ok
        cmd = ssh_glob.commands_run[0]
        # Glob path should not be quoted
        assert "/etc/cron.d/*" in cmd
        assert "'/etc/cron.d/*'" not in cmd

    def test_ac10_service_action_dispatches(self, mock_ssh):
        """AC-10: service_action(ssh, remediation) performs reload or restart based on dict keys."""
        # reload key
        ssh_reload = mock_ssh(
            {"systemctl reload": Result(exit_code=0, stdout="", stderr="")}
        )
        service_action(ssh_reload, {"reload": "sshd"})
        assert any("systemctl reload" in cmd for cmd in ssh_reload.commands_run)

        # restart key
        ssh_restart = mock_ssh(
            {"systemctl restart": Result(exit_code=0, stdout="", stderr="")}
        )
        service_action(ssh_restart, {"restart": "nginx"})
        assert any("systemctl restart" in cmd for cmd in ssh_restart.commands_run)

        # Neither key: no commands should run
        ssh_none = mock_ssh({})
        service_action(ssh_none, {"key": "value"})
        assert ssh_none.commands_run == []
