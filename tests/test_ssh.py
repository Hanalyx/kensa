"""Tests for runner/ssh.py — SSHSession and Result."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from runner.ssh import Result, SSHSession, _shell_quote


class TestResult:
    def test_ok_true_on_zero(self):
        r = Result(exit_code=0, stdout="out", stderr="")
        assert r.ok is True

    def test_ok_false_on_nonzero(self):
        r = Result(exit_code=1, stdout="", stderr="err")
        assert r.ok is False

    def test_ok_false_on_signal(self):
        r = Result(exit_code=127, stdout="", stderr="not found")
        assert r.ok is False


class TestSSHSessionInit:
    def test_stores_all_params(self):
        s = SSHSession(
            hostname="10.0.0.1",
            port=2222,
            user="admin",
            key_path="/tmp/key",
            password="secret",
            timeout=60,
            sudo=True,
        )
        assert s.hostname == "10.0.0.1"
        assert s.port == 2222
        assert s.user == "admin"
        assert s.key_path == "/tmp/key"
        assert s.password == "secret"
        assert s.timeout == 60
        assert s.sudo is True

    def test_defaults(self):
        s = SSHSession(hostname="host")
        assert s.port == 22
        assert s.user is None
        assert s.key_path is None
        assert s.password is None
        assert s.timeout == 30
        assert s.sudo is False


class TestSSHSessionRun:
    def _make_session(self, sudo=False):
        """Create a session with a mocked paramiko client."""
        s = SSHSession(hostname="host", sudo=sudo)
        mock_client = MagicMock()

        # Set up exec_command to return channel-like objects
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"hello"
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
        s._client = mock_client
        return s, mock_client

    def test_run_without_sudo(self):
        s, client = self._make_session(sudo=False)
        result = s.run("echo hello")
        client.exec_command.assert_called_once_with("echo hello", timeout=30)
        assert result.exit_code == 0
        assert result.stdout == "hello"

    def test_run_with_sudo(self):
        s, client = self._make_session(sudo=True)
        s.run("grep PermitRootLogin /etc/ssh/sshd_config")
        cmd = client.exec_command.call_args[0][0]
        assert cmd.startswith("sudo -n sh -c ")
        assert "grep PermitRootLogin /etc/ssh/sshd_config" in cmd

    def test_sudo_wraps_with_quotes(self):
        s, client = self._make_session(sudo=True)
        s.run("echo 'hello world'")
        cmd = client.exec_command.call_args[0][0]
        # The entire original command should be inside the sudo wrapper
        assert "sudo -n sh -c" in cmd
        assert "echo" in cmd

    def test_sudo_handles_pipes(self):
        s, client = self._make_session(sudo=True)
        s.run("grep foo /etc/bar | head -1")
        cmd = client.exec_command.call_args[0][0]
        assert "sudo -n sh -c" in cmd

    def test_run_custom_timeout(self):
        s, client = self._make_session()
        s.run("slow command", timeout=120)
        client.exec_command.assert_called_once_with("slow command", timeout=120)

    def test_run_strips_trailing_newlines(self):
        s, _ = self._make_session()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"line1\nline2\n"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b"warn\n"
        s._client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        result = s.run("cmd")
        assert result.stdout == "line1\nline2"
        assert result.stderr == "warn"

    def test_run_not_connected_raises(self):
        s = SSHSession(hostname="host")
        import pytest

        with pytest.raises(RuntimeError, match="Not connected"):
            s.run("cmd")


class TestSSHSessionContextManager:
    @patch("runner.ssh.paramiko.SSHClient")
    def test_context_manager(self, mock_ssh_class):
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        with SSHSession(hostname="host", user="u", password="p") as s:
            assert s._client is not None

        mock_client.connect.assert_called_once()
        mock_client.close.assert_called_once()


class TestShellQuote:
    def test_simple_string(self):
        assert _shell_quote("hello") == "hello"

    def test_string_with_spaces(self):
        result = _shell_quote("hello world")
        assert " " not in result or result.startswith("'")

    def test_string_with_single_quotes(self):
        result = _shell_quote("it's")
        # shlex.quote handles this correctly
        assert "it" in result and "s" in result
