"""SpecDerived tests for ssh_session module."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from runner.ssh import Result, SSHSession, _AcceptPolicy, _fips_safe_md5


class TestSSHSessionSpecDerived:
    """Spec-derived tests for ssh_session.

    See specs/internal/ssh_session.spec.yaml for specification.
    """

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac1_connect_establishes_paramiko_connection(
        self, mock_paramiko, mock_isfile
    ):
        """AC-1: SSHSession.connect() establishes paramiko SSH connection."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        session = SSHSession("testhost", port=22, user="admin")
        session.connect()

        mock_paramiko.SSHClient.assert_called_once()
        mock_client.connect.assert_called_once()
        call_kwargs = mock_client.connect.call_args
        assert call_kwargs[1]["hostname"] == "testhost"
        assert call_kwargs[1]["port"] == 22
        assert call_kwargs[1]["username"] == "admin"

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac2_explicit_credentials_disable_key_agent(
        self, mock_paramiko, mock_isfile
    ):
        """AC-2: When explicit credentials provided, look_for_keys and allow_agent disabled."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        # With key_path
        session = SSHSession("testhost", key_path="/path/to/key")
        session.connect()
        call_kwargs = mock_client.connect.call_args[1]
        assert call_kwargs["look_for_keys"] is False
        assert call_kwargs["allow_agent"] is False
        assert call_kwargs["key_filename"] == "/path/to/key"

        mock_client.reset_mock()

        # With password
        session2 = SSHSession("testhost", password="secret")
        session2.connect()
        call_kwargs2 = mock_client.connect.call_args[1]
        assert call_kwargs2["look_for_keys"] is False
        assert call_kwargs2["allow_agent"] is False
        assert call_kwargs2["password"] == "secret"

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac3_no_credentials_uses_keys_and_agent(self, mock_paramiko, mock_isfile):
        """AC-3: When no explicit credentials, paramiko tries ~/.ssh keys and agent."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        session = SSHSession("testhost")
        session.connect()

        call_kwargs = mock_client.connect.call_args[1]
        assert "look_for_keys" not in call_kwargs
        assert "allow_agent" not in call_kwargs
        assert "key_filename" not in call_kwargs
        assert "password" not in call_kwargs

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac4_run_returns_result_with_rstripped_output(
        self, mock_paramiko, mock_isfile
    ):
        """AC-4: run(cmd) executes via exec_command, returns Result with rstripped stdout/stderr."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        # Set up exec_command mock
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"output line\n"
        mock_stderr.read.return_value = b"error line\n"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        session = SSHSession("testhost")
        session.connect()
        result = session.run("echo hello")

        mock_client.exec_command.assert_called_once()
        assert isinstance(result, Result)
        assert result.exit_code == 0
        assert result.stdout == "output line"  # rstripped
        assert result.stderr == "error line"  # rstripped

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac5_sudo_wraps_command(self, mock_paramiko, mock_isfile):
        """AC-5: When sudo=True, commands wrapped as 'sudo -n sh -c <quoted>'."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        session = SSHSession("testhost", sudo=True)
        session.connect()
        session.run("cat /etc/shadow")

        actual_cmd = mock_client.exec_command.call_args[0][0]
        assert actual_cmd.startswith("sudo -n sh -c ")
        assert "cat /etc/shadow" in actual_cmd

    def test_ac6_result_ok_property(self):
        """AC-6: Result.ok returns True when exit_code is 0."""
        success = Result(exit_code=0, stdout="ok", stderr="")
        assert success.ok is True

        failure = Result(exit_code=1, stdout="", stderr="error")
        assert failure.ok is False

        failure2 = Result(exit_code=127, stdout="", stderr="not found")
        assert failure2.ok is False

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac7_close_sets_client_none_subsequent_run_raises(
        self, mock_paramiko, mock_isfile
    ):
        """AC-7: close() closes client and sets _client to None; subsequent run() raises RuntimeError."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        session = SSHSession("testhost")
        session.connect()
        assert session._client is not None

        session.close()
        mock_client.close.assert_called_once()
        assert session._client is None

        with pytest.raises(RuntimeError, match="Not connected"):
            session.run("echo hello")

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac8_context_manager(self, mock_paramiko, mock_isfile):
        """AC-8: Context manager calls connect() and close()."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        with SSHSession("testhost") as session:
            assert isinstance(session, SSHSession)
            mock_client.connect.assert_called_once()

        mock_client.close.assert_called_once()

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac9_strict_host_keys_false_uses_accept_policy(
        self, mock_paramiko, mock_isfile
    ):
        """AC-9: strict_host_keys=False accepts unknown keys via _AcceptPolicy."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        session = SSHSession("testhost", strict_host_keys=False)
        session.connect()

        mock_client.set_missing_host_key_policy.assert_called_once()
        policy = mock_client.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(policy, _AcceptPolicy)

    @patch("runner.ssh.os.path.isfile", return_value=False)
    @patch("runner.ssh.paramiko")
    def test_ac10_strict_host_keys_true_uses_reject_policy(
        self, mock_paramiko, mock_isfile
    ):
        """AC-10: strict_host_keys=True rejects unknown keys via RejectPolicy."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client

        session = SSHSession("testhost", strict_host_keys=True)
        session.connect()

        mock_client.set_missing_host_key_policy.assert_called_once()
        policy = mock_client.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(policy, mock_paramiko.RejectPolicy.return_value.__class__)

    def test_ac11_fips_safe_md5_patch(self):
        """AC-11: FIPS-safe MD5 patch wraps hashlib.md5 with usedforsecurity=False."""
        # The module-level patch has already been applied at import time.
        # Verify that hashlib.md5 is the patched version.
        assert hashlib.md5 is _fips_safe_md5

        # Verify it works (doesn't raise even if we don't pass usedforsecurity)
        h = hashlib.md5(b"test")
        assert h is not None
        assert len(h.hexdigest()) == 32
