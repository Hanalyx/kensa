"""Spec-derived tests for security.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/security.spec.yaml — verifying credential handling,
shell injection prevention, host key policy, and security documentation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import click
import paramiko


class TestSecuritySpecDerived:
    """Spec-derived tests for application security posture (AC-1 through AC-10)."""

    def test_ac1_password_option_hides_input(self):
        """AC-1: --password click option has hide_input=True and prompt_required=False."""
        from runner.cli import target_options

        # Build a dummy command with target_options applied
        @click.command()
        @target_options
        def dummy(**kwargs):
            pass

        # Find the --password parameter
        pw_param = None
        for param in dummy.params:
            if param.name == "password":
                pw_param = param
                break

        assert pw_param is not None, "--password parameter not found"
        assert pw_param.hide_input is True, "hide_input should be True"
        assert pw_param.prompt_required is False, "prompt_required should be False"

    def test_ac2_ssh_session_no_password_in_repr(self):
        """AC-2: SSHSession does not expose password in __repr__ or __str__."""
        from runner.ssh import SSHSession

        session = SSHSession("testhost", password="supersecret123")

        repr_str = repr(session)
        str_str = str(session)

        # Password should not appear in repr or str
        assert "supersecret123" not in repr_str
        assert "supersecret123" not in str_str

    def test_ac3_no_credential_interpolation_in_handlers(self):
        """AC-3: No handler interpolates credentials into ssh.run() calls."""
        handlers_dir = (
            Path(__file__).parent.parent.parent.parent / "runner" / "handlers"
        )
        assert handlers_dir.exists(), f"handlers dir not found: {handlers_dir}"

        violations = []
        for py_file in handlers_dir.rglob("*.py"):
            source = py_file.read_text()
            # Look for patterns like password, credential, secret in f-string
            # interpolations near ssh.run() calls
            for i, line in enumerate(source.splitlines(), 1):
                lower = line.lower()
                if ("ssh.run(" in lower or "ssh_session.run(" in lower) and (
                    "password" in lower or "credential" in lower or "secret" in lower
                ):
                    violations.append(f"{py_file.name}:{i}: {line.strip()}")

        assert not violations, (
            "Found potential credential interpolation in ssh.run() calls:\n"
            + "\n".join(violations)
        )

    def test_ac4_shell_util_quote_wraps_shlex(self):
        """AC-4: shell_util.quote() wraps shlex.quote and is callable."""
        import shlex

        from runner.shell_util import quote

        # quote() should produce the same result as shlex.quote()
        for value in ["hello", "hello world", "foo;bar", "$(rm -rf /)", "it's"]:
            assert quote(value) == shlex.quote(value)

        # Dangerous characters are safely quoted
        result = quote("foo;bar")
        assert result == "'foo;bar'"
        result = quote("$(rm -rf /)")
        assert result.startswith("'")

    def test_ac5_shell_util_escape_sed_escapes_metacharacters(self):
        """AC-5: shell_util.escape_sed() escapes BRE metacharacters and delimiter."""
        from runner.shell_util import escape_sed

        # Dot is escaped (BRE metacharacter)
        assert escape_sed("net.ipv4") == r"net\.ipv4"
        # Forward slash is escaped (sed delimiter)
        assert escape_sed("/etc/ssh") == r"\/etc\/ssh"
        # Backslash is escaped
        assert "\\\\" in escape_sed("back\\slash")
        # Caret, dollar, star, brackets
        assert escape_sed("^start$") == r"\^start\$"
        assert escape_sed("file*") == r"file\*"

    def test_ac6_explicit_credentials_disable_key_lookup(self):
        """AC-6: Explicit credentials set look_for_keys=False and allow_agent=False."""
        from runner.ssh import SSHSession

        session = SSHSession("testhost", password="secret")

        with patch("paramiko.SSHClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            # Ensure known_hosts file check doesn't interfere
            with patch("os.path.isfile", return_value=False):
                session.connect()

            # Verify connect was called with key/agent disabled
            call_kwargs = mock_client.connect.call_args[1]
            assert call_kwargs["look_for_keys"] is False
            assert call_kwargs["allow_agent"] is False

        session.close()

    def test_ac6_no_credentials_allows_key_lookup(self):
        """AC-6 (inverse): No explicit credentials lets paramiko try keys and agent."""
        from runner.ssh import SSHSession

        session = SSHSession("testhost")

        with patch("paramiko.SSHClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            with patch("os.path.isfile", return_value=False):
                session.connect()

            call_kwargs = mock_client.connect.call_args[1]
            assert "look_for_keys" not in call_kwargs
            assert "allow_agent" not in call_kwargs

        session.close()

    def test_ac7_strict_host_keys_uses_reject_policy(self):
        """AC-7: strict_host_keys=True uses RejectPolicy."""
        from runner.ssh import SSHSession

        session = SSHSession("testhost", strict_host_keys=True)

        with patch("paramiko.SSHClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            with patch("os.path.isfile", return_value=False):
                session.connect()

            # Find the set_missing_host_key_policy call
            policy_call = mock_client.set_missing_host_key_policy.call_args
            policy = policy_call[0][0]
            assert isinstance(policy, paramiko.RejectPolicy)

        session.close()

    def test_ac7_default_host_keys_uses_accept_policy(self):
        """AC-7 (inverse): strict_host_keys=False uses _AcceptPolicy."""
        from runner.ssh import SSHSession, _AcceptPolicy

        session = SSHSession("testhost", strict_host_keys=False)

        with patch("paramiko.SSHClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            with patch("os.path.isfile", return_value=False):
                session.connect()

            policy_call = mock_client.set_missing_host_key_policy.call_args
            policy = policy_call[0][0]
            assert isinstance(policy, _AcceptPolicy)

        session.close()

    def test_ac8_security_md_documents_threat_model(self):
        """AC-8: context/security.md documents the full threat model."""
        security_md = (
            Path(__file__).parent.parent.parent.parent / "context" / "security.md"
        )
        assert security_md.exists(), "context/security.md not found"

        content = security_md.read_text()

        # Key sections that must exist
        required_sections = [
            "Threat Model",
            "Shell Injection",
            "Credential Safety",
            "Host Key Verification",
            "Idempotency",
        ]
        for section in required_sections:
            assert section in content, f"Missing section: {section}"

        # Secure prompt documented
        assert "prompt" in content.lower() or "hidden input" in content.lower()

    def test_ac9_storage_schema_has_pre_states(self):
        """AC-9: Pre-state snapshots are persisted to SQLite with retention policy."""
        storage_path = (
            Path(__file__).parent.parent.parent.parent / "runner" / "storage.py"
        )
        assert storage_path.exists(), "runner/storage.py not found"

        content = storage_path.read_text()

        # pre_states table should exist
        assert "pre_states" in content, "pre_states table not found in storage.py"
        # Retention-related constants or logic should exist
        assert "snapshot" in content.lower(), "No snapshot references in storage.py"

    def test_ac10_click_type_validation_on_port_and_workers(self):
        """AC-10: Click type validation on --port (int) and --workers (IntRange)."""
        from runner.cli import target_options

        @click.command()
        @target_options
        def dummy(**kwargs):
            pass

        port_param = None
        workers_param = None
        for param in dummy.params:
            if param.name == "port":
                port_param = param
            elif param.name == "workers":
                workers_param = param

        assert port_param is not None, "--port parameter not found"
        assert isinstance(port_param.type, type(click.INT)), "--port should be int type"

        assert workers_param is not None, "--workers parameter not found"
        assert isinstance(
            workers_param.type, click.IntRange
        ), "--workers should be IntRange type"
