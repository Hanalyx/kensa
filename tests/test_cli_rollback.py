"""Tests for kensa rollback --list / --info / --start commands."""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner._types import RollbackResult
from runner.cli import main
from runner.ssh import Result
from runner.storage import ResultStore


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


def _seed_remediation(store: ResultStore, *, host="10.0.0.5", dry_run=False):
    """Create a remediation session with sample data for testing."""
    session_id = store.create_session(hosts=[host], rules_path="rules/")
    rs_id = store.create_remediation_session(
        session_id,
        dry_run=dry_run,
        rollback_on_failure=True,
        snapshot_mode="all",
    )

    # Rule 1: remediated and passed
    rem1 = store.record_remediation(
        rs_id,
        host=host,
        rule_id="ssh-disable-root-login",
        severity="high",
        passed_before=False,
        passed_after=True,
        remediated=True,
        rolled_back=False,
        detail="Set PermitRootLogin=no",
    )
    step1 = store.record_step(rem1, 0, "config_set_dropin", True, "Wrote drop-in")
    store.record_pre_state(
        step1,
        "config_set_dropin",
        {"path": "/etc/ssh/sshd_config.d/00-kensa.conf", "existed": False},
        capturable=True,
    )

    # Rule 2: remediated but rolled back
    rem2 = store.record_remediation(
        rs_id,
        host=host,
        rule_id="sysctl-net-ipv4-forward",
        severity="medium",
        passed_before=False,
        passed_after=False,
        remediated=True,
        rolled_back=True,
        detail="Re-check failed",
    )
    step2 = store.record_step(rem2, 0, "sysctl_set", True, "Set value")
    store.record_pre_state(
        step2,
        "sysctl_set",
        {"key": "net.ipv4.ip_forward", "old_value": "1", "persist_existed": True},
        capturable=True,
    )
    store.record_rollback_event(step2, "sysctl_set", True, "Restored to 1", "inline")

    # Rule 3: passed initially (not remediated)
    store.record_remediation(
        rs_id,
        host=host,
        rule_id="sshd-strong-ciphers",
        severity="medium",
        passed_before=True,
        passed_after=None,
        remediated=False,
    )

    # Rule 4: remediated with non-capturable step
    rem4 = store.record_remediation(
        rs_id,
        host=host,
        rule_id="crypto-policy",
        severity="high",
        passed_before=False,
        passed_after=True,
        remediated=True,
        rolled_back=False,
        detail="Applied crypto policy",
    )
    step4 = store.record_step(
        rem4, 0, "command_exec", True, "update-crypto-policies --set DEFAULT"
    )
    # Record as non-capturable pre-state
    store.record_pre_state(
        step4,
        "command_exec",
        {},
        capturable=False,
    )

    return rs_id


class TestRollbackHelp:
    def test_rollback_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rollback", "--help"])
        assert result.exit_code == 0
        assert "--list" in result.output
        assert "--info" in result.output
        assert "--detail" in result.output

    def test_rollback_no_args_errors(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rollback"])
        assert result.exit_code == 1
        assert "Specify --list" in result.output


class TestRollbackList:
    def test_list_shows_sessions(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list"])

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "Remediation Sessions" in clean
        assert "10.0.0.5" in clean

    def test_list_host_filter(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            _seed_remediation(store, host="10.0.0.5")
            _seed_remediation(store, host="10.0.0.6")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list", "--host", "10.0.0.5"])

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "10.0.0.5" in clean

    def test_list_empty(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        # Initialize empty store
        store = ResultStore(db_path=db_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list"])

        assert result.exit_code == 0
        assert "No remediation sessions found" in result.output

    def test_list_json(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--list", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "id" in data[0]
        assert "hosts" in data[0]
        assert "fixed" in data[0]
        assert "rolled_back" in data[0]


class TestRollbackInfo:
    def test_info_shows_session(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id)])

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert f"Remediation Session #{rs_id}" in clean
        assert "10.0.0.5" in clean
        assert "on-failure (enabled)" in clean
        assert "sysctl-net-ipv4-forward" in clean
        assert "rolled back" in clean

    def test_info_not_found(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_info_detail_shows_prestates(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id), "--detail"])

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        # Should show pre-state data
        assert "Pre-state" in clean or "path:" in clean
        assert "Step 0" in clean

    def test_info_rule_filter(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--info",
                    str(rs_id),
                    "--rule",
                    "ssh-disable-root-login",
                ],
            )

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "ssh-disable-root-login" in clean
        # sysctl rule should not appear in counts
        assert "sysctl-net-ipv4-forward" not in clean

    def test_info_json_output(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id), "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["id"] == rs_id
        assert "remediations" in data
        assert len(data["remediations"]) == 4
        assert data["summary"]["rolled_back"] == 1
        assert data["summary"]["remediated"] == 3

    def test_info_json_with_detail(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["rollback", "--info", str(rs_id), "--json", "--detail"]
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        # Remediated rules should have steps
        remediated = [r for r in data["remediations"] if r["remediated"]]
        assert len(remediated) >= 1
        # At least one should have steps with pre_state_data
        has_steps = [r for r in remediated if "steps" in r]
        assert len(has_steps) >= 1
        step = has_steps[0]["steps"][0]
        assert "mechanism" in step
        assert "pre_state_data" in step

    def test_info_shows_non_capturable(self, tmp_path):
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--info", str(rs_id)])

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "Non-rollbackable" in clean or "not capturable" in clean


class TestRollbackStart:
    """Tests for kensa rollback --start command."""

    def test_start_requires_host(self, tmp_path):
        """--start requires --host to be specified."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(main, ["rollback", "--start", str(rs_id)])

        assert result.exit_code == 1
        assert "--host" in result.output or "--limit" in result.output

    def test_start_session_not_found(self, tmp_path):
        """--start with nonexistent session ID fails."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["rollback", "--start", "999", "--host", "10.0.0.5"]
            )

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_start_host_mismatch(self, tmp_path):
        """--start with wrong host aborts with error showing stored hosts."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store, host="10.0.0.5")
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["rollback", "--start", str(rs_id), "--host", "10.0.0.99"]
            )

        assert result.exit_code == 1
        assert "10.0.0.99" in result.output
        assert "10.0.0.5" in result.output

    def test_start_dry_run(self, tmp_path):
        """--start --dry-run shows what would be rolled back without SSH."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--dry-run",
                ],
            )

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "Dry-run" in clean
        assert "config_set_dropin" in clean
        assert "no action taken" in clean

    def test_start_dry_run_rule_filter(self, tmp_path):
        """--start --dry-run --rule filters to a specific rule."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--dry-run",
                    "--rule",
                    "ssh-disable-root-login",
                ],
            )

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "config_set_dropin" in clean
        # sysctl_set from the other rule should NOT appear
        assert "sysctl_set" not in clean

    def test_start_already_rolled_back(self, tmp_path):
        """Steps already rolled back are skipped."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            # sysctl rule was already rolled back inline
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            # Try to start with --rule targeting the already-rolled-back rule
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--rule",
                    "sysctl-net-ipv4-forward",
                ],
            )

        # Should report already rolled back
        assert result.exit_code == 0
        assert "already rolled back" in result.output

    def test_start_executes_rollback(self, tmp_path):
        """--start executes rollback via SSH and persists events."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        # Mock SSH to avoid real connections
        mock_ssh = MagicMock()
        mock_ssh.run.return_value = Result(stdout="", stderr="", exit_code=0)

        mock_hi = MagicMock()
        mock_hi.hostname = "10.0.0.5"

        with (
            patch("runner.storage.get_db_path", return_value=db_path),
            patch("runner.cli._resolve_hosts", return_value=[mock_hi]),
            patch("runner.cli.connect", return_value=mock_ssh) as mock_connect,
            patch(
                "runner._orchestration.rollback_from_stored",
                return_value=[
                    RollbackResult(0, "config_set_dropin", True, "Restored"),
                ],
            ) as mock_rollback,
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--sudo",
                ],
            )

        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "Rollback complete" in clean
        assert "1 step(s) reversed" in clean

        # Verify connect was called with sudo
        mock_connect.assert_called_once()
        assert mock_connect.call_args.kwargs.get("sudo") is True

        # Verify rollback_from_stored was called
        mock_rollback.assert_called_once()

        # Verify rollback events were persisted
        store2 = ResultStore(db_path=db_path)
        try:
            rems = store2.get_remediations(rs_id)
            ssh_rule = [r for r in rems if r.rule_id == "ssh-disable-root-login"][0]
            steps = store2.get_remediation_steps(ssh_rule.id)
            events = store2.get_rollback_events(steps[0].id)
            assert len(events) == 1
            assert events[0].source == "manual"
            assert events[0].success is True
            # Remediation should be marked as rolled_back
            assert ssh_rule.rolled_back is True
        finally:
            store2.close()

    def test_start_ssh_failure(self, tmp_path):
        """SSH connection failure is reported cleanly."""
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir()
        db_path = db_dir / "results.db"

        store = ResultStore(db_path=db_path)
        try:
            rs_id = _seed_remediation(store)
        finally:
            store.close()

        mock_hi = MagicMock()
        mock_hi.hostname = "10.0.0.5"

        with (
            patch("runner.storage.get_db_path", return_value=db_path),
            patch("runner.cli._resolve_hosts", return_value=[mock_hi]),
            patch(
                "runner.cli.connect",
                side_effect=Exception("Connection refused"),
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "rollback",
                    "--start",
                    str(rs_id),
                    "--host",
                    "10.0.0.5",
                    "--sudo",
                ],
            )

        assert result.exit_code == 1
        assert "Connection refused" in result.output

    def test_start_mutual_exclusion(self):
        """--start and --info cannot be used together."""
        runner = CliRunner()
        result = runner.invoke(
            main, ["rollback", "--start", "1", "--info", "1", "--host", "10.0.0.5"]
        )
        assert result.exit_code == 1
        assert "Only one of" in result.output
