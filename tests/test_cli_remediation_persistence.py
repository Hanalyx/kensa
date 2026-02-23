"""Tests for Phase 2: remediation persistence in SQLite."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from runner.cli import main
from runner.ssh import Result
from runner.storage import ResultStore


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


def _make_mock_ssh():
    """Create a standard mock SSH session."""
    mock_ssh = MagicMock()
    mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
    mock_ssh.__exit__ = MagicMock(return_value=False)
    mock_ssh.connect = MagicMock()
    mock_ssh.close = MagicMock()
    return mock_ssh


def _write_sysctl_rule(tmp_path, *, rule_id="test-rule", with_remediation=True):
    """Write a sysctl test rule with optional remediation."""
    remediation = ""
    if with_remediation:
        remediation = (
            "    remediation:\n"
            "      mechanism: sysctl_set\n"
            "      key: net.ipv4.ip_forward\n"
            "      value: '0'\n"
        )
    rule_file = tmp_path / f"{rule_id}.yml"
    rule_file.write_text(
        f"id: {rule_id}\n"
        "title: Test rule\n"
        "severity: medium\n"
        "category: kernel\n"
        "implementations:\n"
        "  - default: true\n"
        "    check:\n"
        "      method: sysctl_value\n"
        "      key: net.ipv4.ip_forward\n"
        "      expected: '0'\n"
        f"{remediation}"
    )
    return rule_file


class TestRemediationPersistence:
    """Verify remediate command persists results to SQLite."""

    @patch("runner._host_runner.SSHSession")
    def test_remediate_creates_remediation_session(self, mock_session_cls, tmp_path):
        """A remediate run should create a remediation_sessions row."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")  # Failing check
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0
        assert "Stored remediation results" in result.output

        # Verify database contents
        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            assert len(sessions) == 1
            assert sessions[0].dry_run is False
            assert sessions[0].rollback_on_failure is False
            assert sessions[0].snapshot_mode == "all"
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_remediate_persists_remediation_record(self, mock_session_cls, tmp_path):
        """Individual rule remediation data should be persisted."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        check_count = {"n": 0}

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                check_count["n"] += 1
                if check_count["n"] <= 1:
                    return Result(exit_code=0, stdout="1", stderr="")  # Failing first
                return Result(exit_code=0, stdout="0", stderr="")  # Pass on re-check
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            assert len(sessions) >= 1
            rems = store.get_remediations(sessions[0].id)
            assert len(rems) >= 1

            rem = rems[0]
            assert rem.host == "10.0.0.1"
            assert rem.rule_id == "test-rule"
            assert rem.severity == "medium"
            assert rem.remediated is True
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_remediate_persists_step_and_prestate(self, mock_session_cls, tmp_path):
        """Step results and pre-state data should be persisted."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        check_count = {"n": 0}

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                check_count["n"] += 1
                if check_count["n"] <= 1:
                    return Result(exit_code=0, stdout="1", stderr="")
                return Result(exit_code=0, stdout="0", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            if "echo" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            rems = store.get_remediations(sessions[0].id)
            assert len(rems) >= 1

            steps = store.get_remediation_steps(rems[0].id)
            assert len(steps) >= 1
            assert steps[0].mechanism == "sysctl_set"
            assert steps[0].success is True

            # Pre-state should be captured
            if steps[0].pre_state_data is not None:
                assert "key" in steps[0].pre_state_data
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_dry_run_persisted_as_dry_run(self, mock_session_cls, tmp_path):
        """Dry-run remediations should be persisted with dry_run=True."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--dry-run",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            assert len(sessions) == 1
            assert sessions[0].dry_run is True
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_rollback_on_failure_persisted(self, mock_session_cls, tmp_path):
        """--rollback-on-failure should be recorded in the session."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="1", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--rollback-on-failure",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            assert len(sessions) == 1
            assert sessions[0].rollback_on_failure is True
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_rollback_event_persisted_as_inline(self, mock_session_cls, tmp_path):
        """Inline rollback events should be persisted with source='inline'."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                # Always failing — triggers rollback
                return Result(exit_code=0, stdout="1", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            if "echo" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--rollback-on-failure",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0
        assert "rolled back" in result.output

        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            rems = store.get_remediations(sessions[0].id)
            # Find the remediation that was rolled back
            rolled_back_rems = [r for r in rems if r.rolled_back]
            assert len(rolled_back_rems) >= 1

            # Check rollback events
            steps = store.get_remediation_steps(rolled_back_rems[0].id)
            for step in steps:
                events = store.get_rollback_events(step.id)
                for event in events:
                    assert event.source == "inline"
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_passing_rule_not_remediated_still_persisted(
        self, mock_session_cls, tmp_path
    ):
        """A passing rule should still get a remediation record (passed_before=True)."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="0", stderr="")  # Passing
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        store = ResultStore(db_path=db_path)
        try:
            sessions = store.list_remediation_sessions()
            assert len(sessions) == 1
            rems = store.get_remediations(sessions[0].id)
            assert len(rems) >= 1
            # Passing rule: not remediated
            rem = rems[0]
            assert rem.remediated is False
            assert rem.passed_before is True
        finally:
            store.close()

    @patch("runner._host_runner.SSHSession")
    def test_also_persists_to_results_table(self, mock_session_cls, tmp_path):
        """Remediate should also write to the results table for history/diff compat."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                return Result(exit_code=0, stdout="0", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        store = ResultStore(db_path=db_path)
        try:
            # Check that session was created
            sess_list = store.list_sessions()
            assert len(sess_list) >= 1

            # Check that results were written
            results = store.get_results(sess_list[0].id)
            assert len(results) >= 1
            assert results[0].rule_id == "test-rule"
        finally:
            store.close()


class TestRemediationPersistenceRoundTrip:
    """Full round-trip: remediate → read back all fields."""

    @patch("runner._host_runner.SSHSession")
    def test_full_roundtrip(self, mock_session_cls, tmp_path):
        """Write remediation with steps/prestate, read back, verify all fields."""
        mock_ssh = _make_mock_ssh()
        mock_session_cls.return_value = mock_ssh

        check_count = {"n": 0}

        def mock_run(cmd, *, timeout=None):
            if "sysctl -n" in cmd:
                check_count["n"] += 1
                if check_count["n"] <= 1:
                    return Result(exit_code=0, stdout="1", stderr="")
                return Result(exit_code=0, stdout="0", stderr="")
            if "sysctl -w" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            if "echo" in cmd:
                return Result(exit_code=0, stdout="", stderr="")
            return Result(exit_code=0, stdout="", stderr="")

        mock_ssh.run = mock_run

        rule_file = _write_sysctl_rule(tmp_path)
        db_dir = tmp_path / ".kensa"
        db_dir.mkdir(exist_ok=True)
        db_path = db_dir / "results.db"

        with patch("runner.storage.get_db_path", return_value=db_path):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "remediate",
                    "--host",
                    "10.0.0.1",
                    "--rule",
                    str(rule_file),
                ],
            )

        assert result.exit_code == 0

        # Full round-trip read
        store = ResultStore(db_path=db_path)
        try:
            # Level 1: remediation session
            rem_sessions = store.list_remediation_sessions()
            assert len(rem_sessions) == 1
            rs = rem_sessions[0]
            assert rs.dry_run is False

            # Level 2: remediation records
            rems = store.get_remediations(rs.id)
            assert len(rems) >= 1
            rem = rems[0]
            assert rem.host == "10.0.0.1"
            assert rem.rule_id == "test-rule"
            assert rem.remediated is True
            assert rem.passed_after is True

            # Level 3: steps
            steps = store.get_remediation_steps(rem.id)
            assert len(steps) >= 1
            step = steps[0]
            assert step.mechanism == "sysctl_set"
            assert step.success is True

            # Level 4: pre-state (if captured)
            # sysctl_set captures the old value
            if step.pre_state_data is not None:
                assert isinstance(step.pre_state_data, dict)
                assert "key" in step.pre_state_data

            # Level 5: no rollback events (since remediation succeeded)
            events = store.get_rollback_events(step.id)
            assert len(events) == 0
        finally:
            store.close()
