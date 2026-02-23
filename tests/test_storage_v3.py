"""Tests for schema v3 remediation persistence."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from runner.storage import ResultStore


@pytest.fixture()
def store(tmp_path: Path) -> ResultStore:
    """Create a ResultStore with a temp database."""
    db = tmp_path / "test.db"
    return ResultStore(db_path=db)


@pytest.fixture()
def session_id(store: ResultStore) -> int:
    """Create a scan session and return its ID."""
    return store.create_session(hosts=["10.0.0.1"], rules_path="rules/")


class TestSchemaV3Migration:
    def test_schema_version_is_3(self, store: ResultStore) -> None:
        conn = store._get_conn()
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        assert row[0] == 3

    def test_remediation_sessions_table_exists(self, store: ResultStore) -> None:
        conn = store._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='remediation_sessions'"
        )
        assert cursor.fetchone() is not None

    def test_remediations_table_exists(self, store: ResultStore) -> None:
        conn = store._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='remediations'"
        )
        assert cursor.fetchone() is not None

    def test_remediation_steps_table_exists(self, store: ResultStore) -> None:
        conn = store._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='remediation_steps'"
        )
        assert cursor.fetchone() is not None

    def test_pre_states_table_exists(self, store: ResultStore) -> None:
        conn = store._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='pre_states'"
        )
        assert cursor.fetchone() is not None

    def test_rollback_events_table_exists(self, store: ResultStore) -> None:
        conn = store._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='rollback_events'"
        )
        assert cursor.fetchone() is not None

    def test_v2_to_v3_upgrade(self, tmp_path: Path) -> None:
        """Simulate a v2 database upgrading to v3."""
        db = tmp_path / "v2.db"
        conn = sqlite3.connect(str(db))
        # Create v2 schema manually
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version VALUES (2);
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hosts TEXT NOT NULL, rules_path TEXT NOT NULL,
                options TEXT DEFAULT ''
            );
            CREATE TABLE results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL, host TEXT NOT NULL,
                rule_id TEXT NOT NULL, passed INTEGER NOT NULL,
                detail TEXT DEFAULT '', remediated INTEGER DEFAULT 0,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                rule_hash TEXT
            );
            CREATE TABLE evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id INTEGER NOT NULL, method TEXT NOT NULL,
                command TEXT, stdout TEXT, stderr TEXT,
                exit_code INTEGER, expected TEXT, actual TEXT,
                check_timestamp TEXT NOT NULL
            );
            CREATE TABLE framework_refs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id INTEGER NOT NULL, framework TEXT NOT NULL,
                reference TEXT NOT NULL
            );
            """
        )
        # Insert a v2 result to make sure it survives
        conn.execute(
            "INSERT INTO sessions (hosts, rules_path) VALUES ('10.0.0.1', 'rules/')"
        )
        conn.execute(
            "INSERT INTO results (session_id, host, rule_id, passed) "
            "VALUES (1, '10.0.0.1', 'test-rule', 1)"
        )
        conn.commit()
        conn.close()

        # Open with ResultStore — should migrate to v3
        store = ResultStore(db_path=db)
        conn = store._get_conn()

        # Schema version should be 3
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        assert row[0] == 3

        # Existing data should survive
        results = store.get_results(1)
        assert len(results) == 1
        assert results[0].rule_id == "test-rule"

        # New tables should exist
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='remediation_sessions'"
        )
        assert cursor.fetchone() is not None

        store.close()


class TestRemediationPersistence:
    def test_create_remediation_session(
        self, store: ResultStore, session_id: int
    ) -> None:
        rem_sid = store.create_remediation_session(
            session_id,
            dry_run=False,
            rollback_on_failure=True,
            snapshot_mode="all",
        )
        assert rem_sid > 0

        record = store.get_remediation_session(rem_sid)
        assert record is not None
        assert record.session_id == session_id
        assert record.dry_run is False
        assert record.rollback_on_failure is True
        assert record.snapshot_mode == "all"

    def test_record_remediation(self, store: ResultStore, session_id: int) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid,
            "10.0.0.1",
            "ssh-disable-root-login",
            severity="high",
            passed_before=False,
            passed_after=True,
            remediated=True,
            rolled_back=False,
            detail="Set PermitRootLogin no",
        )
        assert rem_id > 0

        records = store.get_remediations(rem_sid)
        assert len(records) == 1
        r = records[0]
        assert r.host == "10.0.0.1"
        assert r.rule_id == "ssh-disable-root-login"
        assert r.severity == "high"
        assert r.passed_before is False
        assert r.passed_after is True
        assert r.remediated is True
        assert r.rolled_back is False
        assert r.detail == "Set PermitRootLogin no"

    def test_record_remediation_with_null_passed_after(
        self, store: ResultStore, session_id: int
    ) -> None:
        rem_sid = store.create_remediation_session(session_id)
        store.record_remediation(rem_sid, "10.0.0.1", "test-rule", passed_before=False)
        records = store.get_remediations(rem_sid)
        assert records[0].passed_after is None

    def test_record_step(self, store: ResultStore, session_id: int) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "test-rule", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True, "Set key=value")
        assert step_id > 0

        steps = store.get_remediation_steps(rem_id)
        assert len(steps) == 1
        s = steps[0]
        assert s.step_index == 0
        assert s.mechanism == "config_set"
        assert s.success is True
        assert s.detail == "Set key=value"
        assert s.pre_state_data is None  # no pre_state recorded yet

    def test_record_pre_state(self, store: ResultStore, session_id: int) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "test-rule", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        pre_state_data = {
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "old_line": "PermitRootLogin yes",
            "existed": True,
            "reload": "sshd",
            "restart": None,
        }
        ps_id = store.record_pre_state(
            step_id, "config_set", pre_state_data, capturable=True
        )
        assert ps_id > 0

        # Verify via get_remediation_steps (which joins pre_states)
        steps = store.get_remediation_steps(rem_id)
        assert len(steps) == 1
        assert steps[0].pre_state_data == pre_state_data
        assert steps[0].pre_state_capturable is True

    def test_record_rollback_event(self, store: ResultStore, session_id: int) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "test-rule", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        rb_id = store.record_rollback_event(
            step_id, "config_set", True, "Restored old line", source="inline"
        )
        assert rb_id > 0

        events = store.get_rollback_events(step_id)
        assert len(events) == 1
        e = events[0]
        assert e.mechanism == "config_set"
        assert e.success is True
        assert e.detail == "Restored old line"
        assert e.source == "inline"

    def test_get_remediations_host_filter(
        self, store: ResultStore, session_id: int
    ) -> None:
        rem_sid = store.create_remediation_session(session_id)
        store.record_remediation(rem_sid, "10.0.0.1", "rule-a", passed_before=False)
        store.record_remediation(rem_sid, "10.0.0.2", "rule-b", passed_before=False)

        host1 = store.get_remediations(rem_sid, host="10.0.0.1")
        assert len(host1) == 1
        assert host1[0].host == "10.0.0.1"

        all_hosts = store.get_remediations(rem_sid)
        assert len(all_hosts) == 2


class TestPreStateJsonSerialization:
    """Verify all mechanism data dicts serialize/deserialize correctly."""

    def _round_trip(
        self, store: ResultStore, session_id: int, mechanism: str, data: dict
    ) -> dict:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "test", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, mechanism, True)
        store.record_pre_state(step_id, mechanism, data)
        steps = store.get_remediation_steps(rem_id)
        return steps[0].pre_state_data  # type: ignore

    def test_config_set_data(self, store: ResultStore, session_id: int) -> None:
        data = {
            "path": "/etc/sysctl.conf",
            "key": "net.ipv4.ip_forward",
            "old_line": "net.ipv4.ip_forward = 1",
            "existed": True,
            "reload": None,
            "restart": None,
        }
        assert self._round_trip(store, session_id, "config_set", data) == data

    def test_file_permissions_data(self, store: ResultStore, session_id: int) -> None:
        data = {
            "entries": [
                {
                    "path": "/etc/passwd",
                    "owner": "root",
                    "group": "root",
                    "mode": "644",
                },
                {
                    "path": "/etc/shadow",
                    "owner": "root",
                    "group": "root",
                    "mode": "000",
                },
            ]
        }
        assert self._round_trip(store, session_id, "file_permissions", data) == data

    def test_sysctl_set_data(self, store: ResultStore, session_id: int) -> None:
        data = {
            "key": "net.ipv4.ip_forward",
            "old_value": "1",
            "persist_file": "/etc/sysctl.d/99-kensa.conf",
            "old_persist_content": None,
            "persist_existed": False,
        }
        assert self._round_trip(store, session_id, "sysctl_set", data) == data

    def test_package_present_data(self, store: ResultStore, session_id: int) -> None:
        data = {"name": "aide", "was_installed": False}
        assert self._round_trip(store, session_id, "package_present", data) == data

    def test_service_enabled_data(self, store: ResultStore, session_id: int) -> None:
        data = {"name": "sshd", "was_enabled": "enabled", "was_active": "active"}
        assert self._round_trip(store, session_id, "service_enabled", data) == data

    def test_command_exec_non_capturable(
        self, store: ResultStore, session_id: int
    ) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "test", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "command_exec", True)
        store.record_pre_state(step_id, "command_exec", {}, capturable=False)
        steps = store.get_remediation_steps(rem_id)
        assert steps[0].pre_state_capturable is False
        assert steps[0].pre_state_data == {}


class TestListRemediationSessions:
    def test_list_sessions(self, store: ResultStore, session_id: int) -> None:
        rs1 = store.create_remediation_session(session_id)
        rs2 = store.create_remediation_session(session_id)

        sessions = store.list_remediation_sessions()
        assert len(sessions) == 2
        session_ids = {s.id for s in sessions}
        assert session_ids == {rs1, rs2}

    def test_list_sessions_host_filter(
        self, store: ResultStore, session_id: int
    ) -> None:
        rs1 = store.create_remediation_session(session_id)
        store.record_remediation(rs1, "10.0.0.1", "rule-a", passed_before=False)

        rs2 = store.create_remediation_session(session_id)
        store.record_remediation(rs2, "10.0.0.2", "rule-b", passed_before=False)

        host1 = store.list_remediation_sessions(host="10.0.0.1")
        assert len(host1) == 1
        assert host1[0].id == rs1

    def test_list_sessions_limit(self, store: ResultStore, session_id: int) -> None:
        for _ in range(5):
            store.create_remediation_session(session_id)
        sessions = store.list_remediation_sessions(limit=3)
        assert len(sessions) == 3


class TestPruneSnapshots:
    def test_prune_old_snapshots(self, store: ResultStore, session_id: int) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "rule-a", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        store.record_pre_state(step_id, "config_set", {"key": "val"})

        # Backdate the remediation_session timestamp to 100 days ago
        conn = store._get_conn()
        old_ts = (datetime.now() - timedelta(days=100)).isoformat()
        conn.execute(
            "UPDATE remediation_sessions SET timestamp = ? WHERE id = ?",
            (old_ts, rem_sid),
        )
        conn.commit()

        # Prune with 90-day archive
        deleted = store.prune_snapshots(archive_days=90)
        assert deleted == 1

        # Step metadata still exists but pre_state is gone
        steps = store.get_remediation_steps(rem_id)
        assert len(steps) == 1
        assert steps[0].pre_state_data is None

    def test_prune_keeps_recent_snapshots(
        self, store: ResultStore, session_id: int
    ) -> None:
        rem_sid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rem_sid, "10.0.0.1", "rule-a", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        store.record_pre_state(step_id, "config_set", {"key": "val"})

        # Prune — should keep everything (timestamp is now)
        deleted = store.prune_snapshots(archive_days=90)
        assert deleted == 0

        steps = store.get_remediation_steps(rem_id)
        assert steps[0].pre_state_data == {"key": "val"}


class TestFullRemediationRoundTrip:
    """Integration test: write a full remediation, read it all back."""

    def test_full_round_trip(self, store: ResultStore, session_id: int) -> None:
        # Create remediation session
        rem_sid = store.create_remediation_session(
            session_id,
            dry_run=False,
            rollback_on_failure=True,
            snapshot_mode="all",
        )

        # Record a remediation with 2 steps
        rem_id = store.record_remediation(
            rem_sid,
            "10.0.0.1",
            "ssh-disable-root-login",
            severity="high",
            passed_before=False,
            passed_after=True,
            remediated=True,
            rolled_back=False,
            detail="Fixed",
        )

        # Step 0: config_set_dropin
        step0_id = store.record_step(
            rem_id, 0, "config_set_dropin", True, "Created drop-in"
        )
        store.record_pre_state(
            step0_id,
            "config_set_dropin",
            {
                "path": "/etc/ssh/sshd_config.d/00-kensa.conf",
                "existed": False,
                "old_content": None,
            },
        )

        # Step 1: command_exec (non-capturable)
        step1_id = store.record_step(rem_id, 1, "command_exec", True, "Reloaded sshd")
        store.record_pre_state(step1_id, "command_exec", {}, capturable=False)

        # Read it all back
        rs = store.get_remediation_session(rem_sid)
        assert rs is not None
        assert rs.rollback_on_failure is True

        rems = store.get_remediations(rem_sid)
        assert len(rems) == 1
        assert rems[0].rule_id == "ssh-disable-root-login"
        assert rems[0].passed_after is True

        steps = store.get_remediation_steps(rem_id)
        assert len(steps) == 2

        assert steps[0].mechanism == "config_set_dropin"
        assert steps[0].pre_state_data["existed"] is False
        assert steps[0].pre_state_capturable is True

        assert steps[1].mechanism == "command_exec"
        assert steps[1].pre_state_capturable is False

    def test_round_trip_with_rollback(
        self, store: ResultStore, session_id: int
    ) -> None:
        rem_sid = store.create_remediation_session(session_id, rollback_on_failure=True)
        rem_id = store.record_remediation(
            rem_sid,
            "10.0.0.1",
            "sysctl-forward",
            passed_before=False,
            passed_after=False,
            remediated=True,
            rolled_back=True,
            severity="medium",
        )

        step_id = store.record_step(rem_id, 0, "sysctl_set", True, "Set value")
        store.record_pre_state(
            step_id,
            "sysctl_set",
            {"key": "net.ipv4.ip_forward", "old_value": "1"},
        )
        store.record_rollback_event(
            step_id, "sysctl_set", True, "Restored to 1", source="inline"
        )

        # Read back
        rems = store.get_remediations(rem_sid)
        assert rems[0].rolled_back is True

        steps = store.get_remediation_steps(rem_id)
        assert steps[0].pre_state_data["old_value"] == "1"

        events = store.get_rollback_events(step_id)
        assert len(events) == 1
        assert events[0].success is True
        assert events[0].source == "inline"
