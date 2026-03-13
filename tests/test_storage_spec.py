"""Spec-derived tests for ResultStore.

Spec: specs/data/result_store.spec.yaml
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from runner._types import Evidence
from runner.storage import (
    DiffReport,
    ResultStore,
    compute_rule_hash,
    diff_sessions,
)


@pytest.fixture()
def store(tmp_path: Path) -> ResultStore:
    """Create a ResultStore with a temp database."""
    db = tmp_path / "test.db"
    return ResultStore(db_path=db)


@pytest.fixture()
def session_id(store: ResultStore) -> int:
    """Create a scan session and return its ID."""
    return store.create_session(hosts=["10.0.0.1"], rules_path="rules/")


class TestResultStoreSpecDerived:
    """Spec-derived tests for ResultStore.

    See specs/data/result_store.spec.yaml for specification.
    """

    def test_ac1_fresh_init_creates_v3_tables(self, tmp_path):
        """AC-1: Fresh init creates all v3 tables."""
        db = tmp_path / "fresh.db"
        store = ResultStore(db_path=db)
        conn = store._get_conn()

        expected_tables = {
            "schema_version",
            "sessions",
            "results",
            "evidence",
            "framework_refs",
            "remediation_sessions",
            "remediations",
            "remediation_steps",
            "pre_states",
            "rollback_events",
        }
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        actual_tables = {row["name"] for row in cursor.fetchall()}
        assert expected_tables.issubset(actual_tables)

        # Schema version is 4
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        assert row[0] == 4
        store.close()

    def test_ac2_v2_migration_preserves_data(self, tmp_path):
        """AC-2: v2 database migrated to v3 preserving existing data."""
        db = tmp_path / "v2.db"
        conn = sqlite3.connect(str(db))
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
            INSERT INTO sessions (hosts, rules_path) VALUES ('10.0.0.1', 'rules/');
            INSERT INTO results (session_id, host, rule_id, passed, detail)
                VALUES (1, '10.0.0.1', 'test-rule', 1, 'ok');
            """
        )
        conn.commit()
        conn.close()

        # Open with ResultStore — should migrate to v4
        store = ResultStore(db_path=db)
        conn2 = store._get_conn()

        # Schema version updated
        row = conn2.execute("SELECT version FROM schema_version").fetchone()
        assert row[0] == 4

        # Existing data preserved
        results = store.get_results(1)
        assert len(results) == 1
        assert results[0].rule_id == "test-rule"
        assert results[0].passed is True

        # New v3 tables exist
        cursor = conn2.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='remediation_sessions'"
        )
        assert cursor.fetchone() is not None
        store.close()

    def test_ac3_session_round_trip(self, store):
        """AC-3: create_session persists and get_session retrieves."""
        sid = store.create_session(
            hosts=["10.0.0.1", "10.0.0.2"],
            rules_path="rules/access-control/",
            options="--severity high",
        )
        assert sid > 0

        session = store.get_session(sid)
        assert session is not None
        assert session.hosts == ["10.0.0.1", "10.0.0.2"]
        assert session.rules_path == "rules/access-control/"
        assert session.options == "--severity high"

    def test_ac4_record_result_with_evidence_and_refs(self, store, session_id):
        """AC-4: record_result persists result, evidence, and framework_refs."""
        ev = Evidence(
            method="command",
            command="grep PermitRootLogin /etc/ssh/sshd_config",
            stdout="PermitRootLogin no",
            stderr="",
            exit_code=0,
            expected="exit=0, stdout contains 'no'",
            actual="PermitRootLogin no",
            timestamp=datetime.now(timezone.utc),
        )
        refs = {"cis_rhel9": "5.1.12", "stig_rhel9": "V-123456"}

        rid = store.record_result(
            session_id,
            "10.0.0.1",
            "ssh-disable-root-login",
            passed=True,
            detail="PermitRootLogin no",
            evidence=ev,
            framework_refs=refs,
        )
        assert rid > 0

        # Verify result
        results = store.get_results(session_id)
        assert len(results) == 1
        assert results[0].passed is True

    def test_ac5_get_evidence(self, store, session_id):
        """AC-5: get_evidence retrieves Evidence or None."""
        ev = Evidence(
            method="command",
            command="test_cmd",
            stdout="ok",
            stderr="",
            exit_code=0,
            expected="exit=0",
            actual="ok",
            timestamp=datetime.now(timezone.utc),
        )
        rid = store.record_result(session_id, "10.0.0.1", "rule-a", True, evidence=ev)
        retrieved = store.get_evidence(rid)
        assert retrieved is not None
        assert retrieved.method == "command"
        assert retrieved.stdout == "ok"

        # No evidence case
        rid2 = store.record_result(session_id, "10.0.0.1", "rule-b", True)
        assert store.get_evidence(rid2) is None

    def test_ac6_get_framework_refs(self, store, session_id):
        """AC-6: get_framework_refs returns dict or empty dict."""
        refs = {"cis": "5.1.12", "stig": "V-123"}
        rid = store.record_result(
            session_id, "10.0.0.1", "rule-a", True, framework_refs=refs
        )
        retrieved = store.get_framework_refs(rid)
        assert retrieved == refs

        # No refs case
        rid2 = store.record_result(session_id, "10.0.0.1", "rule-b", True)
        assert store.get_framework_refs(rid2) == {}

    def test_ac7_remediation_session(self, store, session_id):
        """AC-7: create_remediation_session persists and retrieves."""
        rsid = store.create_remediation_session(
            session_id,
            dry_run=True,
            rollback_on_failure=True,
            snapshot_mode="risk_based",
        )
        assert rsid > 0

        record = store.get_remediation_session(rsid)
        assert record is not None
        assert record.session_id == session_id
        assert record.dry_run is True
        assert record.rollback_on_failure is True
        assert record.snapshot_mode == "risk_based"

    def test_ac8_record_remediation(self, store, session_id):
        """AC-8: record_remediation persists all fields including nullable passed_after."""
        rsid = store.create_remediation_session(session_id)
        store.record_remediation(
            rsid,
            "10.0.0.1",
            "ssh-disable-root",
            severity="high",
            passed_before=False,
            passed_after=True,
            remediated=True,
            rolled_back=False,
            detail="Fixed",
        )
        records = store.get_remediations(rsid)
        assert len(records) == 1
        r = records[0]
        assert r.severity == "high"
        assert r.passed_before is False
        assert r.passed_after is True
        assert r.remediated is True
        assert r.rolled_back is False

        # Nullable passed_after
        rsid2 = store.create_remediation_session(session_id)
        store.record_remediation(rsid2, "10.0.0.1", "rule-b", passed_before=False)
        recs2 = store.get_remediations(rsid2)
        assert recs2[0].passed_after is None

    def test_ac9_record_step(self, store, session_id):
        """AC-9: record_step persists step_index, mechanism, success, detail."""
        rsid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rsid, "10.0.0.1", "rule-a", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True, "Set key=val")
        assert step_id > 0

        steps = store.get_remediation_steps(rem_id)
        assert len(steps) == 1
        assert steps[0].step_index == 0
        assert steps[0].mechanism == "config_set"
        assert steps[0].success is True
        assert steps[0].detail == "Set key=val"

    def test_ac10_pre_state_json_round_trip(self, store, session_id):
        """AC-10: record_pre_state round-trips JSON data correctly."""
        rsid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rsid, "10.0.0.1", "rule-a", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        data = {
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "old_line": "PermitRootLogin yes",
            "existed": True,
            "nested": {"a": [1, 2, 3]},
        }
        store.record_pre_state(step_id, "config_set", data, capturable=True)

        steps = store.get_remediation_steps(rem_id)
        assert steps[0].pre_state_data == data
        assert steps[0].pre_state_capturable is True

    def test_ac11_rollback_event(self, store, session_id):
        """AC-11: record_rollback_event persists all fields."""
        rsid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rsid, "10.0.0.1", "rule-a", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        store.record_rollback_event(
            step_id, "config_set", True, "Restored old line", source="manual"
        )

        events = store.get_rollback_events(step_id)
        assert len(events) == 1
        assert events[0].mechanism == "config_set"
        assert events[0].success is True
        assert events[0].detail == "Restored old line"
        assert events[0].source == "manual"

    def test_ac12_get_history(self, store, session_id):
        """AC-12: get_history returns HistoryEntry list filtered by host."""
        store.record_result(session_id, "10.0.0.1", "rule-a", True, "ok")
        store.record_result(session_id, "10.0.0.1", "rule-b", False, "fail")
        store.record_result(session_id, "10.0.0.2", "rule-a", True, "ok")

        history = store.get_history("10.0.0.1")
        assert len(history) == 2
        assert all(h.host == "10.0.0.1" for h in history)

        # Filter by rule_id
        history_rule = store.get_history("10.0.0.1", rule_id="rule-a")
        assert len(history_rule) == 1
        assert history_rule[0].rule_id == "rule-a"

    def test_ac13_diff_sessions(self, store):
        """AC-13: diff_sessions classifies changes correctly."""
        sid1 = store.create_session(hosts=["h1"], rules_path="r/")
        store.record_result(sid1, "h1", "rule-a", True, "ok")  # will regress
        store.record_result(sid1, "h1", "rule-b", False, "fail")  # will resolve
        store.record_result(sid1, "h1", "rule-c", True, "ok")  # unchanged

        sid2 = store.create_session(hosts=["h1"], rules_path="r/")
        store.record_result(sid2, "h1", "rule-a", False, "fail")  # regression
        store.record_result(sid2, "h1", "rule-b", True, "ok")  # resolved
        store.record_result(sid2, "h1", "rule-c", True, "ok")  # unchanged
        store.record_result(sid2, "h1", "rule-d", False, "fail")  # new failure

        report = diff_sessions(store, sid1, sid2)
        assert isinstance(report, DiffReport)
        summary = report.summary()
        assert summary["regressions"] == 1
        assert summary["resolved"] == 1
        assert summary["new_failures"] == 1
        assert summary["unchanged"] == 1

    def test_ac14_prune_old_results(self, store):
        """AC-14: prune_old_results deletes sessions older than retention_days."""
        sid = store.create_session(hosts=["h1"], rules_path="r/")
        store.record_result(sid, "h1", "rule-a", True)

        # Backdate session
        conn = store._get_conn()
        old_ts = (datetime.now() - timedelta(days=100)).isoformat()
        conn.execute("UPDATE sessions SET timestamp = ? WHERE id = ?", (old_ts, sid))
        conn.commit()

        deleted = store.prune_old_results(days=90)
        assert deleted == 1
        assert store.get_session(sid) is None

    def test_ac15_prune_snapshots(self, store, session_id):
        """AC-15: prune_snapshots deletes old pre_states, preserves step metadata."""
        rsid = store.create_remediation_session(session_id)
        rem_id = store.record_remediation(
            rsid, "10.0.0.1", "rule-a", passed_before=False
        )
        step_id = store.record_step(rem_id, 0, "config_set", True)
        store.record_pre_state(step_id, "config_set", {"key": "val"})

        # Backdate remediation session
        conn = store._get_conn()
        old_ts = (datetime.now() - timedelta(days=100)).isoformat()
        conn.execute(
            "UPDATE remediation_sessions SET timestamp = ? WHERE id = ?",
            (old_ts, rsid),
        )
        conn.commit()

        deleted = store.prune_snapshots(archive_days=90)
        assert deleted == 1

        # Step metadata preserved, pre_state gone
        steps = store.get_remediation_steps(rem_id)
        assert len(steps) == 1
        assert steps[0].pre_state_data is None

    def test_ac16_single_connection_pattern(self, store):
        """AC-16: Repeated _get_conn() returns same connection."""
        conn1 = store._get_conn()
        conn2 = store._get_conn()
        assert conn1 is conn2

    def test_ac17_close_releases_connection(self, store):
        """AC-17: close() releases connection; next call creates new one."""
        conn1 = store._get_conn()
        store.close()
        assert store._conn is None

        conn2 = store._get_conn()
        assert conn2 is not conn1

    def test_ac18_compute_rule_hash(self):
        """AC-18: compute_rule_hash returns 16-char SHA-256 prefix."""
        h = compute_rule_hash("id: test-rule\ntitle: Test Rule\n")
        assert isinstance(h, str)
        assert len(h) == 16
        # Deterministic
        assert compute_rule_hash("same") == compute_rule_hash("same")
        assert compute_rule_hash("a") != compute_rule_hash("b")
