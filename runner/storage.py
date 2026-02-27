"""Result persistence using SQLite.

This module provides storage for compliance scan results, enabling historical
queries and diff reporting. Results are stored in a local SQLite database.

Example:
    >>> from runner.storage import ResultStore
    >>> store = ResultStore()
    >>> session_id = store.create_session(hosts=["192.168.1.100"], rules_path="rules/")
    >>> store.record_result(session_id, "192.168.1.100", "ssh-disable-root-login", True, "PermitRootLogin=no")
    >>> store.close()

"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from runner._types import Evidence

if TYPE_CHECKING:
    pass


@dataclass
class Session:
    """A scan session record."""

    id: int
    timestamp: datetime
    hosts: list[str]
    rules_path: str
    options: str


@dataclass
class ResultRecord:
    """A single rule result record."""

    id: int
    session_id: int
    host: str
    rule_id: str
    passed: bool
    detail: str
    remediated: bool
    timestamp: datetime
    rule_hash: str | None


@dataclass
class HistoryEntry:
    """A summary entry for history display."""

    session_id: int
    timestamp: datetime
    host: str
    rule_id: str
    passed: bool
    remediated: bool


@dataclass
class RemediationSessionRecord:
    """A remediation session record."""

    id: int
    session_id: int
    dry_run: bool
    rollback_on_failure: bool
    snapshot_mode: str
    timestamp: datetime


@dataclass
class RemediationRecord:
    """A single rule remediation record."""

    id: int
    remediation_session_id: int
    host: str
    rule_id: str
    severity: str | None
    passed_before: bool
    passed_after: bool | None
    remediated: bool
    rolled_back: bool
    detail: str
    timestamp: datetime
    steps: list[RemediationStepRecord] = field(default_factory=list)


@dataclass
class RemediationStepRecord:
    """A single remediation step record."""

    id: int
    remediation_id: int
    step_index: int
    mechanism: str
    success: bool
    detail: str
    pre_state_data: dict | None = None
    pre_state_capturable: bool = True


@dataclass
class RollbackEventRecord:
    """A rollback event log entry."""

    id: int
    step_id: int
    mechanism: str
    success: bool
    detail: str
    timestamp: datetime
    source: str


def _parse_timestamp(value: str | datetime) -> datetime:
    """Parse a timestamp that may be a string or already a datetime."""
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def get_db_path(project_root: Path | None = None) -> Path:
    """Get the database path for the project.

    Args:
        project_root: Project root directory. Defaults to current directory.

    Returns:
        Path to the SQLite database file.

    """
    root = project_root or Path.cwd()
    db_dir = root / ".kensa"
    db_dir.mkdir(exist_ok=True)
    return db_dir / "results.db"


class ResultStore:
    """SQLite-based result storage.

    Stores compliance scan results for historical queries and diff reporting.

    Attributes:
        db_path: Path to the SQLite database file.
        retention_days: Number of days to retain results (default 90).

    """

    SCHEMA_VERSION = 4

    def __init__(
        self,
        db_path: Path | None = None,
        retention_days: int = 90,
    ):
        """Initialize the result store.

        Args:
            db_path: Path to database file. Defaults to .kensa/results.db.
            retention_days: Days to retain results before pruning.

        """
        self.db_path = db_path or get_db_path()
        self.retention_days = retention_days
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hosts TEXT NOT NULL,
                rules_path TEXT NOT NULL,
                options TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                passed INTEGER NOT NULL,
                detail TEXT DEFAULT '',
                remediated INTEGER DEFAULT 0,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                rule_hash TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id);
            CREATE INDEX IF NOT EXISTS idx_results_host ON results(host);
            CREATE INDEX IF NOT EXISTS idx_results_rule ON results(rule_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp);
            """
        )

        # Check current schema version and migrate if needed
        cursor = conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cursor.fetchone()
        current_version = row[0] if row else 0

        if current_version < 2:
            self._migrate_to_v2(conn)

        if current_version < 3:
            self._migrate_to_v3(conn)

        if current_version < 4:
            self._migrate_to_v4(conn)

        # Set or update schema version
        if row is None:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (self.SCHEMA_VERSION,),
            )
        elif current_version < self.SCHEMA_VERSION:
            conn.execute(
                "UPDATE schema_version SET version = ?",
                (self.SCHEMA_VERSION,),
            )

        conn.commit()

    def _migrate_to_v2(self, conn: sqlite3.Connection) -> None:
        """Migrate database to schema version 2 (add evidence and framework_refs)."""
        conn.executescript(
            """
            -- Evidence table for storing raw check evidence
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id INTEGER NOT NULL,
                method TEXT NOT NULL,
                command TEXT,
                stdout TEXT,
                stderr TEXT,
                exit_code INTEGER,
                expected TEXT,
                actual TEXT,
                check_timestamp TEXT NOT NULL,
                FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
            );

            -- Framework references table
            CREATE TABLE IF NOT EXISTS framework_refs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id INTEGER NOT NULL,
                framework TEXT NOT NULL,
                reference TEXT NOT NULL,
                FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_result ON evidence(result_id);
            CREATE INDEX IF NOT EXISTS idx_framework_refs_result ON framework_refs(result_id);
            CREATE INDEX IF NOT EXISTS idx_framework_refs_framework ON framework_refs(framework);
            """
        )

    def _migrate_to_v3(self, conn: sqlite3.Connection) -> None:
        """Migrate database to schema version 3 (add remediation persistence)."""
        conn.executescript(
            """
            -- Remediation session (one per kensa remediate invocation)
            CREATE TABLE IF NOT EXISTS remediation_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                dry_run INTEGER NOT NULL DEFAULT 0,
                rollback_on_failure INTEGER NOT NULL DEFAULT 0,
                snapshot_mode TEXT NOT NULL DEFAULT 'all',
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );

            -- One row per rule remediated on a host
            CREATE TABLE IF NOT EXISTS remediations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remediation_session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT,
                passed_before INTEGER NOT NULL,
                passed_after INTEGER,
                remediated INTEGER NOT NULL DEFAULT 0,
                rolled_back INTEGER NOT NULL DEFAULT 0,
                detail TEXT DEFAULT '',
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (remediation_session_id)
                    REFERENCES remediation_sessions(id) ON DELETE CASCADE
            );

            -- One row per remediation step
            CREATE TABLE IF NOT EXISTS remediation_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remediation_id INTEGER NOT NULL,
                step_index INTEGER NOT NULL,
                mechanism TEXT NOT NULL,
                success INTEGER NOT NULL,
                detail TEXT DEFAULT '',
                FOREIGN KEY (remediation_id)
                    REFERENCES remediations(id) ON DELETE CASCADE
            );

            -- Pre-state snapshot for a step (the rollback payload)
            CREATE TABLE IF NOT EXISTS pre_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                step_id INTEGER NOT NULL,
                mechanism TEXT NOT NULL,
                data_json TEXT NOT NULL,
                capturable INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (step_id)
                    REFERENCES remediation_steps(id) ON DELETE CASCADE
            );

            -- Rollback event log
            CREATE TABLE IF NOT EXISTS rollback_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                step_id INTEGER NOT NULL,
                mechanism TEXT NOT NULL,
                success INTEGER NOT NULL,
                detail TEXT DEFAULT '',
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL DEFAULT 'inline',
                FOREIGN KEY (step_id)
                    REFERENCES remediation_steps(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_rem_sessions_session
                ON remediation_sessions(session_id);
            CREATE INDEX IF NOT EXISTS idx_remediations_session
                ON remediations(remediation_session_id);
            CREATE INDEX IF NOT EXISTS idx_remediations_host_rule
                ON remediations(host, rule_id);
            CREATE INDEX IF NOT EXISTS idx_rem_steps_remediation
                ON remediation_steps(remediation_id);
            CREATE INDEX IF NOT EXISTS idx_pre_states_step
                ON pre_states(step_id);
            CREATE INDEX IF NOT EXISTS idx_rollback_events_step
                ON rollback_events(step_id);
            """
        )

    def _migrate_to_v4(self, conn: sqlite3.Connection) -> None:
        """Migrate database to schema version 4 (add session duration)."""
        # Check if column already exists (idempotent)
        cursor = conn.execute("PRAGMA table_info(sessions)")
        columns = {row[1] for row in cursor.fetchall()}
        if "duration_seconds" not in columns:
            conn.execute(
                "ALTER TABLE sessions ADD COLUMN duration_seconds REAL DEFAULT NULL"
            )

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def create_session(
        self,
        hosts: list[str],
        rules_path: str,
        options: str = "",
    ) -> int:
        """Create a new scan session.

        Args:
            hosts: List of target hosts.
            rules_path: Path to rules directory or file.
            options: CLI options used for the scan.

        Returns:
            Session ID for recording results.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO sessions (hosts, rules_path, options)
            VALUES (?, ?, ?)
            """,
            (",".join(hosts), rules_path, options),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def record_result(
        self,
        session_id: int,
        host: str,
        rule_id: str,
        passed: bool,
        detail: str = "",
        remediated: bool = False,
        rule_hash: str | None = None,
        evidence: Evidence | None = None,
        framework_refs: dict[str, str] | None = None,
    ) -> int:
        """Record a rule result with optional evidence and framework references.

        Args:
            session_id: Session ID from create_session().
            host: Target host.
            rule_id: Rule identifier.
            passed: Whether the check passed.
            detail: Result detail message.
            remediated: Whether remediation was applied.
            rule_hash: Hash of rule content for change detection.
            evidence: Raw evidence from the check (for audit).
            framework_refs: Framework references (e.g., {"cis_rhel9_v2": "5.1.12"}).

        Returns:
            Result record ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO results (session_id, host, rule_id, passed, detail, remediated, rule_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                host,
                rule_id,
                int(passed),
                detail,
                int(remediated),
                rule_hash,
            ),
        )
        result_id = cursor.lastrowid

        # Store evidence if provided
        if evidence is not None:
            conn.execute(
                """
                INSERT INTO evidence (result_id, method, command, stdout, stderr,
                                      exit_code, expected, actual, check_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    evidence.method,
                    evidence.command,
                    evidence.stdout,
                    evidence.stderr,
                    evidence.exit_code,
                    evidence.expected,
                    evidence.actual,
                    evidence.timestamp.isoformat(),
                ),
            )

        # Store framework references if provided
        if framework_refs:
            for framework, reference in framework_refs.items():
                conn.execute(
                    """
                    INSERT INTO framework_refs (result_id, framework, reference)
                    VALUES (?, ?, ?)
                    """,
                    (result_id, framework, reference),
                )

        conn.commit()
        return result_id  # type: ignore

    def get_session(self, session_id: int) -> Session | None:
        """Get session by ID.

        Args:
            session_id: Session ID.

        Returns:
            Session object or None if not found.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, timestamp, hosts, rules_path, options FROM sessions WHERE id = ?",
            (session_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return Session(
            id=row["id"],
            timestamp=_parse_timestamp(row["timestamp"]),
            hosts=row["hosts"].split(","),
            rules_path=row["rules_path"],
            options=row["options"],
        )

    def get_results(self, session_id: int) -> list[ResultRecord]:
        """Get all results for a session.

        Args:
            session_id: Session ID.

        Returns:
            List of result records.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT id, session_id, host, rule_id, passed, detail, remediated, timestamp, rule_hash
            FROM results
            WHERE session_id = ?
            ORDER BY host, rule_id
            """,
            (session_id,),
        )
        return [
            ResultRecord(
                id=row["id"],
                session_id=row["session_id"],
                host=row["host"],
                rule_id=row["rule_id"],
                passed=bool(row["passed"]),
                detail=row["detail"],
                remediated=bool(row["remediated"]),
                timestamp=_parse_timestamp(row["timestamp"]),
                rule_hash=row["rule_hash"],
            )
            for row in cursor.fetchall()
        ]

    def get_evidence(self, result_id: int) -> Evidence | None:
        """Retrieve evidence for a specific result.

        Args:
            result_id: Result record ID.

        Returns:
            Evidence object or None if not found.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT method, command, stdout, stderr, exit_code, expected, actual, check_timestamp
            FROM evidence
            WHERE result_id = ?
            """,
            (result_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return Evidence(
            method=row["method"],
            command=row["command"],
            stdout=row["stdout"] or "",
            stderr=row["stderr"] or "",
            exit_code=row["exit_code"] or 0,
            expected=row["expected"],
            actual=row["actual"],
            timestamp=_parse_timestamp(row["check_timestamp"]),
        )

    def get_framework_refs(self, result_id: int) -> dict[str, str]:
        """Retrieve all framework references for a result.

        Args:
            result_id: Result record ID.

        Returns:
            Dict mapping framework keys to their references.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT framework, reference
            FROM framework_refs
            WHERE result_id = ?
            """,
            (result_id,),
        )
        return {row["framework"]: row["reference"] for row in cursor.fetchall()}

    def get_results_by_timerange(
        self,
        start: datetime,
        end: datetime,
        host: str | None = None,
        rule_id: str | None = None,
        framework: str | None = None,
    ) -> list[ResultRecord]:
        """Query results within a time range with optional filters.

        Args:
            start: Start of time range (inclusive).
            end: End of time range (inclusive).
            host: Filter by host (optional).
            rule_id: Filter by rule ID (optional).
            framework: Filter by framework (optional, requires join).

        Returns:
            List of result records matching the criteria.

        """
        conn = self._get_conn()

        query = """
            SELECT DISTINCT r.id, r.session_id, r.host, r.rule_id, r.passed,
                   r.detail, r.remediated, r.timestamp, r.rule_hash
            FROM results r
        """
        params: list = []

        if framework:
            query += " JOIN framework_refs f ON r.id = f.result_id"

        query += " WHERE r.timestamp BETWEEN ? AND ?"
        params.extend([start.isoformat(), end.isoformat()])

        if host:
            query += " AND r.host = ?"
            params.append(host)

        if rule_id:
            query += " AND r.rule_id = ?"
            params.append(rule_id)

        if framework:
            query += " AND f.framework = ?"
            params.append(framework)

        query += " ORDER BY r.timestamp DESC"

        cursor = conn.execute(query, params)
        return [
            ResultRecord(
                id=row["id"],
                session_id=row["session_id"],
                host=row["host"],
                rule_id=row["rule_id"],
                passed=bool(row["passed"]),
                detail=row["detail"],
                remediated=bool(row["remediated"]),
                timestamp=_parse_timestamp(row["timestamp"]),
                rule_hash=row["rule_hash"],
            )
            for row in cursor.fetchall()
        ]

    def list_sessions(
        self,
        host: str | None = None,
        limit: int = 20,
    ) -> list[Session]:
        """List recent sessions.

        Args:
            host: Filter by host (optional).
            limit: Maximum number of sessions to return.

        Returns:
            List of sessions, most recent first.

        """
        conn = self._get_conn()
        if host:
            cursor = conn.execute(
                """
                SELECT DISTINCT s.id, s.timestamp, s.hosts, s.rules_path, s.options
                FROM sessions s
                JOIN results r ON s.id = r.session_id
                WHERE r.host = ?
                ORDER BY s.timestamp DESC
                LIMIT ?
                """,
                (host, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT id, timestamp, hosts, rules_path, options
                FROM sessions
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )

        return [
            Session(
                id=row["id"],
                timestamp=_parse_timestamp(row["timestamp"]),
                hosts=row["hosts"].split(","),
                rules_path=row["rules_path"],
                options=row["options"],
            )
            for row in cursor.fetchall()
        ]

    def get_history(
        self,
        host: str,
        rule_id: str | None = None,
        limit: int = 50,
    ) -> list[HistoryEntry]:
        """Get result history for a host.

        Args:
            host: Target host.
            rule_id: Filter by rule ID (optional).
            limit: Maximum entries to return.

        Returns:
            List of history entries, most recent first.

        """
        conn = self._get_conn()
        if rule_id:
            cursor = conn.execute(
                """
                SELECT r.session_id, r.timestamp, r.host, r.rule_id, r.passed, r.remediated
                FROM results r
                WHERE r.host = ? AND r.rule_id = ?
                ORDER BY r.timestamp DESC
                LIMIT ?
                """,
                (host, rule_id, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT r.session_id, r.timestamp, r.host, r.rule_id, r.passed, r.remediated
                FROM results r
                WHERE r.host = ?
                ORDER BY r.timestamp DESC
                LIMIT ?
                """,
                (host, limit),
            )

        return [
            HistoryEntry(
                session_id=row["session_id"],
                timestamp=_parse_timestamp(row["timestamp"]),
                host=row["host"],
                rule_id=row["rule_id"],
                passed=bool(row["passed"]),
                remediated=bool(row["remediated"]),
            )
            for row in cursor.fetchall()
        ]

    def prune_old_results(self, days: int | None = None) -> int:
        """Remove results older than retention period.

        Args:
            days: Days to retain. Defaults to self.retention_days.

        Returns:
            Number of sessions deleted.

        """
        days = days or self.retention_days
        cutoff = datetime.now() - timedelta(days=days)
        conn = self._get_conn()

        # Delete old sessions (CASCADE will delete results)
        cursor = conn.execute(
            "DELETE FROM sessions WHERE timestamp < ?",
            (cutoff.isoformat(),),
        )
        conn.commit()
        return cursor.rowcount

    def get_stats(self) -> dict:
        """Get database statistics.

        Returns:
            Dict with session_count, result_count, oldest_session, newest_session.

        """
        conn = self._get_conn()

        session_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        result_count = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]

        oldest = conn.execute("SELECT MIN(timestamp) FROM sessions").fetchone()[0]
        newest = conn.execute("SELECT MAX(timestamp) FROM sessions").fetchone()[0]

        return {
            "session_count": session_count,
            "result_count": result_count,
            "oldest_session": oldest,
            "newest_session": newest,
            "db_path": str(self.db_path),
        }

    # ── Remediation persistence (schema v3) ─────────────────────────────────

    def create_remediation_session(
        self,
        session_id: int,
        *,
        dry_run: bool = False,
        rollback_on_failure: bool = False,
        snapshot_mode: str = "all",
    ) -> int:
        """Create a remediation session linked to a scan session.

        Args:
            session_id: Parent session ID from create_session().
            dry_run: Whether this was a dry-run invocation.
            rollback_on_failure: Whether inline rollback was enabled.
            snapshot_mode: Snapshot capture mode (all, risk_based, none).

        Returns:
            Remediation session ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO remediation_sessions
                (session_id, dry_run, rollback_on_failure, snapshot_mode)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, int(dry_run), int(rollback_on_failure), snapshot_mode),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def record_remediation(
        self,
        remediation_session_id: int,
        host: str,
        rule_id: str,
        *,
        severity: str | None = None,
        passed_before: bool = False,
        passed_after: bool | None = None,
        remediated: bool = False,
        rolled_back: bool = False,
        detail: str = "",
    ) -> int:
        """Record a rule remediation result.

        Args:
            remediation_session_id: Parent remediation session ID.
            host: Target host.
            rule_id: Rule identifier.
            severity: Rule severity.
            passed_before: Check result before remediation.
            passed_after: Check result after remediation (None if not re-checked).
            remediated: Whether remediation was applied.
            rolled_back: Whether rollback was executed.
            detail: Remediation outcome detail.

        Returns:
            Remediation record ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO remediations
                (remediation_session_id, host, rule_id, severity,
                 passed_before, passed_after, remediated, rolled_back, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                remediation_session_id,
                host,
                rule_id,
                severity,
                int(passed_before),
                int(passed_after) if passed_after is not None else None,
                int(remediated),
                int(rolled_back),
                detail,
            ),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def record_step(
        self,
        remediation_id: int,
        step_index: int,
        mechanism: str,
        success: bool,
        detail: str = "",
    ) -> int:
        """Record a remediation step.

        Args:
            remediation_id: Parent remediation record ID.
            step_index: Step index within the remediation.
            mechanism: Remediation mechanism name.
            success: Whether the step succeeded.
            detail: Step outcome detail.

        Returns:
            Step record ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO remediation_steps
                (remediation_id, step_index, mechanism, success, detail)
            VALUES (?, ?, ?, ?, ?)
            """,
            (remediation_id, step_index, mechanism, int(success), detail),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def record_pre_state(
        self,
        step_id: int,
        mechanism: str,
        data: dict,
        capturable: bool = True,
    ) -> int:
        """Record a pre-state snapshot for a remediation step.

        Args:
            step_id: Parent step record ID.
            mechanism: Mechanism name.
            data: Pre-state data dict (JSON-serializable).
            capturable: Whether this mechanism supports rollback.

        Returns:
            Pre-state record ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO pre_states (step_id, mechanism, data_json, capturable)
            VALUES (?, ?, ?, ?)
            """,
            (step_id, mechanism, json.dumps(data), int(capturable)),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def record_rollback_event(
        self,
        step_id: int,
        mechanism: str,
        success: bool,
        detail: str = "",
        source: str = "inline",
    ) -> int:
        """Record a rollback event.

        Args:
            step_id: The step that was rolled back.
            mechanism: Mechanism name.
            success: Whether rollback succeeded.
            detail: Rollback outcome detail.
            source: Rollback trigger ('inline' or 'manual').

        Returns:
            Rollback event record ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO rollback_events
                (step_id, mechanism, success, detail, source)
            VALUES (?, ?, ?, ?, ?)
            """,
            (step_id, mechanism, int(success), detail, source),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def get_remediation_session(
        self, remediation_session_id: int
    ) -> RemediationSessionRecord | None:
        """Get a remediation session by ID.

        Args:
            remediation_session_id: Remediation session ID.

        Returns:
            RemediationSessionRecord or None if not found.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT id, session_id, dry_run, rollback_on_failure,
                   snapshot_mode, timestamp
            FROM remediation_sessions WHERE id = ?
            """,
            (remediation_session_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return RemediationSessionRecord(
            id=row["id"],
            session_id=row["session_id"],
            dry_run=bool(row["dry_run"]),
            rollback_on_failure=bool(row["rollback_on_failure"]),
            snapshot_mode=row["snapshot_mode"],
            timestamp=_parse_timestamp(row["timestamp"]),
        )

    def get_remediations(
        self, remediation_session_id: int, *, host: str | None = None
    ) -> list[RemediationRecord]:
        """Get all remediation records for a session.

        Args:
            remediation_session_id: Remediation session ID.
            host: Optional host filter.

        Returns:
            List of remediation records.

        """
        conn = self._get_conn()
        query = """
            SELECT id, remediation_session_id, host, rule_id, severity,
                   passed_before, passed_after, remediated, rolled_back,
                   detail, timestamp
            FROM remediations
            WHERE remediation_session_id = ?
        """
        params: list = [remediation_session_id]
        if host:
            query += " AND host = ?"
            params.append(host)
        query += " ORDER BY host, rule_id"

        cursor = conn.execute(query, params)
        return [
            RemediationRecord(
                id=row["id"],
                remediation_session_id=row["remediation_session_id"],
                host=row["host"],
                rule_id=row["rule_id"],
                severity=row["severity"],
                passed_before=bool(row["passed_before"]),
                passed_after=(
                    bool(row["passed_after"])
                    if row["passed_after"] is not None
                    else None
                ),
                remediated=bool(row["remediated"]),
                rolled_back=bool(row["rolled_back"]),
                detail=row["detail"],
                timestamp=_parse_timestamp(row["timestamp"]),
            )
            for row in cursor.fetchall()
        ]

    def get_remediation_steps(self, remediation_id: int) -> list[RemediationStepRecord]:
        """Get all steps for a remediation, including pre-state data.

        Args:
            remediation_id: Remediation record ID.

        Returns:
            List of step records with pre-state data populated.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT s.id, s.remediation_id, s.step_index, s.mechanism,
                   s.success, s.detail,
                   p.data_json, p.capturable
            FROM remediation_steps s
            LEFT JOIN pre_states p ON p.step_id = s.id
            WHERE s.remediation_id = ?
            ORDER BY s.step_index
            """,
            (remediation_id,),
        )
        return [
            RemediationStepRecord(
                id=row["id"],
                remediation_id=row["remediation_id"],
                step_index=row["step_index"],
                mechanism=row["mechanism"],
                success=bool(row["success"]),
                detail=row["detail"],
                pre_state_data=(
                    json.loads(row["data_json"]) if row["data_json"] else None
                ),
                pre_state_capturable=(
                    bool(row["capturable"]) if row["capturable"] is not None else True
                ),
            )
            for row in cursor.fetchall()
        ]

    def get_rollback_events(self, step_id: int) -> list[RollbackEventRecord]:
        """Get rollback events for a step.

        Args:
            step_id: Step record ID.

        Returns:
            List of rollback events.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT id, step_id, mechanism, success, detail, timestamp, source
            FROM rollback_events
            WHERE step_id = ?
            ORDER BY timestamp
            """,
            (step_id,),
        )
        return [
            RollbackEventRecord(
                id=row["id"],
                step_id=row["step_id"],
                mechanism=row["mechanism"],
                success=bool(row["success"]),
                detail=row["detail"],
                timestamp=_parse_timestamp(row["timestamp"]),
                source=row["source"],
            )
            for row in cursor.fetchall()
        ]

    def list_remediation_sessions(
        self,
        host: str | None = None,
        limit: int = 20,
    ) -> list[RemediationSessionRecord]:
        """List recent remediation sessions.

        Args:
            host: Filter by host (optional).
            limit: Maximum sessions to return.

        Returns:
            List of remediation session records, most recent first.

        """
        conn = self._get_conn()
        if host:
            cursor = conn.execute(
                """
                SELECT DISTINCT rs.id, rs.session_id, rs.dry_run,
                       rs.rollback_on_failure, rs.snapshot_mode, rs.timestamp
                FROM remediation_sessions rs
                JOIN remediations r ON rs.id = r.remediation_session_id
                WHERE r.host = ?
                ORDER BY rs.timestamp DESC
                LIMIT ?
                """,
                (host, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT id, session_id, dry_run, rollback_on_failure,
                       snapshot_mode, timestamp
                FROM remediation_sessions
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )

        return [
            RemediationSessionRecord(
                id=row["id"],
                session_id=row["session_id"],
                dry_run=bool(row["dry_run"]),
                rollback_on_failure=bool(row["rollback_on_failure"]),
                snapshot_mode=row["snapshot_mode"],
                timestamp=_parse_timestamp(row["timestamp"]),
            )
            for row in cursor.fetchall()
        ]

    def mark_remediation_rolled_back(self, remediation_id: int) -> None:
        """Mark a remediation record as rolled back.

        Args:
            remediation_id: Remediation record ID.

        """
        conn = self._get_conn()
        conn.execute(
            "UPDATE remediations SET rolled_back = 1 WHERE id = ?",
            (remediation_id,),
        )
        conn.commit()

    def prune_snapshots(
        self,
        archive_days: int = 90,
    ) -> int:
        """Remove pre-state data older than the archive period.

        Remediation metadata is preserved; only the pre_states rows are deleted.

        Args:
            archive_days: Days after which pre-state data is pruned.

        Returns:
            Number of pre_state rows deleted.

        """
        cutoff = datetime.now() - timedelta(days=archive_days)
        conn = self._get_conn()
        cursor = conn.execute(
            """
            DELETE FROM pre_states
            WHERE step_id IN (
                SELECT s.id FROM remediation_steps s
                JOIN remediations r ON s.remediation_id = r.id
                JOIN remediation_sessions rs ON r.remediation_session_id = rs.id
                WHERE rs.timestamp < ?
            )
            """,
            (cutoff.isoformat(),),
        )
        conn.commit()
        return cursor.rowcount


def compute_rule_hash(rule_content: str) -> str:
    """Compute hash of rule content for change detection.

    Args:
        rule_content: Rule YAML content as string.

    Returns:
        SHA-256 hash prefix (16 chars).

    """
    return hashlib.sha256(rule_content.encode()).hexdigest()[:16]


@dataclass
class DiffEntry:
    """A single entry in a diff report."""

    host: str
    rule_id: str
    status: str  # "new_failure", "resolved", "new_pass", "regression", "unchanged"
    old_passed: bool | None
    new_passed: bool | None
    old_detail: str | None
    new_detail: str | None


@dataclass
class DiffReport:
    """Diff between two sessions."""

    session1_id: int
    session2_id: int
    session1_timestamp: datetime
    session2_timestamp: datetime
    entries: list[DiffEntry]

    @property
    def new_failures(self) -> list[DiffEntry]:
        """Rules that newly failed (passed before, fail now)."""
        return [e for e in self.entries if e.status == "regression"]

    @property
    def resolved(self) -> list[DiffEntry]:
        """Rules that are now passing (failed before, pass now)."""
        return [e for e in self.entries if e.status == "resolved"]

    @property
    def new_passes(self) -> list[DiffEntry]:
        """Rules that are new and passing (not in old, pass in new)."""
        return [e for e in self.entries if e.status == "new_pass"]

    @property
    def new_fails(self) -> list[DiffEntry]:
        """Rules that are new and failing (not in old, fail in new)."""
        return [e for e in self.entries if e.status == "new_failure"]

    @property
    def unchanged(self) -> list[DiffEntry]:
        """Rules with no change in status."""
        return [e for e in self.entries if e.status == "unchanged"]

    def summary(self) -> dict:
        """Summary counts."""
        return {
            "regressions": len(self.new_failures),
            "resolved": len(self.resolved),
            "new_passes": len(self.new_passes),
            "new_failures": len(self.new_fails),
            "unchanged": len(self.unchanged),
            "total_changes": len(self.entries) - len(self.unchanged),
        }


def diff_sessions(store: ResultStore, session1_id: int, session2_id: int) -> DiffReport:
    """Compare two sessions and generate a diff report.

    Args:
        store: ResultStore instance.
        session1_id: Older session ID.
        session2_id: Newer session ID.

    Returns:
        DiffReport with all changes.

    """
    session1 = store.get_session(session1_id)
    session2 = store.get_session(session2_id)

    if session1 is None:
        raise ValueError(f"Session {session1_id} not found")
    if session2 is None:
        raise ValueError(f"Session {session2_id} not found")

    results1 = store.get_results(session1_id)
    results2 = store.get_results(session2_id)

    # Build lookup maps: (host, rule_id) -> result
    map1: dict[tuple[str, str], ResultRecord] = {
        (r.host, r.rule_id): r for r in results1
    }
    map2: dict[tuple[str, str], ResultRecord] = {
        (r.host, r.rule_id): r for r in results2
    }

    entries = []
    all_keys = set(map1.keys()) | set(map2.keys())

    for host, rule_id in sorted(all_keys):
        old = map1.get((host, rule_id))
        new = map2.get((host, rule_id))

        if old is None and new is not None:
            # New in session2
            status = "new_pass" if new.passed else "new_failure"
            entries.append(
                DiffEntry(
                    host=host,
                    rule_id=rule_id,
                    status=status,
                    old_passed=None,
                    new_passed=new.passed,
                    old_detail=None,
                    new_detail=new.detail,
                )
            )
        elif old is not None and new is None:
            # Removed in session2 (skip for now - not a meaningful change)
            continue
        else:
            # Both exist - compare
            assert old is not None and new is not None
            if old.passed and not new.passed:
                status = "regression"
            elif not old.passed and new.passed:
                status = "resolved"
            else:
                status = "unchanged"

            entries.append(
                DiffEntry(
                    host=host,
                    rule_id=rule_id,
                    status=status,
                    old_passed=old.passed,
                    new_passed=new.passed,
                    old_detail=old.detail,
                    new_detail=new.detail,
                )
            )

    return DiffReport(
        session1_id=session1_id,
        session2_id=session2_id,
        session1_timestamp=session1.timestamp,
        session2_timestamp=session2.timestamp,
        entries=entries,
    )
