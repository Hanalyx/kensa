package store

// schemaVersion is the current schema number. Migrations (in
// migrations) are appended; never edited or removed
// (transaction-log spec C-06).
const schemaVersion = 2

// migrations is the ordered list of DDL statements. Each migration's
// index corresponds to the schema version it produces. Migration 0 is
// "no schema yet"; migration 1 is the initial schema.
var migrations = []string{
	// Migration 1: initial schema.
	`
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS transactions (
    id              TEXT PRIMARY KEY,
    rule_id         TEXT NOT NULL,
    host_id         TEXT NOT NULL,
    fleet_id        TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    transactional   INTEGER NOT NULL,
    severity        TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    committed_at    TEXT,
    rolled_back_at  TEXT,
    envelope_json   TEXT NOT NULL,
    envelope_sig    BLOB NOT NULL,
    error_text      TEXT
);

CREATE INDEX IF NOT EXISTS idx_transactions_host       ON transactions(host_id);
CREATE INDEX IF NOT EXISTS idx_transactions_fleet      ON transactions(fleet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_rule       ON transactions(rule_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status     ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_started_at ON transactions(started_at);
CREATE INDEX IF NOT EXISTS idx_transactions_severity   ON transactions(severity);

-- Child tables intentionally have no foreign keys to transactions(id).
-- The engine writes pre_states BEFORE the transactions row exists
-- (engine-transaction spec C-02 / AC-04: pre-state persisted before
-- any apply runs, when terminal status is not yet known). A FK would
-- block this load order. Orphan rows are cleaned up by the retention
-- task per transaction-log spec C-05.
CREATE TABLE IF NOT EXISTS steps (
    transaction_id TEXT NOT NULL,
    step_index     INTEGER NOT NULL,
    mechanism      TEXT NOT NULL,
    capturable     INTEGER NOT NULL,
    success        INTEGER NOT NULL,
    stranded       INTEGER NOT NULL DEFAULT 0,
    detail         TEXT,
    PRIMARY KEY (transaction_id, step_index)
);

CREATE INDEX IF NOT EXISTS idx_steps_mechanism ON steps(mechanism);

CREATE TABLE IF NOT EXISTS pre_states (
    transaction_id TEXT NOT NULL,
    step_index     INTEGER NOT NULL,
    mechanism      TEXT NOT NULL,
    capturable     INTEGER NOT NULL,
    state_json     TEXT NOT NULL,
    captured_at    TEXT NOT NULL,
    PRIMARY KEY (transaction_id, step_index)
);

CREATE TABLE IF NOT EXISTS framework_refs (
    transaction_id TEXT NOT NULL,
    framework_id   TEXT NOT NULL,
    control_id     TEXT NOT NULL,
    PRIMARY KEY (transaction_id, framework_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_framework_refs_framework_control
    ON framework_refs(framework_id, control_id);

CREATE TABLE IF NOT EXISTS rollback_events (
    transaction_id TEXT NOT NULL,
    step_index     INTEGER NOT NULL,
    source         TEXT NOT NULL,
    executed_at    TEXT NOT NULL,
    success        INTEGER NOT NULL,
    detail         TEXT
);

CREATE INDEX IF NOT EXISTS idx_rollback_events_txn ON rollback_events(transaction_id);
`,
	// Migration 2 (Phase 4 / C-039): introduce the session model.
	//
	// A session groups the transactions produced by one CLI
	// invocation. Pre-Phase-4 the store had transactions but no
	// session header; queries by "everything that ran on host X
	// at time T" required a string-prefix search on started_at.
	// Sessions make `kensa diff`, `kensa history --stats`, and
	// the session-aware rollback workflow possible.
	//
	// Existing transactions are kept addressable. The session_id
	// column is NULL on legacy rows (everything that lived in
	// the store before this migration). The kensa-migrate tool
	// (C-040) backfills synthetic sessions for those rows; until
	// that runs, queries that filter by session simply see the
	// NULL set as "no sessions yet."
	`
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    started_at    TEXT NOT NULL,
    finished_at   TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    subcommand    TEXT NOT NULL DEFAULT '',
    args_summary  TEXT NOT NULL DEFAULT '',
    -- Counts denormalized at write time for fast --stats and
    -- list rendering. The transactions table is the source of
    -- truth; these are caches the writer maintains.
    txn_total     INTEGER NOT NULL DEFAULT 0,
    txn_committed INTEGER NOT NULL DEFAULT 0,
    txn_rolled    INTEGER NOT NULL DEFAULT 0,
    txn_failed    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_hostname   ON sessions(hostname);
CREATE INDEX IF NOT EXISTS idx_sessions_subcommand ON sessions(subcommand);

ALTER TABLE transactions ADD COLUMN session_id TEXT;

CREATE INDEX IF NOT EXISTS idx_transactions_session ON transactions(session_id);
`,
}
