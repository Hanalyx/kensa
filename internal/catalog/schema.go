package catalog

// schemaDDL is the normalized control-catalog schema. It is created idempotently
// on Open. The model is deliberately relational: a benchmark has many controls,
// a control has many idents (CCIs and other external identifiers), and crossref
// edges connect identifier systems (for example CCI to NIST 800-53). The coverage
// table records which corpus rule cites which benchmark control, stored raw so a
// citation that matches no ingested control surfaces as drift rather than vanishing.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS benchmark (
    id           INTEGER PRIMARY KEY,
    framework    TEXT NOT NULL,            -- cis | stig | nist_800_53
    os           TEXT NOT NULL,            -- rhel8 | rhel9 | rhel10 | ubuntu22 | ubuntu24
    version      TEXT NOT NULL,            -- benchmark release label (e.g. V2R8, v2.0.0)
    release_date TEXT,
    source_file  TEXT,
    license      TEXT,                     -- public-domain | cis-restricted | open
    UNIQUE(framework, os, version)
);

CREATE TABLE IF NOT EXISTS control (
    id           INTEGER PRIMARY KEY,
    benchmark_id INTEGER NOT NULL REFERENCES benchmark(id) ON DELETE CASCADE,
    control_id   TEXT NOT NULL,            -- vuln id (STIG) or recommendation number (CIS)
    secondary_id TEXT,                     -- STIG id where present
    severity     TEXT,
    automatable  INTEGER,                  -- 1 | 0 | NULL when unknown
    title        TEXT,                     -- omitted for cis-restricted rows
    UNIQUE(benchmark_id, control_id)
);

CREATE TABLE IF NOT EXISTS ident (
    control_pk INTEGER NOT NULL REFERENCES control(id) ON DELETE CASCADE,
    system     TEXT NOT NULL,              -- e.g. cci
    value      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crossref (
    from_system TEXT NOT NULL,
    from_id     TEXT NOT NULL,
    to_system   TEXT NOT NULL,
    to_id       TEXT NOT NULL,
    UNIQUE(from_system, from_id, to_system, to_id)
);

CREATE TABLE IF NOT EXISTS coverage (
    rule_id    TEXT NOT NULL,              -- Kensa corpus rule id
    framework  TEXT NOT NULL,
    os         TEXT NOT NULL,
    control_id TEXT NOT NULL,              -- the benchmark control the rule cites
    UNIQUE(rule_id, framework, os, control_id)
);

-- A rule's functional verification on an OS: that its check (and optionally
-- remediate/rollback) was proven to work on a live host, independent of whether
-- any framework benchmark exists for that OS yet. This is the "Kensa knows this
-- works here" fact — separate from the benchmark mapping in coverage. A control
-- body blessing the rule (CIS/STIG) is joined in later; functional truth does
-- not wait on it.
CREATE TABLE IF NOT EXISTS verification (
    rule_id     TEXT NOT NULL,
    os          TEXT NOT NULL,
    scope       TEXT NOT NULL,   -- check | remediate | rollback | full (check+remediate+rollback)
    host        TEXT,            -- e.g. fleet:192.168.1.248 | container:ubuntu24.04
    verified_at TEXT,            -- ISO date
    notes       TEXT,
    UNIQUE(rule_id, os, scope)
);

CREATE INDEX IF NOT EXISTS idx_control_lookup ON control(benchmark_id, control_id);
CREATE INDEX IF NOT EXISTS idx_coverage_lookup ON coverage(framework, os, control_id);
CREATE INDEX IF NOT EXISTS idx_verification_os ON verification(os);
`
