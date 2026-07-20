-- Ephemeral Canary V0 observation store (spec §12).
--
-- SQLite is deliberately only a diagnostic/history sink.  Runtime current
-- state is initialized by the scheduler on every process start and is never
-- restored from these rows.

CREATE TABLE IF NOT EXISTS attempts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       TEXT NOT NULL,
    attempted_at    TEXT NOT NULL,
    observed_at     TEXT,
    state           TEXT NOT NULL,
    reason          TEXT NOT NULL,
    attempt_reason  TEXT NOT NULL,
    latency_ms      INTEGER,
    config_digest   TEXT NOT NULL,
    statement_json  TEXT NOT NULL,
    evidence_json   TEXT,
    evidence_digest TEXT,
    nonce           TEXT,
    manifest_digest TEXT,
    transport_warning TEXT
);

CREATE INDEX IF NOT EXISTS attempts_target_newest
    ON attempts(target_id, attempted_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS current_targets (
    target_id         TEXT PRIMARY KEY,
    target_name       TEXT NOT NULL,
    target_origin     TEXT NOT NULL,
    -- Null until a real probe attempt completes. Startup PENDING and timer
    -- transitions are current-state publications, not probe attempts.
    last_attempted_at TEXT,
    observed_at       TEXT,
    expires_at        TEXT NOT NULL,
    state             TEXT NOT NULL,
    reason            TEXT NOT NULL,
    transport_warning TEXT,
    config_digest     TEXT NOT NULL,
    statement_json    TEXT NOT NULL,
    evidence_json     TEXT,
    evidence_digest   TEXT,
    nonce             TEXT,
    manifest_digest   TEXT
);
