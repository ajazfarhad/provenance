CREATE TABLE IF NOT EXISTS audit_trails (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    targets TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    trail_id TEXT NOT NULL,
    type TEXT NOT NULL,
    at TIMESTAMP NOT NULL,
    actor TEXT NOT NULL,
    targets TEXT NOT NULL DEFAULT '[]',
    commands TEXT NOT NULL DEFAULT '[]',
    result TEXT,
    evidence TEXT NOT NULL DEFAULT '[]',
    correlation_id TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_events_trail_seq_idx ON audit_events (trail_id, seq);
CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at);
CREATE INDEX IF NOT EXISTS audit_events_type_idx ON audit_events (type);
