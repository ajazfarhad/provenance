CREATE TABLE IF NOT EXISTS audit_trails (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    targets JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    trail_id TEXT NOT NULL REFERENCES audit_trails(id) ON DELETE RESTRICT,
    type TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL,
    actor JSONB NOT NULL,
    targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    commands JSONB NOT NULL DEFAULT '[]'::jsonb,
    result JSONB,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    correlation_id TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_events_trail_seq_idx ON audit_events (trail_id, seq);
CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at);
CREATE INDEX IF NOT EXISTS audit_events_type_idx ON audit_events (type);
CREATE INDEX IF NOT EXISTS audit_events_targets_gin ON audit_events USING GIN (targets);
