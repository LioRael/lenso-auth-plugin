CREATE TABLE auth_managed_sessions (
    session_id TEXT PRIMARY KEY REFERENCES auth_sessions(session_id),
    issued_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    idle_timeout_seconds INTEGER NOT NULL CHECK (idle_timeout_seconds > 0),
    renew_interval_seconds INTEGER NOT NULL CHECK (renew_interval_seconds > 0),
    last_renew_at TEXT NOT NULL,
    CHECK (absolute_expires_at > issued_at)
);
CREATE TABLE auth_session_rotations (
    token_digest TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES auth_sessions(session_id)
);
CREATE INDEX auth_session_rotations_session_idx ON auth_session_rotations(session_id);
