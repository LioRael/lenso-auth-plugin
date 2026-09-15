CREATE TABLE auth_sessions (
    session_id text PRIMARY KEY,
    subject text NOT NULL,
    actor_kind text NOT NULL,
    assurance text NOT NULL,
    audience text[] NOT NULL,
    claims jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (cardinality(audience) > 0),
    CHECK (expires_at > created_at)
);

CREATE TABLE api_tokens (
    token_id text PRIMARY KEY,
    token_digest bytea UNIQUE NOT NULL,
    session_id text NOT NULL REFERENCES auth_sessions(session_id),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (expires_at > created_at)
);

CREATE INDEX api_tokens_session_id_idx ON api_tokens(session_id);
