CREATE TABLE auth_session_delegations (
    session_id text PRIMARY KEY REFERENCES auth_sessions(session_id),
    parent_session_id text NOT NULL REFERENCES auth_sessions(session_id),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (session_id <> parent_session_id)
);
CREATE INDEX auth_session_delegations_parent_idx ON auth_session_delegations(parent_session_id);
