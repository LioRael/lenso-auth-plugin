CREATE TABLE identity_subjects (
    subject_id text PRIMARY KEY,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE identity_bindings (
    provider text NOT NULL,
    external_subject text NOT NULL,
    subject_id text NOT NULL REFERENCES identity_subjects(subject_id),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (provider, external_subject)
);

CREATE INDEX identity_bindings_subject_idx ON identity_bindings(subject_id);

CREATE TABLE auth_sessions (
    session_id text PRIMARY KEY,
    token_digest bytea UNIQUE NOT NULL,
    subject_id text NOT NULL REFERENCES identity_subjects(subject_id),
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

CREATE INDEX auth_sessions_subject_idx ON auth_sessions(subject_id);
