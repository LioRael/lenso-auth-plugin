CREATE TABLE password_credentials (
    identifier text PRIMARY KEY,
    subject_id text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE password_login_failures (
    identifier text NOT NULL,
    failed_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE INDEX password_login_failures_lookup_idx
    ON password_login_failures(identifier, failed_at);
