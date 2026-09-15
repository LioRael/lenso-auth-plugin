CREATE TABLE oidc_authorization_codes (
    code_digest bytea PRIMARY KEY,
    subject_id text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    code_challenge text NOT NULL,
    nonce text,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (expires_at > created_at)
);

CREATE INDEX oidc_codes_expiry_idx ON oidc_authorization_codes(expires_at);
