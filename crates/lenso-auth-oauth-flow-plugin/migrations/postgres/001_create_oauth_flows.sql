CREATE TABLE oauth_flows (
    state_digest bytea PRIMARY KEY,
    provider text NOT NULL,
    verifier_nonce bytea NOT NULL,
    encrypted_verifier bytea NOT NULL,
    return_to text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (expires_at > created_at)
);

CREATE INDEX oauth_flows_expiry_idx ON oauth_flows(expires_at);
