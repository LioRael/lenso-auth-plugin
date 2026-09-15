CREATE TABLE auth_oidc_schema(version INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE oidc_authorization_codes (
 code_digest TEXT PRIMARY KEY,
 subject_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 redirect_uri TEXT NOT NULL,
 scope TEXT NOT NULL,
 code_challenge TEXT NOT NULL,
 nonce TEXT,
 expires_at TEXT NOT NULL,
 consumed_at TEXT,
 created_at TEXT NOT NULL,
 CHECK(expires_at > created_at)
);
CREATE INDEX oidc_codes_expiry_idx ON oidc_authorization_codes(expires_at);
INSERT INTO auth_oidc_schema VALUES(1,'908cae7d94fdd122aac9e3813dc12509fca9b86a7cb471d906272b4f465847ce');
