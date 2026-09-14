CREATE TABLE auth_oauth_schema(version INTEGER PRIMARY KEY CHECK(version=1), fingerprint TEXT NOT NULL);
CREATE TABLE oauth_flows (
 state_digest TEXT PRIMARY KEY NOT NULL,
 provider TEXT NOT NULL,
 verifier_nonce TEXT NOT NULL,
 encrypted_verifier TEXT NOT NULL,
 oidc_nonce TEXT,
 return_to TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 consumed_at TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z','now'))
);
INSERT INTO auth_oauth_schema VALUES(1,'6c15b7330f8d7614265c3acc63d9eb58f21b74beb03a7a355a4c0fcb45fae2ba');
