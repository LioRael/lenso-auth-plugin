CREATE TABLE auth_api_token_schema(version INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE auth_sessions (
 session_id TEXT PRIMARY KEY, subject TEXT NOT NULL, actor_kind TEXT NOT NULL,
 assurance TEXT NOT NULL, audience TEXT NOT NULL, claims TEXT NOT NULL,
 expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL,
 CHECK(json_valid(audience) AND json_array_length(audience)>0),
 CHECK(json_valid(claims)), CHECK(expires_at>created_at)
);
CREATE TABLE api_tokens (
 token_id TEXT PRIMARY KEY, token_digest TEXT UNIQUE NOT NULL,
 session_id TEXT NOT NULL REFERENCES auth_sessions(session_id), expires_at TEXT NOT NULL,
 revoked_at TEXT, created_at TEXT NOT NULL, CHECK(expires_at>created_at)
);
CREATE INDEX api_tokens_session_id_idx ON api_tokens(session_id);
INSERT INTO auth_api_token_schema VALUES(1,'d58aeed9f2569d8d24b83b2d81e5a7ecc33ad0fb7e6c2097be282e6f280e52db');
