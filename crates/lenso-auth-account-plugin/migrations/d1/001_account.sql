-- Auth-owned D1 schema. Explicit operator migration only; preparation verifies it.
CREATE TABLE auth_account_schema(version INTEGER PRIMARY KEY CHECK(version=1), fingerprint TEXT NOT NULL);
CREATE TABLE identity_subjects (
 subject_id TEXT PRIMARY KEY NOT NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
 disabled_reason TEXT, disabled_until TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z','now'))
);
CREATE TABLE identity_bindings (
 provider TEXT NOT NULL, external_subject TEXT NOT NULL,
 subject_id TEXT NOT NULL REFERENCES identity_subjects(subject_id),
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z','now')),
 PRIMARY KEY(provider,external_subject)
);
CREATE INDEX identity_bindings_subject_idx ON identity_bindings(subject_id);
CREATE TABLE auth_sessions (
 session_id TEXT PRIMARY KEY NOT NULL, token_digest TEXT UNIQUE NOT NULL,
 subject_id TEXT NOT NULL REFERENCES identity_subjects(subject_id),
 actor_kind TEXT NOT NULL, assurance TEXT NOT NULL,
 audience TEXT NOT NULL CHECK(json_valid(audience) AND json_type(audience)='array' AND json_array_length(audience)>0),
 claims TEXT NOT NULL CHECK(json_valid(claims) AND json_type(claims)='object'),
 expires_at TEXT NOT NULL, revoked_at TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z','now')),
 CHECK(expires_at>created_at)
);
CREATE INDEX auth_sessions_subject_idx ON auth_sessions(subject_id);
CREATE TABLE auth_session_delegations (
 session_id TEXT PRIMARY KEY NOT NULL REFERENCES auth_sessions(session_id),
 parent_session_id TEXT NOT NULL REFERENCES auth_sessions(session_id),
 CHECK(session_id<>parent_session_id)
);
CREATE INDEX auth_session_delegations_parent_idx ON auth_session_delegations(parent_session_id);
INSERT INTO auth_account_schema VALUES(1,'e2ab982504b77776e928387519fb612fcd4b0213007713ad5389d79910a1db12');
