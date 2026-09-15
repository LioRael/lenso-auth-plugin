CREATE TABLE auth_password_schema(version INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE password_credentials(identifier TEXT PRIMARY KEY, subject_id TEXT NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE password_login_failures(identifier TEXT NOT NULL, failed_at TEXT NOT NULL);
CREATE INDEX password_login_failures_lookup_idx ON password_login_failures(identifier, failed_at);
CREATE INDEX password_login_failures_stale_idx ON password_login_failures(failed_at);
INSERT INTO auth_password_schema VALUES(1,'edd64339e40c2de926965d72b30d332ed8d50a099031596add7dbbe8f09dce40');
