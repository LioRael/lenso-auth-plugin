CREATE TABLE auth_phone_schema(version INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE phone_identities(phone TEXT PRIMARY KEY,subject_id TEXT UNIQUE NOT NULL);
CREATE TABLE phone_otp_challenges(
 challenge_id TEXT PRIMARY KEY,phone TEXT NOT NULL,purpose TEXT NOT NULL,code_digest TEXT NOT NULL,
 client_ip TEXT,attempts INTEGER NOT NULL DEFAULT 0,expires_at TEXT NOT NULL,resend_after TEXT NOT NULL,
 consumed_at TEXT,created_at TEXT NOT NULL,CHECK(purpose IN ('login','register')),CHECK(expires_at>created_at)
);
CREATE INDEX phone_otp_phone_created_idx ON phone_otp_challenges(phone,created_at DESC);
CREATE INDEX phone_otp_ip_created_idx ON phone_otp_challenges(client_ip,created_at DESC);
CREATE TABLE phone_passwords(subject_id TEXT PRIMARY KEY,phone TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE phone_login_failures(phone TEXT NOT NULL,failed_at TEXT NOT NULL);
CREATE INDEX phone_login_failure_idx ON phone_login_failures(phone,failed_at);
CREATE INDEX phone_login_failures_stale_idx ON phone_login_failures(failed_at);
INSERT INTO auth_phone_schema VALUES(1,'a43943ded1db550678ceed87ba38b8d24925bfe35b56bafdec2ecdd6ca428c3a');
