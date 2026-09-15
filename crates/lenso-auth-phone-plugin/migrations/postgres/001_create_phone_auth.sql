CREATE TABLE phone_identities (
    phone text PRIMARY KEY,
    subject_id text UNIQUE NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE phone_otp_challenges (
    challenge_id text PRIMARY KEY,
    phone text NOT NULL,
    purpose text NOT NULL,
    code_digest bytea NOT NULL,
    client_ip text,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    resend_after timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (purpose IN ('login', 'register')),
    CHECK (expires_at > created_at)
);

CREATE INDEX phone_otp_phone_created_idx
    ON phone_otp_challenges(phone, created_at DESC);
CREATE INDEX phone_otp_ip_created_idx
    ON phone_otp_challenges(client_ip, created_at DESC);

CREATE TABLE phone_passwords (
    subject_id text PRIMARY KEY,
    phone text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE phone_login_failures (
    phone text NOT NULL,
    failed_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE INDEX phone_login_failure_idx ON phone_login_failures(phone, failed_at);
