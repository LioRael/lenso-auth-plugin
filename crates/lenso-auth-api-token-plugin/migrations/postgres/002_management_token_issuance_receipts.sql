CREATE TABLE management_token_issuances (
 caller_instance text NOT NULL,
 subject text NOT NULL,
 idempotency_key text NOT NULL,
 intent_digest text NOT NULL CHECK (length(intent_digest) = 64),
 token_id text NOT NULL UNIQUE REFERENCES api_tokens(token_id),
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY (caller_instance, subject, idempotency_key)
);
