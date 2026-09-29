CREATE TABLE scoped_delegation_receipts (
    issuer_caller TEXT NOT NULL,
    subject_id TEXT NOT NULL REFERENCES identity_subjects(subject_id),
    idempotency_key TEXT NOT NULL,
    parent_session_id TEXT NOT NULL REFERENCES auth_sessions(session_id),
    session_id TEXT NOT NULL UNIQUE REFERENCES auth_sessions(session_id),
    intent TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer_caller, subject_id, idempotency_key)
);
