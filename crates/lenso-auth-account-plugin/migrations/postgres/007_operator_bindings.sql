CREATE TABLE auth_operator_bindings (
 binding_id TEXT PRIMARY KEY,
 source_issuer TEXT NOT NULL,
 source_subject TEXT NOT NULL,
 deployment TEXT NOT NULL,
 scope_kind TEXT NOT NULL,
 scope_id TEXT NOT NULL,
 operator_subject TEXT NOT NULL UNIQUE REFERENCES identity_subjects(subject_id),
 revision BIGINT NOT NULL CHECK(revision > 0),
 status TEXT NOT NULL CHECK(status IN ('pending','active','revoked')),
 audit_event_id TEXT NOT NULL DEFAULT '',
 policy_revision TEXT NOT NULL DEFAULT '',
 revocation_state TEXT NOT NULL DEFAULT 'none' CHECK(revocation_state IN ('none','pending','complete')),
 revocation_audit_event_id TEXT NOT NULL DEFAULT '',
 revoked_by TEXT NOT NULL DEFAULT '',
 revoked_at TEXT NOT NULL DEFAULT '',
 UNIQUE(source_issuer, source_subject, deployment)
);
