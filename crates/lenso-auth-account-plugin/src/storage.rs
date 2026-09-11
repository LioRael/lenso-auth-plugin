use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
use serde_json::Value;
use sha2::Sha256;
use time::OffsetDateTime;

use crate::AccountError;

macro_rules! effective_subject_status_sql {
    () => {
        "CASE WHEN i.status = 'disabled' AND (i.disabled_until IS NULL OR i.disabled_until > transaction_timestamp()) THEN 'disabled' ELSE 'active' END"
    };
}

const ENSURE_IDENTITY_QUERY: &str = concat!(
    "SELECT b.subject_id, ",
    effective_subject_status_sql!(),
    " AS status FROM identity_bindings b JOIN identity_subjects i ON i.subject_id = b.subject_id WHERE b.provider = $1 AND b.external_subject = $2 FOR UPDATE OF b, i"
);
const READ_RACED_IDENTITY_QUERY: &str = concat!(
    "SELECT b.subject_id, ",
    effective_subject_status_sql!(),
    " AS status FROM identity_bindings b JOIN identity_subjects i ON i.subject_id = b.subject_id WHERE b.provider = $1 AND b.external_subject = $2"
);
const SUBJECT_STATUS_QUERY: &str = concat!(
    "SELECT ",
    effective_subject_status_sql!(),
    " FROM identity_subjects i WHERE i.subject_id = $1"
);
const LOCK_SUBJECT_STATUS_QUERY: &str = concat!(
    "SELECT ",
    effective_subject_status_sql!(),
    " FROM identity_subjects i WHERE i.subject_id = $1 FOR UPDATE OF i"
);
const LOAD_SESSION_QUERY: &str = concat!(
    "SELECT s.subject_id, ",
    effective_subject_status_sql!(),
    " AS status, s.actor_kind, s.assurance, s.audience, s.claims, LEAST(s.expires_at, p.expires_at) AS expires_at, (s.revoked_at IS NOT NULL OR p.revoked_at IS NOT NULL) AS revoked FROM auth_sessions s JOIN identity_subjects i ON i.subject_id = s.subject_id LEFT JOIN auth_session_delegations d ON d.session_id = s.session_id LEFT JOIN auth_sessions p ON p.session_id = d.parent_session_id WHERE s.token_digest = $1"
);

#[derive(Clone, Debug)]
pub(crate) struct StoredSession {
    pub subject: String,
    pub status: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub expires_at: OffsetDateTime,
    pub revoked: bool,
}

#[derive(Debug)]
pub(crate) struct NewSession {
    pub session_id: String,
    pub digest: Vec<u8>,
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IssueSessionOutcome {
    Inserted,
    Disabled,
    InvalidSubject,
}

pub(crate) async fn ensure_identity(
    postgres: &OwnedPostgres,
    provider: &str,
    external_subject: &str,
    new_subject: &str,
) -> Result<(String, String, bool), AccountError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin identity"))?;
    let existing = lenso_postgres_kit::sqlx::query(ENSURE_IDENTITY_QUERY)
        .bind(provider)
        .bind(external_subject)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db("read identity binding"))?;
    if let Some(row) = existing {
        transaction
            .commit()
            .await
            .map_err(db("commit identity read"))?;
        return Ok((
            row.try_get("subject_id").map_err(db("decode subject"))?,
            row.try_get("status").map_err(db("decode status"))?,
            false,
        ));
    }
    lenso_postgres_kit::sqlx::query("INSERT INTO identity_subjects (subject_id) VALUES ($1)")
        .bind(new_subject)
        .execute(&mut *transaction)
        .await
        .map_err(db("create subject"))?;
    let inserted = lenso_postgres_kit::sqlx::query("INSERT INTO identity_bindings (provider, external_subject, subject_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(provider).bind(external_subject).bind(new_subject).execute(&mut *transaction).await.map_err(db("create identity binding"))?;
    if inserted.rows_affected() == 0 {
        transaction
            .rollback()
            .await
            .map_err(db("rollback identity race"))?;
        let row = lenso_postgres_kit::sqlx::query(READ_RACED_IDENTITY_QUERY)
            .bind(provider)
            .bind(external_subject)
            .fetch_one(postgres.pool())
            .await
            .map_err(db("read raced identity"))?;
        return Ok((
            row.try_get("subject_id").map_err(db("decode subject"))?,
            row.try_get("status").map_err(db("decode status"))?,
            false,
        ));
    }
    transaction.commit().await.map_err(db("commit identity"))?;
    Ok((new_subject.to_owned(), "active".to_owned(), true))
}

pub(crate) async fn subject_status(
    postgres: &OwnedPostgres,
    subject: &str,
) -> Result<Option<String>, AccountError> {
    lenso_postgres_kit::sqlx::query_scalar(SUBJECT_STATUS_QUERY)
        .bind(subject)
        .fetch_optional(postgres.pool())
        .await
        .map_err(db("read subject status"))
}

pub(crate) async fn issue_session(
    postgres: &OwnedPostgres,
    session: &NewSession,
) -> Result<IssueSessionOutcome, AccountError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin session issue"))?;
    let status: Option<String> = lenso_postgres_kit::sqlx::query_scalar(LOCK_SUBJECT_STATUS_QUERY)
        .bind(&session.subject)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db("lock subject for session issue"))?;
    let outcome = match status.as_deref() {
        Some("active") => None,
        Some(_) => Some(IssueSessionOutcome::Disabled),
        None => Some(IssueSessionOutcome::InvalidSubject),
    };
    if let Some(outcome) = outcome {
        transaction
            .commit()
            .await
            .map_err(db("commit rejected session issue"))?;
        return Ok(outcome);
    }
    lenso_postgres_kit::sqlx::query("INSERT INTO auth_sessions (session_id, token_digest, subject_id, actor_kind, assurance, audience, claims, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&session.session_id)
        .bind(&session.digest)
        .bind(&session.subject)
        .bind(&session.actor_kind)
        .bind(&session.assurance)
        .bind(&session.audience)
        .bind(lenso_postgres_kit::sqlx::types::Json(&session.claims))
        .bind(session.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(db("issue session"))?;
    transaction
        .commit()
        .await
        .map_err(db("commit session issue"))?;
    Ok(IssueSessionOutcome::Inserted)
}

pub(crate) async fn revoke_session(
    postgres: &OwnedPostgres,
    session_id: &str,
) -> Result<Option<bool>, AccountError> {
    let exists: Option<bool> = lenso_postgres_kit::sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(postgres.pool())
    .await
    .map_err(db("read session"))?;
    let Some(already_revoked) = exists else {
        return Ok(None);
    };
    if !already_revoked {
        lenso_postgres_kit::sqlx::query("UPDATE auth_sessions SET revoked_at = transaction_timestamp() WHERE session_id = $1 AND revoked_at IS NULL")
            .bind(session_id).execute(postgres.pool()).await.map_err(db("revoke session"))?;
    }
    Ok(Some(!already_revoked))
}

pub(crate) async fn revoke_credential(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<bool>, AccountError> {
    lenso_postgres_kit::sqlx::query_scalar(
        "WITH updated AS (UPDATE auth_sessions SET revoked_at = transaction_timestamp() WHERE token_digest = $1 AND revoked_at IS NULL RETURNING 1) SELECT CASE WHEN EXISTS (SELECT 1 FROM updated) THEN TRUE WHEN EXISTS (SELECT 1 FROM auth_sessions WHERE token_digest = $1) THEN FALSE ELSE NULL END",
    )
    .bind(digest)
    .fetch_one(postgres.pool())
    .await
    .map_err(db("revoke credential"))
}

pub(crate) async fn load_session(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<StoredSession>, AccountError> {
    let row = lenso_postgres_kit::sqlx::query(LOAD_SESSION_QUERY)
        .bind(digest)
        .fetch_optional(postgres.pool())
        .await
        .map_err(db("load session"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let claims: lenso_postgres_kit::sqlx::types::Json<BTreeMap<String, Value>> =
        row.try_get("claims").map_err(db("decode claims"))?;
    Ok(Some(StoredSession {
        subject: row.try_get("subject_id").map_err(db("decode subject"))?,
        status: row.try_get("status").map_err(db("decode status"))?,
        actor_kind: row.try_get("actor_kind").map_err(db("decode actor kind"))?,
        assurance: row.try_get("assurance").map_err(db("decode assurance"))?,
        audience: row.try_get("audience").map_err(db("decode audience"))?,
        claims: claims.0,
        expires_at: row.try_get("expires_at").map_err(db("decode expiry"))?,
        revoked: row.try_get("revoked").map_err(db("decode revocation"))?,
    }))
}

pub(crate) fn token_digest(pepper: &[u8], token: &str) -> Result<Vec<u8>, AccountError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper).map_err(|_| AccountError::InvalidSecretMaterial)?;
    mac.update(token.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn db(operation: &'static str) -> impl FnOnce(lenso_postgres_kit::sqlx::Error) -> AccountError {
    move |source| AccountError::Database { operation, source }
}
