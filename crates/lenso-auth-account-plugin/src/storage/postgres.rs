use super::{
    AccountError, BTreeMap, GrantParent, IssueSessionOutcome, NewSession, OffsetDateTime,
    StoredSession, Value, validate_grant,
};
use crate::{
    ListSessionsResponseSessionsItem, ListSubjectsResponseSubjectsItem,
    ListSubjectsResponseSubjectsItemStatus, format_time, runtime,
};
use lenso_postgres_kit::OwnedPostgres;
use sqlx::Row;
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
    let existing = sqlx::query(ENSURE_IDENTITY_QUERY)
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
    sqlx::query("INSERT INTO identity_subjects (subject_id) VALUES ($1)")
        .bind(new_subject)
        .execute(&mut *transaction)
        .await
        .map_err(db("create subject"))?;
    let inserted = sqlx::query("INSERT INTO identity_bindings (provider, external_subject, subject_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(provider).bind(external_subject).bind(new_subject).execute(&mut *transaction).await.map_err(db("create identity binding"))?;
    if inserted.rows_affected() == 0 {
        transaction
            .rollback()
            .await
            .map_err(db("rollback identity race"))?;
        let row = sqlx::query(READ_RACED_IDENTITY_QUERY)
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
    sqlx::query_scalar(SUBJECT_STATUS_QUERY)
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
    let status: Option<String> = sqlx::query_scalar(LOCK_SUBJECT_STATUS_QUERY)
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
    sqlx::query("INSERT INTO auth_sessions (session_id, token_digest, subject_id, actor_kind, assurance, audience, claims, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&session.session_id)
        .bind(&session.digest)
        .bind(&session.subject)
        .bind(&session.actor_kind)
        .bind(&session.assurance)
        .bind(&session.audience)
        .bind(sqlx::types::Json(&session.claims))
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
    let exists: Option<bool> = sqlx::query_scalar(
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
        sqlx::query("UPDATE auth_sessions SET revoked_at = transaction_timestamp() WHERE session_id = $1 AND revoked_at IS NULL")
            .bind(session_id).execute(postgres.pool()).await.map_err(db("revoke session"))?;
    }
    Ok(Some(!already_revoked))
}

pub(crate) async fn revoke_credential(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<bool>, AccountError> {
    sqlx::query_scalar(
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
    let row = sqlx::query(LOAD_SESSION_QUERY)
        .bind(digest)
        .fetch_optional(postgres.pool())
        .await
        .map_err(db("load session"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let claims: sqlx::types::Json<BTreeMap<String, Value>> =
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

fn db(operation: &'static str) -> impl FnOnce(sqlx::Error) -> AccountError {
    move |source| AccountError::Database { operation, source }
}

pub(crate) async fn list_subjects(
    postgres: &OwnedPostgres,
    request: &crate::ListSubjectsRequest,
) -> Result<Vec<crate::ListSubjectsResponseSubjectsItem>, crate::RuntimeFailure> {
    let rows = sqlx::query("SELECT subject_id, CASE WHEN status='disabled' AND (disabled_until IS NULL OR disabled_until > transaction_timestamp()) THEN 'disabled' ELSE 'active' END AS effective_status, disabled_reason, disabled_until, created_at FROM identity_subjects WHERE ($1::text IS NULL OR subject_id > $1) ORDER BY subject_id LIMIT $2")
                .bind(&request.cursor).bind(request.limit).fetch_all(postgres.pool()).await.map_err(|error| runtime(AccountError::Database { operation: "list subjects", source: error }))?;
    let mut subjects = Vec::with_capacity(rows.len());
    for row in rows {
        let created_at: OffsetDateTime = row.try_get("created_at").map_err(|error| {
            runtime(AccountError::Database {
                operation: "decode subject creation",
                source: error,
            })
        })?;
        let disabled_until: Option<OffsetDateTime> =
            row.try_get("disabled_until").map_err(|error| {
                runtime(AccountError::Database {
                    operation: "decode subject disable expiry",
                    source: error,
                })
            })?;
        let status: String = row.try_get("effective_status").map_err(|error| {
            runtime(AccountError::Database {
                operation: "decode subject status",
                source: error,
            })
        })?;
        subjects.push(ListSubjectsResponseSubjectsItem {
            subject: row.try_get("subject_id").map_err(|error| {
                runtime(AccountError::Database {
                    operation: "decode subject",
                    source: error,
                })
            })?,
            status: if status == "disabled" {
                ListSubjectsResponseSubjectsItemStatus::Disabled
            } else {
                ListSubjectsResponseSubjectsItemStatus::Active
            },
            disabled_reason: row.try_get("disabled_reason").map_err(|error| {
                runtime(AccountError::Database {
                    operation: "decode subject disable reason",
                    source: error,
                })
            })?,
            disabled_until: disabled_until.map(format_time).transpose()?,
            created_at: format_time(created_at)?,
        });
    }
    Ok(subjects)
}

pub(crate) async fn list_sessions(
    postgres: &OwnedPostgres,
    request: &crate::ListSessionsRequest,
) -> Result<Vec<crate::ListSessionsResponseSessionsItem>, crate::RuntimeFailure> {
    let rows = sqlx::query("SELECT session_id,subject_id,actor_kind,assurance,expires_at,revoked_at IS NOT NULL AS revoked,created_at FROM auth_sessions WHERE ($1::text IS NULL OR subject_id=$1) AND ($2::text IS NULL OR session_id>$2) ORDER BY session_id LIMIT $3").bind(&request.subject).bind(&request.cursor).bind(request.limit).fetch_all(postgres.pool()).await.map_err(|source| runtime(AccountError::Database { operation: "list sessions", source }))?;
    let mut sessions = Vec::with_capacity(rows.len());
    for row in rows {
        let expires_at: OffsetDateTime = row.try_get("expires_at").map_err(|source| {
            runtime(AccountError::Database {
                operation: "decode session expiry",
                source,
            })
        })?;
        let created_at: OffsetDateTime = row.try_get("created_at").map_err(|source| {
            runtime(AccountError::Database {
                operation: "decode session creation",
                source,
            })
        })?;
        sessions.push(ListSessionsResponseSessionsItem {
            session_id: row.try_get("session_id").map_err(|source| {
                runtime(AccountError::Database {
                    operation: "decode session id",
                    source,
                })
            })?,
            subject: row.try_get("subject_id").map_err(|source| {
                runtime(AccountError::Database {
                    operation: "decode session subject",
                    source,
                })
            })?,
            actor_kind: row.try_get("actor_kind").map_err(|source| {
                runtime(AccountError::Database {
                    operation: "decode actor kind",
                    source,
                })
            })?,
            assurance: row.try_get("assurance").map_err(|source| {
                runtime(AccountError::Database {
                    operation: "decode assurance",
                    source,
                })
            })?,
            expires_at: format_time(expires_at)?,
            revoked: row.try_get("revoked").map_err(|source| {
                runtime(AccountError::Database {
                    operation: "decode revocation",
                    source,
                })
            })?,
            created_at: format_time(created_at)?,
        });
    }
    Ok(sessions)
}

pub(crate) async fn set_subject_status(
    postgres: &OwnedPostgres,
    subject: &str,
    status: &str,
    reason: Option<String>,
    until: Option<OffsetDateTime>,
) -> Result<Option<bool>, crate::RuntimeFailure> {
    let mut transaction = postgres.pool().begin().await.map_err(|source| {
        runtime(AccountError::Database {
            operation: "begin subject status",
            source,
        })
    })?;
    let result = sqlx::query("UPDATE identity_subjects SET status=$2,disabled_reason=$3,disabled_until=$4 WHERE subject_id=$1 AND (status,disabled_reason,disabled_until) IS DISTINCT FROM ($2,$3,$4)").bind(subject).bind(status).bind(reason).bind(until).execute(&mut *transaction).await.map_err(|source| runtime(AccountError::Database { operation: "set subject status", source }))?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_subjects WHERE subject_id=$1)")
            .bind(subject)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|source| {
                runtime(AccountError::Database {
                    operation: "check subject",
                    source,
                })
            })?;
    if status == "disabled" {
        sqlx::query("UPDATE auth_sessions SET revoked_at=transaction_timestamp() WHERE subject_id=$1 AND revoked_at IS NULL").bind(subject).execute(&mut *transaction).await.map_err(|source| runtime(AccountError::Database { operation: "revoke disabled subject sessions", source }))?;
    }
    transaction.commit().await.map_err(|source| {
        runtime(AccountError::Database {
            operation: "commit subject status",
            source,
        })
    })?;
    Ok(exists.then_some(result.rows_affected() == 1))
}

use crate::RuntimeFailure;
use lenso_capability_auth_delegation::GrantError;
pub(crate) async fn create_grant(
    postgres: &OwnedPostgres,
    parent_digest: &[u8],
    session_id: &str,
    digest: &[u8],
    audience: &[String],
    expires_at: OffsetDateTime,
) -> Result<Result<String, GrantError>, RuntimeFailure> {
    let mut tx = postgres.pool().begin().await.map_err(grant_db)?;
    let parent = sqlx::query("SELECT s.session_id,s.subject_id,s.actor_kind,s.assurance,s.audience,s.claims,s.expires_at,s.revoked_at IS NOT NULL AS revoked,(i.status = 'disabled' AND (i.disabled_until IS NULL OR i.disabled_until > transaction_timestamp())) AS disabled FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id WHERE s.token_digest=$1 FOR SHARE OF s,i")
        .bind(parent_digest).fetch_optional(&mut *tx).await.map_err(grant_db)?;
    let Some(parent) = parent else {
        return Ok(Err(GrantError::InvalidCredential));
    };
    let parent_id: String = parent.try_get("session_id").map_err(grant_db)?;
    let nested: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_session_delegations WHERE session_id=$1)",
    )
    .bind(&parent_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(grant_db)?;
    let facts = GrantParent {
        subject: parent.try_get("subject_id").map_err(grant_db)?,
        actor_kind: parent.try_get("actor_kind").map_err(grant_db)?,
        audience: parent.try_get("audience").map_err(grant_db)?,
        expires_at: parent.try_get("expires_at").map_err(grant_db)?,
        revoked: parent.try_get("revoked").map_err(grant_db)?,
        disabled: parent.try_get("disabled").map_err(grant_db)?,
        nested,
    };
    let subject = match validate_grant(
        Some(&facts),
        audience,
        expires_at,
        OffsetDateTime::now_utc(),
    ) {
        Ok(subject) => subject,
        Err(error) => return Ok(Err(error)),
    };
    sqlx::query("INSERT INTO auth_sessions(session_id,token_digest,subject_id,actor_kind,assurance,audience,claims,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(session_id).bind(digest).bind(&subject)
        .bind(parent.try_get::<String,_>("actor_kind").map_err(grant_db)?)
        .bind(parent.try_get::<String,_>("assurance").map_err(grant_db)?)
        .bind(audience).bind(parent.try_get::<serde_json::Value,_>("claims").map_err(grant_db)?)
        .bind(expires_at).execute(&mut *tx).await.map_err(grant_db)?;
    sqlx::query("INSERT INTO auth_session_delegations(session_id,parent_session_id) VALUES($1,$2)")
        .bind(session_id)
        .bind(parent_id)
        .execute(&mut *tx)
        .await
        .map_err(grant_db)?;
    tx.commit().await.map_err(grant_db)?;
    Ok(Ok(subject))
}

fn grant_db(_: sqlx::Error) -> RuntimeFailure {
    runtime("delegated session storage failed")
}
