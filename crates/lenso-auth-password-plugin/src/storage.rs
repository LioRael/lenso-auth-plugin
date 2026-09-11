use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
use time::OffsetDateTime;

use crate::PasswordPluginError;

const LOGIN_FAILURE_LOCK_PREFIX: &str = "lenso-auth-password-login:";
pub(crate) const STALE_FAILURE_PRUNE_BATCH: i64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureAdmission {
    Recorded,
    RateLimited,
}

pub(crate) async fn insert_credential(
    postgres: &OwnedPostgres,
    identifier: &str,
    subject: &str,
    hash: &str,
) -> Result<bool, PasswordPluginError> {
    let result = lenso_postgres_kit::sqlx::query("INSERT INTO password_credentials (identifier, subject_id, password_hash) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(identifier).bind(subject).bind(hash).execute(postgres.pool()).await.map_err(db("store password credential"))?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn load_credential(
    postgres: &OwnedPostgres,
    identifier: &str,
) -> Result<Option<(String, String)>, PasswordPluginError> {
    let row = lenso_postgres_kit::sqlx::query(
        "SELECT subject_id, password_hash FROM password_credentials WHERE identifier = $1",
    )
    .bind(identifier)
    .fetch_optional(postgres.pool())
    .await
    .map_err(db("load password credential"))?;
    row.map(|row| {
        Ok((
            row.try_get("subject_id")
                .map_err(db("decode password subject"))?,
            row.try_get("password_hash")
                .map_err(db("decode password hash"))?,
        ))
    })
    .transpose()
}

pub(crate) async fn failure_limit_reached(
    postgres: &OwnedPostgres,
    identifier: &str,
    since: OffsetDateTime,
    max_failures: u32,
) -> Result<bool, PasswordPluginError> {
    prune_stale_login_failures(postgres, since).await?;
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin login failure check"))?;
    lock_login_failures(&mut transaction, identifier).await?;
    prune_login_failures(&mut transaction, identifier, since).await?;
    let count: i64 = lenso_postgres_kit::sqlx::query_scalar(
        "SELECT count(*) FROM password_login_failures WHERE identifier = $1 AND failed_at >= $2",
    )
    .bind(identifier)
    .bind(since)
    .fetch_one(&mut *transaction)
    .await
    .map_err(db("count login failures"))?;
    transaction
        .commit()
        .await
        .map_err(db("commit login failure check"))?;
    Ok(count >= i64::from(max_failures))
}

pub(crate) async fn record_failure_if_allowed(
    postgres: &OwnedPostgres,
    identifier: &str,
    since: OffsetDateTime,
    max_failures: u32,
) -> Result<FailureAdmission, PasswordPluginError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin login failure record"))?;
    lock_login_failures(&mut transaction, identifier).await?;
    prune_login_failures(&mut transaction, identifier, since).await?;
    let inserted = lenso_postgres_kit::sqlx::query_scalar::<_, i32>(
        "INSERT INTO password_login_failures (identifier) SELECT $1 WHERE (SELECT count(*) FROM password_login_failures WHERE identifier = $1 AND failed_at >= $2) < $3 RETURNING 1",
    )
        .bind(identifier)
        .bind(since)
        .bind(i64::from(max_failures))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(db("record login failure"))?;
    transaction
        .commit()
        .await
        .map_err(db("commit login failure record"))?;
    Ok(if inserted.is_some() {
        FailureAdmission::Recorded
    } else {
        FailureAdmission::RateLimited
    })
}

pub(crate) async fn clear_failures(
    postgres: &OwnedPostgres,
    identifier: &str,
) -> Result<(), PasswordPluginError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin login failure clear"))?;
    lock_login_failures(&mut transaction, identifier).await?;
    lenso_postgres_kit::sqlx::query("DELETE FROM password_login_failures WHERE identifier = $1")
        .bind(identifier)
        .execute(&mut *transaction)
        .await
        .map_err(db("clear login failures"))?;
    transaction
        .commit()
        .await
        .map_err(db("commit login failure clear"))?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn current_failure_count(
    postgres: &OwnedPostgres,
    identifier: &str,
    since: OffsetDateTime,
) -> Result<i64, PasswordPluginError> {
    lenso_postgres_kit::sqlx::query_scalar(
        "SELECT count(*) FROM password_login_failures WHERE identifier = $1 AND failed_at >= $2",
    )
    .bind(identifier)
    .bind(since)
    .fetch_one(postgres.pool())
    .await
    .map_err(db("count current login failures"))
}

async fn lock_login_failures(
    transaction: &mut lenso_postgres_kit::sqlx::Transaction<'_, lenso_postgres_kit::sqlx::Postgres>,
    identifier: &str,
) -> Result<(), PasswordPluginError> {
    let key = format!("{LOGIN_FAILURE_LOCK_PREFIX}{identifier}");
    lenso_postgres_kit::sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut **transaction)
        .await
        .map_err(db("lock login failures"))?;
    Ok(())
}

async fn prune_login_failures(
    transaction: &mut lenso_postgres_kit::sqlx::Transaction<'_, lenso_postgres_kit::sqlx::Postgres>,
    identifier: &str,
    since: OffsetDateTime,
) -> Result<(), PasswordPluginError> {
    lenso_postgres_kit::sqlx::query(
        "DELETE FROM password_login_failures WHERE identifier = $1 AND failed_at < $2",
    )
    .bind(identifier)
    .bind(since)
    .execute(&mut **transaction)
    .await
    .map_err(db("prune login failures"))?;
    Ok(())
}

pub(crate) async fn prune_stale_login_failures(
    postgres: &OwnedPostgres,
    before: OffsetDateTime,
) -> Result<u64, PasswordPluginError> {
    let result = lenso_postgres_kit::sqlx::query(
        "WITH stale AS (SELECT ctid FROM password_login_failures WHERE failed_at < $1 ORDER BY failed_at, ctid FOR UPDATE SKIP LOCKED LIMIT $2) DELETE FROM password_login_failures AS failures USING stale WHERE failures.ctid = stale.ctid",
    )
    .bind(before)
    .bind(STALE_FAILURE_PRUNE_BATCH)
    .execute(postgres.pool())
    .await
    .map_err(db("prune stale login failures"))?;
    Ok(result.rows_affected())
}

fn db(
    operation: &'static str,
) -> impl FnOnce(lenso_postgres_kit::sqlx::Error) -> PasswordPluginError {
    move |source| PasswordPluginError::Database { operation, source }
}
