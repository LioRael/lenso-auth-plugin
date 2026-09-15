use super::{FailureAdmission, OffsetDateTime, PasswordPluginError};
use crate::workers::{D1Binding, field, statement, timestamp};
use serde_json::json;
fn fail(_: ()) -> PasswordPluginError {
    PasswordPluginError::Storage
}

pub(super) async fn insert_credential(
    db: &D1Binding,
    identifier: &str,
    subject: &str,
    hash: &str,
) -> Result<bool, PasswordPluginError> {
    let result=db.run(vec![statement("INSERT INTO password_credentials(identifier,subject_id,password_hash) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",vec![json!(identifier),json!(subject),json!(hash)])]).await.map_err(fail)?;
    Ok(result[0].meta.changes == 1)
}
pub(super) async fn load_credential(
    db: &D1Binding,
    identifier: &str,
) -> Result<Option<(String, String)>, PasswordPluginError> {
    let result = db
        .run(vec![statement(
            "SELECT subject_id,password_hash FROM password_credentials WHERE identifier=?1",
            vec![json!(identifier)],
        )])
        .await
        .map_err(fail)?;
    result[0]
        .results
        .first()
        .map(|row| {
            Ok((
                field(row, "subject_id").map_err(fail)?,
                field(row, "password_hash").map_err(fail)?,
            ))
        })
        .transpose()
}
pub(super) async fn failure_limit_reached(
    db: &D1Binding,
    identifier: &str,
    since: OffsetDateTime,
    max_failures: u32,
) -> Result<bool, PasswordPluginError> {
    let result=db.run(vec![
        statement("DELETE FROM password_login_failures WHERE rowid IN (SELECT rowid FROM password_login_failures WHERE failed_at<?1 ORDER BY failed_at,rowid LIMIT 256)",vec![timestamp(since)]),
        statement("SELECT count(*) AS failures FROM password_login_failures WHERE identifier=?1 AND failed_at>=?2",vec![json!(identifier),timestamp(since)]),
    ]).await.map_err(fail)?;
    let row = result[1]
        .results
        .first()
        .ok_or(PasswordPluginError::Storage)?;
    Ok(field::<u32>(row, "failures").map_err(fail)? >= max_failures)
}
pub(super) async fn record_failure_if_allowed(
    db: &D1Binding,
    identifier: &str,
    since: OffsetDateTime,
    max_failures: u32,
) -> Result<FailureAdmission, PasswordPluginError> {
    let result=db.run(vec![
        statement("DELETE FROM password_login_failures WHERE identifier=?1 AND failed_at<?2",vec![json!(identifier),timestamp(since)]),
        statement("INSERT INTO password_login_failures(identifier,failed_at) SELECT ?1,?4 WHERE (SELECT count(*) FROM password_login_failures WHERE identifier=?1 AND failed_at>=?2)<?3",vec![json!(identifier),timestamp(since),json!(max_failures),timestamp(OffsetDateTime::now_utc())]),
    ]).await.map_err(fail)?;
    Ok(if result[1].meta.changes == 1 {
        FailureAdmission::Recorded
    } else {
        FailureAdmission::RateLimited
    })
}
pub(super) async fn clear_failures(
    db: &D1Binding,
    identifier: &str,
) -> Result<(), PasswordPluginError> {
    db.run(vec![statement(
        "DELETE FROM password_login_failures WHERE identifier=?1",
        vec![json!(identifier)],
    )])
    .await
    .map_err(fail)?;
    Ok(())
}
