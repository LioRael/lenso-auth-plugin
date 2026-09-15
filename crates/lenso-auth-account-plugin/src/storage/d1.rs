use super::{
    AccountError, GrantParent, IssueSessionOutcome, NewSession, OffsetDateTime, StoredSession,
    Value, validate_grant,
};
use crate::workers::{D1Binding, decode_time, field, statement, timestamp};
use crate::{RuntimeFailure, format_time, runtime};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_capability_auth_delegation::GrantError;
use serde_json::json;
const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%f000000Z','now')";
const STATUS: &str = "CASE WHEN i.status='disabled' AND (i.disabled_until IS NULL OR i.disabled_until>strftime('%Y-%m-%dT%H:%M:%f000000Z','now')) THEN 'disabled' ELSE 'active' END";
fn fail(_: ()) -> AccountError {
    AccountError::Storage
}
fn rt(_: ()) -> RuntimeFailure {
    runtime(AccountError::Storage)
}
fn digest_value(bytes: &[u8]) -> Value {
    json!(URL_SAFE_NO_PAD.encode(bytes))
}
fn decode<T: serde::de::DeserializeOwned>(row: &Value, key: &str) -> Result<T, AccountError> {
    field(row, key).map_err(fail)
}

pub(crate) async fn ensure_identity(
    db: &D1Binding,
    provider: &str,
    external: &str,
    subject: &str,
) -> Result<(String, String, bool), AccountError> {
    let p = vec![json!(provider), json!(external), json!(subject)];
    let results=db.run(vec![
        statement("INSERT INTO identity_subjects(subject_id) SELECT ?3 WHERE NOT EXISTS(SELECT 1 FROM identity_bindings WHERE provider=?1 AND external_subject=?2)",p.clone()),
        statement("INSERT INTO identity_bindings(provider,external_subject,subject_id) SELECT ?1,?2,?3 WHERE NOT EXISTS(SELECT 1 FROM identity_bindings WHERE provider=?1 AND external_subject=?2)",p.clone()),
        statement(format!("SELECT b.subject_id,{STATUS} AS status FROM identity_bindings b JOIN identity_subjects i ON i.subject_id=b.subject_id WHERE b.provider=?1 AND b.external_subject=?2"),p[..2].to_vec())
    ]).await.map_err(fail)?;
    let row = results[2].results.first().ok_or(AccountError::Storage)?;
    Ok((
        decode(row, "subject_id")?,
        decode(row, "status")?,
        results[0].meta.changes == 1,
    ))
}
pub(crate) async fn subject_status(
    db: &D1Binding,
    subject: &str,
) -> Result<Option<String>, AccountError> {
    let results = db
        .run(vec![statement(
            format!("SELECT {STATUS} AS status FROM identity_subjects i WHERE subject_id=?1"),
            vec![json!(subject)],
        )])
        .await
        .map_err(fail)?;
    results[0]
        .results
        .first()
        .map(|r| decode(r, "status"))
        .transpose()
}
pub(crate) async fn issue_session(
    db: &D1Binding,
    s: &NewSession,
) -> Result<IssueSessionOutcome, AccountError> {
    let results=db.run(vec![
        statement(format!("SELECT {STATUS} AS status FROM identity_subjects i WHERE subject_id=?1"),vec![json!(s.subject)]),
        statement(format!("INSERT INTO auth_sessions(session_id,token_digest,subject_id,actor_kind,assurance,audience,claims,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 FROM identity_subjects i WHERE i.subject_id=?3 AND ({STATUS})='active'"),vec![json!(s.session_id),digest_value(&s.digest),json!(s.subject),json!(s.actor_kind),json!(s.assurance),json!(serde_json::to_string(&s.audience).map_err(|_|AccountError::Storage)?),json!(serde_json::to_string(&s.claims).map_err(|_|AccountError::Storage)?),timestamp(s.expires_at)])
    ]).await.map_err(fail)?;
    if results[1].meta.changes == 1 {
        return Ok(IssueSessionOutcome::Inserted);
    }
    Ok(if results[0].results.is_empty() {
        IssueSessionOutcome::InvalidSubject
    } else {
        IssueSessionOutcome::Disabled
    })
}
async fn revoke(db: &D1Binding, column: &str, value: Value) -> Result<Option<bool>, AccountError> {
    let r=db.run(vec![statement(format!("UPDATE auth_sessions SET revoked_at={NOW} WHERE {column}=?1 AND revoked_at IS NULL"),vec![value.clone()]),statement(format!("SELECT session_id FROM auth_sessions WHERE {column}=?1"),vec![value])]).await.map_err(fail)?;
    Ok((!r[1].results.is_empty()).then_some(r[0].meta.changes == 1))
}
pub(crate) async fn revoke_session(db: &D1Binding, id: &str) -> Result<Option<bool>, AccountError> {
    revoke(db, "session_id", json!(id)).await
}
pub(crate) async fn revoke_credential(
    db: &D1Binding,
    digest: &[u8],
) -> Result<Option<bool>, AccountError> {
    revoke(db, "token_digest", digest_value(digest)).await
}
pub(crate) async fn load_session(
    db: &D1Binding,
    digest: &[u8],
) -> Result<Option<StoredSession>, AccountError> {
    let r=db.run(vec![statement(format!("SELECT s.subject_id,{STATUS} AS status,s.actor_kind,s.assurance,s.audience,s.claims,CASE WHEN p.expires_at IS NULL OR s.expires_at<p.expires_at THEN s.expires_at ELSE p.expires_at END AS expires_at,(s.revoked_at IS NOT NULL OR p.revoked_at IS NOT NULL) AS revoked FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id LEFT JOIN auth_session_delegations d ON d.session_id=s.session_id LEFT JOIN auth_sessions p ON p.session_id=d.parent_session_id WHERE s.token_digest=?1"),vec![digest_value(digest)])]).await.map_err(fail)?;
    let Some(row) = r[0].results.first() else {
        return Ok(None);
    };
    Ok(Some(StoredSession {
        subject: decode(row, "subject_id")?,
        status: decode(row, "status")?,
        actor_kind: decode(row, "actor_kind")?,
        assurance: decode(row, "assurance")?,
        audience: serde_json::from_str(&decode::<String>(row, "audience")?)
            .map_err(|_| AccountError::Storage)?,
        claims: serde_json::from_str(&decode::<String>(row, "claims")?)
            .map_err(|_| AccountError::Storage)?,
        expires_at: decode_time(row, "expires_at").map_err(fail)?,
        revoked: decode::<i64>(row, "revoked")? != 0,
    }))
}
pub(crate) async fn list_subjects(
    db: &D1Binding,
    q: &crate::ListSubjectsRequest,
) -> Result<Vec<crate::ListSubjectsResponseSubjectsItem>, RuntimeFailure> {
    let r = db.run(vec![subject_page_statement(q)]).await.map_err(rt)?;
    r[0].results
        .iter()
        .map(|row| {
            let status: String = field(row, "effective_status").map_err(rt)?;
            Ok(crate::ListSubjectsResponseSubjectsItem {
                subject: field(row, "subject_id").map_err(rt)?,
                status: if status == "disabled" {
                    crate::ListSubjectsResponseSubjectsItemStatus::Disabled
                } else {
                    crate::ListSubjectsResponseSubjectsItemStatus::Active
                },
                disabled_reason: field(row, "disabled_reason").map_err(rt)?,
                disabled_until: field::<Option<String>>(row, "disabled_until")
                    .map_err(rt)?
                    .map(|v| {
                        OffsetDateTime::parse(&v, &time::format_description::well_known::Rfc3339)
                            .map_err(|_| rt(()))
                            .and_then(format_time)
                    })
                    .transpose()?,
                created_at: format_time(decode_time(row, "created_at").map_err(rt)?)?,
            })
        })
        .collect()
}
pub(crate) async fn list_sessions(
    db: &D1Binding,
    q: &crate::ListSessionsRequest,
) -> Result<Vec<crate::ListSessionsResponseSessionsItem>, RuntimeFailure> {
    let r = db.run(vec![session_page_statement(q)]).await.map_err(rt)?;
    r[0].results
        .iter()
        .map(|row| {
            Ok(crate::ListSessionsResponseSessionsItem {
                session_id: field(row, "session_id").map_err(rt)?,
                subject: field(row, "subject_id").map_err(rt)?,
                actor_kind: field(row, "actor_kind").map_err(rt)?,
                assurance: field(row, "assurance").map_err(rt)?,
                expires_at: format_time(decode_time(row, "expires_at").map_err(rt)?)?,
                revoked: field::<i64>(row, "revoked").map_err(rt)? != 0,
                created_at: format_time(decode_time(row, "created_at").map_err(rt)?)?,
            })
        })
        .collect()
}

fn subject_page_statement(q: &crate::ListSubjectsRequest) -> crate::workers::Statement {
    let select = format!(
        "SELECT subject_id,{STATUS} AS effective_status,disabled_reason,disabled_until,created_at FROM identity_subjects i"
    );
    match q.cursor.as_ref() {
        Some(cursor) => statement(
            format!("{select} WHERE subject_id>?1 ORDER BY subject_id LIMIT ?2"),
            vec![json!(cursor), json!(q.limit)],
        ),
        None => statement(
            format!("{select} ORDER BY subject_id LIMIT ?1"),
            vec![json!(q.limit)],
        ),
    }
}

fn session_page_statement(q: &crate::ListSessionsRequest) -> crate::workers::Statement {
    let select = "SELECT session_id,subject_id,actor_kind,assurance,expires_at,revoked_at IS NOT NULL AS revoked,created_at FROM auth_sessions";
    match (q.subject.as_ref(), q.cursor.as_ref()) {
        (None, None) => statement(
            format!("{select} ORDER BY session_id LIMIT ?1"),
            vec![json!(q.limit)],
        ),
        (Some(subject), None) => statement(
            format!("{select} WHERE subject_id=?1 ORDER BY session_id LIMIT ?2"),
            vec![json!(subject), json!(q.limit)],
        ),
        (None, Some(cursor)) => statement(
            format!("{select} WHERE session_id>?1 ORDER BY session_id LIMIT ?2"),
            vec![json!(cursor), json!(q.limit)],
        ),
        (Some(subject), Some(cursor)) => statement(
            format!("{select} WHERE subject_id=?1 AND session_id>?2 ORDER BY session_id LIMIT ?3"),
            vec![json!(subject), json!(cursor), json!(q.limit)],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subjects(cursor: Option<&str>) -> crate::ListSubjectsRequest {
        crate::ListSubjectsRequest {
            cursor: cursor.map(str::to_owned),
            limit: 2,
        }
    }

    fn sessions(subject: Option<&str>, cursor: Option<&str>) -> crate::ListSessionsRequest {
        crate::ListSessionsRequest {
            subject: subject.map(str::to_owned),
            cursor: cursor.map(str::to_owned),
            limit: 2,
        }
    }

    #[test]
    fn subject_pages_use_nullable_free_first_and_seek_queries() {
        let first = subject_page_statement(&subjects(None));
        assert_eq!(
            first.sql,
            format!(
                "SELECT subject_id,{STATUS} AS effective_status,disabled_reason,disabled_until,created_at FROM identity_subjects i ORDER BY subject_id LIMIT ?1"
            )
        );
        assert_eq!(first.params, vec![json!(2)]);

        let deep = subject_page_statement(&subjects(Some("usr_001")));
        assert_eq!(
            deep.sql,
            format!(
                "SELECT subject_id,{STATUS} AS effective_status,disabled_reason,disabled_until,created_at FROM identity_subjects i WHERE subject_id>?1 ORDER BY subject_id LIMIT ?2"
            )
        );
        assert_eq!(deep.params, vec![json!("usr_001"), json!(2)]);
    }

    #[test]
    fn session_pages_select_each_subject_and_cursor_variant() {
        let select = "SELECT session_id,subject_id,actor_kind,assurance,expires_at,revoked_at IS NOT NULL AS revoked,created_at FROM auth_sessions";
        let cases = [
            (
                sessions(None, None),
                format!("{select} ORDER BY session_id LIMIT ?1"),
                vec![json!(2)],
            ),
            (
                sessions(Some("usr_001"), None),
                format!("{select} WHERE subject_id=?1 ORDER BY session_id LIMIT ?2"),
                vec![json!("usr_001"), json!(2)],
            ),
            (
                sessions(None, Some("ses_001")),
                format!("{select} WHERE session_id>?1 ORDER BY session_id LIMIT ?2"),
                vec![json!("ses_001"), json!(2)],
            ),
            (
                sessions(Some("usr_001"), Some("ses_001")),
                format!(
                    "{select} WHERE subject_id=?1 AND session_id>?2 ORDER BY session_id LIMIT ?3"
                ),
                vec![json!("usr_001"), json!("ses_001"), json!(2)],
            ),
        ];

        for (request, sql, params) in cases {
            let statement = session_page_statement(&request);
            assert_eq!(statement.sql, sql);
            assert_eq!(statement.params, params);
            assert!(!statement.sql.contains("IS NULL OR"));
        }
    }
}
pub(crate) async fn set_subject_status(
    db: &D1Binding,
    subject: &str,
    status: &str,
    reason: Option<String>,
    until: Option<OffsetDateTime>,
) -> Result<Option<bool>, RuntimeFailure> {
    let mut statements = vec![statement(
        "UPDATE identity_subjects SET status=?2,disabled_reason=?3,disabled_until=?4 WHERE subject_id=?1 AND (status IS NOT ?2 OR disabled_reason IS NOT ?3 OR disabled_until IS NOT ?4)",
        vec![
            json!(subject),
            json!(status),
            json!(reason),
            until.map_or(Value::Null, timestamp),
        ],
    )];
    if status == "disabled" {
        statements.push(statement(format!("UPDATE auth_sessions SET revoked_at={NOW} WHERE subject_id=?1 AND revoked_at IS NULL"),vec![json!(subject)]));
    }
    statements.push(statement(
        "SELECT subject_id FROM identity_subjects WHERE subject_id=?1",
        vec![json!(subject)],
    ));
    let r = db.run(statements).await.map_err(rt)?;
    Ok((!r.last().ok_or_else(|| rt(()))?.results.is_empty()).then_some(r[0].meta.changes == 1))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_grant(
    db: &D1Binding,
    parent_digest: &[u8],
    id: &str,
    digest: &[u8],
    audience: &[String],
    expiry: OffsetDateTime,
) -> Result<Result<String, GrantError>, RuntimeFailure> {
    let now = OffsetDateTime::now_utc();
    let parent_status = STATUS.replace(NOW, "?2");
    let select = format!(
        "SELECT s.session_id,s.subject_id,s.actor_kind,s.assurance,s.audience,s.claims,s.expires_at,s.revoked_at IS NOT NULL AS revoked,({parent_status})='disabled' AS disabled,EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AS nested FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id WHERE s.token_digest=?1"
    );
    let scope = serde_json::to_string(audience).map_err(|_| rt(()))?;
    let guard_status = STATUS.replace(NOW, "?6");
    let guard = format!(
        "s.token_digest=?1 AND s.actor_kind='user' AND s.revoked_at IS NULL AND ({guard_status})='active' AND s.expires_at>?6 AND s.expires_at>=?5 AND NOT EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AND NOT EXISTS(SELECT 1 FROM json_each(?4) requested WHERE NOT EXISTS(SELECT 1 FROM json_each(s.audience) allowed WHERE allowed.value=requested.value))"
    );
    let r=db.run(vec![
        statement(select,vec![digest_value(parent_digest),timestamp(now)]),
        statement(format!("INSERT INTO auth_sessions(session_id,token_digest,subject_id,actor_kind,assurance,audience,claims,expires_at) SELECT ?2,?3,s.subject_id,s.actor_kind,s.assurance,?4,s.claims,?5 FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id WHERE {guard}"),vec![digest_value(parent_digest),json!(id),digest_value(digest),json!(scope),timestamp(expiry),timestamp(now)]),
        statement("INSERT INTO auth_session_delegations(session_id,parent_session_id) SELECT child.session_id,parent.session_id FROM auth_sessions child JOIN auth_sessions parent ON parent.token_digest=?1 WHERE child.session_id=?2",vec![digest_value(parent_digest),json!(id)])
    ]).await.map_err(rt)?;
    let parent = r[0]
        .results
        .first()
        .map(|row| {
            Ok::<_, RuntimeFailure>(GrantParent {
                subject: field(row, "subject_id").map_err(rt)?,
                actor_kind: field(row, "actor_kind").map_err(rt)?,
                audience: serde_json::from_str(&field::<String>(row, "audience").map_err(rt)?)
                    .map_err(|_| rt(()))?,
                expires_at: decode_time(row, "expires_at").map_err(rt)?,
                revoked: field::<i64>(row, "revoked").map_err(rt)? != 0,
                disabled: field::<i64>(row, "disabled").map_err(rt)? != 0,
                nested: field::<i64>(row, "nested").map_err(rt)? != 0,
            })
        })
        .transpose()?;
    let valid = validate_grant(parent.as_ref(), audience, expiry, now);
    match valid {
        Ok(subject) if r[1].meta.changes == 1 && r[2].meta.changes == 1 => Ok(Ok(subject)),
        Err(error) if r[1].meta.changes == 0 && r[2].meta.changes == 0 => Ok(Err(error)),
        _ => Err(rt(())),
    }
}
