//! Account-owned managed-session transitions. Every mutation is one primary D1
//! batch transaction; neither a stale refresh nor a failed check changes state.
use super::super::{
    AccountError, IssueSessionOutcome, ManagedSessionPolicy, NewManagedSession, NewSession,
    RenewSessionOutcome, SessionMetadata,
};
use super::{NOW, STATUS, decode, digest_value, fail};
use crate::workers::{D1Binding, decode_time, statement, timestamp};
use serde_json::{Value, json};
use time::OffsetDateTime;

const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%f000000Z";

pub(crate) async fn issue_managed_session(
    db: &D1Binding,
    session: &NewSession,
    managed: &NewManagedSession,
) -> Result<IssueSessionOutcome, AccountError> {
    let r = db.run(vec![
        statement(format!("SELECT {STATUS} AS status FROM identity_subjects i WHERE subject_id=?1"), vec![json!(session.subject)]),
        statement(format!("INSERT INTO auth_sessions(session_id,token_digest,subject_id,actor_kind,assurance,audience,claims,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 FROM identity_subjects i WHERE i.subject_id=?3 AND ({STATUS})='active'"), vec![
            json!(session.session_id), digest_value(&session.digest), json!(session.subject),
            json!(session.actor_kind), json!(session.assurance),
            json!(serde_json::to_string(&session.audience).map_err(|_| AccountError::Storage)?),
            json!(serde_json::to_string(&session.claims).map_err(|_| AccountError::Storage)?),
            timestamp(session.expires_at),
        ]),
        statement("INSERT INTO auth_managed_sessions(session_id,issued_at,absolute_expires_at,idle_timeout_seconds,renew_interval_seconds,last_renew_at) SELECT session_id,?2,?3,?4,?5,?6 FROM auth_sessions WHERE session_id=?1 AND changes()=1", vec![
            json!(session.session_id), timestamp(managed.issued_at), timestamp(managed.absolute_expires_at),
            json!(managed.idle_timeout_seconds), json!(managed.renew_interval_seconds), timestamp(managed.last_renew_at),
        ]),
    ]).await.map_err(fail)?;
    if r[1].meta.changes == 1 && r[2].meta.changes == 1 {
        return Ok(IssueSessionOutcome::Inserted);
    }
    if r[1].meta.changes != 0 || r[2].meta.changes != 0 {
        return Err(AccountError::Storage);
    }
    Ok(if r[0].results.is_empty() {
        IssueSessionOutcome::InvalidSubject
    } else {
        IssueSessionOutcome::Disabled
    })
}

pub(crate) async fn renew_session(
    db: &D1Binding,
    old_digest: &[u8],
    new_digest: &[u8],
    policy: &ManagedSessionPolicy,
) -> Result<RenewSessionOutcome, AccountError> {
    if old_digest == new_digest {
        return Err(AccountError::Storage);
    }
    // Both time arithmetic and comparisons stay in normalized UTC, including
    // fractional seconds. Current policy can only narrow the issued envelope.
    let absolute = format!(
        "min(m.absolute_expires_at,strftime('{TIME_FORMAT}',m.issued_at,'+' || ?3 || ' seconds'))"
    );
    let next_expiry = format!(
        "min({absolute},strftime('{TIME_FORMAT}','now','+' || min(m.idle_timeout_seconds,?4) || ' seconds'))"
    );
    let due = format!(
        "strftime('{TIME_FORMAT}',m.last_renew_at,'+' || max(m.renew_interval_seconds,?5) || ' seconds')"
    );
    let effective_expiry = format!(
        "min(s.expires_at,strftime('{TIME_FORMAT}',m.last_renew_at,'+' || min(m.idle_timeout_seconds,?4) || ' seconds'),{absolute})"
    );
    let params = vec![
        digest_value(old_digest),
        digest_value(new_digest),
        json!(policy.absolute_timeout_seconds),
        json!(policy.idle_timeout_seconds),
        json!(policy.renew_interval_seconds),
    ];
    let guard = format!(
        "s.token_digest=?1 AND s.revoked_at IS NULL AND ({STATUS})='active' AND {effective_expiry}>{NOW} AND {absolute}>{NOW} AND {due}<={NOW} AND NOT EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AND NOT EXISTS(SELECT 1 FROM auth_session_rotations WHERE token_digest=?2)"
    );
    let r = db.run(vec![
        statement(format!("UPDATE auth_sessions SET token_digest=?2,expires_at=(SELECT {next_expiry} FROM auth_managed_sessions m WHERE m.session_id=auth_sessions.session_id) WHERE session_id IN (SELECT s.session_id FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id JOIN auth_managed_sessions m ON m.session_id=s.session_id WHERE {guard})"), params.clone()),
        // changes() is connection-local within this atomic D1 batch. The ledger
        // and metadata update are permitted only by the immediately preceding
        // successful mutation; a constraint error rolls the whole batch back.
        statement("INSERT INTO auth_session_rotations(token_digest,session_id) SELECT ?1,session_id FROM auth_sessions WHERE token_digest=?2 AND changes()=1", params[..2].to_vec()),
        statement(format!("UPDATE auth_managed_sessions SET last_renew_at={NOW} WHERE session_id IN (SELECT session_id FROM auth_sessions WHERE token_digest=?2) AND changes()=1"), params[..2].to_vec()),
        statement(metadata_sql(&effective_expiry, &absolute, &due), params),
    ]).await.map_err(fail)?;
    if r[0].meta.changes == 1 {
        if r[1].meta.changes != 1 || r[2].meta.changes != 1 {
            return Err(AccountError::Storage);
        }
        let row = r[3].results.first().ok_or(AccountError::Storage)?;
        return Ok(RenewSessionOutcome::Rotated {
            session_id: decode(row, "session_id")?,
            expires_at: decode_time(row, "expires_at").map_err(fail)?,
            absolute_expires_at: decode_time(row, "absolute_expires_at").map_err(fail)?,
            renew_after: decode_time(row, "renew_after").map_err(fail)?,
        });
    }
    if r[1].meta.changes != 0 || r[2].meta.changes != 0 {
        return Err(AccountError::Storage);
    }
    // A complete, still-valid current credential can only fail its guarded CAS
    // on a historical new-token collision. Treat that as storage/entropy failure.
    rejection(r[3].results.first(), true)?.ok_or(AccountError::Storage)
}

pub(crate) async fn session_metadata(
    db: &D1Binding,
    digest: &[u8],
    policy: &ManagedSessionPolicy,
) -> Result<Result<SessionMetadata, RenewSessionOutcome>, AccountError> {
    let absolute = format!(
        "min(m.absolute_expires_at,strftime('{TIME_FORMAT}',m.issued_at,'+' || ?3 || ' seconds'))"
    );
    let expiry = format!(
        "min(s.expires_at,strftime('{TIME_FORMAT}',m.last_renew_at,'+' || min(m.idle_timeout_seconds,?4) || ' seconds'),{absolute})"
    );
    let due = format!(
        "strftime('{TIME_FORMAT}',m.last_renew_at,'+' || max(m.renew_interval_seconds,?5) || ' seconds')"
    );
    let r = db
        .run(vec![statement(
            metadata_sql(&expiry, &absolute, &due),
            vec![
                digest_value(digest),
                Value::Null,
                json!(policy.absolute_timeout_seconds),
                json!(policy.idle_timeout_seconds),
                json!(policy.renew_interval_seconds),
            ],
        )])
        .await
        .map_err(fail)?;
    let row = r[0].results.first();
    if let Some(error) = rejection(row, false)? {
        return Ok(Err(error));
    }
    let row = row.ok_or(AccountError::Storage)?;
    Ok(Ok(SessionMetadata {
        session_id: decode(row, "session_id")?,
        expires_at: decode_time(row, "expires_at").map_err(fail)?,
        absolute_expires_at: decode_time(row, "absolute_expires_at").map_err(fail)?,
        renew_after: decode_time(row, "renew_after").map_err(fail)?,
    }))
}

/// Additional current-policy bound for a managed session or its managed parent.
/// Legacy sessions with no managed parent retain their original stored expiry.
pub(crate) async fn policy_expiry(
    db: &D1Binding,
    session_id: &str,
    policy: &ManagedSessionPolicy,
) -> Result<Option<OffsetDateTime>, AccountError> {
    let own = format!(
        "min(s.expires_at,m.absolute_expires_at,strftime('{TIME_FORMAT}',m.issued_at,'+' || ?2 || ' seconds'),strftime('{TIME_FORMAT}',m.last_renew_at,'+' || min(m.idle_timeout_seconds,?3) || ' seconds'))"
    );
    let parent = format!(
        "min(s.expires_at,p.expires_at,pm.absolute_expires_at,strftime('{TIME_FORMAT}',pm.issued_at,'+' || ?2 || ' seconds'),strftime('{TIME_FORMAT}',pm.last_renew_at,'+' || min(pm.idle_timeout_seconds,?3) || ' seconds'))"
    );
    let sql = format!(
        "SELECT CASE WHEN m.session_id IS NOT NULL AND pm.session_id IS NOT NULL THEN min({own},{parent}) WHEN m.session_id IS NOT NULL THEN {own} WHEN pm.session_id IS NOT NULL THEN {parent} ELSE NULL END AS policy_expires_at FROM auth_sessions s LEFT JOIN auth_managed_sessions m ON m.session_id=s.session_id LEFT JOIN auth_session_delegations d ON d.session_id=s.session_id LEFT JOIN auth_sessions p ON p.session_id=d.parent_session_id LEFT JOIN auth_managed_sessions pm ON pm.session_id=p.session_id WHERE s.session_id=?1"
    );
    let r = db
        .run(vec![statement(
            sql,
            vec![
                json!(session_id),
                json!(policy.absolute_timeout_seconds),
                json!(policy.idle_timeout_seconds),
            ],
        )])
        .await
        .map_err(fail)?;
    let Some(row) = r[0].results.first() else {
        return Ok(None);
    };
    if decode::<Option<String>>(row, "policy_expires_at")?.is_none() {
        return Ok(None);
    }
    decode_time(row, "policy_expires_at")
        .map(Some)
        .map_err(fail)
}

fn metadata_sql(expiry: &str, absolute: &str, due: &str) -> String {
    format!(
        "SELECT s.session_id,{expiry} AS expires_at,s.revoked_at IS NOT NULL AS revoked,({STATUS})='disabled' AS disabled,s.token_digest=?1 AS current_credential,m.session_id IS NOT NULL AS managed,EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AS delegated,{absolute} AS absolute_expires_at,min({due},{absolute}) AS renew_after,{NOW} AS database_now FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id LEFT JOIN auth_managed_sessions m ON m.session_id=s.session_id WHERE s.token_digest=?1 OR s.session_id IN (SELECT session_id FROM auth_session_rotations WHERE token_digest=?1)"
    )
}

fn flag(row: &Value, name: &str) -> Result<bool, AccountError> {
    Ok(decode::<i64>(row, name)? != 0)
}

fn rejection(
    row: Option<&Value>,
    check_due: bool,
) -> Result<Option<RenewSessionOutcome>, AccountError> {
    let Some(row) = row else {
        return Ok(Some(RenewSessionOutcome::InvalidCredential));
    };
    if flag(row, "revoked")? || flag(row, "disabled")? {
        return Ok(Some(RenewSessionOutcome::Revoked));
    }
    if !flag(row, "current_credential")? {
        return Ok(Some(RenewSessionOutcome::StaleCredential));
    }
    if !flag(row, "managed")? || flag(row, "delegated")? {
        return Ok(Some(RenewSessionOutcome::Unsupported));
    }
    let now = decode_time(row, "database_now").map_err(fail)?;
    if decode_time(row, "expires_at").map_err(fail)? <= now
        || decode_time(row, "absolute_expires_at").map_err(fail)? <= now
    {
        return Ok(Some(RenewSessionOutcome::Expired));
    }
    if check_due && decode_time(row, "renew_after").map_err(fail)? > now {
        return Ok(Some(RenewSessionOutcome::TooEarly));
    }
    Ok(None)
}
