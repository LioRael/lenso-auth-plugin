//! Managed issue/rotation are transactions sharing identity -> session lock order.
use super::super::{ManagedSessionPolicy, NewManagedSession, RenewSessionOutcome, SessionMetadata};
use super::{
    AccountError, IssueSessionOutcome, LOCK_SUBJECT_STATUS_QUERY, NewSession, OffsetDateTime,
    OwnedPostgres, Row, db,
};
use time::Duration;

pub(crate) async fn issue_managed_session(
    pg: &OwnedPostgres,
    session: &NewSession,
    managed: &NewManagedSession,
) -> Result<IssueSessionOutcome, AccountError> {
    let mut tx = pg.pool().begin().await.map_err(db("begin managed issue"))?;
    let status: Option<String> = sqlx::query_scalar(LOCK_SUBJECT_STATUS_QUERY)
        .bind(&session.subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db("lock managed issue subject"))?;
    let outcome = match status.as_deref() {
        Some("active") => None,
        Some(_) => Some(IssueSessionOutcome::Disabled),
        None => Some(IssueSessionOutcome::InvalidSubject),
    };
    if let Some(outcome) = outcome {
        tx.commit()
            .await
            .map_err(db("commit rejected managed issue"))?;
        return Ok(outcome);
    }
    sqlx::query("INSERT INTO auth_sessions(session_id,token_digest,subject_id,actor_kind,assurance,audience,claims,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&session.session_id).bind(&session.digest).bind(&session.subject).bind(&session.actor_kind)
        .bind(&session.assurance).bind(&session.audience).bind(sqlx::types::Json(&session.claims)).bind(session.expires_at)
        .execute(&mut *tx).await.map_err(db("insert managed session"))?;
    sqlx::query("INSERT INTO auth_managed_sessions(session_id,issued_at,absolute_expires_at,idle_timeout_seconds,renew_interval_seconds,last_renew_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(&session.session_id).bind(managed.issued_at).bind(managed.absolute_expires_at)
        .bind(i64::try_from(managed.idle_timeout_seconds).expect("validated policy"))
        .bind(i64::try_from(managed.renew_interval_seconds).expect("validated policy"))
        .bind(managed.last_renew_at).execute(&mut *tx).await.map_err(db("insert managed policy"))?;
    tx.commit().await.map_err(db("commit managed issue"))?;
    Ok(IssueSessionOutcome::Inserted)
}

// Keep the lock order, eligibility checks and commit in one auditable transaction.
#[allow(clippy::too_many_lines)]
pub(crate) async fn renew_session(
    pg: &OwnedPostgres,
    old_digest: &[u8],
    new_digest: &[u8],
    policy: &ManagedSessionPolicy,
) -> Result<RenewSessionOutcome, AccountError> {
    use RenewSessionOutcome as Outcome;
    if old_digest == new_digest {
        return Err(AccountError::Storage);
    }
    let mut tx = pg
        .pool()
        .begin()
        .await
        .map_err(db("begin session renewal"))?;
    // The initial lookup is only a stable identifier hint. All security checks
    // are re-read after taking the same lock order as issue and subject disable.
    let target = sqlx::query("SELECT session_id,subject_id FROM auth_sessions WHERE token_digest=$1 OR session_id IN(SELECT session_id FROM auth_session_rotations WHERE token_digest=$1)")
        .bind(old_digest).fetch_optional(&mut *tx).await.map_err(db("find renewal session"))?;
    let Some(target) = target else {
        tx.commit().await.map_err(db("commit unknown renewal"))?;
        return Ok(Outcome::InvalidCredential);
    };
    let id: String = target
        .try_get("session_id")
        .map_err(db("decode renewal session"))?;
    let subject: String = target
        .try_get("subject_id")
        .map_err(db("decode renewal subject"))?;
    let _: Option<String> = sqlx::query_scalar(LOCK_SUBJECT_STATUS_QUERY)
        .bind(&subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db("lock renewal subject"))?;
    let row = sqlx::query("SELECT s.token_digest,s.revoked_at,s.expires_at,i.status,i.disabled_until,m.issued_at,m.absolute_expires_at,m.idle_timeout_seconds,m.renew_interval_seconds,m.last_renew_at,EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AS delegated FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id LEFT JOIN auth_managed_sessions m ON m.session_id=s.session_id WHERE s.session_id=$1 FOR UPDATE OF s")
        .bind(&id).fetch_one(&mut *tx).await.map_err(db("lock renewal session"))?;
    // clock_timestamp after lock acquisition prevents requests queued across an
    // expiry boundary from extending a session using an earlier host timestamp.
    let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .map_err(db("read renewal database clock"))?;
    let current: Vec<u8> = row
        .try_get("token_digest")
        .map_err(db("decode renewal digest"))?;
    let revoked: Option<OffsetDateTime> = row
        .try_get("revoked_at")
        .map_err(db("decode renewal revocation"))?;
    let status: String = row.try_get("status").map_err(db("decode renewal status"))?;
    let disabled_until: Option<OffsetDateTime> = row
        .try_get("disabled_until")
        .map_err(db("decode disable deadline"))?;
    let issued_at: Option<OffsetDateTime> =
        row.try_get("issued_at").map_err(db("decode issue time"))?;
    let delegated: bool = row.try_get("delegated").map_err(db("decode delegation"))?;
    let rejected = if revoked.is_some()
        || (status == "disabled" && disabled_until.is_none_or(|until| until > now))
    {
        Some(Outcome::Revoked)
    } else if current != old_digest {
        Some(Outcome::StaleCredential)
    } else if issued_at.is_none() || delegated {
        Some(Outcome::Unsupported)
    } else {
        None
    };
    if let Some(rejected) = rejected {
        tx.commit().await.map_err(db("commit rejected renewal"))?;
        return Ok(rejected);
    }
    let issued_at = issued_at.expect("managed checked");
    let stored_absolute: OffsetDateTime = row
        .try_get("absolute_expires_at")
        .map_err(db("decode absolute deadline"))?;
    let absolute = stored_absolute.min(issued_at + seconds(policy.absolute_timeout_seconds));
    let expires: OffsetDateTime = row
        .try_get("expires_at")
        .map_err(db("decode idle deadline"))?;
    let stored_idle: i64 = row
        .try_get("idle_timeout_seconds")
        .map_err(db("decode idle policy"))?;
    let stored_interval: i64 = row
        .try_get("renew_interval_seconds")
        .map_err(db("decode renewal policy"))?;
    let last: OffsetDateTime = row
        .try_get("last_renew_at")
        .map_err(db("decode last renewal"))?;
    let interval = stored_interval
        .max(i64::try_from(policy.renew_interval_seconds).expect("validated policy"));
    let idle =
        stored_idle.min(i64::try_from(policy.idle_timeout_seconds).expect("validated policy"));
    let failure = if expires.min(last + Duration::seconds(idle)) <= now || absolute <= now {
        Some(Outcome::Expired)
    } else if now < last + Duration::seconds(interval) {
        Some(Outcome::TooEarly)
    } else {
        None
    };
    if let Some(failure) = failure {
        tx.commit()
            .await
            .map_err(db("commit failed renewal policy"))?;
        return Ok(failure);
    }
    let reused: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_session_rotations WHERE token_digest=$1)",
    )
    .bind(new_digest)
    .fetch_one(&mut *tx)
    .await
    .map_err(db("reject reused session digest"))?;
    if reused {
        return Err(AccountError::Storage);
    }
    let expires_at = absolute.min(now + Duration::seconds(idle));
    sqlx::query("INSERT INTO auth_session_rotations(token_digest,session_id) VALUES($1,$2)")
        .bind(old_digest)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(db("record rotated digest"))?;
    let changed = sqlx::query("UPDATE auth_sessions SET token_digest=$2,expires_at=$3 WHERE session_id=$1 AND token_digest=$4 AND revoked_at IS NULL")
        .bind(&id).bind(new_digest).bind(expires_at).bind(old_digest).execute(&mut *tx).await.map_err(db("rotate session credential"))?;
    if changed.rows_affected() != 1 {
        return Err(AccountError::Storage);
    }
    sqlx::query("UPDATE auth_managed_sessions SET last_renew_at=$2 WHERE session_id=$1")
        .bind(&id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db("record session renewal"))?;
    tx.commit().await.map_err(db("commit session renewal"))?;
    Ok(Outcome::Rotated {
        session_id: id,
        expires_at,
        absolute_expires_at: absolute,
        renew_after: absolute.min(now + Duration::seconds(interval)),
    })
}

pub(crate) async fn session_metadata(
    pg: &OwnedPostgres,
    digest: &[u8],
    policy: &ManagedSessionPolicy,
) -> Result<Result<SessionMetadata, RenewSessionOutcome>, AccountError> {
    use RenewSessionOutcome as Outcome;
    let row = sqlx::query("SELECT s.session_id,s.token_digest,s.revoked_at,s.expires_at,i.status,i.disabled_until,m.issued_at,m.absolute_expires_at,m.idle_timeout_seconds,m.renew_interval_seconds,m.last_renew_at,EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AS delegated,clock_timestamp() AS database_now FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id LEFT JOIN auth_managed_sessions m ON m.session_id=s.session_id WHERE s.token_digest=$1 OR s.session_id IN(SELECT session_id FROM auth_session_rotations WHERE token_digest=$1)")
        .bind(digest).fetch_optional(pg.pool()).await.map_err(db("read managed session metadata"))?;
    let Some(row) = row else {
        return Ok(Err(Outcome::InvalidCredential));
    };
    let now: OffsetDateTime = row
        .try_get("database_now")
        .map_err(db("decode metadata clock"))?;
    let revoked: Option<OffsetDateTime> = row
        .try_get("revoked_at")
        .map_err(db("decode metadata revocation"))?;
    let status: String = row
        .try_get("status")
        .map_err(db("decode metadata status"))?;
    let until: Option<OffsetDateTime> = row
        .try_get("disabled_until")
        .map_err(db("decode metadata disable deadline"))?;
    if revoked.is_some() || (status == "disabled" && until.is_none_or(|until| until > now)) {
        return Ok(Err(Outcome::Revoked));
    }
    let current: Vec<u8> = row
        .try_get("token_digest")
        .map_err(db("decode metadata digest"))?;
    if current != digest {
        return Ok(Err(Outcome::StaleCredential));
    }
    let issued: Option<OffsetDateTime> = row
        .try_get("issued_at")
        .map_err(db("decode metadata issue time"))?;
    let delegated: bool = row
        .try_get("delegated")
        .map_err(db("decode metadata delegation"))?;
    let Some(issued) = issued.filter(|_| !delegated) else {
        return Ok(Err(Outcome::Unsupported));
    };
    let absolute: OffsetDateTime = row
        .try_get("absolute_expires_at")
        .map_err(db("decode metadata absolute deadline"))?;
    let absolute = absolute.min(issued + seconds(policy.absolute_timeout_seconds));
    let expires: OffsetDateTime = row
        .try_get("expires_at")
        .map_err(db("decode metadata expiry"))?;
    let idle: i64 = row
        .try_get("idle_timeout_seconds")
        .map_err(db("decode metadata idle policy"))?;
    let interval: i64 = row
        .try_get("renew_interval_seconds")
        .map_err(db("decode metadata interval"))?;
    let last: OffsetDateTime = row
        .try_get("last_renew_at")
        .map_err(db("decode metadata last renewal"))?;
    let expires = expires.min(absolute).min(
        last + Duration::seconds(
            idle.min(i64::try_from(policy.idle_timeout_seconds).expect("validated policy")),
        ),
    );
    if expires <= now {
        return Ok(Err(Outcome::Expired));
    }
    Ok(Ok(SessionMetadata {
        session_id: row
            .try_get("session_id")
            .map_err(db("decode metadata session"))?,
        expires_at: expires,
        absolute_expires_at: absolute,
        renew_after: absolute.min(
            last + Duration::seconds(
                interval
                    .max(i64::try_from(policy.renew_interval_seconds).expect("validated policy")),
            ),
        ),
    }))
}

fn seconds(value: u64) -> Duration {
    Duration::seconds(i64::try_from(value).expect("validated policy"))
}

pub(crate) async fn policy_expiry(
    pg: &OwnedPostgres,
    session_id: &str,
    policy: &ManagedSessionPolicy,
) -> Result<Option<OffsetDateTime>, AccountError> {
    sqlx::query_scalar("SELECT LEAST(s.expires_at,p.expires_at,m.absolute_expires_at,m.issued_at+($2*interval '1 second'),m.last_renew_at+(LEAST(m.idle_timeout_seconds,$3)*interval '1 second'),pm.absolute_expires_at,pm.issued_at+($2*interval '1 second'),pm.last_renew_at+(LEAST(pm.idle_timeout_seconds,$3)*interval '1 second')) FROM auth_sessions s LEFT JOIN auth_managed_sessions m ON m.session_id=s.session_id LEFT JOIN auth_session_delegations d ON d.session_id=s.session_id LEFT JOIN auth_sessions p ON p.session_id=d.parent_session_id LEFT JOIN auth_managed_sessions pm ON pm.session_id=p.session_id WHERE s.session_id=$1 AND (m.session_id IS NOT NULL OR pm.session_id IS NOT NULL)")
        .bind(session_id).bind(i64::try_from(policy.absolute_timeout_seconds).expect("validated policy"))
        .bind(i64::try_from(policy.idle_timeout_seconds).expect("validated policy"))
        .fetch_optional(pg.pool()).await.map_err(db("read managed parent policy expiry"))
}

#[cfg(test)]
#[path = "postgres_managed/tests.rs"]
mod tests;
