use super::{
    Engine, FailureAdmission, OffsetDateTime, OtpReservation, OtpReservationOutcome,
    RuntimeFailure, URL_SAFE_NO_PAD, VerifyOtpError, VerifyOtpRequest, failure, otp_digest,
    otp_matches,
};
use crate::workers::{D1Binding, decode_time, field, statement, timestamp};
use serde_json::json;
fn fail(_: ()) -> RuntimeFailure {
    failure("Phone storage unavailable")
}

pub(super) async fn reserve_otp_challenge(
    db: &D1Binding,
    r: &OtpReservation<'_>,
) -> Result<OtpReservationOutcome, RuntimeFailure> {
    let since = timestamp(r.now - r.start_window);
    let now = timestamp(r.now);
    let result=db.run(vec![
        statement("SELECT count(*) AS starts FROM phone_otp_challenges WHERE client_ip IS ?1 AND created_at>=?2",vec![json!(r.client_ip),since.clone()]),
        statement("SELECT resend_after FROM phone_otp_challenges WHERE phone=?1 ORDER BY created_at DESC,rowid DESC LIMIT 1",vec![json!(r.phone)]),
        statement("INSERT INTO phone_otp_challenges(challenge_id,phone,purpose,code_digest,client_ip,expires_at,resend_after,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE (SELECT count(*) FROM phone_otp_challenges WHERE client_ip IS ?5 AND created_at>=?9)<?10 AND NOT EXISTS(SELECT 1 FROM (SELECT resend_after FROM phone_otp_challenges WHERE phone=?2 ORDER BY created_at DESC,rowid DESC LIMIT 1) WHERE resend_after>?8)",vec![json!(r.challenge_id),json!(r.phone),json!(r.purpose),json!(URL_SAFE_NO_PAD.encode(r.code_digest)),json!(r.client_ip),timestamp(r.expires_at),timestamp(r.resend_after),now,since,json!(r.max_starts)]),
    ]).await.map_err(fail)?;
    if result[2].meta.changes == 1 {
        return Ok(OtpReservationOutcome::Inserted);
    }
    if field::<i64>(result[0].results.first().ok_or_else(|| fail(()))?, "starts").map_err(fail)?
        >= r.max_starts
    {
        return Ok(OtpReservationOutcome::RateLimited);
    }
    if result[1]
        .results
        .first()
        .map(|row| decode_time(row, "resend_after"))
        .transpose()
        .map_err(fail)?
        .is_some_and(|until| until > r.now)
    {
        return Ok(OtpReservationOutcome::ResendTooSoon);
    }
    Err(fail(()))
}
pub(super) async fn consume(
    db: &D1Binding,
    r: &VerifyOtpRequest,
    secret: &[u8],
    max_attempts: i32,
) -> Result<Result<String, VerifyOtpError>, RuntimeFailure> {
    let now = OffsetDateTime::now_utc();
    let candidate = otp_digest(secret, &r.challenge_id, &r.code)?;
    let result=db.run(vec![
        statement("SELECT phone,code_digest,attempts,expires_at,consumed_at IS NOT NULL AS consumed,expires_at<=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') AS expired FROM phone_otp_challenges WHERE challenge_id=?1",vec![json!(r.challenge_id)]),
        statement("UPDATE phone_otp_challenges SET attempts=attempts+CASE WHEN code_digest<>?2 THEN 1 ELSE 0 END,consumed_at=CASE WHEN code_digest=?2 THEN strftime('%Y-%m-%dT%H:%M:%f000000Z','now') ELSE NULL END WHERE challenge_id=?1 AND consumed_at IS NULL AND expires_at>?3 AND expires_at>strftime('%Y-%m-%dT%H:%M:%f000000Z','now') AND attempts<?4 RETURNING phone,consumed_at IS NOT NULL AS accepted",vec![json!(r.challenge_id),json!(URL_SAFE_NO_PAD.encode(candidate)),timestamp(now),json!(max_attempts)]),
    ]).await.map_err(fail)?;
    let Some(row) = result[0].results.first() else {
        return Ok(Err(VerifyOtpError::InvalidChallenge));
    };
    if field::<i64>(row, "consumed").map_err(fail)? != 0 {
        return Ok(Err(VerifyOtpError::InvalidChallenge));
    }
    let attempts: i32 = field(row, "attempts").map_err(fail)?;
    if attempts >= max_attempts {
        return Ok(Err(VerifyOtpError::TooManyAttempts));
    }
    if field::<i64>(row, "expired").map_err(fail)? != 0 {
        return Ok(Err(VerifyOtpError::Expired));
    }
    let changed = result[1].results.first().ok_or_else(|| fail(()))?;
    let stored = URL_SAFE_NO_PAD
        .decode(field::<String>(row, "code_digest").map_err(fail)?)
        .map_err(|_| fail(()))?;
    let matches = otp_matches(secret, &r.challenge_id, &r.code, &stored)?;
    if matches != (field::<i64>(changed, "accepted").map_err(fail)? != 0) {
        return Err(fail(()));
    }
    if !matches {
        return Ok(Err(if attempts + 1 >= max_attempts {
            VerifyOtpError::TooManyAttempts
        } else {
            VerifyOtpError::InvalidCode
        }));
    }
    Ok(Ok(field(row, "phone").map_err(fail)?))
}
pub(super) async fn delete_challenge(db: &D1Binding, id: &str) -> Result<(), RuntimeFailure> {
    db.run(vec![statement(
        "DELETE FROM phone_otp_challenges WHERE challenge_id=?1",
        vec![json!(id)],
    )])
    .await
    .map_err(fail)?;
    Ok(())
}
pub(super) async fn bind_identity(
    db: &D1Binding,
    phone: &str,
    subject: &str,
) -> Result<(), RuntimeFailure> {
    db.run(vec![statement("INSERT INTO phone_identities(phone,subject_id)VALUES(?1,?2)ON CONFLICT(phone)DO UPDATE SET subject_id=excluded.subject_id",vec![json!(phone),json!(subject)])]).await.map_err(fail)?;
    Ok(())
}
pub(super) async fn phone_for_subject(
    db: &D1Binding,
    subject: &str,
) -> Result<Option<String>, RuntimeFailure> {
    let result = db
        .run(vec![statement(
            "SELECT phone FROM phone_identities WHERE subject_id=?1",
            vec![json!(subject)],
        )])
        .await
        .map_err(fail)?;
    result[0]
        .results
        .first()
        .map(|row| field(row, "phone").map_err(fail))
        .transpose()
}
pub(super) async fn set_password(
    db: &D1Binding,
    subject: &str,
    phone: &str,
    hash: &str,
) -> Result<(), RuntimeFailure> {
    db.run(vec![statement("INSERT INTO phone_passwords(subject_id,phone,password_hash,updated_at)VALUES(?1,?2,?3,?4)ON CONFLICT(subject_id)DO UPDATE SET password_hash=excluded.password_hash,updated_at=excluded.updated_at",vec![json!(subject),json!(phone),json!(hash),timestamp(OffsetDateTime::now_utc())])]).await.map_err(fail)?;
    Ok(())
}
pub(super) async fn password(
    db: &D1Binding,
    phone: &str,
) -> Result<Option<(String, String)>, RuntimeFailure> {
    let result = db
        .run(vec![statement(
            "SELECT subject_id,password_hash FROM phone_passwords WHERE phone=?1",
            vec![json!(phone)],
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
pub(super) async fn phone_failure_limit_reached(
    db: &D1Binding,
    phone: &str,
    since: OffsetDateTime,
    max_failures: i64,
) -> Result<bool, RuntimeFailure> {
    let result=db.run(vec![
        statement("DELETE FROM phone_login_failures WHERE rowid IN (SELECT rowid FROM phone_login_failures WHERE failed_at<?1 ORDER BY failed_at,rowid LIMIT 256)",vec![timestamp(since)]),
        statement("SELECT count(*) AS failures FROM phone_login_failures WHERE phone=?1 AND failed_at>=?2",vec![json!(phone),timestamp(since)]),
    ]).await.map_err(fail)?;
    Ok(field::<i64>(
        result[1].results.first().ok_or_else(|| fail(()))?,
        "failures",
    )
    .map_err(fail)?
        >= max_failures)
}
pub(super) async fn record_phone_failure_if_allowed(
    db: &D1Binding,
    phone: &str,
    since: OffsetDateTime,
    max_failures: i64,
) -> Result<FailureAdmission, RuntimeFailure> {
    let result=db.run(vec![
        statement("DELETE FROM phone_login_failures WHERE phone=?1 AND failed_at<?2",vec![json!(phone),timestamp(since)]),
        statement("INSERT INTO phone_login_failures(phone,failed_at) SELECT ?1,?4 WHERE (SELECT count(*) FROM phone_login_failures WHERE phone=?1 AND failed_at>=?2)<?3",vec![json!(phone),timestamp(since),json!(max_failures),timestamp(OffsetDateTime::now_utc())]),
    ]).await.map_err(fail)?;
    Ok(if result[1].meta.changes == 1 {
        FailureAdmission::Recorded
    } else {
        FailureAdmission::RateLimited
    })
}
pub(super) async fn clear_phone_failures(
    db: &D1Binding,
    phone: &str,
) -> Result<(), RuntimeFailure> {
    db.run(vec![statement(
        "DELETE FROM phone_login_failures WHERE phone=?1",
        vec![json!(phone)],
    )])
    .await
    .map_err(fail)?;
    Ok(())
}
