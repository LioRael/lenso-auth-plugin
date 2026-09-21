#[cfg(feature = "workers")]
use super::{Engine, URL_SAFE_NO_PAD, failure, otp_digest, workers};
use super::{
    FailureAdmission, OffsetDateTime, OtpReservation, OtpReservationOutcome, RuntimeFailure,
    VerifyOtpError, VerifyOtpRequest, otp_matches,
};
#[cfg(feature = "postgres")]
use super::{OwnedPostgres, Row, db};
#[derive(Clone, Debug)]
pub(crate) enum PhoneStore {
    #[cfg(feature = "postgres")]
    Postgres(OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(workers::D1Binding),
}
impl PhoneStore {
    #[cfg_attr(
        not(feature = "postgres"),
        allow(
            clippy::unused_async,
            reason = "Native storage shutdown is asynchronous"
        )
    )]
    #[cfg_attr(
        not(feature = "postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub(crate) async fn close(&self) {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => pg.pool().close().await,
            #[cfg(feature = "workers")]
            Self::D1(_) => (),
        }
    }
    pub(crate) async fn reserve_otp_challenge(
        &self,
        reservation: &OtpReservation<'_>,
    ) -> Result<OtpReservationOutcome, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => super::reserve_otp_challenge(pg, reservation).await,
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::reserve_otp_challenge(binding, reservation).await,
        }
    }
    pub(crate) async fn phone_failure_limit_reached(
        &self,
        phone: &str,
        since: OffsetDateTime,
        max_failures: i64,
    ) -> Result<bool, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                super::phone_failure_limit_reached(pg, phone, since, max_failures).await
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => {
                d1::phone_failure_limit_reached(binding, phone, since, max_failures).await
            }
        }
    }
    pub(crate) async fn record_phone_failure_if_allowed(
        &self,
        phone: &str,
        since: OffsetDateTime,
        max_failures: i64,
    ) -> Result<FailureAdmission, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                super::record_phone_failure_if_allowed(pg, phone, since, max_failures).await
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => {
                d1::record_phone_failure_if_allowed(binding, phone, since, max_failures).await
            }
        }
    }
    pub(crate) async fn clear_phone_failures(&self, phone: &str) -> Result<(), RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => super::clear_phone_failures(pg, phone).await,
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::clear_phone_failures(binding, phone).await,
        }
    }
    pub(crate) async fn consume(
        &self,
        r: &VerifyOtpRequest,
        secret: &[u8],
        max_attempts: i32,
    ) -> Result<Result<String, VerifyOtpError>, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => consume_postgres(pg, r, secret, max_attempts).await,
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::consume(binding, r, secret, max_attempts).await,
        }
    }
    pub(crate) async fn delete_challenge(&self, id: &str) -> Result<(), RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                sqlx::query("DELETE FROM phone_otp_challenges WHERE challenge_id=$1")
                    .bind(id)
                    .execute(pg.pool())
                    .await
                    .map_err(db)?;
                Ok(())
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::delete_challenge(binding, id).await,
        }
    }
    pub(crate) async fn bind_identity(
        &self,
        phone: &str,
        subject: &str,
    ) -> Result<(), RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                sqlx::query("INSERT INTO phone_identities(phone,subject_id)VALUES($1,$2)ON CONFLICT(phone)DO UPDATE SET subject_id=EXCLUDED.subject_id").bind(phone).bind(subject).execute(pg.pool()).await.map_err(db)?;
                Ok(())
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::bind_identity(binding, phone, subject).await,
        }
    }
    pub(crate) async fn phone_for_subject(
        &self,
        subject: &str,
    ) -> Result<Option<String>, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                sqlx::query_scalar("SELECT phone FROM phone_identities WHERE subject_id=$1")
                    .bind(subject)
                    .fetch_optional(pg.pool())
                    .await
                    .map_err(db)
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::phone_for_subject(binding, subject).await,
        }
    }
    pub(crate) async fn set_password(
        &self,
        subject: &str,
        phone: &str,
        hash: &str,
    ) -> Result<(), RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                sqlx::query("INSERT INTO phone_passwords(subject_id,phone,password_hash)VALUES($1,$2,$3)ON CONFLICT(subject_id)DO UPDATE SET password_hash=EXCLUDED.password_hash,updated_at=transaction_timestamp()").bind(subject).bind(phone).bind(hash).execute(pg.pool()).await.map_err(db)?;
                Ok(())
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::set_password(binding, subject, phone, hash).await,
        }
    }
    pub(crate) async fn password(
        &self,
        phone: &str,
    ) -> Result<Option<(String, String)>, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => {
                let row = sqlx::query(
                    "SELECT subject_id,password_hash FROM phone_passwords WHERE phone=$1",
                )
                .bind(phone)
                .fetch_optional(pg.pool())
                .await
                .map_err(db)?;
                row.map(|row| {
                    Ok((
                        row.try_get("subject_id").map_err(db)?,
                        row.try_get("password_hash").map_err(db)?,
                    ))
                })
                .transpose()
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::password(binding, phone).await,
        }
    }
}
#[cfg(feature = "workers")]
mod d1;
#[cfg(feature = "postgres")]
async fn consume_postgres(
    postgres: &OwnedPostgres,
    r: &VerifyOtpRequest,
    secret: &[u8],
    max_attempts: i32,
) -> Result<Result<String, VerifyOtpError>, RuntimeFailure> {
    let mut tx = postgres.pool().begin().await.map_err(db)?;
    let row=sqlx::query("SELECT phone,code_digest,attempts,expires_at,consumed_at IS NOT NULL AS consumed FROM phone_otp_challenges WHERE challenge_id=$1 FOR UPDATE").bind(&r.challenge_id).fetch_optional(&mut*tx).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(Err(VerifyOtpError::InvalidChallenge));
    };
    if row.try_get::<bool, _>("consumed").map_err(db)? {
        return Ok(Err(VerifyOtpError::InvalidChallenge));
    }
    let attempts: i32 = row.try_get("attempts").map_err(db)?;
    if attempts >= max_attempts {
        return Ok(Err(VerifyOtpError::TooManyAttempts));
    }
    let expires: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
    if expires <= OffsetDateTime::now_utc() {
        return Ok(Err(VerifyOtpError::Expired));
    }
    let stored: Vec<u8> = row.try_get("code_digest").map_err(db)?;
    if !otp_matches(secret, &r.challenge_id, &r.code, &stored)? {
        sqlx::query("UPDATE phone_otp_challenges SET attempts=attempts+1 WHERE challenge_id=$1")
            .bind(&r.challenge_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        return Ok(Err(if attempts + 1 >= max_attempts {
            VerifyOtpError::TooManyAttempts
        } else {
            VerifyOtpError::InvalidCode
        }));
    }
    sqlx::query(
        "UPDATE phone_otp_challenges SET consumed_at=transaction_timestamp() WHERE challenge_id=$1",
    )
    .bind(&r.challenge_id)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    let phone: String = row.try_get("phone").map_err(db)?;
    Ok(Ok(phone))
}
