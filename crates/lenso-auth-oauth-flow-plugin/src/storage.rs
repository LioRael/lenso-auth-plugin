use crate::{ConsumeError, OffsetDateTime, RuntimeFailure, failure};
#[derive(Clone, Debug)]
pub(crate) enum FlowStore {
    #[cfg(feature = "postgres")]
    Postgres(lenso_postgres_kit::OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(crate::workers::D1Binding),
}
#[derive(Debug)]
pub(crate) struct EncryptedFlow {
    pub digest: Vec<u8>,
    pub provider: String,
    pub nonce: Vec<u8>,
    pub encrypted: Vec<u8>,
    pub return_to: String,
    pub expiry: OffsetDateTime,
    pub oidc_nonce: Option<String>,
}
impl FlowStore {
    #[cfg_attr(not(feature = "postgres"), allow(clippy::unused_async))]
    pub(crate) async fn close(&self) {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => pg.pool().close().await,
            #[cfg(feature = "workers")]
            Self::D1(_) => (),
        }
    }
}
pub(crate) async fn create(store: &FlowStore, row: EncryptedFlow) -> Result<(), RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        FlowStore::Postgres(pg) => postgres::create(pg, row).await,
        #[cfg(feature = "workers")]
        FlowStore::D1(db) => d1::create(db, row).await,
    }
}
pub(crate) async fn consume(
    store: &FlowStore,
    digest: &[u8],
    provider: &str,
) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        FlowStore::Postgres(pg) => postgres::consume(pg, digest, provider).await,
        #[cfg(feature = "workers")]
        FlowStore::D1(db) => d1::consume(db, digest, provider).await,
    }
}
fn validate(
    provider: &str,
    expected: &str,
    consumed: bool,
    expiry: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), ConsumeError> {
    if provider != expected {
        return Err(ConsumeError::ProviderMismatch);
    }
    if consumed {
        return Err(ConsumeError::AlreadyConsumed);
    }
    if expiry <= now {
        return Err(ConsumeError::Expired);
    }
    Ok(())
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::{ConsumeError, EncryptedFlow, OffsetDateTime, RuntimeFailure, failure, validate};
    use lenso_postgres_kit::OwnedPostgres;
    use sqlx::Row;
    fn db(_: sqlx::Error) -> RuntimeFailure {
        failure("OAuth storage operation failed")
    }
    pub(super) async fn create(pg: &OwnedPostgres, r: EncryptedFlow) -> Result<(), RuntimeFailure> {
        sqlx::query("INSERT INTO oauth_flows(state_digest,provider,verifier_nonce,encrypted_verifier,return_to,expires_at,oidc_nonce) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(r.digest).bind(r.provider).bind(r.nonce).bind(r.encrypted).bind(r.return_to).bind(r.expiry).bind(r.oidc_nonce).execute(pg.pool()).await.map_err(db)?;
        Ok(())
    }
    pub(super) async fn consume(
        pg: &OwnedPostgres,
        digest: &[u8],
        expected: &str,
    ) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
        let mut tx = pg.pool().begin().await.map_err(db)?;
        let row=sqlx::query("SELECT provider,verifier_nonce,encrypted_verifier,oidc_nonce,return_to,expires_at,consumed_at IS NOT NULL AS consumed FROM oauth_flows WHERE state_digest=$1 FOR UPDATE").bind(digest).fetch_optional(&mut *tx).await.map_err(db)?;
        let Some(row) = row else {
            return Ok(Err(ConsumeError::InvalidState));
        };
        let provider: String = row.try_get("provider").map_err(db)?;
        let expiry: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
        if let Err(e) = validate(
            &provider,
            expected,
            row.try_get("consumed").map_err(db)?,
            expiry,
            OffsetDateTime::now_utc(),
        ) {
            return Ok(Err(e));
        }
        sqlx::query(
            "UPDATE oauth_flows SET consumed_at=transaction_timestamp() WHERE state_digest=$1",
        )
        .bind(digest)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Ok(EncryptedFlow {
            digest: digest.to_vec(),
            provider,
            nonce: row.try_get("verifier_nonce").map_err(db)?,
            encrypted: row.try_get("encrypted_verifier").map_err(db)?,
            return_to: row.try_get("return_to").map_err(db)?,
            expiry,
            oidc_nonce: row.try_get("oidc_nonce").map_err(db)?,
        }))
    }
}
#[cfg(feature = "workers")]
mod d1 {
    use super::{ConsumeError, EncryptedFlow, OffsetDateTime, RuntimeFailure, failure, validate};
    use crate::workers::{D1Binding, decode_time, field, statement, timestamp};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    fn fail(_: ()) -> RuntimeFailure {
        failure("OAuth storage operation failed")
    }
    pub(super) async fn create(db: &D1Binding, r: EncryptedFlow) -> Result<(), RuntimeFailure> {
        db.run(vec![statement("INSERT INTO oauth_flows(state_digest,provider,verifier_nonce,encrypted_verifier,return_to,expires_at,oidc_nonce) VALUES(?1,?2,?3,?4,?5,?6,?7)",vec![json!(URL_SAFE_NO_PAD.encode(r.digest)),json!(r.provider),json!(URL_SAFE_NO_PAD.encode(r.nonce)),json!(URL_SAFE_NO_PAD.encode(r.encrypted)),json!(r.return_to),timestamp(r.expiry),json!(r.oidc_nonce)])]).await.map_err(fail)?;
        Ok(())
    }
    pub(super) async fn consume(
        db: &D1Binding,
        digest: &[u8],
        expected: &str,
    ) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
        let now = OffsetDateTime::now_utc();
        let key = json!(URL_SAFE_NO_PAD.encode(digest));
        let r=db.run(vec![
            statement("SELECT provider,verifier_nonce,encrypted_verifier,oidc_nonce,return_to,expires_at,consumed_at IS NOT NULL AS consumed,strftime('%Y-%m-%dT%H:%M:%f000000Z','now') AS observed_now FROM oauth_flows WHERE state_digest=?1",vec![key.clone()]),
            statement("UPDATE oauth_flows SET consumed_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') WHERE state_digest=?1 AND provider=?2 AND consumed_at IS NULL AND expires_at>?3 AND expires_at>strftime('%Y-%m-%dT%H:%M:%f000000Z','now')",vec![key,json!(expected),timestamp(now)])
        ]).await.map_err(fail)?;
        let Some(row) = r[0].results.first() else {
            return Ok(Err(ConsumeError::InvalidState));
        };
        let provider: String = field(row, "provider").map_err(fail)?;
        let expiry = decode_time(row, "expires_at").map_err(fail)?;
        let now = now.max(decode_time(row, "observed_now").map_err(fail)?);
        if let Err(e) = validate(
            &provider,
            expected,
            field::<i64>(row, "consumed").map_err(fail)? != 0,
            expiry,
            now,
        ) {
            if r[1].meta.changes != 0 {
                return Err(fail(()));
            }
            return Ok(Err(e));
        }
        if r[1].meta.changes != 1 {
            return Err(fail(()));
        }
        Ok(Ok(EncryptedFlow {
            digest: digest.to_vec(),
            provider,
            nonce: URL_SAFE_NO_PAD
                .decode(field::<String>(row, "verifier_nonce").map_err(fail)?)
                .map_err(|_| fail(()))?,
            encrypted: URL_SAFE_NO_PAD
                .decode(field::<String>(row, "encrypted_verifier").map_err(fail)?)
                .map_err(|_| fail(()))?,
            return_to: field(row, "return_to").map_err(fail)?,
            expiry,
            oidc_nonce: field(row, "oidc_nonce").map_err(fail)?,
        }))
    }
}
