#[cfg(feature = "workers")]
use super::workers;
use super::{AuthorizeRequest, ExchangeRequest, OffsetDateTime, RuntimeFailure, pkce};
#[cfg(feature = "postgres")]
use super::{OwnedPostgres, Row, db};
#[derive(Clone, Debug)]
pub(crate) enum OidcStore {
    #[cfg(feature = "postgres")]
    Postgres(OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(workers::D1Binding),
}
#[derive(Debug)]
pub(crate) struct ConsumedCode {
    pub subject: String,
    pub scope: String,
    pub nonce: Option<String>,
}
impl OidcStore {
    #[cfg_attr(
        not(feature = "postgres"),
        allow(
            clippy::unused_async,
            reason = "Native storage shutdown is asynchronous"
        )
    )]
    #[cfg_attr(not(feature = "postgres"), allow(clippy::unused_async, clippy::unused_async_trait_impl))]
    pub(crate) async fn close(&self) {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => pg.pool().close().await,
            #[cfg(feature = "workers")]
            Self::D1(_) => (),
        }
    }
    pub(crate) async fn insert(
        &self,
        digest: &[u8],
        r: &AuthorizeRequest,
        expires: OffsetDateTime,
    ) -> Result<(), RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(postgres) => {
                sqlx::query("INSERT INTO oidc_authorization_codes(code_digest,subject_id,client_id,redirect_uri,scope,code_challenge,nonce,expires_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(digest).bind(&r.subject).bind(&r.client_id).bind(&r.redirect_uri).bind(&r.scope).bind(&r.code_challenge).bind(&r.nonce).bind(expires).execute(postgres.pool()).await.map_err(db)?;
                Ok(())
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::insert(binding, digest, r, expires).await,
        }
    }
    pub(crate) async fn consume(
        &self,
        digest: &[u8],
        r: &ExchangeRequest,
    ) -> Result<Option<ConsumedCode>, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(postgres) => {
                let mut tx = postgres.pool().begin().await.map_err(db)?;
                let row=sqlx::query("SELECT subject_id,client_id,redirect_uri,scope,code_challenge,nonce,expires_at,consumed_at IS NOT NULL AS consumed FROM oidc_authorization_codes WHERE code_digest=$1 FOR UPDATE").bind(digest).fetch_optional(&mut*tx).await.map_err(db)?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let expires: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
                if row.try_get::<bool, _>("consumed").map_err(db)?
                    || expires <= OffsetDateTime::now_utc()
                    || row.try_get::<String, _>("client_id").map_err(db)? != r.client_id
                    || row.try_get::<String, _>("redirect_uri").map_err(db)? != r.redirect_uri
                    || pkce(&r.code_verifier)
                        != row.try_get::<String, _>("code_challenge").map_err(db)?
                {
                    return Ok(None);
                }
                sqlx::query("UPDATE oidc_authorization_codes SET consumed_at=transaction_timestamp() WHERE code_digest=$1").bind(digest).execute(&mut*tx).await.map_err(db)?;
                tx.commit().await.map_err(db)?;
                let subject: String = row.try_get("subject_id").map_err(db)?;
                let scope: String = row.try_get("scope").map_err(db)?;
                let nonce: Option<String> = row.try_get("nonce").map_err(db)?;
                Ok(Some(ConsumedCode {
                    subject,
                    scope,
                    nonce,
                }))
            }
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::consume(binding, digest, r).await,
        }
    }
}
#[cfg(feature = "workers")]
mod d1;
