use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use time::OffsetDateTime;

use crate::AuthPluginError;

#[derive(Clone, Debug)]
pub(crate) struct StoredCredential {
    pub(crate) subject: String,
    pub(crate) actor_kind: String,
    pub(crate) assurance: String,
    pub(crate) audience: Vec<String>,
    pub(crate) claims: BTreeMap<String, Value>,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) revoked: bool,
}

pub(crate) fn token_digest(pepper: &[u8], token: &str) -> Result<Vec<u8>, AuthPluginError> {
    if pepper.len() < 32 {
        return Err(AuthPluginError::InvalidSecretMaterial);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper)
        .map_err(|_| AuthPluginError::InvalidSecretMaterial)?;
    mac.update(token.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(feature = "workers")]
mod d1;
#[cfg(feature = "postgres")]
mod postgres;
#[derive(Clone, Debug)]
pub(crate) enum ApiTokenStore {
    #[cfg(feature = "postgres")]
    Postgres(lenso_postgres_kit::OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(crate::workers::D1Binding),
}
impl ApiTokenStore {
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
    #[cfg(feature = "workers")]
    pub(crate) async fn prepare_workers(
        binding: crate::workers::D1Binding,
    ) -> Result<Self, crate::AuthOperatorError> {
        crate::migration::verify(&binding)
            .await
            .map_err(|_| crate::AuthOperatorError::Storage)?;
        Ok(Self::D1(binding))
    }
}

pub(crate) async fn load_credential(
    store: &ApiTokenStore,
    digest: &[u8],
) -> Result<Option<StoredCredential>, AuthPluginError> {
    match store {
        #[cfg(feature = "postgres")]
        ApiTokenStore::Postgres(pg) => postgres::load_credential(pg, digest).await,
        #[cfg(feature = "workers")]
        ApiTokenStore::D1(binding) => d1::load_credential(binding, digest).await,
    }
}

#[cfg(feature = "workers")]
pub(crate) use d1::{
    issue as issue_workers, revoke_session as revoke_session_workers,
    revoke_token as revoke_token_workers,
};
