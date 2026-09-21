use crate::AccountError;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;
use time::OffsetDateTime;

#[cfg(feature = "workers")]
mod d1;
#[cfg(feature = "postgres")]
pub(crate) mod postgres;
#[derive(Clone, Debug)]
pub(crate) struct StoredSession {
    pub subject: String,
    pub status: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub expires_at: OffsetDateTime,
    pub revoked: bool,
}

#[derive(Debug)]
pub(crate) struct NewSession {
    pub session_id: String,
    pub digest: Vec<u8>,
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IssueSessionOutcome {
    Inserted,
    Disabled,
    InvalidSubject,
}

pub(crate) fn token_digest(pepper: &[u8], token: &str) -> Result<Vec<u8>, AccountError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper).map_err(|_| AccountError::InvalidSecretMaterial)?;
    mac.update(token.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

#[derive(Clone, Debug)]
pub(crate) enum AccountStore {
    #[cfg(feature = "postgres")]
    Postgres(lenso_postgres_kit::OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(crate::workers::D1Binding),
}
impl AccountStore {
    #[cfg_attr(
        not(feature = "postgres"),
        allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub(crate) async fn close(&self) {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => pg.pool().close().await,
            #[cfg(feature = "workers")]
            Self::D1(_) => (),
        }
    }
}

pub(crate) async fn ensure_identity(
    store: &AccountStore,
    provider: &str,
    external_subject: &str,
    new_subject: &str,
) -> Result<(String, String, bool), AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            postgres::ensure_identity(pg, provider, external_subject, new_subject).await
        }
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => {
            d1::ensure_identity(binding, provider, external_subject, new_subject).await
        }
    }
}

pub(crate) async fn subject_status(
    store: &AccountStore,
    subject: &str,
) -> Result<Option<String>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::subject_status(pg, subject).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::subject_status(binding, subject).await,
    }
}

pub(crate) async fn issue_session(
    store: &AccountStore,
    session: &NewSession,
) -> Result<IssueSessionOutcome, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::issue_session(pg, session).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::issue_session(binding, session).await,
    }
}

pub(crate) async fn revoke_session(
    store: &AccountStore,
    session_id: &str,
) -> Result<Option<bool>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::revoke_session(pg, session_id).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::revoke_session(binding, session_id).await,
    }
}

pub(crate) async fn revoke_credential(
    store: &AccountStore,
    digest: &[u8],
) -> Result<Option<bool>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::revoke_credential(pg, digest).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::revoke_credential(binding, digest).await,
    }
}

pub(crate) async fn load_session(
    store: &AccountStore,
    digest: &[u8],
) -> Result<Option<StoredSession>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::load_session(pg, digest).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::load_session(binding, digest).await,
    }
}

pub(crate) async fn list_subjects(
    store: &AccountStore,
    request: &crate::ListSubjectsRequest,
) -> Result<Vec<crate::ListSubjectsResponseSubjectsItem>, crate::RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::list_subjects(pg, request).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::list_subjects(binding, request).await,
    }
}

pub(crate) async fn list_sessions(
    store: &AccountStore,
    request: &crate::ListSessionsRequest,
) -> Result<Vec<crate::ListSessionsResponseSessionsItem>, crate::RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => postgres::list_sessions(pg, request).await,
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => d1::list_sessions(binding, request).await,
    }
}

pub(crate) async fn set_subject_status(
    store: &AccountStore,
    subject: &str,
    status: &str,
    reason: Option<String>,
    until: Option<OffsetDateTime>,
) -> Result<Option<bool>, crate::RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            postgres::set_subject_status(pg, subject, status, reason, until).await
        }
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => {
            d1::set_subject_status(binding, subject, status, reason, until).await
        }
    }
}

pub(crate) async fn create_grant(
    store: &AccountStore,
    parent_digest: &[u8],
    session_id: &str,
    digest: &[u8],
    audience: &[String],
    expires_at: OffsetDateTime,
) -> Result<Result<String, lenso_capability_auth_delegation::GrantError>, crate::RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            postgres::create_grant(pg, parent_digest, session_id, digest, audience, expires_at)
                .await
        }
        #[cfg(feature = "workers")]
        AccountStore::D1(binding) => {
            d1::create_grant(
                binding,
                parent_digest,
                session_id,
                digest,
                audience,
                expires_at,
            )
            .await
        }
    }
}

#[derive(Debug)]
struct GrantParent {
    subject: String,
    actor_kind: String,
    audience: Vec<String>,
    expires_at: OffsetDateTime,
    revoked: bool,
    disabled: bool,
    nested: bool,
}
fn validate_grant(
    parent: Option<&GrantParent>,
    audience: &[String],
    expiry: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<String, lenso_capability_auth_delegation::GrantError> {
    use lenso_capability_auth_delegation::GrantError;
    let p = parent.ok_or(GrantError::InvalidCredential)?;
    if p.revoked || p.disabled {
        return Err(GrantError::Revoked);
    }
    if p.actor_kind != "user" {
        return Err(GrantError::InvalidCredential);
    }
    if p.expires_at <= now {
        return Err(GrantError::Expired);
    }
    if expiry > p.expires_at || audience.iter().any(|v| !p.audience.contains(v)) {
        return Err(GrantError::InvalidScope);
    }
    if p.nested {
        return Err(GrantError::NestedDelegation);
    }
    Ok(p.subject.clone())
}
