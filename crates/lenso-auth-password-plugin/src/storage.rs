use crate::PasswordPluginError;
use time::OffsetDateTime;
#[cfg(feature = "workers")]
mod d1;
#[cfg(feature = "postgres")]
pub(crate) mod postgres;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureAdmission {
    Recorded,
    RateLimited,
}

#[derive(Clone, Debug)]
pub(crate) enum PasswordStore {
    #[cfg(feature = "postgres")]
    Postgres(lenso_postgres_kit::OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(crate::workers::D1Binding),
}
impl PasswordStore {
    #[cfg_attr(
        not(feature = "postgres"),
        allow(
            clippy::unused_async,
            reason = "Native storage shutdown is asynchronous"
        )
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
pub(crate) async fn insert_credential(
    store: &PasswordStore,
    identifier: &str,
    subject: &str,
    hash: &str,
) -> Result<bool, PasswordPluginError> {
    match store {
        #[cfg(feature = "postgres")]
        PasswordStore::Postgres(pg) => {
            postgres::insert_credential(pg, identifier, subject, hash).await
        }
        #[cfg(feature = "workers")]
        PasswordStore::D1(binding) => {
            d1::insert_credential(binding, identifier, subject, hash).await
        }
    }
}
pub(crate) async fn load_credential(
    store: &PasswordStore,
    identifier: &str,
) -> Result<Option<(String, String)>, PasswordPluginError> {
    match store {
        #[cfg(feature = "postgres")]
        PasswordStore::Postgres(pg) => postgres::load_credential(pg, identifier).await,
        #[cfg(feature = "workers")]
        PasswordStore::D1(binding) => d1::load_credential(binding, identifier).await,
    }
}
pub(crate) async fn failure_limit_reached(
    store: &PasswordStore,
    identifier: &str,
    since: OffsetDateTime,
    max_failures: u32,
) -> Result<bool, PasswordPluginError> {
    match store {
        #[cfg(feature = "postgres")]
        PasswordStore::Postgres(pg) => {
            postgres::failure_limit_reached(pg, identifier, since, max_failures).await
        }
        #[cfg(feature = "workers")]
        PasswordStore::D1(binding) => {
            d1::failure_limit_reached(binding, identifier, since, max_failures).await
        }
    }
}
pub(crate) async fn record_failure_if_allowed(
    store: &PasswordStore,
    identifier: &str,
    since: OffsetDateTime,
    max_failures: u32,
) -> Result<FailureAdmission, PasswordPluginError> {
    match store {
        #[cfg(feature = "postgres")]
        PasswordStore::Postgres(pg) => {
            postgres::record_failure_if_allowed(pg, identifier, since, max_failures).await
        }
        #[cfg(feature = "workers")]
        PasswordStore::D1(binding) => {
            d1::record_failure_if_allowed(binding, identifier, since, max_failures).await
        }
    }
}
pub(crate) async fn clear_failures(
    store: &PasswordStore,
    identifier: &str,
) -> Result<(), PasswordPluginError> {
    match store {
        #[cfg(feature = "postgres")]
        PasswordStore::Postgres(pg) => postgres::clear_failures(pg, identifier).await,
        #[cfg(feature = "workers")]
        PasswordStore::D1(binding) => d1::clear_failures(binding, identifier).await,
    }
}
