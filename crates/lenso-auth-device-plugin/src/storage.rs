#[cfg(feature = "workers")]
use super::workers;
use super::{
    ListResponseDevicesItem, ObserveRequest, ObserveResponse, RuntimeFailure, SetTrustOutcome,
    SetTrustRequest,
};
use super::{OffsetDateTime, Rfc3339};
#[cfg(feature = "postgres")]
use super::{OwnedPostgres, db};

#[derive(Clone, Debug)]
pub(crate) enum DeviceStore {
    #[cfg(feature = "postgres")]
    Postgres(OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(workers::D1Binding),
}

pub(crate) fn failure() -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: "Device Auth storage unavailable".into(),
    }
}

impl DeviceStore {
    #[cfg_attr(
        not(feature = "postgres"),
        allow(
            clippy::unused_async,
            reason = "Native storage shutdown is asynchronous"
        )
    )]
    #[cfg_attr(
        not(feature = "postgres"),
        allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub(crate) async fn close(&self) {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(postgres) => postgres.pool().close().await,
            #[cfg(feature = "workers")]
            Self::D1(_) => (),
        }
    }
    pub(crate) async fn observe(
        &self,
        request: ObserveRequest,
    ) -> Result<ObserveResponse, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => observe_postgres(pg, request).await,
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::observe(binding, request).await,
        }
    }
    pub(crate) async fn list(
        &self,
        subject: &str,
    ) -> Result<Vec<ListResponseDevicesItem>, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => list_postgres(pg, subject).await,
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::list(binding, subject).await,
        }
    }
    pub(crate) async fn set_trust(
        &self,
        request: &SetTrustRequest,
    ) -> Result<SetTrustOutcome, RuntimeFailure> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => super::set_device_trust(pg, request).await,
            #[cfg(feature = "workers")]
            Self::D1(binding) => d1::set_trust(binding, request).await,
        }
    }
}

#[cfg(feature = "workers")]
mod d1;

#[cfg(feature = "postgres")]
async fn observe_postgres(
    postgres: &lenso_postgres_kit::OwnedPostgres,
    request: ObserveRequest,
) -> Result<ObserveResponse, RuntimeFailure> {
    use sqlx::Row;
    let row=sqlx::query("INSERT INTO auth_devices(subject_id,device_id,last_seen_ip,last_seen_user_agent) VALUES($1,$2,$3,$4) ON CONFLICT(subject_id,device_id) DO UPDATE SET last_seen_ip=EXCLUDED.last_seen_ip,last_seen_user_agent=EXCLUDED.last_seen_user_agent,updated_at=transaction_timestamp() RETURNING (created_at=updated_at) AS created,trusted_at IS NOT NULL AS trusted").bind(&request.subject).bind(&request.device_id).bind(&request.client_ip).bind(&request.user_agent).fetch_one(postgres.pool()).await.map_err(db)?;
    Ok(ObserveResponse {
        device_id: request.device_id,
        created: row.try_get("created").map_err(db)?,
        trusted: row.try_get("trusted").map_err(db)?,
    })
}
#[cfg(feature = "postgres")]
async fn list_postgres(
    postgres: &lenso_postgres_kit::OwnedPostgres,
    subject: &str,
) -> Result<Vec<ListResponseDevicesItem>, RuntimeFailure> {
    use sqlx::Row;
    let rows=sqlx::query("SELECT device_id,trusted_at IS NOT NULL AS trusted,primary_at IS NOT NULL AS primary,last_seen_ip,last_seen_user_agent,updated_at FROM auth_devices WHERE subject_id=$1 ORDER BY updated_at DESC LIMIT 200").bind(subject).fetch_all(postgres.pool()).await.map_err(db)?;
    let devices = rows
        .into_iter()
        .map(|row| -> Result<_, RuntimeFailure> {
            let updated: OffsetDateTime = row.try_get("updated_at").map_err(db)?;
            Ok(ListResponseDevicesItem {
                device_id: row.try_get("device_id").map_err(db)?,
                trusted: row.try_get("trusted").map_err(db)?,
                primary: row.try_get("primary").map_err(db)?,
                last_seen_ip: row.try_get("last_seen_ip").map_err(db)?,
                last_seen_user_agent: row.try_get("last_seen_user_agent").map_err(db)?,
                updated_at: updated.format(&Rfc3339).map_err(|error| {
                    RuntimeFailure::PluginFailure {
                        detail: error.to_string(),
                    }
                })?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(devices)
}
