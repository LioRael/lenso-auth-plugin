//! Durable device observations and trust facts.
#[cfg(feature = "postgres")]
mod operator;
#[cfg(feature = "postgres")]
mod schema;
mod storage;
#[cfg(feature = "workers")]
pub mod workers;

use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_device_auth as device;
use lenso_capability_device_auth::{
    DeviceList, DeviceObserve, DeviceProvider, DeviceSetTrust, ListError, ListRequest,
    ListResponse, ListResponseDevicesItem, ObserveError, ObserveRequest, ObserveResponse,
    SetTrustError, SetTrustRequest, SetTrustResponse,
};
use lenso_capability_secrets as secrets;
#[cfg(feature = "postgres")]
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
#[cfg(feature = "postgres")]
use lenso_postgres_kit::OwnedPostgres;
#[cfg(feature = "postgres")]
pub use operator::{DeviceAuthOperator, DeviceOperatorError};
#[cfg(feature = "postgres")]
use schema::schema_plan;
use serde::{Deserialize, Serialize};
#[cfg(feature = "postgres")]
use std::time::Duration as StdDuration;
use std::{cell::RefCell, fmt, rc::Rc};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[cfg(feature = "postgres")]
use zeroize::Zeroizing;

#[cfg(feature = "postgres")]
const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetTrustOutcome {
    Updated,
    NotFound,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthConfig {
    schema: String,
    #[serde(default)]
    #[lenso(default = "")]
    database_url_secret: String,
    #[serde(default)]
    #[lenso(default = "")]
    d1_binding: String,
}
impl DeviceAuthConfig {
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
    ) -> Result<Self, RuntimeFailure> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            d1_binding: String::new(),
        };
        validate_config(&value)?;
        Ok(value)
    }
}

fn validate_config(config: &DeviceAuthConfig) -> Result<(), RuntimeFailure> {
    let valid_name = |value: &str| {
        !value.is_empty()
            && value.len() <= 63
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'_'))
            })
    };
    if !valid_name(&config.schema)
        || matches!(config.schema.as_str(), "public" | "information_schema")
        || config.schema.starts_with("pg_")
        || config.database_url_secret.len() > 256
        || (config.d1_binding.is_empty() && config.database_url_secret.is_empty())
        || (!config.d1_binding.is_empty()
            && (!config.database_url_secret.is_empty()
                || config.d1_binding.len() > 128
                || !config
                    .d1_binding
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')))
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid Device Auth storage configuration".into(),
        });
    }
    Ok(())
}

#[lenso::plugin(lifecycle, validate = validate_config)]
#[derive(Clone)]
struct DeviceAuthPlugin {
    #[config]
    config: DeviceAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<storage::DeviceStore>>>,
    #[allow(dead_code)]
    d1: EventStorageBinding,
}
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for DeviceAuthPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthProvider")
            .field("prepared", &self.state.borrow().is_some())
            .finish()
    }
}
impl DeviceAuthPlugin {
    fn store(&self) -> Result<storage::DeviceStore, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::PluginFailure {
                detail: "Device Auth is not prepared".to_owned(),
            })
    }
}
#[provides(device::Device)]
impl DeviceProvider for DeviceAuthPlugin {
    fn observe(
        &self,
        _context: InvocationContext,
        request: ObserveRequest,
    ) -> NativeRequestFuture<DeviceObserve> {
        let store = self.store();
        Box::pin(async move {
            let store = store?;
            if !valid(&request.subject) {
                return Ok(Err(ObserveError::InvalidSubject));
            }
            if !valid(&request.device_id) {
                return Ok(Err(ObserveError::InvalidDevice));
            }
            store.observe(request).await.map(Ok)
        })
    }
    fn list(
        &self,
        _context: InvocationContext,
        request: ListRequest,
    ) -> NativeRequestFuture<DeviceList> {
        let store = self.store();
        Box::pin(async move {
            let store = store?;
            if !valid(&request.subject) {
                return Ok(Err(ListError::InvalidSubject));
            }
            store
                .list(&request.subject)
                .await
                .map(|devices| Ok(ListResponse { devices }))
        })
    }
    fn set_trust(
        &self,
        _context: InvocationContext,
        request: SetTrustRequest,
    ) -> NativeRequestFuture<DeviceSetTrust> {
        let store = self.store();
        Box::pin(async move {
            let store = store?;
            if !valid(&request.subject) {
                return Ok(Err(SetTrustError::InvalidSubject));
            }
            if !valid(&request.device_id) {
                return Ok(Err(SetTrustError::InvalidDevice));
            }
            if store.set_trust(&request).await? == SetTrustOutcome::NotFound {
                return Ok(Err(SetTrustError::NotFound));
            }
            Ok(Ok(SetTrustResponse { changed: true }))
        })
    }
}

#[cfg(feature = "postgres")]
async fn set_device_trust(
    postgres: &OwnedPostgres,
    request: &SetTrustRequest,
) -> Result<SetTrustOutcome, RuntimeFailure> {
    let mut transaction = postgres.pool().begin().await.map_err(db)?;
    let locked_devices: Vec<String> = sqlx::query_scalar(
        "SELECT device_id FROM auth_devices WHERE subject_id=$1 ORDER BY device_id FOR UPDATE",
    )
    .bind(&request.subject)
    .fetch_all(&mut *transaction)
    .await
    .map_err(db)?;
    if !locked_devices
        .iter()
        .any(|device_id| device_id == &request.device_id)
    {
        transaction.commit().await.map_err(db)?;
        return Ok(SetTrustOutcome::NotFound);
    }
    if request.primary {
        sqlx::query(
            "UPDATE auth_devices SET primary_at=NULL WHERE subject_id=$1 AND primary_at IS NOT NULL",
        )
        .bind(&request.subject)
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
    }
    sqlx::query("UPDATE auth_devices SET trusted_at=CASE WHEN $3 THEN transaction_timestamp() ELSE NULL END,primary_at=CASE WHEN $4 THEN transaction_timestamp() ELSE NULL END,updated_at=transaction_timestamp() WHERE subject_id=$1 AND device_id=$2")
        .bind(&request.subject)
        .bind(&request.device_id)
        .bind(request.trusted)
        .bind(request.primary)
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
    transaction.commit().await.map_err(db)?;
    Ok(SetTrustOutcome::Updated)
}

impl Lifecycle for DeviceAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        if !config.d1_binding.is_empty() {
            #[cfg(feature = "workers")]
            {
                let binding = self
                    .d1
                    .as_ref()
                    .filter(|binding| binding.name() == config.d1_binding)
                    .ok_or_else(storage::failure)?
                    .clone();
                let result = binding.run(vec![workers::statement(
                    "SELECT version FROM auth_device_schema WHERE version=1 AND fingerprint='a406b7c5c8b3d1f656723dda5a41a912d4f434031fa9dfcf6e6372c0dc128994'", vec![])]).await.map_err(|()| storage::failure())?;
                if result[0].results.len() != 1 {
                    return Err(storage::failure());
                }
                self.state.replace(Some(storage::DeviceStore::D1(binding)));
                return Ok(());
            }
            #[cfg(not(feature = "workers"))]
            return Err(storage::failure());
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = context;
            Err(storage::failure())
        }
        #[cfg(feature = "postgres")]
        {
            let state = self.state.clone();
            let cancellation = context.cancellation();
            let invocation = context
                .dependencies()
                .invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
            let database_url = self
                .secrets
                .resolve_with_context(
                    invocation,
                    ResolveRequest {
                        reference: config.database_url_secret,
                    },
                )
                .await
                .map(|value| Zeroizing::new(value.value))
                .map_err(|error| match error {
                    SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                        detail: "device database secret was rejected".to_owned(),
                    },
                    SecretsInvocationError::Runtime(error) => error,
                })?;
            let postgres = OwnedPostgres::prepare(
                &database_url,
                schema_plan(config.schema).map_err(|error| {
                    RuntimeFailure::InvalidResolvedPlan {
                        detail: error.to_string(),
                    }
                })?,
            )
            .await
            .map_err(|error| RuntimeFailure::PluginFailure {
                detail: error.to_string(),
            })?;
            state.replace(Some(storage::DeviceStore::Postgres(postgres)));
            Ok(())
        }
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let postgres = self.state.borrow_mut().take();
        if let Some(postgres) = postgres {
            postgres.close().await;
        }
        Ok(())
    }
}
fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
#[cfg(feature = "postgres")]
fn db(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: format!("Device Auth storage operation failed: {error}"),
    }
}

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use super::*;

    async fn test_postgres(label: &str) -> (String, String, OwnedPostgres) {
        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("device_{label}_test_{}_{suffix}", std::process::id());
        DeviceAuthOperator::setup(&database_url, &schema)
            .await
            .unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        (database_url, schema, postgres)
    }

    async fn cleanup_test_postgres(database_url: &str, schema: &str, postgres: OwnedPostgres) {
        use sqlx::{AssertSqlSafe, Executor};

        postgres.pool().close().await;
        let cleanup_pool = sqlx::PgPool::connect(database_url).await.unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    async fn insert_device(
        postgres: &OwnedPostgres,
        subject: &str,
        device_id: &str,
        primary: bool,
    ) {
        sqlx::query("INSERT INTO auth_devices(subject_id,device_id,primary_at) VALUES($1,$2,CASE WHEN $3 THEN transaction_timestamp() ELSE NULL END)")
            .bind(subject)
            .bind(device_id)
            .bind(primary)
            .execute(postgres.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn nonexistent_primary_target_leaves_existing_primary_unchanged() {
        let (database_url, schema, postgres) = test_postgres("missing_primary").await;
        let subject = "subject-a";
        insert_device(&postgres, subject, "old-primary", true).await;

        let outcome = set_device_trust(
            &postgres,
            &SetTrustRequest {
                subject: subject.to_owned(),
                device_id: "missing-device".to_owned(),
                trusted: true,
                primary: true,
            },
        )
        .await
        .unwrap();
        let primary: Option<String> = sqlx::query_scalar(
            "SELECT device_id FROM auth_devices WHERE subject_id=$1 AND primary_at IS NOT NULL",
        )
        .bind(subject)
        .fetch_optional(postgres.pool())
        .await
        .unwrap();

        assert_eq!(outcome, SetTrustOutcome::NotFound);
        assert_eq!(primary.as_deref(), Some("old-primary"));
        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn concurrent_primary_assignments_leave_exactly_one_primary() {
        let (database_url, schema, postgres) = test_postgres("concurrent_primary").await;
        let subject = "subject-a";
        insert_device(&postgres, subject, "device-a", false).await;
        insert_device(&postgres, subject, "device-b", false).await;
        let first = SetTrustRequest {
            subject: subject.to_owned(),
            device_id: "device-a".to_owned(),
            trusted: true,
            primary: true,
        };
        let second = SetTrustRequest {
            subject: subject.to_owned(),
            device_id: "device-b".to_owned(),
            trusted: true,
            primary: true,
        };

        let (first_outcome, second_outcome) = tokio::join!(
            set_device_trust(&postgres, &first),
            set_device_trust(&postgres, &second),
        );
        let primary_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_devices WHERE subject_id=$1 AND primary_at IS NOT NULL",
        )
        .bind(subject)
        .fetch_one(postgres.pool())
        .await
        .unwrap();

        assert_eq!(first_outcome.unwrap(), SetTrustOutcome::Updated);
        assert_eq!(second_outcome.unwrap(), SetTrustOutcome::Updated);
        assert_eq!(primary_count, 1);
        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }
}

#[cfg(feature = "workers")]
type EventStorageBinding = Option<workers::D1Binding>;
#[cfg(not(feature = "workers"))]
type EventStorageBinding = ();

/// Creates a fresh generated factory with its exact event-owned D1 binding.
#[cfg(feature = "workers")]
pub fn workers_factory(
    binding_name: impl Into<Rc<str>>,
    batch: js_sys::Function,
) -> impl lenso_native_adapter::NativePluginFactory {
    let binding = workers::D1Binding::new(binding_name, batch);
    lenso_native_adapter::ConfiguredPluginFactory::<DeviceAuthPlugin, _>::new(move |plugin| {
        if plugin.config.d1_binding != binding.name() {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Device Auth requires its exact D1 binding".into(),
            });
        }
        plugin.d1 = Some(binding.clone());
        Ok(())
    })
}
