//! Opt-in Native + PostgreSQL qualification for the OAuth reference flow.
//!
//! This is intentionally ignored in ordinary local runs: a passing unit test
//! cannot prove a selected production PostgreSQL target. A qualified Host
//! supplies `LENSO_POSTGRES_TEST_URL`, and this test then crosses the real
//! Kernel, generated Factory, Capability endpoint, lifecycle-owned PostgreSQL
//! store, and a fresh Kernel restart. It is not a direct storage test.

use std::{
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration as StdDuration,
};

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_oauth_flow_plugin::{OAuthFlowOperator, PACKAGE_ID, native_postgres_factory};
use lenso_capability_oauth_flow::{
    self as flow, ConsumeError, ConsumeRequest, CreateRequest, OauthFlowConsume, OauthFlowCreate,
    OauthFlowRevoke, RevokeError, RevokeRequest,
};
use lenso_capability_secrets::{
    self as secrets, ResolveError, ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint,
    SecretsProvider,
};
use lenso_kernel::{
    InvocationContext, Kernel, NativeApp, NativeRequestEndpoint, NativeRequestFuture,
    RuntimeFailure, ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_runner::TokioDriver;
use sqlx::{AssertSqlSafe, Executor, PgPool};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const CALLER_PACKAGE_ID: &str = "test.oauth-flow-native-caller";
const SECRETS_PACKAGE_ID: &str = "test.oauth-flow-native-secrets";
const PROVIDER: &str = "github";
const RETURN_TO: &str = "/settings/security";
static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct CallerFactory;

impl NativePluginFactory for CallerFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Clone)]
struct StaticSecretsFactory {
    database_url: Rc<str>,
}

impl std::fmt::Debug for StaticSecretsFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StaticSecretsFactory").finish()
    }
}

impl NativePluginFactory for StaticSecretsFactory {
    fn package_id(&self) -> &'static str {
        SECRETS_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let database_url = self.database_url.clone();
        let endpoint = Rc::new(SecretsEndpoint::new(StaticSecretsProvider { database_url }))
            as Rc<dyn NativeRequestEndpoint>;
        Ok(NativePluginInstance::new(vec![endpoint]))
    }
}

#[derive(Clone, Debug)]
struct StaticSecretsProvider {
    database_url: Rc<str>,
}

impl SecretsProvider for StaticSecretsProvider {
    fn resolve(
        &self,
        _: InvocationContext,
        request: ResolveRequest,
    ) -> NativeRequestFuture<Secrets> {
        let result = match request.reference.as_str() {
            "test/oauth-encryption-key" => Ok(ResolveResponse {
                value: "0123456789abcdef0123456789abcdef".to_owned(),
            }),
            "test/postgres-url" => Ok(ResolveResponse {
                value: self.database_url.to_string(),
            }),
            _ => Err(ResolveError::UnknownReference),
        };
        Box::pin(std::future::ready(Ok(result)))
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn native_postgres_reference_preserves_atomic_oauth_invariants_across_kernel_restart() {
    let database_url = std::env::var("LENSO_POSTGRES_TEST_URL").unwrap();
    let schema = unique_schema("oauth_reference");
    OAuthFlowOperator::setup(&database_url, &schema)
        .await
        .unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();

    tokio::task::LocalSet::new()
        .run_until(async {
            let app = start(&database_url, &schema).await;
            let shared = create(&app, OffsetDateTime::now_utc() + Duration::minutes(5)).await;
            let (first, second) =
                tokio::join!(consume(&app, &shared.state), consume(&app, &shared.state),);
            let first = first.unwrap();
            let second = second.unwrap();
            assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
            assert!(first.is_ok() || matches!(first, Err(ConsumeError::AlreadyConsumed)));
            assert!(second.is_ok() || matches!(second, Err(ConsumeError::AlreadyConsumed)));

            let revoked = create(&app, OffsetDateTime::now_utc() + Duration::minutes(5)).await;
            assert!(revoke(&app, &revoked.state).await.unwrap().is_ok());
            assert!(matches!(
                consume(&app, &revoked.state).await.unwrap(),
                Err(ConsumeError::Revoked)
            ));
            assert!(matches!(
                revoke(&app, &revoked.state).await.unwrap(),
                Err(RevokeError::AlreadyRevoked)
            ));

            let expiring = create(&app, OffsetDateTime::now_utc() + Duration::minutes(5)).await;
            // The runtime owns a schema-scoped connection pool.  This direct
            // operator probe must name the same isolated schema explicitly;
            // the generic test pool intentionally has no ambient search path.
            // Keep the storage invariant `expires_at > created_at` true while
            // making the state expired to the runtime.
            pool.execute(AssertSqlSafe(format!(
                "UPDATE \"{schema}\".oauth_flows SET created_at = transaction_timestamp() - interval '2 seconds', expires_at = transaction_timestamp() - interval '1 second'"
            )))
            .await
            .unwrap();
            assert!(matches!(
                consume(&app, &expiring.state).await.unwrap(),
                Err(ConsumeError::Expired)
            ));

            let survives_restart =
                create(&app, OffsetDateTime::now_utc() + Duration::minutes(5)).await;
            assert_eq!(
                app.shutdown(StdDuration::from_secs(1)).await,
                ShutdownOutcome::Clean
            );
            let restarted = start(&database_url, &schema).await;
            assert!(
                consume(&restarted, &survives_restart.state)
                    .await
                    .unwrap()
                    .is_ok()
            );
            assert_eq!(
                restarted.shutdown(StdDuration::from_secs(1)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;

    cleanup(&pool, &schema).await;
}

async fn start(database_url: &str, schema: &str) -> NativeApp {
    Kernel::start_native(
        plan(schema),
        TokioDriver::new(),
        NativePluginRegistry::new()
            .with_factory(CallerFactory)
            .with_factory(StaticSecretsFactory {
                database_url: Rc::from(database_url),
            })
            .with_factory(native_postgres_factory()),
    )
    .await
    .unwrap()
}

fn plan(schema: &str) -> ResolvedAppPlan {
    let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE_ID).with_requirement(
        CapabilityRequirementPlan::one(flow::CAPABILITY_ID, flow::DESCRIPTOR_VERSION),
    );
    let oauth = PluginInstancePlan::new("oauth", PACKAGE_ID)
        .with_configuration(
            serde_json::json!({
                "schema": schema,
                "database_url_secret": "test/postgres-url",
                "d1_binding": "",
                "encryption_key_secret": "test/oauth-encryption-key",
            })
            .to_string(),
        )
        .with_requirement(CapabilityRequirementPlan::one(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            flow::CAPABILITY_ID,
            flow::DESCRIPTOR_VERSION,
            [
                flow::CONSUME_OPERATION,
                flow::CREATE_OPERATION,
                flow::REVOKE_OPERATION,
            ],
        ));
    let secrets = PluginInstancePlan::new("secrets", SECRETS_PACKAGE_ID).with_capability(
        CapabilityEndpointPlan::new(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            [secrets::RESOLVE_OPERATION],
        ),
    );
    AppComposition::new(
        vec![caller, oauth, secrets],
        vec![
            CapabilityBinding::new(
                "caller",
                flow::CAPABILITY_ID,
                flow::DESCRIPTOR_VERSION,
                "oauth",
            ),
            CapabilityBinding::new(
                "oauth",
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
                "secrets",
            ),
        ],
    )
    .resolve()
    .unwrap()
}

async fn create(app: &NativeApp, expiry: OffsetDateTime) -> flow::CreateResponse {
    app.invoke::<OauthFlowCreate>(
        "caller",
        flow::CREATE_OPERATION,
        CreateRequest {
            provider: PROVIDER.to_owned(),
            return_to: RETURN_TO.to_owned(),
            expires_at: expiry.format(&Rfc3339).unwrap(),
        },
    )
    .await
    .unwrap()
    .unwrap()
}

async fn consume(
    app: &NativeApp,
    state: &str,
) -> Result<Result<flow::ConsumeResponse, ConsumeError>, RuntimeFailure> {
    app.invoke::<OauthFlowConsume>(
        "caller",
        flow::CONSUME_OPERATION,
        ConsumeRequest {
            provider: PROVIDER.to_owned(),
            state: state.to_owned(),
        },
    )
    .await
}

async fn revoke(
    app: &NativeApp,
    state: &str,
) -> Result<Result<flow::RevokeResponse, RevokeError>, RuntimeFailure> {
    app.invoke::<OauthFlowRevoke>(
        "caller",
        flow::REVOKE_OPERATION,
        RevokeRequest {
            provider: PROVIDER.to_owned(),
            state: state.to_owned(),
        },
    )
    .await
}

fn unique_schema(label: &str) -> String {
    format!(
        "lenso_{label}_{}_{}",
        std::process::id(),
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    )
}

async fn cleanup(pool: &PgPool, schema: &str) {
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
}
