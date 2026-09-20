//! Real native-Kernel reference scenarios over the deterministic Auth store.
//!
//! This is deliberately not a direct provider test: each operation crosses a
//! resolved App Plan, generated linked Factory, Capability endpoint, and real
//! Kernel routing. The simulated world supplies only time, entropy, faults,
//! and its durable private store.

use std::{cell::Cell, rc::Rc, time::Duration as StdDuration};

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_oauth_flow_plugin::{
    PACKAGE_ID,
    simulated::{OAuthSimulation, OAuthSimulationBoundary, OAuthSimulationFault},
    simulated_factory,
};
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
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const CALLER_PACKAGE_ID: &str = "test.oauth-flow-caller";
const SECRETS_PACKAGE_ID: &str = "test.oauth-flow-secrets";
const PROVIDER: &str = "github";
const RETURN_TO: &str = "/settings/security";

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
struct StaticSecretsFactory;

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
        let endpoint =
            Rc::new(SecretsEndpoint::new(StaticSecretsProvider)) as Rc<dyn NativeRequestEndpoint>;
        Ok(NativePluginInstance::new(vec![endpoint]))
    }
}

#[derive(Clone, Copy, Debug)]
struct StaticSecretsProvider;

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
            _ => Err(ResolveError::UnknownReference),
        };
        Box::pin(std::future::ready(Ok(result)))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn deterministic_reference_preserves_business_invariants_through_real_kernel_paths() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let initial = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
            let clock = Rc::new(Cell::new(initial));
            let simulation = simulation(clock.clone());
            let app = start(simulation.clone()).await;

            let shared = create(&app, initial + Duration::minutes(5)).await;
            let (first, second) =
                tokio::join!(consume(&app, &shared.state), consume(&app, &shared.state),);
            let first = first.unwrap();
            let second = second.unwrap();
            let success_count = usize::from(first.is_ok()) + usize::from(second.is_ok());
            assert_eq!(success_count, 1, "exactly one consume may succeed");
            assert!(first.is_ok() || matches!(first, Err(ConsumeError::AlreadyConsumed)));
            assert!(second.is_ok() || matches!(second, Err(ConsumeError::AlreadyConsumed)));

            let revoked = create(&app, initial + Duration::minutes(5)).await;
            assert!(revoke(&app, &revoked.state).await.unwrap().is_ok());
            assert!(matches!(
                consume(&app, &revoked.state).await.unwrap(),
                Err(ConsumeError::Revoked)
            ));
            assert!(matches!(
                revoke(&app, &revoked.state).await.unwrap(),
                Err(RevokeError::AlreadyRevoked)
            ));

            let expiring = create(&app, initial + Duration::seconds(1)).await;
            clock.set(initial + Duration::seconds(1));
            assert!(matches!(
                consume(&app, &expiring.state).await.unwrap(),
                Err(ConsumeError::Expired)
            ));

            let survives_restart = create(&app, initial + Duration::minutes(5)).await;
            assert_eq!(
                app.shutdown(StdDuration::from_secs(1)).await,
                ShutdownOutcome::Clean
            );

            let restarted = start(simulation).await;
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
}

#[tokio::test(flavor = "current_thread")]
async fn durable_commit_before_response_is_reported_as_uncertain_without_replaying() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let initial = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
            let clock = Rc::new(Cell::new(initial));
            let fail_once = Rc::new(Cell::new(true));
            let simulation = simulation(clock).with_fault_hook({
                let fail_once = fail_once.clone();
                move |boundary| {
                    (boundary == OAuthSimulationBoundary::AfterConsumeDurableCommit
                        && fail_once.replace(false))
                    .then_some(OAuthSimulationFault::DroppedConnection)
                }
            });
            let app = start(simulation.clone()).await;
            let created = create(&app, initial + Duration::minutes(5)).await;

            let first = consume(&app, &created.state).await;
            assert!(matches!(first, Err(RuntimeFailure::PluginFailure { .. })));
            assert_eq!(
                app.shutdown(StdDuration::from_secs(1)).await,
                ShutdownOutcome::Clean
            );
            let restarted = start(simulation).await;
            assert!(matches!(
                consume(&restarted, &created.state).await.unwrap(),
                Err(ConsumeError::AlreadyConsumed)
            ));
            assert_eq!(
                restarted.shutdown(StdDuration::from_secs(1)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

async fn start(simulation: OAuthSimulation) -> NativeApp {
    Kernel::start_native(plan(), TokioDriver::new(), registry(simulation))
        .await
        .unwrap()
}

fn registry(simulation: OAuthSimulation) -> NativePluginRegistry {
    NativePluginRegistry::new()
        .with_factory(CallerFactory)
        .with_factory(StaticSecretsFactory)
        .with_factory(simulated_factory(simulation))
}

fn plan() -> ResolvedAppPlan {
    let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE_ID).with_requirement(
        CapabilityRequirementPlan::one(flow::CAPABILITY_ID, flow::DESCRIPTOR_VERSION),
    );
    let oauth = PluginInstancePlan::new("oauth", PACKAGE_ID)
        .with_configuration(
            serde_json::json!({
                "schema": "oauth",
                "database_url_secret": "",
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

fn simulation(clock: Rc<Cell<OffsetDateTime>>) -> OAuthSimulation {
    let sequence = Rc::new(Cell::new(0_u8));
    OAuthSimulation::new(
        move || clock.get(),
        move |output| {
            let seed = sequence.get();
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = seed.wrapping_add(u8::try_from(index).unwrap());
            }
            sequence.set(seed.wrapping_add(1));
        },
        [7; 32],
    )
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
