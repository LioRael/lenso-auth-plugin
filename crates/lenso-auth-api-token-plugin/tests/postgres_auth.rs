use std::{
    collections::BTreeMap,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration as StdDuration,
};

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_api_token_plugin::{
    ApiTokenAuthConfig, ApiTokenAuthOperator, IssueApiToken, PACKAGE_ID, assertion_public_key,
};
use lenso_auth_sdk::credential::{
    CredentialBinding, MANAGEMENT_CEILING_CLAIM, ManagementCredentialCeiling,
    ManagementResourceScope,
};
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AuthOutcome, CredentialEvidence,
    FixedClock, TypedActor, audience, authenticate_request, decode_auth_response,
};
use lenso_capability_auth::{
    AUTHENTICATE_OPERATION, Auth, AuthenticateError, CAPABILITY_ID as AUTH_CAPABILITY_ID,
    DESCRIPTOR_VERSION as AUTH_DESCRIPTOR_VERSION,
};
use lenso_capability_credential_state as credential_state;
use lenso_capability_secrets::{
    CAPABILITY_ID as SECRETS_CAPABILITY_ID, DESCRIPTOR_VERSION as SECRETS_DESCRIPTOR_VERSION,
    RESOLVE_OPERATION, ResolveError, ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint,
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
use serde_json::json;
use sqlx::{AssertSqlSafe, Executor, PgPool, postgres::PgPoolOptions};
use time::{Duration, OffsetDateTime};

const CALLER_PACKAGE_ID: &str = "test.auth-caller";
const SECRETS_PACKAGE_ID: &str = "test.static-secrets";
const SIGNING_SECRET: &str = "integration-signing-secret-with-high-entropy";
const TOKEN_PEPPER: &str = "integration-token-pepper-with-high-entropy";
static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct CallerFactory;

impl NativePluginFactory for CallerFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _context: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Clone)]
struct StaticSecretsFactory {
    values: BTreeMap<String, String>,
}

impl std::fmt::Debug for StaticSecretsFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticSecretsFactory")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl NativePluginFactory for StaticSecretsFactory {
    fn package_id(&self) -> &'static str {
        SECRETS_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _context: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let endpoint = Rc::new(SecretsEndpoint::new(StaticSecretsProvider {
            values: self.values.clone(),
        })) as Rc<dyn NativeRequestEndpoint>;
        Ok(NativePluginInstance::new(vec![endpoint]))
    }
}

#[derive(Clone)]
struct StaticSecretsProvider {
    values: BTreeMap<String, String>,
}

impl std::fmt::Debug for StaticSecretsProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticSecretsProvider")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SecretsProvider for StaticSecretsProvider {
    fn resolve(
        &self,
        _context: InvocationContext,
        request: ResolveRequest,
    ) -> NativeRequestFuture<Secrets> {
        let result = self
            .values
            .get(&request.reference)
            .cloned()
            .map(|value| ResolveResponse { value })
            .ok_or(ResolveError::UnknownReference);
        Box::pin(futures::future::ready(Ok(result)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestActor(String);

impl TypedActor for TestActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".to_owned(),
                actual: assertion.actor_kind().to_owned(),
            });
        }
        Ok(Self(assertion.subject().to_owned()))
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn composed_auth_issues_publicly_verifiable_assertions_and_observes_revocation() {
    let database_url = database_url();
    let schema = unique_schema("lifecycle");
    let admin = admin_pool(&database_url).await;
    ApiTokenAuthOperator::setup(&database_url, &schema)
        .await
        .unwrap();
    let operator = ApiTokenAuthOperator::connect(&database_url, &schema)
        .await
        .unwrap();
    let issued = operator
        .issue(
            TOKEN_PEPPER.as_bytes(),
            IssueApiToken {
                subject: "user-123".to_owned(),
                actor_kind: "user".to_owned(),
                assurance: "api-token".to_owned(),
                audience: vec![audience("example.secure@1", "read")],
                claims: BTreeMap::from([
                    ("tenant".to_owned(), json!("acme")),
                    (
                        MANAGEMENT_CEILING_CLAIM.into(),
                        json!(ManagementCredentialCeiling {
                            deployment: "deployment-a".into(),
                            permissions: vec![
                                "auth.subject.read".into(),
                                "auth.session.revoke".into()
                            ],
                            resource_scopes: vec![ManagementResourceScope {
                                kind: "management-deployment".into(),
                                id: "deployment-a".into()
                            }]
                        }),
                    ),
                ]),
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            },
        )
        .await
        .unwrap();
    let token = issued.expose_secret().to_owned();
    let metadata = operator
        .list_management_credentials("user-123", "deployment-a", 1, None)
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].credential_id, issued.token_id());
    assert!(metadata[0].active);
    assert!(!format!("{metadata:?}").contains(&token));
    assert!(
        operator
            .list_management_credentials("user-123", "deployment-b", 1, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        operator
            .list_management_credentials("another-user", "deployment-a", 1, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        operator
            .list_management_credentials("user-123", "deployment-a", 1, Some(issued.token_id()))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        operator
            .list_management_credentials("user-123", "deployment-a", 0, None)
            .await
            .is_err()
    );

    assert!(!format!("{issued:?}").contains(&token));

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let driver = TokioDriver::new();
            let app = Kernel::start_native(
                plan(&schema, SIGNING_SECRET),
                driver,
                registry(&database_url, SIGNING_SECRET, TOKEN_PEPPER),
            )
            .await
            .expect("configured Auth Plugin should prepare");
            exercise_auth(&app, &operator, issued.session_id(), &token).await;
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;

    cleanup(&admin, &schema).await;
}

async fn exercise_auth(
    app: &NativeApp,
    operator: &ApiTokenAuthOperator,
    session_id: &str,
    token: &str,
) {
    let absent = app
        .invoke::<Auth>("caller", AUTHENTICATE_OPERATION, authenticate_request(None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decode_auth_response(absent).unwrap(), AuthOutcome::Absent);

    let invalid = app
        .invoke::<Auth>(
            "caller",
            AUTHENTICATE_OPERATION,
            authenticate_request(Some(CredentialEvidence::new(
                "bearer",
                format!("lenso_at_{}", "x".repeat(43)),
            ))),
        )
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(invalid, AuthenticateError::Invalid);

    let response = app
        .invoke::<Auth>(
            "caller",
            AUTHENTICATE_OPERATION,
            authenticate_request(Some(CredentialEvidence::new("bearer", token))),
        )
        .await
        .unwrap()
        .unwrap();
    let AuthOutcome::Authenticated(assertion) = decode_auth_response(response).unwrap() else {
        panic!("valid token should authenticate");
    };
    let context = assertion
        .attach(app.invocation_context(None, lenso_kernel::CancellationToken::new()))
        .unwrap();
    let verifier = ActorAssertionVerifier::from_public_key_base64(
        "auth.api-token",
        &assertion_public_key(SIGNING_SECRET),
    )
    .unwrap();
    let actor = verifier
        .project_context::<TestActor>(
            &context,
            "example.secure@1",
            "read",
            &FixedClock::new(OffsetDateTime::now_utc()),
        )
        .unwrap();
    assert_eq!(actor, TestActor("user-123".to_owned()));

    exercise_credential_state(app, operator, &assertion, session_id).await;
    let revoked = app
        .invoke::<Auth>(
            "caller",
            AUTHENTICATE_OPERATION,
            authenticate_request(Some(CredentialEvidence::new("bearer", token))),
        )
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(revoked, AuthenticateError::Revoked);
}

async fn exercise_credential_state(
    app: &NativeApp,
    operator: &ApiTokenAuthOperator,
    assertion: &ActorAssertion,
    session_id: &str,
) {
    let binding = CredentialBinding::from_assertion(assertion).unwrap();
    assert_eq!(binding.session_id, session_id);
    let request = || credential_state::InspectRequest {
        credential_id: binding.credential_id.clone(),
        session_id: binding.session_id.clone(),
    };
    let current = app
        .invoke::<credential_state::CredentialState>(
            "caller",
            credential_state::INSPECT_OPERATION,
            request(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(current.active);
    assert_eq!(current.subject, assertion.subject());
    assert_eq!(
        CredentialBinding::from_claims(&current.claims).unwrap(),
        binding
    );
    exercise_reference_rejection(app, &binding).await;
    let signed = ManagementCredentialCeiling::from_assertion(assertion).unwrap();
    let mut narrowed = signed.clone();
    narrowed.permissions.pop();
    assert!(
        operator
            .attenuate_management_credential(&binding, &narrowed)
            .await
            .unwrap()
    );
    assert!(
        operator
            .attenuate_management_credential(&binding, &signed)
            .await
            .is_err()
    );
    let current = app
        .invoke::<credential_state::CredentialState>(
            "caller",
            credential_state::INSPECT_OPERATION,
            request(),
        )
        .await
        .unwrap()
        .unwrap();
    let ceiling = ManagementCredentialCeiling::from_claims(&current.claims).unwrap();
    assert!(!ceiling.allows(
        "deployment-a",
        "auth.session.revoke",
        "management-deployment",
        "deployment-a"
    ));
    assert!(signed.allows(
        "deployment-a",
        "auth.session.revoke",
        "management-deployment",
        "deployment-a"
    ));
    assert!(!format!("{current:?}").contains("acme"));
    assert!(operator.revoke_session(session_id).await.unwrap());
    let current = app
        .invoke::<credential_state::CredentialState>(
            "caller",
            credential_state::INSPECT_OPERATION,
            request(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!current.active);
    assert!(
        !operator
            .attenuate_management_credential(&binding, &narrowed)
            .await
            .unwrap()
    );
}

async fn exercise_reference_rejection(app: &NativeApp, binding: &CredentialBinding) {
    let request = || credential_state::InspectRequest {
        credential_id: binding.credential_id.clone(),
        session_id: binding.session_id.clone(),
    };
    assert_eq!(
        app.invoke::<credential_state::CredentialState>(
            "observer",
            credential_state::INSPECT_OPERATION,
            request()
        )
        .await
        .unwrap()
        .unwrap_err(),
        credential_state::InspectError::PermissionDenied
    );
    assert_eq!(
        app.invoke::<credential_state::CredentialState>(
            "caller",
            credential_state::INSPECT_OPERATION,
            credential_state::InspectRequest {
                credential_id: binding.credential_id.clone(),
                session_id: "ses_other".into()
            }
        )
        .await
        .unwrap()
        .unwrap_err(),
        credential_state::InspectError::NotFound
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn preparation_rejects_signing_key_mismatch_without_leaking_secrets() {
    let database_url = database_url();
    let schema = unique_schema("mismatch");
    let admin = admin_pool(&database_url).await;
    ApiTokenAuthOperator::setup(&database_url, &schema)
        .await
        .unwrap();
    let local = tokio::task::LocalSet::new();
    let error = local
        .run_until(async {
            Kernel::start_native(
                plan(&schema, "different-signing-secret"),
                TokioDriver::new(),
                registry(&database_url, SIGNING_SECRET, TOKEN_PEPPER),
            )
            .await
            .unwrap_err()
        })
        .await;
    assert!(matches!(
        error,
        RuntimeFailure::PluginFailure { detail }
            if detail.contains("does not match")
                && !detail.contains(SIGNING_SECRET)
                && !detail.contains(TOKEN_PEPPER)
    ));
    cleanup(&admin, &schema).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn preparation_requires_explicit_setup_and_never_creates_schema() {
    let database_url = database_url();
    let schema = unique_schema("missing");
    let admin = admin_pool(&database_url).await;
    let local = tokio::task::LocalSet::new();
    let error = local
        .run_until(async {
            Kernel::start_native(
                plan(&schema, SIGNING_SECRET),
                TokioDriver::new(),
                registry(&database_url, SIGNING_SECRET, TOKEN_PEPPER),
            )
            .await
            .unwrap_err()
        })
        .await;
    assert!(matches!(error, RuntimeFailure::PluginFailure { .. }));
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)")
            .bind(&schema)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert!(!exists, "Plugin preparation must not run setup");
}

fn plan(schema: &str, public_key_secret: &str) -> ResolvedAppPlan {
    let config = ApiTokenAuthConfig::new(
        schema,
        "auth.api-token",
        assertion_public_key(public_key_secret),
        "auth/database-url",
        "auth/assertion-signing-key",
        "auth/token-pepper",
        60,
    )
    .unwrap();
    let config = config
        .with_credential_state_callers(vec!["caller".into()])
        .unwrap();
    let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE_ID)
        .with_requirement(CapabilityRequirementPlan::one(
            AUTH_CAPABILITY_ID,
            AUTH_DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            credential_state::CAPABILITY_ID,
            credential_state::DESCRIPTOR_VERSION,
        ));
    let observer = PluginInstancePlan::new("observer", CALLER_PACKAGE_ID).with_requirement(
        CapabilityRequirementPlan::one(
            credential_state::CAPABILITY_ID,
            credential_state::DESCRIPTOR_VERSION,
        ),
    );
    let auth = PluginInstancePlan::new("auth", PACKAGE_ID)
        .with_configuration(serde_json::to_string(&config).unwrap())
        .with_requirement(CapabilityRequirementPlan::one(
            SECRETS_CAPABILITY_ID,
            SECRETS_DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            AUTH_CAPABILITY_ID,
            AUTH_DESCRIPTOR_VERSION,
            [AUTHENTICATE_OPERATION],
        ));
    let auth = auth.with_capability(CapabilityEndpointPlan::new(
        credential_state::CAPABILITY_ID,
        credential_state::DESCRIPTOR_VERSION,
        [credential_state::INSPECT_OPERATION],
    ));
    let secrets = PluginInstancePlan::new("secrets", SECRETS_PACKAGE_ID).with_capability(
        CapabilityEndpointPlan::new(
            SECRETS_CAPABILITY_ID,
            SECRETS_DESCRIPTOR_VERSION,
            [RESOLVE_OPERATION],
        ),
    );
    AppComposition::new(
        vec![caller, observer, auth, secrets],
        vec![
            CapabilityBinding::new(
                "caller",
                credential_state::CAPABILITY_ID,
                credential_state::DESCRIPTOR_VERSION,
                "auth",
            ),
            CapabilityBinding::new(
                "observer",
                credential_state::CAPABILITY_ID,
                credential_state::DESCRIPTOR_VERSION,
                "auth",
            ),
            CapabilityBinding::new(
                "auth",
                SECRETS_CAPABILITY_ID,
                SECRETS_DESCRIPTOR_VERSION,
                "secrets",
            ),
            CapabilityBinding::new(
                "caller",
                AUTH_CAPABILITY_ID,
                AUTH_DESCRIPTOR_VERSION,
                "auth",
            ),
        ],
    )
    .resolve()
    .unwrap()
}

fn registry(database_url: &str, signing_secret: &str, token_pepper: &str) -> NativePluginRegistry {
    NativePluginRegistry::new()
        .with_linked_factories()
        .with_factory(CallerFactory)
        .with_factory(StaticSecretsFactory {
            values: BTreeMap::from([
                ("auth/database-url".to_owned(), database_url.to_owned()),
                (
                    "auth/assertion-signing-key".to_owned(),
                    signing_secret.to_owned(),
                ),
                ("auth/token-pepper".to_owned(), token_pepper.to_owned()),
            ]),
        })
}

fn database_url() -> String {
    std::env::var("LENSO_POSTGRES_TEST_URL")
        .expect("LENSO_POSTGRES_TEST_URL must be set for ignored acceptance tests")
}

fn unique_schema(label: &str) -> String {
    let sequence = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    format!("lenso_auth_{label}_{}_{}", std::process::id(), sequence)
}

async fn admin_pool(database_url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .unwrap()
}

async fn cleanup(admin: &PgPool, schema: &str) {
    admin
        .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
}
