use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_account_admin_agent_tools_plugin::{
    LIST_SESSIONS_TOOL, LIST_SUBJECTS_TOOL, SET_SUBJECT_STATUS_TOOL,
};
use lenso_auth_account_plugin::{AccountAuthConfig, AccountAuthOperator, assertion_public_key};
use lenso_capability_account_admin as admin;
use lenso_capability_agent_tool_provider as tool;
use lenso_capability_auth as auth;
use lenso_capability_auth_delegation as delegation;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_identity_directory as directory;
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
use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor, PgPool};
use lenso_runner::TokioDriver;
use serde_json::{Value, json};
use std::{collections::BTreeMap, rc::Rc, time::Duration};
const CALLER_PACKAGE_ID: &str = "test.auth-caller";
const SECRETS_PACKAGE_ID: &str = "test.static-secrets";
const SIGNING_SECRET: &str = "integration-signing-secret-with-high-entropy";
const TOKEN_PEPPER: &str = "integration-token-pepper-with-high-entropy";
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

fn endpoint(id: &str, version: &str, operations: &[&str]) -> CapabilityEndpointPlan {
    let mut operations = operations.to_vec();
    operations.sort_unstable();
    let endpoint = CapabilityEndpointPlan::new(id, version, operations);
    if [
        admin::CAPABILITY_ID,
        directory::CAPABILITY_ID,
        issuer::CAPABILITY_ID,
    ]
    .contains(&id)
    {
        endpoint.with_cross_lane_transfer()
    } else {
        endpoint
    }
}

fn account_config(schema: &str, authorized: bool) -> AccountAuthConfig {
    let config = AccountAuthConfig::new(
        schema,
        "test.account",
        assertion_public_key(SIGNING_SECRET),
        "auth/database-url",
        "auth/assertion-signing-key",
        "auth/token-pepper",
        60,
    )
    .unwrap()
    .with_admin_callers(if authorized {
        vec!["account-tools".into()]
    } else {
        vec![]
    })
    .unwrap();
    config
        .with_delegation_callers(if authorized {
            vec!["caller".into()]
        } else {
            vec![]
        })
        .unwrap()
}

fn plan(schema: &str, tools: bool, authorized: bool) -> ResolvedAppPlan {
    let config = account_config(schema, authorized);
    let account = PluginInstancePlan::new("account", "lenso.auth.account")
        .with_configuration(serde_json::to_string(&config).unwrap())
        .with_capability(endpoint(
            delegation::CAPABILITY_ID,
            delegation::DESCRIPTOR_VERSION,
            &["grant"],
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        ))
        .with_capability(endpoint(
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            &["authenticate"],
        ))
        .with_capability(endpoint(
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            &["ensure_identity", "read_status"],
        ))
        .with_capability(endpoint(
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
            &["issue", "revoke", "revoke_credential"],
        ))
        .with_capability(endpoint(
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            &["list_subjects", "list_sessions", "set_subject_status"],
        ));
    let mut caller = PluginInstancePlan::new("caller", CALLER_PACKAGE_ID);
    let mut bindings = vec![CapabilityBinding::new(
        "account",
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
        "secrets",
    )];
    for (id, version) in [
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION),
        (delegation::CAPABILITY_ID, delegation::DESCRIPTOR_VERSION),
        (directory::CAPABILITY_ID, directory::DESCRIPTOR_VERSION),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION),
    ] {
        caller = caller.with_requirement(CapabilityRequirementPlan::one(id, version));
        bindings.push(CapabilityBinding::new("caller", id, version, "account"));
    }
    let mut instances = vec![
        account,
        PluginInstancePlan::new("secrets", SECRETS_PACKAGE_ID).with_capability(endpoint(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            &["resolve"],
        )),
    ];
    if tools {
        caller = caller.with_requirement(CapabilityRequirementPlan::one(
            tool::CAPABILITY_ID,
            tool::DESCRIPTOR_VERSION,
        ));
        instances.push(
            PluginInstancePlan::new("account-tools", "lenso.auth.account-admin.agent-tools")
                .with_requirement(CapabilityRequirementPlan::one(
                    admin::CAPABILITY_ID,
                    admin::DESCRIPTOR_VERSION,
                ))
                .with_capability(endpoint(
                    tool::CAPABILITY_ID,
                    tool::DESCRIPTOR_VERSION,
                    &["catalog", "execute"],
                )),
        );
        bindings.push(CapabilityBinding::new(
            "caller",
            tool::CAPABILITY_ID,
            tool::DESCRIPTOR_VERSION,
            "account-tools",
        ));
        bindings.push(CapabilityBinding::new(
            "account-tools",
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            "account",
        ));
    }
    instances.push(caller);
    AppComposition::new(instances, bindings).resolve().unwrap()
}

async fn start(url: &str, schema: &str, tools: bool, authorized: bool) -> NativeApp {
    // Retain the real linked providers, not replacement business fixtures.
    let _ = lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON;
    let _ = lenso_auth_account_admin_agent_tools_plugin::PLUGIN_DESCRIPTOR_JSON;
    Kernel::start_native(
        plan(schema, tools, authorized),
        TokioDriver::new(),
        NativePluginRegistry::new()
            .with_linked_factories()
            .with_factory(CallerFactory)
            .with_factory(StaticSecretsFactory {
                values: BTreeMap::from([
                    ("auth/database-url".into(), url.into()),
                    ("auth/assertion-signing-key".into(), SIGNING_SECRET.into()),
                    ("auth/token-pepper".into(), TOKEN_PEPPER.into()),
                ]),
            }),
    )
    .await
    .unwrap()
}

async fn execute(
    app: &NativeApp,
    name: &str,
    arguments: Value,
) -> Result<tool::ExecuteResponse, tool::ExecuteError> {
    app.invoke::<tool::ToolProviderExecute>(
        "caller",
        tool::EXECUTE_OPERATION,
        tool::ExecuteRequest {
            name: name.into(),
            arguments_json: arguments.to_string().try_into().unwrap(),
        },
    )
    .await
    .unwrap()
}

async fn authenticate(
    app: &NativeApp,
    token: &str,
) -> Result<auth::AuthResponse, auth::AuthenticateError> {
    app.invoke::<auth::Auth>(
        "caller",
        auth::AUTHENTICATE_OPERATION,
        auth::AuthRequest {
            credential: Some(auth::AuthenticateRequestCredential {
                scheme: "session".into(),
                value: token.into(),
            }),
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL; exercised by CI"]
async fn real_business_tools_preserve_authority_state_and_removal() {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").expect("dedicated test PostgreSQL required");
    let schema = format!("agent_business_{}", std::process::id());
    AccountAuthOperator::setup(&url, &schema).await.unwrap();
    AccountAuthOperator::upgrade(&url, &schema).await.unwrap();
    tokio::task::LocalSet::new().run_until(async {
        let app = start(&url, &schema, true, true).await;
        let subject = app.invoke::<directory::DirectoryEnsureIdentity>("caller", "ensure_identity",
            directory::EnsureIdentityRequest { provider: "test".into(), external_subject: "business-tool-user".into() }).await.unwrap().unwrap().subject;
        let issued = app.invoke::<issuer::CredentialIssuerIssue>("caller", "issue",
            serde_json::from_value(json!({"subject": subject, "actor_kind":"user", "assurance":"test",
                "audience":["test.read@1:read"], "claims":{},
                "expires_at": (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).format(&time::format_description::well_known::Rfc3339).unwrap()})).unwrap()).await.unwrap().unwrap();
        let token = issued.credential;
        assert!(authenticate(&app, &token).await.is_ok());
        let catalog = app.invoke::<tool::ToolProviderCatalog>("caller", "catalog", tool::CatalogRequest {}).await.unwrap().unwrap();
        assert_eq!(catalog.tools.len(), 3);
        let subjects = execute(&app, LIST_SUBJECTS_TOOL, json!({"limit":10,"cursor":null})).await.unwrap();
        let subjects: Value = serde_json::from_str(&subjects.content).unwrap();
        assert_eq!(subjects["subjects"][0]["subject"], subject);
        assert_eq!(subjects["subjects"][0]["status"], "active");
        let sessions = execute(&app, LIST_SESSIONS_TOOL, json!({"subject":subject,"limit":10,"cursor":null})).await.unwrap();
        assert!(!sessions.content.contains(&token));
        assert!(!sessions.content.contains(SIGNING_SECRET));
        assert!(!sessions.content.contains(TOKEN_PEPPER));
        assert!(matches!(execute(&app, "authenticate", json!({})).await, Err(tool::ExecuteError::NotFound)));
        assert!(matches!(execute(&app, LIST_SUBJECTS_TOOL, json!({"limit":0,"cursor":null})).await, Err(tool::ExecuteError::InvalidArguments)));
        assert!(matches!(execute(&app, SET_SUBJECT_STATUS_TOOL, json!({"subject":"missing","status":"disabled","reason":null,"disabled_until":null})).await, Err(tool::ExecuteError::NotFound)));
        let disable = json!({"subject":subject,"status":"disabled","reason":"test change","disabled_until":null});
        let cancellation = lenso_kernel::CancellationToken::new();
        cancellation.cancel();
        let cancelled = app.invoke_with_context::<tool::ToolProviderExecute>("caller", "execute",
            InvocationContext::new(100, None, cancellation), tool::ExecuteRequest {
                name: SET_SUBJECT_STATUS_TOOL.into(), arguments_json: disable.to_string().try_into().unwrap(),
            }).await;
        assert!(matches!(cancelled, Err(RuntimeFailure::Cancelled { .. })));
        assert!(authenticate(&app, &token).await.is_ok(), "cancelled mutation must not disable the account");
        execute(&app, SET_SUBJECT_STATUS_TOOL, disable.clone()).await.unwrap();
        assert!(matches!(authenticate(&app, &token).await, Err(auth::AuthenticateError::Revoked)));
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);

        // New runtime, same durable provider; remove the allowlisted caller grant.
        let app = start(&url, &schema, true, false).await;
        assert!(matches!(execute(&app, LIST_SUBJECTS_TOOL, json!({"limit":10,"cursor":null})).await, Err(tool::ExecuteError::PermissionDenied)));
        let enable = json!({"subject":subject,"status":"active","reason":null,"disabled_until":null});
        assert!(matches!(execute(&app, SET_SUBJECT_STATUS_TOOL, enable.clone()).await, Err(tool::ExecuteError::PermissionDenied)));
        assert!(matches!(authenticate(&app, &token).await, Err(auth::AuthenticateError::Revoked)));
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);

        let app = start(&url, &schema, true, true).await;
        let subjects = execute(&app, LIST_SUBJECTS_TOOL, json!({"limit":10,"cursor":null})).await.unwrap();
        let subjects: Value = serde_json::from_str(&subjects.content).unwrap();
        assert_eq!(subjects["subjects"][0]["status"], "disabled");
        execute(&app, SET_SUBJECT_STATUS_TOOL, enable).await.unwrap();
        assert!(matches!(authenticate(&app, &token).await, Err(auth::AuthenticateError::Revoked)), "enable must not resurrect revoked credentials");
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);

        // Remove the Tool Plugin entirely; business facts and Auth still work.
        let app = start(&url, &schema, false, false).await;
        let status = app.invoke::<directory::DirectoryReadStatus>("caller", "read_status", directory::ReadStatusRequest { subject }).await.unwrap().unwrap();
        assert_eq!(status.status, directory::ReadStatusResponseStatus::Active);
        assert!(app.handle::<tool::ToolProviderExecute>("caller").is_err(), "removed Tool must not remain callable");
        assert!(matches!(authenticate(&app, &token).await, Err(auth::AuthenticateError::Revoked)));
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);
        let app = start(&url, &schema, true, true).await;
        let pool = PgPool::connect(&url).await.unwrap();
        pool.execute(AssertSqlSafe(format!("ALTER TABLE \"{schema}\".identity_subjects RENAME TO unavailable_subjects"))).await.unwrap();
        let failure = app.invoke::<tool::ToolProviderExecute>("caller", "execute", tool::ExecuteRequest {
            name: LIST_SUBJECTS_TOOL.into(), arguments_json: json!({"limit":10,"cursor":null}).to_string().try_into().unwrap(),
        }).await;
        assert!(matches!(failure, Err(RuntimeFailure::PluginFailure { .. })), "database failure must remain Runtime, not a business denial");
        pool.execute(AssertSqlSafe(format!("ALTER TABLE \"{schema}\".unavailable_subjects RENAME TO identity_subjects"))).await.unwrap();
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);
        pool.close().await;
    }).await;
    let pool = PgPool::connect(&url).await.unwrap();
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL; exercised by CI"]
async fn delegated_user_session_requires_grant_and_survives_restart() {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").unwrap();
    let schema = format!("agent_delegation_{}", std::process::id());
    AccountAuthOperator::setup(&url, &schema).await.unwrap();
    tokio::task::LocalSet::new().run_until(async {
        let app = start(&url, &schema, false, true).await;
        let subject = app.invoke::<directory::DirectoryEnsureIdentity>("caller", "ensure_identity",
            directory::EnsureIdentityRequest { provider: "test".into(), external_subject: "delegated-user".into() }).await.unwrap().unwrap().subject;
        let expiry = |minutes| (time::OffsetDateTime::now_utc() + time::Duration::minutes(minutes)).format(&time::format_description::well_known::Rfc3339).unwrap();
        let issued = app.invoke::<issuer::CredentialIssuerIssue>("caller", "issue", serde_json::from_value(json!({
            "subject":subject,"actor_kind":"user","assurance":"test","claims":{},
            "audience":["lenso.projects@1:get_issue","lenso.projects@1:update_issue"],"expires_at":expiry(30)
        })).unwrap()).await.unwrap().unwrap();
        let request = delegation::GrantRequest { parent_credential:issued.credential.clone(), audience:vec!["lenso.projects@1:get_issue".into()], expires_at:expiry(5) };
        assert!(!format!("{request:?}").contains(&issued.credential));
        let grant = app.invoke::<delegation::Delegation>("caller", "grant", request.clone()).await.unwrap().unwrap();
        assert_eq!(grant.subject, subject);
        assert!(!format!("{grant:?}").contains(&grant.credential));
        let authenticated = authenticate(&app, &grant.credential).await.unwrap().assertion.unwrap();
        assert_eq!(authenticated.subject, subject);
        assert_eq!(authenticated.audience, request.audience);
        let mut wider = request.clone(); wider.audience = vec!["lenso.projects@1:archive_issue".into()];
        assert!(matches!(app.invoke::<delegation::Delegation>("caller","grant",wider).await.unwrap(), Err(delegation::GrantError::InvalidScope)));
        let mut nested = request.clone(); nested.parent_credential = grant.credential.clone(); nested.expires_at = expiry(1);
        assert!(matches!(app.invoke::<delegation::Delegation>("caller","grant",nested).await.unwrap(), Err(delegation::GrantError::NestedDelegation)));
        let mut expired = request.clone(); expired.expires_at = expiry(-1);
        assert!(matches!(app.invoke::<delegation::Delegation>("caller","grant",expired).await.unwrap(), Err(delegation::GrantError::Expired)));
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);
        let app = start(&url, &schema, false, false).await;
        assert!(authenticate(&app, &grant.credential).await.is_ok());
        assert!(matches!(app.invoke::<delegation::Delegation>("caller","grant",request).await.unwrap(), Err(delegation::GrantError::PermissionDenied)));
        app.invoke::<issuer::CredentialIssuerRevokeCredential>("caller","revoke_credential", issuer::RevokeCredentialRequest { scheme:"session".into(), credential:issued.credential }).await.unwrap().unwrap();
        assert!(matches!(authenticate(&app,&grant.credential).await, Err(auth::AuthenticateError::Revoked)));
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);
    }).await;
    let pool = PgPool::connect(&url).await.unwrap();
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
    pool.close().await;
}
