use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan,
};
use lenso_auth_account_plugin::{AccountAuthConfig, AccountAuthOperator, assertion_public_key};
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
        Box::pin(std::future::ready(Ok(result)))
    }
}

use lenso_capability_http_endpoint as http;
fn instance(key: &str, descriptor: &str, config: &Value) -> PluginInstancePlan {
    let descriptor: Value = serde_json::from_str(descriptor).unwrap();
    let mut result = PluginInstancePlan::new(key, descriptor["plugin_id"].as_str().unwrap())
        .with_configuration(config.to_string());
    for entry in descriptor["provided_capabilities"].as_array().unwrap() {
        let mut endpoint = CapabilityEndpointPlan::new(
            entry["capability_id"].as_str().unwrap(),
            entry["descriptor_version"].as_str().unwrap(),
            entry["operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap()),
        );
        if entry["cross_lane_transfer"] == true {
            endpoint = endpoint.with_cross_lane_transfer();
        }
        result = result.with_capability(endpoint);
    }
    for entry in descriptor["required_capabilities"].as_array().unwrap() {
        result = result.with_requirement(CapabilityRequirementPlan::one(
            entry["capability_id"].as_str().unwrap(),
            entry["descriptor_version"].as_str().unwrap(),
        ));
    }
    result
}
async fn start(url: &str, schema: &str) -> NativeApp {
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
    .with_delegation_callers(vec!["consent".into()])
    .unwrap();
    let account = instance(
        "account",
        lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON,
        &serde_json::to_value(config).unwrap(),
    );
    let consent = instance(
        "consent",
        lenso_auth_agent_connection_plugin::PLUGIN_DESCRIPTOR_JSON,
        &json!({"origin":"https://projects.test","label":"Projects","audience":["lenso.projects@1:get_issue"],"grant_ttl_seconds":300,"login_path":"/login"}),
    );
    let secrets = PluginInstancePlan::new("secrets", SECRETS_PACKAGE_ID).with_capability(
        CapabilityEndpointPlan::new(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            ["resolve"],
        ),
    );
    let mut caller = PluginInstancePlan::new("caller", CALLER_PACKAGE_ID);
    let mut bindings = vec![
        CapabilityBinding::new(
            "account",
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            "secrets",
        ),
        CapabilityBinding::new(
            "consent",
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            "account",
        ),
        CapabilityBinding::new(
            "consent",
            delegation::CAPABILITY_ID,
            delegation::DESCRIPTOR_VERSION,
            "account",
        ),
    ];
    for (id, version, target) in [
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION, "account"),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            "account",
        ),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION, "account"),
        (http::CAPABILITY_ID, http::DESCRIPTOR_VERSION, "consent"),
    ] {
        caller = caller.with_requirement(CapabilityRequirementPlan::one(id, version));
        bindings.push(CapabilityBinding::new("caller", id, version, target));
    }
    Kernel::start_native(
        AppComposition::new(vec![account, consent, secrets, caller], bindings)
            .resolve()
            .unwrap(),
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
async fn request(
    app: &NativeApp,
    route: &str,
    credential: Option<&str>,
    body: String,
    origin: Option<&str>,
    query: Option<String>,
) -> http::HandleResponse {
    app.invoke::<http::EndpointHandle>(
        "caller",
        "handle",
        http::HandleRequest {
            method: if route == "authorize" { "GET" } else { "POST" }.into(),
            path: format!("/auth/agent/{route}"),
            route_id: format!("auth.agent-connection.{route}"),
            request_id: "test".into(),
            body: body.into_bytes().into(),
            credential: credential.map(|value| http::HandleRequestCredential {
                scheme: "session".into(),
                value: value.into(),
            }),
            headers: origin
                .map(|value| {
                    vec![http::HandleRequestHeadersItem {
                        name: "origin".into(),
                        value: value.into(),
                    }]
                })
                .unwrap_or_default(),
            path_parameters: vec![],
            query,
        },
    )
    .await
    .unwrap()
    .unwrap()
}
fn field(html: &str, name: &str) -> String {
    html.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn browser_consent_hands_off_only_a_restricted_authenticated_grant() {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").unwrap();
    let schema = format!("browser_grant_{}", std::process::id());
    AccountAuthOperator::setup(&url, &schema).await.unwrap();
    tokio::task::LocalSet::new().run_until(async{
        let app=start(&url,&schema).await;
        let subject=app.invoke::<directory::DirectoryEnsureIdentity>("caller","ensure_identity",directory::EnsureIdentityRequest{provider:"test".into(),external_subject:"browser-user".into()}).await.unwrap().unwrap().subject;
        let parent=app.invoke::<issuer::CredentialIssuerIssue>("caller","issue",serde_json::from_value(json!({"subject":subject,"actor_kind":"user","assurance":"test","claims":{},"audience":["lenso.projects@1:get_issue","lenso.projects@1:update_issue"],"expires_at":(time::OffsetDateTime::now_utc()+time::Duration::hours(1)).format(&time::format_description::well_known::Rfc3339).unwrap()})).unwrap()).await.unwrap().unwrap();
        let begin=request(&app,"begin",None,String::new(),None,None).await;
        let begin:Value=serde_json::from_slice(begin.body.as_ref()).unwrap();
        assert!(!begin.to_string().contains(&parent.credential));
        let id=begin["attempt_id"].as_str().unwrap();let query=Some(format!("attempt={id}"));
        let unauthenticated = request(&app,"authorize",None,String::new(),None,query.clone()).await;
        assert_eq!(unauthenticated.status,401);
        let html = String::from_utf8(unauthenticated.body.as_ref().to_vec()).unwrap();
        assert!(html.contains("https://projects.test/login?return_to="));
        assert!(!html.contains(&parent.credential));
        let page=request(&app,"authorize",Some(&parent.credential),String::new(),None,query).await;
        assert_eq!(page.status,200);
        assert!(page.headers.iter().any(|header|header.name=="referrer-policy" && header.value=="same-origin"));
        let html=std::str::from_utf8(page.body.as_ref()).unwrap();assert!(!html.contains(&parent.credential));assert!(!html.contains(begin["polling_secret"].as_str().unwrap()));
        let body=format!("attempt={id}&consent={}",field(html,"consent"));
        assert_eq!(request(&app,"approve",Some(&parent.credential),body.clone(),Some("https://attacker.test"),None).await.status,403);
        assert_eq!(request(&app,"approve",Some(&parent.credential),body.clone(),Some("https://projects.test"),None).await.status,200);
        assert_eq!(request(&app,"approve",Some(&parent.credential),body,Some("https://projects.test"),None).await.status,403);
        assert_eq!(request(&app,"poll",None,json!({"attempt_id":id,"polling_secret":"wrong"}).to_string(),None,None).await.status,404);
        let poll=request(&app,"poll",None,json!({"attempt_id":id,"polling_secret":begin["polling_secret"]}).to_string(),None,None).await;
        let poll:Value=serde_json::from_slice(poll.body.as_ref()).unwrap();assert_eq!(poll["state"],"connected");assert_eq!(poll["grant"]["subject"],subject);assert_eq!(poll["grant"]["audience"],json!(["lenso.projects@1:get_issue"]));
        let child=poll["grant"]["credential"].as_str().unwrap();assert_ne!(child,parent.credential);
        app.invoke::<issuer::CredentialIssuerRevokeCredential>("caller","revoke_credential",issuer::RevokeCredentialRequest{scheme:"session".into(),credential:parent.credential}).await.unwrap().unwrap();
        let authenticated=app.invoke::<auth::Auth>("caller","authenticate",auth::AuthRequest{credential:Some(auth::AuthenticateRequestCredential{scheme:"session".into(),value:child.into()})}).await.unwrap();assert!(matches!(authenticated,Err(auth::AuthenticateError::Revoked)));
        assert_eq!(app.shutdown(Duration::from_secs(2)).await,ShutdownOutcome::Clean);
    }).await;
    let pool = PgPool::connect(&url).await.unwrap();
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
    pool.close().await;
}
